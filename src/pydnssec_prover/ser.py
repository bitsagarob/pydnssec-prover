"""
Logic to read and write resource record (streams) from DNS wire format

This module provides functions to parse DNS records from RFC 9102 format and 
serialize them back to wire format.
"""

from typing import List, Tuple, Optional, Union
import struct
from io import BytesIO


class SerializationError(Exception):
    """Error during serialization/deserialization"""
    pass


def read_u8(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a u8 from bytes at offset, return (value, new_offset)"""
    if offset >= len(data):
        raise SerializationError("Not enough data for u8")
    return data[offset], offset + 1


def read_u16(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a u16 from bytes at offset in big-endian format"""
    if offset + 1 >= len(data):
        raise SerializationError("Not enough data for u16")
    return struct.unpack('>H', data[offset:offset + 2])[0], offset + 2


def read_u32(data: bytes, offset: int) -> Tuple[int, int]:
    """Read a u32 from bytes at offset in big-endian format"""
    if offset + 3 >= len(data):
        raise SerializationError("Not enough data for u32")
    return struct.unpack('>I', data[offset:offset + 4])[0], offset + 4


def read_u8_len_prefixed_bytes(data: bytes, offset: int) -> Tuple[bytes, int]:
    """Read length-prefixed bytes where length is a u8"""
    if offset >= len(data):
        raise SerializationError("Not enough data for length byte")
    length = data[offset]
    offset += 1
    if offset + length > len(data):
        raise SerializationError("Not enough data for prefixed bytes")
    return data[offset:offset + length], offset + length


def write_nsec_types_bitmap(out: BytesIO, types: bytes):
    """Write NSEC types bitmap to output stream"""
    if len(types) != 8192:
        raise SerializationError("NSEC types bitmap must be 8192 bytes")
    
    # Process in 32-byte chunks (windows)
    for idx in range(0, len(types), 32):
        chunk = types[idx:idx + 32]
        # Find last non-zero byte in this window
        last_nonzero_idx = None
        for i in range(len(chunk) - 1, -1, -1):
            if chunk[i] != 0:
                last_nonzero_idx = i
                break
        
        if last_nonzero_idx is not None:
            window_block = idx // 32
            bitmap_length = last_nonzero_idx + 1
            out.write(struct.pack('B', window_block))
            out.write(struct.pack('B', bitmap_length))
            out.write(chunk[:bitmap_length])


def nsec_types_bitmap_len(types: bytes) -> int:
    """Calculate the serialized length of an NSEC types bitmap"""
    if len(types) != 8192:
        raise SerializationError("NSEC types bitmap must be 8192 bytes")
    
    total_len = 0
    for idx in range(0, len(types), 32):
        chunk = types[idx:idx + 32]
        # Find last non-zero byte in this window  
        last_nonzero_idx = None
        for i in range(len(chunk) - 1, -1, -1):
            if chunk[i] != 0:
                last_nonzero_idx = i
                break
        
        if last_nonzero_idx is not None:
            total_len += 2 + last_nonzero_idx + 1  # window_block + length + data
    
    return total_len


def read_nsec_types_bitmap(data: bytes, offset: int, length: int) -> Tuple[bytes, int]:
    """Read NSEC types bitmap from wire format"""
    types = bytearray(8192)
    end_offset = offset + length
    
    while offset < end_offset:
        if offset + 1 >= end_offset:
            raise SerializationError("Incomplete NSEC bitmap window header")
        
        window_block = data[offset]
        bitmap_length = data[offset + 1]
        offset += 2

        if bitmap_length == 0 or bitmap_length > 32:
            raise SerializationError("Invalid NSEC bitmap window length")

        if offset + bitmap_length > end_offset:
            raise SerializationError("NSEC bitmap window extends beyond available data")
        
        start_idx = window_block * 32
        if start_idx + bitmap_length > 8192:
            raise SerializationError("NSEC bitmap window exceeds maximum size")
        
        types[start_idx:start_idx + bitmap_length] = data[offset:offset + bitmap_length]
        offset += bitmap_length
    
    return bytes(types), offset


# A compression pointer may only be followed this many times. Without a cap the two bytes
# "\xc0\x00" are a self-reference that never terminates.
NAME_RECURSION_LIMIT = 255


def _do_read_wire_packet_labels(data: bytes, offset: int, wire_packet: bytes,
                                name: bytearray, recursion_limit: int) -> int:
    """Read the labels of a name into `name`, returning the offset just past it"""
    while True:
        if offset >= len(data):
            raise SerializationError("Unexpected end of data while reading name")

        length = data[offset]
        offset += 1

        if length == 0:
            if not name:
                name.extend(b'.')
            break
        elif length >= 0xc0 and recursion_limit > 0:
            if offset >= len(data):
                raise SerializationError("Incomplete compression pointer")
            pointer_offset = ((length & 0x3f) << 8) | data[offset]
            offset += 1
            if pointer_offset >= len(wire_packet):
                raise SerializationError("Compression pointer beyond packet bounds")
            _do_read_wire_packet_labels(wire_packet, pointer_offset, wire_packet, name,
                                        recursion_limit - 1)
            break

        # A label must be followed by at least the terminating zero byte, so strictly more than
        # `length` bytes have to remain.
        if len(data) - offset <= length:
            raise SerializationError("Label extends beyond available data")
        if length > 63:
            raise SerializationError("DNS label too long")

        name.extend(data[offset:offset + length])
        name.extend(b'.')
        offset += length

        if len(name) > 255:
            raise SerializationError("Name too long")

    return offset


def read_wire_packet_name_bytes(data: bytes, offset: int,
                                wire_packet: Optional[bytes] = None) -> Tuple[bytes, int]:
    """
    Read a DNS name from wire format as raw bytes, handling compression against wire_packet.

    Pass an empty wire_packet to reject compression pointers outright.

    Returns (name_bytes, new_offset)
    """
    if wire_packet is None:
        wire_packet = data

    name = bytearray()
    offset = _do_read_wire_packet_labels(data, offset, wire_packet, name, NAME_RECURSION_LIMIT)
    if len(name) > 255:
        raise SerializationError("Name too long")
    return bytes(name), offset


def read_wire_packet_name(data: bytes, offset: int, wire_packet: Optional[bytes] = None) -> Tuple[str, int]:
    """
    Read a DNS name from wire format, handling compression if wire_packet is provided

    Returns (name_string, new_offset)
    """
    name, offset = read_wire_packet_name_bytes(data, offset, wire_packet)
    try:
        return name.decode('utf-8'), offset
    except UnicodeDecodeError:
        raise SerializationError("Invalid UTF-8 in DNS label")


def write_name(out: BytesIO, name: str):
    """Write a DNS name in wire format"""
    canonical_name = name.lower()
    if canonical_name == ".":
        out.write(b'\x00')
    else:
        # Remove trailing dot if present for processing
        if canonical_name.endswith('.'):
            canonical_name = canonical_name[:-1]
        
        for label in canonical_name.split('.'):
            label_bytes = label.encode('utf-8')
            if len(label_bytes) > 63:
                raise SerializationError("DNS label too long")
            out.write(struct.pack('B', len(label_bytes)))
            out.write(label_bytes)
        out.write(b'\x00')  # End of name


def write_name_without_case_modification(out: BytesIO, name_bytes: bytes):
    """
    Write a DNS name in wire format from raw bytes, preserving case

    RFC 6840 section 5.1 forbids lowercasing the NSEC next_name field, and the bytes may not be a
    valid host name at all.
    """
    if name_bytes == b".":
        out.write(b'\x00')
    else:
        for label in name_bytes.split(b'.'):
            if len(label) > 63:
                raise SerializationError("DNS label too long")
            out.write(struct.pack('B', len(label)))
            out.write(label)


def name_len(name: str) -> int:
    """Calculate the wire format length of a DNS name"""
    canonical_name = name.lower()
    if canonical_name == ".":
        return 1
    else:
        if canonical_name.endswith('.'):
            canonical_name = canonical_name[:-1]
        
        total_len = 1  # Final null byte
        for label in canonical_name.split('.'):
            total_len += 1 + len(label.encode('utf-8'))  # Length byte + label
        return total_len 
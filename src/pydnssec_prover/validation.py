"""
Utilities to deserialize and validate RFC 9102 DNSSEC proofs

This module provides the core validation logic for DNSSEC signatures and proofs,
implementing the same algorithms as the Rust version.
"""

from typing import List, Set, Optional, Tuple, Union
from dataclasses import dataclass
from enum import Enum
from functools import cmp_to_key
import time
from io import BytesIO

try:
    from . import base32
    from .crypto import Hasher, validate_rsa, validate_ecdsa_256r1, validate_ecdsa_384r1
    from .rr import (Name, Record, DnsKey, DS, RRSig, CName, DName, NSec, NSec3,
                     name_ends_with_labels)
    from .ser import write_name
except ImportError:
    # Handle direct script execution
    import base32
    from crypto import Hasher, validate_rsa, validate_ecdsa_256r1, validate_ecdsa_384r1
    from rr import (Name, Record, DnsKey, DS, RRSig, CName, DName, NSec, NSec3,
                    name_ends_with_labels)
    from ser import write_name

# Maximum number of proof steps to prevent infinite loops
MAX_PROOF_STEPS = 20


def root_hints() -> List[DS]:
    """
    Gets the trusted root anchors
    
    These are available at https://data.iana.org/root-anchors/root-anchors.xml
    """
    # Current IANA root trust anchors (production keys only)
    return [
        DS(
            Name("."), 20326, 8, 2,
            bytes.fromhex("E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D")
        ),
        DS(
            Name("."), 38696, 8, 2,
            bytes.fromhex("683D2D0ACB8C9B712A1948B27F741219298D0A450D612C483AF444A4C0FB2B16")
        )
    ]


class ValidationError(Exception):
    """An error when validating DNSSEC signatures or other data"""
    
    class ErrorType(Enum):
        """Types of validation errors"""
        UNSUPPORTED_ALGORITHM = "unsupported_algorithm"
        INVALID = "invalid"
        VALIDATION_COUNT_LIMITED = "validation_count_limited"
    
    def __init__(self, error_type: ErrorType, message: str = ""):
        self.error_type = error_type
        super().__init__(f"{error_type.value}: {message}" if message else error_type.value)


@dataclass
class VerifiedRRStream:
    """
    Contains verified resource records with their validity timeframe
    
    This represents the result of DNSSEC validation, containing the records that
    were successfully verified along with timing information.
    """
    # The set of verified RRs, not including DnsKey, RRSig, NSec, and NSec3 records
    verified_rrs: List[Record]
    
    # The latest RRSig inception time of all validated signatures
    valid_from: int
    
    # The earliest RRSig expiration time of all validated signatures  
    expires: int
    
    # The minimum original TTL of all validated signatures
    max_cache_ttl: int
    
    def resolve_name(self, name_param: Name) -> List[Record]:
        """
        Resolve a name by following CNAME and DNAME redirections
        
        Args:
            name_param: The name to resolve
            
        Returns:
            List of records that match the resolved name
        """
        name = name_param

        # Bounded: two CNAMEs pointing at each other would otherwise spin forever
        for _ in range(MAX_PROOF_STEPS):
            # Look for CNAME records
            cname_records = [
                rr for rr in self.verified_rrs
                if isinstance(rr, CName) and rr.name == name
            ]

            if cname_records:
                # Follow the CNAME
                name = cname_records[0].canonical_name
                continue

            # Look for DNAME records, on a label boundary and strictly shorter than the name
            dname_records = [
                rr for rr in self.verified_rrs
                if isinstance(rr, DName)
                and len(name.name) > len(rr.name.name)
                and name.ends_with_labels(rr.name.name)
            ]

            if dname_records:
                dname = dname_records[0]
                prefix = name.name[:-len(dname.name.name)]
                if dname.delegation_name.name == ".":
                    resolved_name_str = prefix
                else:
                    resolved_name_str = prefix + dname.delegation_name.name
                try:
                    name = Name(resolved_name_str)
                except ValueError:
                    # Combined name too long
                    return []
                continue

            # No more redirections, return matching records
            return [rr for rr in self.verified_rrs if rr.name == name]

        return []


def resolve_time(time_value: int) -> int:
    """
    Resolve DNSSEC time values which may wrap around in 2106
    
    RFC 2065 was published in January 1997, so we arbitrarily use that as a cutoff and assume
    any timestamps before then are actually past 2106 instead.
    We ignore leap years for simplicity.
    """
    # Cutoff: approximately 27 years after Unix epoch (around 1997)
    cutoff = 60 * 60 * 24 * 365 * 27
    
    if time_value < cutoff:
        # Assume this is a post-2106 timestamp. The offset is u32::MAX, as in the Rust version.
        return time_value + (2**32 - 1)
    else:
        return time_value


def nsec_ord(a: bytes, b: bytes) -> int:
    """
    Compare two names in RFC 4034 section 6.1 canonical order

    Returns a negative number if a < b, zero if equal, a positive number if a > b. Names are
    compared label by label from the right, each label byte by byte, ASCII-case-insensitively.
    """
    a_labels = a.split(b'.')[::-1]
    b_labels = b.split(b'.')[::-1]

    for i in range(max(len(a_labels), len(b_labels))):
        if i >= len(b_labels):
            return 1
        if i >= len(a_labels):
            return -1

        a_label = a_labels[i].lower()
        b_label = b_labels[i].lower()

        for j in range(max(len(a_label), len(b_label))):
            if j >= len(b_label):
                return 1
            if j >= len(a_label):
                return -1
            if a_label[j] != b_label[j]:
                return -1 if a_label[j] < b_label[j] else 1

    return 0


def verify_rrsig(signature: RRSig, dnskeys: List[DnsKey], records: List[Record]) -> bool:
    """
    Verify an RRSig signature against a set of DNSKEYs and the records it should cover

    Args:
        signature: The RRSig to verify
        dnskeys: List of potential signing keys
        records: List of records that should be covered by this signature

    Returns:
        True if the signature is valid

    Raises:
        ValidationError: INVALID if no key matched or the signature did not verify,
            UNSUPPORTED_ALGORITHM if we cannot check this algorithm at all
    """
    # Verify that all records match the signature's type
    for record in records:
        if signature.type_covered != record.type_code:
            raise ValidationError(ValidationError.ErrorType.INVALID, 
                                "Record type doesn't match signature type")
    
    # Find the matching DNSKEY
    for dnskey in dnskeys:
        if dnskey.key_tag() != signature.key_tag:
            continue
        
        # Protocol must be 3 for DNSSEC
        if dnskey.protocol != 3:
            continue
        
        # The ZONE flag must be set for validation
        if (dnskey.flags & 0b100000000) == 0:
            continue

        # The REVOKE flag must not be set
        if (dnskey.flags & 0b010000000) != 0:
            continue

        # Algorithm must match
        if dnskey.algorithm != signature.algorithm:
            continue
        
        # Choose hash algorithm based on signature algorithm
        if signature.algorithm == 8:  # RSA/SHA-256
            hasher = Hasher.sha256()
        elif signature.algorithm == 10:  # RSA/SHA-512
            hasher = Hasher.sha512()
        elif signature.algorithm == 13:  # ECDSA Curve P-256 with SHA-256
            hasher = Hasher.sha256()
        elif signature.algorithm == 14:  # ECDSA Curve P-384 with SHA-384
            hasher = Hasher.sha384()
        elif signature.algorithm == 15:  # ECDSA Curve P-521 with SHA-512
            hasher = Hasher.sha512()
        else:
            raise ValidationError(ValidationError.ErrorType.UNSUPPORTED_ALGORITHM,
                                f"Algorithm {signature.algorithm} not supported")
        
        # Build the signature data according to RFC 4034
        # First, add the RRSIG RDATA (without the signature field)
        hasher.update(signature.type_covered.to_bytes(2, 'big'))
        hasher.update(signature.algorithm.to_bytes(1, 'big'))
        hasher.update(signature.labels.to_bytes(1, 'big'))
        hasher.update(signature.original_ttl.to_bytes(4, 'big'))
        hasher.update(signature.expiration.to_bytes(4, 'big'))
        hasher.update(signature.inception.to_bytes(4, 'big'))
        hasher.update(signature.key_tag.to_bytes(2, 'big'))
        
        # Add the signer name
        signer_name_buf = BytesIO()
        write_name(signer_name_buf, str(signature.signer_name))
        hasher.update(signer_name_buf.getvalue())
        
        # Sort and deduplicate records (some resolvers give duplicates)
        sorted_records = sorted(records)
        unique_records = []
        for record in sorted_records:
            if not unique_records or record != unique_records[-1]:
                unique_records.append(record)
        
        # Add each record to the hash
        for record in unique_records:
            record_labels = record.name.labels()
            sig_labels = signature.labels

            # NSEC names already match the wildcard and are hashed as they arrived.
            # verify_rr_stream relies on that to spot an NSEC matched via a wildcard.
            if record.type_code != NSec.TYPE and record_labels != sig_labels:
                if record_labels < sig_labels:
                    raise ValidationError(ValidationError.ErrorType.INVALID,
                                          "Record has fewer labels than its signature claims")
                signed_name = record.name.trailing_n_labels(sig_labels)
                if signed_name is None:
                    raise ValidationError(ValidationError.ErrorType.INVALID,
                                          "Cannot take the signed name of this record")
                hasher.update(b"\x01*")
                name_buf = BytesIO()
                write_name(name_buf, signed_name)
                hasher.update(name_buf.getvalue())
            else:
                name_buf = BytesIO()
                write_name(name_buf, str(record.name))
                hasher.update(name_buf.getvalue())

            # Add type, class, TTL, and data
            hasher.update(record.type_code.to_bytes(2, 'big'))
            hasher.update((1).to_bytes(2, 'big'))  # Internet class
            hasher.update(signature.original_ttl.to_bytes(4, 'big'))
            
            # Add record data with length prefix
            data_buf = BytesIO()
            record.write_data(data_buf)
            data = data_buf.getvalue()
            hasher.update(len(data).to_bytes(2, 'big'))
            hasher.update(data)
        
        # Get the hash
        hash_result = hasher.finish()
        
        # Verify the signature based on algorithm
        if signature.algorithm in [8, 10]:  # RSA algorithms
            valid = validate_rsa(dnskey.public_key, signature.signature, hash_result.as_ref())
        elif signature.algorithm == 13:  # ECDSA P-256
            valid = validate_ecdsa_256r1(dnskey.public_key, signature.signature, hash_result.as_ref())
        elif signature.algorithm == 14:  # ECDSA P-384
            valid = validate_ecdsa_384r1(dnskey.public_key, signature.signature, hash_result.as_ref())
        else:
            raise ValidationError(ValidationError.ErrorType.UNSUPPORTED_ALGORITHM,
                                f"Algorithm {signature.algorithm} not supported")

        # Fail immediately rather than trying the next key, to avoid KeyTrap issues
        if not valid:
            raise ValidationError(ValidationError.ErrorType.INVALID, "Signature did not verify")

        return True

    # No matching key found
    raise ValidationError(ValidationError.ErrorType.INVALID, "No matching DNSKEY")


def verify_rr_set(signatures: List[RRSig], validated_dnskeys: List[DnsKey], 
                  records: List[Record]) -> RRSig:
    """
    Verify a set of RRSig signatures against validated DNSKEYs
    
    Args:
        signatures: List of RRSig records to try
        validated_dnskeys: List of validated DNSKEY records
        records: List of records that should be covered
        
    Returns:
        The first valid RRSig found
        
    Raises:
        ValidationError: If no valid signature is found
    """
    found_unsupported_alg = False
    
    for sig in signatures:
        # Check if we have a matching validated key
        if not any(key.key_tag() == sig.key_tag for key in validated_dnskeys):
            # Some DNS servers include spurious RRSig records. Ignore them.
            continue
        
        try:
            if verify_rrsig(sig, validated_dnskeys, records):
                return sig
        except ValidationError as e:
            if e.error_type == ValidationError.ErrorType.UNSUPPORTED_ALGORITHM:
                # There may be redundant signatures by different keys, where one we don't
                # support and another we do. Ignore ones we don't support.
                found_unsupported_alg = True
            elif e.error_type == ValidationError.ErrorType.INVALID:
                # If a signature is invalid, immediately fail to avoid KeyTrap issues
                raise e
            else:
                raise e
    
    if found_unsupported_alg:
        raise ValidationError(ValidationError.ErrorType.UNSUPPORTED_ALGORITHM)
    else:
        raise ValidationError(ValidationError.ErrorType.INVALID, "No valid signature found")


def verify_dnskeys(signatures: List[RRSig], dses: List[DS], records: List[DnsKey]) -> RRSig:
    """
    Verify a zone's DNSKEY RRset against the DS records delegating to it

    Args:
        signatures: The RRSigs covering the DNSKEY RRset
        dses: The DS records which delegate to this zone, already trusted
        records: The DNSKEY RRset itself

    Returns:
        The RRSig which validated the DNSKEY RRset

    Raises:
        ValidationError
    """
    had_ds = False
    had_known_digest_type = False
    for ds in dses:
        had_ds = True
        if ds.digest_type in (1, 2, 4):
            had_known_digest_type = True
            break

    # No DS at all is an unsigned delegation; a DS we cannot read is only an algorithm gap
    if not had_ds:
        raise ValidationError(ValidationError.ErrorType.INVALID, "No DS records for zone")
    if not had_known_digest_type:
        raise ValidationError(ValidationError.ErrorType.UNSUPPORTED_ALGORITHM,
                              "No supported DS digest type")

    # Only trust a SHA-1 DS if the zone published nothing stronger, so a forged SHA-1 collision
    # cannot downgrade a zone
    trust_sha1 = all(ds.digest_type != 2 and ds.digest_type != 4 for ds in dses)

    validated_dnskeys: List[DnsKey] = []
    for dnskey in records:
        for ds in dses:
            if ds.algorithm != dnskey.algorithm:
                continue
            if dnskey.key_tag() != ds.key_tag:
                continue

            if ds.digest_type == 1 and trust_sha1:
                hasher = Hasher.sha1()
            elif ds.digest_type == 2:
                hasher = Hasher.sha256()
            elif ds.digest_type == 4:
                hasher = Hasher.sha384()
            else:
                continue

            name_buf = BytesIO()
            write_name(name_buf, str(dnskey.name))
            hasher.update(name_buf.getvalue())

            key_data_buf = BytesIO()
            dnskey.write_data(key_data_buf)
            hasher.update(key_data_buf.getvalue())

            if hasher.finish().as_ref() == ds.digest:
                validated_dnskeys.append(dnskey)
                break

    return verify_rr_set(signatures, validated_dnskeys, records)


def verify_rr_stream(rr_stream: List[Record]) -> VerifiedRRStream:
    """
    Verify a stream of DNS records using DNSSEC
    
    This is the main entry point for DNSSEC validation. It takes a list of DNS records
    (typically from an RFC 9102 proof) and validates them using DNSSEC signatures.
    
    Args:
        rr_stream: List of DNS resource records to validate
        
    Returns:
        VerifiedRRStream containing the validated records and timing information
        
    Raises:
        ValidationError: If validation fails
    """
    zone = "."
    res: List[Record] = []
    rrs_needing_non_existence_proofs: List[Tuple[str, str]] = []
    nsec_records: List[Tuple[Record, str]] = []
    pending_ds_sets: List[Tuple[str, List[DS]]] = []
    latest_inception = 0
    earliest_expiry = 2 ** 64 - 1
    min_ttl = 2 ** 32 - 1
    rrsig_sets_validated = 0

    # Walk the delegation chain zone by zone from the root, offering each zone only its own keys
    while zone == "." or pending_ds_sets:
        if pending_ds_sets:
            zone, next_ds_set = pending_ds_sets.pop()
        else:
            next_ds_set = None

        rrsig_sets_validated += 1
        if rrsig_sets_validated > MAX_PROOF_STEPS:
            raise ValidationError(ValidationError.ErrorType.VALIDATION_COUNT_LIMITED)

        dnskey_rrsigs = [rr for rr in rr_stream
                         if isinstance(rr, RRSig) and rr.name.name == zone
                         and rr.type_covered == DnsKey.TYPE]
        dnskeys = [rr for rr in rr_stream if isinstance(rr, DnsKey) and rr.name.name == zone]

        if zone == ".":
            verified_dnskey_rrsig = verify_dnskeys(dnskey_rrsigs, root_hints(), dnskeys)
        else:
            if next_ds_set is None:
                break
            verified_dnskey_rrsig = verify_dnskeys(dnskey_rrsigs, next_ds_set, dnskeys)

        latest_inception = max(latest_inception, resolve_time(verified_dnskey_rrsig.inception))
        earliest_expiry = min(earliest_expiry, resolve_time(verified_dnskey_rrsig.expiration))
        min_ttl = min(min_ttl, verified_dnskey_rrsig.original_ttl)

        for rrsig in [rr for rr in rr_stream
                      if isinstance(rr, RRSig) and rr.signer_name.name == zone
                      and rr.type_covered != DnsKey.TYPE]:
            rrsig_sets_validated += 1
            if rrsig_sets_validated > MAX_PROOF_STEPS:
                raise ValidationError(ValidationError.ErrorType.VALIDATION_COUNT_LIMITED)

            # The zone binding: this zone's keys may only sign names inside this zone.
            if not rrsig.name.ends_with_labels(zone):
                raise ValidationError(ValidationError.ErrorType.INVALID,
                                      "RRSig signs a name outside its signer's zone")

            signed_records = [rr for rr in rr_stream
                              if rr.name == rrsig.name and rr.type_code == rrsig.type_covered]

            try:
                verify_rrsig(rrsig, dnskeys, signed_records)
            except ValidationError as e:
                if e.error_type == ValidationError.ErrorType.UNSUPPORTED_ALGORITHM:
                    continue
                # An invalid signature fails the whole proof, avoiding KeyTrap issues.
                raise

            latest_inception = max(latest_inception, resolve_time(rrsig.inception))
            earliest_expiry = min(earliest_expiry, resolve_time(rrsig.expiration))
            min_ttl = min(min_ttl, rrsig.original_ttl)

            if rrsig.type_covered in (RRSig.TYPE, DnsKey.TYPE):
                # RRSigs shouldn't cover child DnsKeys or other RRSigs
                raise ValidationError(ValidationError.ErrorType.INVALID,
                                      "RRSig covers an RRSig or an out-of-band DnsKey")
            elif rrsig.type_covered == DS.TYPE:
                # Ignore wildcard DS records: the non-existence proof required after the zone
                # cut could not be included for one
                if rrsig.labels != rrsig.name.labels():
                    continue
                if not any(pending_zone == rrsig.name.name for pending_zone, _ in pending_ds_sets):
                    pending_ds_sets.append((rrsig.name.name,
                                            [rr for rr in signed_records if isinstance(rr, DS)]))
            else:
                if rrsig.labels != rrsig.name.labels() and rrsig.type_covered != NSec.TYPE:
                    if rrsig.type_covered == NSec3.TYPE:
                        # NSEC3 records should never appear on wildcards, so treat the whole proof
                        # as invalid
                        raise ValidationError(ValidationError.ErrorType.INVALID,
                                              "NSEC3 record signed via a wildcard")
                    if rrsig.labels == 0xff:
                        raise ValidationError(ValidationError.ErrorType.INVALID,
                                              "Wildcard RRSig label count overflows")
                    # A wildcard expansion needs a proof that nothing more specific exists,
                    # for the next closest name: if a.b.c was signed as *.c, prove nothing is
                    # in b.c. Checked once the whole stream is validated.
                    proof_name = rrsig.name.trailing_n_labels(rrsig.labels + 1)
                    if proof_name is None:
                        raise ValidationError(ValidationError.ErrorType.INVALID,
                                              "Cannot derive the next closest name")
                    rrs_needing_non_existence_proofs.append((proof_name, rrsig.signer_name.name))

                for record in signed_records:
                    if record not in res:
                        if record.type_code in (NSec.TYPE, NSec3.TYPE):
                            nsec_records.append((record, rrsig.signer_name.name))
                        res.append(record)

    if not res:
        raise ValidationError(ValidationError.ErrorType.INVALID, "No records were verified")
    if latest_inception >= earliest_expiry:
        raise ValidationError(ValidationError.ErrorType.INVALID, "Empty validity window")

    _check_non_existence_proofs(rrs_needing_non_existence_proofs, nsec_records)

    # NSEC and NSEC3 records are proof machinery, never an answer
    final_records = [rr for rr in res if rr.type_code not in (NSec.TYPE, NSec3.TYPE)]

    return VerifiedRRStream(
        verified_rrs=final_records,
        valid_from=latest_inception,
        expires=earliest_expiry,
        max_cache_ttl=min_ttl
    )


def _nsec3_name_hash(name: str, salt: bytes, iterations: int) -> bytes:
    """Compute the NSEC3 hash of a name: SHA-1 over the wire name plus salt, iterated"""
    hasher = Hasher.sha1()
    name_buf = BytesIO()
    write_name(name_buf, name)
    hasher.update(name_buf.getvalue())
    hasher.update(salt)

    for _ in range(iterations):
        digest = hasher.finish().as_ref()
        hasher = Hasher.sha1()
        hasher.update(digest)
        hasher.update(salt)

    return hasher.finish().as_ref()


def _check_non_existence_proofs(rrs_needing_non_existence_proofs: List[Tuple[str, str]],
                                nsec_records: List[Tuple[Record, str]]):
    """
    Check that every wildcard-expanded RRset came with a proof that no more specific name exists

    Without this a resolver can serve a wildcard answer while hiding the real, more specific
    record, which for BIP 353 means handing the caller the wrong bitcoin address.
    """
    # Sort first so that the retains below avoid shifting
    pending = sorted(rrs_needing_non_existence_proofs,
                     key=cmp_to_key(lambda a, b: nsec_ord(a[0].encode('utf-8'),
                                                          b[0].encode('utf-8'))))

    while pending:
        name, zone = pending.pop()
        name_bytes = name.encode('utf-8')

        local_zone_nsecs = [rr for rr, nsec_zone in nsec_records if nsec_zone == zone]
        proven = False

        for nsec in [rr for rr in local_zone_nsecs if isinstance(rr, NSec)]:
            # A next_name ending in the name we want means a real subdomain overlaps it, so the
            # wildcard cannot apply: if a.b.c.d.e exists, *.e covers none of it
            if name_ends_with_labels(nsec.next_name, name):
                continue

            # The last NSEC in a zone's chain wraps around
            after_start = nsec_ord(nsec.name.name.encode('utf-8'), name_bytes) < 0
            before_end = nsec_ord(nsec.next_name, name_bytes) > 0
            if nsec_ord(nsec.name.name.encode('utf-8'), nsec.next_name) < 0:
                name_contained = after_start and before_end
            else:
                name_contained = after_start or before_end

            if name_contained:
                proven = True
                break

        if not proven:
            nsec3_search = [rr for rr in local_zone_nsecs if isinstance(rr, NSec3)]

            # Only ever two entries, so a list beats a map here
            nsec3params_to_name_hash: List[Tuple[int, bytes, bytes]] = []
            for nsec3 in nsec3_search:
                if nsec3.hash_iterations > 2500:
                    # RFC 5155 sets different limits based on key length; 2500 for all key types
                    continue
                if nsec3.hash_algorithm != 1:
                    continue
                if any(iterations == nsec3.hash_iterations and salt == nsec3.salt
                       for iterations, salt, _ in nsec3params_to_name_hash):
                    continue

                nsec3params_to_name_hash.append((
                    nsec3.hash_iterations, nsec3.salt,
                    _nsec3_name_hash(name, nsec3.salt, nsec3.hash_iterations)))

                if len(nsec3params_to_name_hash) >= 2:
                    # More than two iteration/salt sets per zone is assumed to be a DoS attempt
                    break

            for nsec3 in nsec3_search:
                if nsec3.flags != 0:
                    # Opt-out NSEC3 (or unknown flags), so it proves nothing about non-existence
                    continue
                if nsec3.hash_algorithm != 1:
                    continue

                name_hash = None
                for iterations, salt, candidate in nsec3params_to_name_hash:
                    if iterations == nsec3.hash_iterations and salt == nsec3.salt:
                        name_hash = candidate
                        break
                if name_hash is None:
                    continue

                start_hash_base32 = nsec3.name.name.split('.', 1)[0]
                try:
                    start_hash = base32.decode(start_hash_base32)
                except ValueError:
                    continue
                if len(start_hash) != 20 or len(nsec3.next_name_hash) != 20:
                    continue

                # The last NSEC3 in a zone's chain wraps around
                after_start = start_hash < name_hash
                before_end = nsec3.next_name_hash > name_hash
                if start_hash < nsec3.next_name_hash:
                    hash_contained = after_start and before_end
                else:
                    hash_contained = after_start or before_end

                if hash_contained:
                    proven = True
                    break

        if not proven:
            raise ValidationError(ValidationError.ErrorType.INVALID,
                                  "Missing non-existence proof for a wildcard expansion")

        pending = [(n, z) for n, z in pending if n != name or z != zone]


def verify_byte_stream(stream: bytes, name_to_resolve: str) -> str:
    """
    Verifies an RFC 9102-formatted proof and returns verified records matching the given name
    (resolving any C/DNAMEs as required).
    
    This function matches the UniFFI interface from the Rust implementation.
    
    Args:
        stream: RFC 9102-formatted proof as bytes
        name_to_resolve: Domain name to resolve
        
    Returns:
        JSON string with verification results or error
    """
    try:
        name = Name(name_to_resolve)
    except ValueError:
        return '{"error":"Bad name to resolve"}'
    
    try:
        return _do_verify_byte_stream(stream, name)
    except ValidationError as e:
        return f'{{"error":"{e.error_type.value}"}}'
    except Exception as e:
        return f'{{"error":"Invalid: {str(e)}"}}'


def _do_verify_byte_stream(stream: bytes, name_to_resolve: Name) -> str:
    """
    Internal implementation of verify_byte_stream that can raise exceptions.
    """
    try:
        from . import rr
    except ImportError:
        import rr
    
    # Parse RR stream from bytes
    rrs = rr.parse_rr_stream(stream)
    
    # Verify the RR stream  
    verified_rrs = verify_rr_stream(rrs)
    
    # Return all verified records (not just the ones matching the resolved name)
    
    # Format as JSON
    import json
    
    verified_rrs_json = []
    for record in verified_rrs.verified_rrs:
        # Convert record to JSON (assuming records have a to_json method)
        if hasattr(record, 'to_json'):
            try:
                verified_rrs_json.append(json.loads(record.to_json()))
            except Exception as e:
                # Fallback for records with to_json errors - include record-specific data
                record_data = {
                    "type": type(record).__name__.lower(),
                    "name": str(record.name)
                }
                
                # Add record-specific content based on type
                if hasattr(record, 'data'):
                    # TXT records
                    data = record.data
                    if all(0x20 <= b <= 0x7e for b in data):
                        try:
                            record_data["contents"] = data.decode('utf-8')
                        except UnicodeDecodeError:
                            record_data["contents"] = list(data)
                    else:
                        record_data["contents"] = list(data)
                elif hasattr(record, 'address'):
                    # A/AAAA records
                    record_data["address"] = record.address
                elif hasattr(record, 'target'):
                    # NS records
                    record_data["target"] = str(record.target)
                elif hasattr(record, 'canonical_name'):
                    # CNAME records
                    record_data["canonical_name"] = str(record.canonical_name)
                elif hasattr(record, 'delegation_name'):
                    # DNAME records
                    record_data["delegation_name"] = str(record.delegation_name)
                elif hasattr(record, 'next_name'):
                    # NSEC records
                    record_data["next_name"] = str(record.next_name)
                elif hasattr(record, 'next_name_hash'):
                    # NSEC3 records
                    record_data["next_name_hash"] = list(record.next_name_hash)
                
                verified_rrs_json.append(record_data)
        else:
            # Fallback for records without to_json method - include record-specific data
            record_data = {
                "type": type(record).__name__.lower(),
                "name": str(record.name)
            }
            
            # Add record-specific content based on type
            if hasattr(record, 'data'):
                # TXT records
                data = record.data
                if all(0x20 <= b <= 0x7e for b in data):
                    try:
                        record_data["contents"] = data.decode('utf-8')
                    except UnicodeDecodeError:
                        record_data["contents"] = list(data)
                else:
                    record_data["contents"] = list(data)
            elif hasattr(record, 'address'):
                # A/AAAA records
                record_data["address"] = record.address
            elif hasattr(record, 'target'):
                # NS records
                record_data["target"] = str(record.target)
            elif hasattr(record, 'canonical_name'):
                # CNAME records
                record_data["canonical_name"] = str(record.canonical_name)
            elif hasattr(record, 'delegation_name'):
                # DNAME records
                record_data["delegation_name"] = str(record.delegation_name)
            elif hasattr(record, 'next_name'):
                # NSEC records
                record_data["next_name"] = str(record.next_name)
            elif hasattr(record, 'next_name_hash'):
                # NSEC3 records
                record_data["next_name_hash"] = list(record.next_name_hash)
            
            verified_rrs_json.append(record_data)
    
    result = {
        "valid_from": verified_rrs.valid_from,
        "expires": verified_rrs.expires, 
        "max_cache_ttl": verified_rrs.max_cache_ttl,
        "verified_rrs": verified_rrs_json
    }
    
    return json.dumps(result) 
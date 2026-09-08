"""
ECDSA validation through the system libcrypto, for hosts too slow to do it in Python

This is the same pattern embit uses for secp256k1: a pure-Python implementation that is always
correct and always available, plus an optional native one selected at import. It exists because
ECDSA is where the time goes. Measured on one live silentpayments.net proof, whole chain 23.45 ms:
P-256 verification was 21.95 ms of it across 4 signatures, RSA 0.46 ms across 2, parsing 1.04 ms.
RSA is already native -- it is a single pow() -- so only ECDSA is accelerated here.

DNSSEC hands us a signature as raw r||s and a public key as raw x||y (RFC 6605), and it hands the
validator a digest rather than a message. EVP_PKEY_verify takes a digest directly for ECDSA, which
is why it is used here in preference to the EVP_DigestVerify family.

Only the stable public API is called -- d2i_PUBKEY, EVP_PKEY_CTX_new, EVP_PKEY_verify_init,
EVP_PKEY_verify and the two frees -- all of which are present and unchanged from OpenSSL 1.0.2
through 3.x. The SeedSigner OS target builds OpenSSL 3.4.1, forced on rather than LibreSSL, because
BR2_PACKAGE_PYTHON3_SSL selects BR2_PACKAGE_OPENSSL_FORCE_LIBOPENSSL.

Importing this module either yields a working, self-tested backend or raises BackendUnavailable.
There is deliberately no third outcome: a backend that quietly falls back to something slower or,
worse, to something that answers differently, is the failure mode this whole file exists to avoid.
"""

import ctypes
import ctypes.util
import sys


class BackendUnavailable(Exception):
    """Raised at import when libcrypto is missing, unusable, or fails its self-test"""


# SubjectPublicKeyInfo prefixes for an uncompressed point on each curve. Everything after these
# bytes is 0x04 || x || y, so a DNSSEC public key becomes a DER key by concatenation.
_SPKI_PREFIX = {
    32: bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200"),  # prime256v1
    48: bytes.fromhex("3076301006072a8648ce3d020106052b81040022036200"),      # secp384r1
}


# macOS ships an unversioned /usr/lib/libcrypto.dylib that is not meant to be linked against:
# dlopen'ing it makes dyld abort() the whole process rather than fail, so the `except OSError`
# below never gets a turn and the caller cannot survive it. ctypes.util.find_library("crypto")
# answers with exactly that file, which is why it is not consulted there. Only versioned dylibs
# are tried, by the names and locations a real OpenSSL install uses.
_DARWIN_NAMES = [
    "libcrypto.3.dylib",
    "libcrypto.1.1.dylib",
    "/opt/homebrew/opt/openssl@3/lib/libcrypto.3.dylib",
    "/usr/local/opt/openssl@3/lib/libcrypto.3.dylib",
]


def _load_libcrypto():
    if sys.platform == "darwin":
        names = list(_DARWIN_NAMES)
    else:
        names = ["libcrypto.so.3", "libcrypto.so.1.1", "libcrypto.so"]
        found = ctypes.util.find_library("crypto")
        if found:
            names.insert(0, found)
    for name in names:
        try:
            return ctypes.CDLL(name)
        except OSError:
            continue
    raise BackendUnavailable("no libcrypto could be loaded (tried %s)" % ", ".join(names))


_lib = _load_libcrypto()

try:
    _lib.d2i_PUBKEY.restype = ctypes.c_void_p
    _lib.d2i_PUBKEY.argtypes = [
        ctypes.c_void_p, ctypes.POINTER(ctypes.POINTER(ctypes.c_ubyte)), ctypes.c_long]
    _lib.EVP_PKEY_free.argtypes = [ctypes.c_void_p]
    _lib.EVP_PKEY_CTX_new.restype = ctypes.c_void_p
    _lib.EVP_PKEY_CTX_new.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    _lib.EVP_PKEY_CTX_free.argtypes = [ctypes.c_void_p]
    _lib.EVP_PKEY_verify_init.argtypes = [ctypes.c_void_p]
    _lib.EVP_PKEY_verify.argtypes = [
        ctypes.c_void_p, ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p, ctypes.c_size_t]
except AttributeError as e:
    raise BackendUnavailable("libcrypto is missing a required symbol: %s" % e)


def _der_uint(v: bytes) -> bytes:
    """Encode a big-endian unsigned integer as a DER INTEGER"""
    v = v.lstrip(b"\x00")
    if not v:
        v = b"\x00"
    if v[0] & 0x80:
        v = b"\x00" + v
    return b"\x02" + bytes([len(v)]) + v


def _sig_to_der(sig: bytes, coord_bytes: int) -> bytes:
    """Turn a raw r||s DNSSEC signature into the DER SEQUENCE OpenSSL expects"""
    body = _der_uint(sig[:coord_bytes]) + _der_uint(sig[coord_bytes:])
    # Both integers are at most coord_bytes+1 long, so the body never reaches the 128-byte
    # threshold where DER would need a long-form length.
    return b"\x30" + bytes([len(body)]) + body


def _verify(pk: bytes, sig: bytes, digest: bytes, coord_bytes: int) -> bool:
    if len(pk) != coord_bytes * 2 or len(sig) != coord_bytes * 2:
        return False

    spki = _SPKI_PREFIX[coord_bytes] + b"\x04" + pk
    buf = (ctypes.c_ubyte * len(spki)).from_buffer_copy(spki)
    cursor = ctypes.cast(ctypes.pointer(buf), ctypes.POINTER(ctypes.c_ubyte))
    pkey = _lib.d2i_PUBKEY(None, ctypes.byref(cursor), len(spki))
    if not pkey:
        # A point that is not on the curve lands here, which is a refusal, not an error.
        return False

    try:
        der = _sig_to_der(sig, coord_bytes)
        ctx = _lib.EVP_PKEY_CTX_new(ctypes.c_void_p(pkey), None)
        if not ctx:
            raise BackendUnavailable("EVP_PKEY_CTX_new failed")
        try:
            if _lib.EVP_PKEY_verify_init(ctypes.c_void_p(ctx)) != 1:
                raise BackendUnavailable("EVP_PKEY_verify_init failed")
            return _lib.EVP_PKEY_verify(
                ctypes.c_void_p(ctx), der, len(der), digest, len(digest)) == 1
        finally:
            _lib.EVP_PKEY_CTX_free(ctypes.c_void_p(ctx))
    finally:
        _lib.EVP_PKEY_free(ctypes.c_void_p(pkey))


def validate_ecdsa_256r1(pk: bytes, sig: bytes, hash_input: bytes) -> bool:
    return _verify(pk, sig, hash_input, 32)


def validate_ecdsa_384r1(pk: bytes, sig: bytes, hash_input: bytes) -> bool:
    return _verify(pk, sig, hash_input, 48)


# Known-answer vectors, taken from the Wycheproof suites this repo already tests against
# (tests/ecdsa_secp256r1_sha256_test.json and tests/ecdsa_secp384r1_sha384_test.json, first valid
# case of each). They are checked at import, on the device, against this backend only. The pure
# Python implementation is deliberately NOT run here: cross-checking the two costs four software
# verifications at every boot, which is precisely the cost this backend exists to avoid. The
# cross-check belongs in the test suite, where it runs over the whole corpus instead of two cases.
_SELF_TEST = [
    (validate_ecdsa_256r1,
     bytes.fromhex("04aaec73635726f213fb8a9e64da3b8632e41495a944d0045b522eba7240fad5"
                   "87d9315798aaa3a5ba01775787ced05eaaf7b4e09fc81d6d1aa546e8365d525d"),
     bytes.fromhex("b292a619339f6e567a305c951c0dcbcc42d16e47f219f9e98e76e09d8770b34a"
                   "0177e60492c5a8242f76f07bfe3661bde59ec2a17ce5bd2dab2abebdf89a62e2"),
     bytes.fromhex("e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")),
    (validate_ecdsa_384r1,
     bytes.fromhex("29bdb76d5fa741bfd70233cb3a66cc7d44beb3b0663d92a8136650478bcefb61"
                   "ef182e155a54345a5e8e5e88f064e5bc9a525ab7f764dad3dae1468c2b419f3b"
                   "62b9ba917d5e8c4fb1ec47404a3fc76474b2713081be9db4c00e043ada9fc4a3"),
     bytes.fromhex("32401249714e9091f05a5e109d5c1216fdc05e98614261aa0dbd9e9cd4415dee"
                   "29238afbd3b103c1e40ee5c9144aee0f4326756fb2c4fd726360dd6479b58494"
                   "78c7a9d054a833a58c1631c33b63c3441336ddf2c7fe0ed129aae6d4ddfeb753"),
     bytes.fromhex("38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da"
                   "274edebfe76f65fbd51ad2f14898b95b")),
]


def _self_test():
    """Prove this backend accepts what it must and rejects what it must, or refuse to be used"""
    for fn, pk, sig, digest in _SELF_TEST:
        curve = fn.__name__

        if fn(pk, sig, digest) is not True:
            raise BackendUnavailable("%s rejected a known-good signature" % curve)

        # Flipping the last bit of the digest must break it. A backend that ignores the digest
        # entirely -- the worst possible failure, because every proof would validate -- dies here.
        bad_digest = digest[:-1] + bytes([digest[-1] ^ 1])
        if fn(pk, sig, bad_digest) is not False:
            raise BackendUnavailable("%s accepted a signature over the wrong digest" % curve)

        bad_sig = sig[:-1] + bytes([sig[-1] ^ 1])
        if fn(pk, bad_sig, digest) is not False:
            raise BackendUnavailable("%s accepted a tampered signature" % curve)

        if fn(pk, sig[:-1], digest) is not False:
            raise BackendUnavailable("%s accepted a truncated signature" % curve)


_self_test()

"""
Cryptographic verification implementations for DNSSEC

This module provides RSA and ECDSA signature validation functionality
for DNSSEC, supporting secp256r1 and secp384r1 curves.

ECDSA has two interchangeable implementations. The pure-Python one is always present and is the
reference; the libcrypto one is roughly 60x faster and is what makes chain validation practical on
a device like a Pi Zero. Which one is in use is recorded in ECDSA_BACKEND and is meant to be shown
to the user rather than kept quiet, because "it validated" and "it validated using the code we
tested" are different claims.

Set PYDNSSEC_ECDSA_BACKEND to pick:

    auto     (default) libcrypto if it imports and passes its self-test, else pure Python
    openssl  libcrypto or nothing -- raises if it is unavailable
    python   pure Python, even where libcrypto would work
"""

import os

try:
    from .rsa import validate_rsa
    from .secp256r1 import validate_ecdsa as _py_ecdsa_256r1
    from .secp384r1 import validate_ecdsa as _py_ecdsa_384r1
    from .hash import Hasher, HashResult
except ImportError:
    # Handle direct script execution
    from rsa import validate_rsa
    from secp256r1 import validate_ecdsa as _py_ecdsa_256r1
    from secp384r1 import validate_ecdsa as _py_ecdsa_384r1
    from hash import Hasher, HashResult


def _select_ecdsa_backend():
    """Return (name, detail, verify_256r1, verify_384r1) honouring PYDNSSEC_ECDSA_BACKEND"""
    choice = os.environ.get("PYDNSSEC_ECDSA_BACKEND", "auto").strip().lower()
    if choice not in ("auto", "openssl", "python"):
        raise ValueError("PYDNSSEC_ECDSA_BACKEND must be auto, openssl or python, not %r" % choice)

    if choice == "python":
        return "python", "selected explicitly", _py_ecdsa_256r1, _py_ecdsa_384r1

    try:
        from .ecdsa_openssl import validate_ecdsa_256r1, validate_ecdsa_384r1
    except Exception as e:
        # Importing that module runs its own known-answer self-test, so landing here means either
        # libcrypto is absent or it answered wrongly. Both are reasons not to use it.
        if choice == "openssl":
            raise
        return "python", "libcrypto unusable: %s" % e, _py_ecdsa_256r1, _py_ecdsa_384r1

    return "openssl", "libcrypto self-test passed", validate_ecdsa_256r1, validate_ecdsa_384r1


ECDSA_BACKEND, ECDSA_BACKEND_DETAIL, validate_ecdsa_256r1, validate_ecdsa_384r1 = \
    _select_ecdsa_backend()

__all__ = [
    'validate_rsa',
    'validate_ecdsa_256r1',
    'validate_ecdsa_384r1',
    'Hasher',
    'HashResult',
    'ECDSA_BACKEND',
    'ECDSA_BACKEND_DETAIL',
]

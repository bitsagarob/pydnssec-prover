"""
The libcrypto ECDSA backend must answer exactly what the pure-Python one answers

The pure-Python implementation is the reference: it is the ported code, it is what the existing
suite checks against Wycheproof, and it is what runs where libcrypto is missing. The native backend
is only a speed-up, so the single property worth testing is that it is indistinguishable.

Two levels of evidence here. Wycheproof covers the adversarial edges of ECDSA itself -- signatures
with r or s out of range, truncated and over-padded values, the special cases around zero. The
DNSSEC corpus covers whole real proofs, where a divergence would show up as a chain that validates
under one backend and not the other, which is the failure that would actually reach a user.
"""

import json
import os

import pytest

from pydnssec_prover.crypto.hash import Hasher
from pydnssec_prover.crypto.secp256r1 import validate_ecdsa as py_256r1
from pydnssec_prover.crypto.secp384r1 import validate_ecdsa as py_384r1
from pydnssec_prover.rr import Name, Txt, parse_rr_stream
from pydnssec_prover.validation import verify_rr_stream, ValidationError

from test_corpus import CASES, CORPUS_DIR
from test_crypto import decode_asn, open_file

openssl = pytest.importorskip(
    "pydnssec_prover.crypto.ecdsa_openssl",
    reason="libcrypto is not available or failed its self-test")

SUITES = [
    ("ecdsa_secp256r1_sha256_test.json", 32, Hasher.sha256, py_256r1, "validate_ecdsa_256r1"),
    ("ecdsa_secp384r1_sha384_test.json", 48, Hasher.sha384, py_384r1, "validate_ecdsa_384r1"),
]


def _digest(hasher_factory, msg):
    h = hasher_factory()
    h.update(msg)
    return h.finish().as_ref()


def _wycheproof_cases(filename, coord_bytes, hasher_factory):
    """Yield (tcId, comment, pk, raw_sig, digest, expected) for every decodable case"""
    data = json.loads(open_file(filename))
    for group in data["testGroups"]:
        pk_str = group["publicKey"]["uncompressed"]
        assert pk_str[:2] == "04"
        pk = bytes.fromhex(pk_str[2:])
        for test in group["tests"]:
            sig = decode_asn(test["sig"], coord_bytes)
            if sig is None:
                # A signature the DER parser refuses never reaches either backend
                continue
            yield (test["tcId"], test["comment"], pk, sig,
                   _digest(hasher_factory, bytes.fromhex(test["msg"])),
                   test["result"] == "valid")


@pytest.mark.parametrize("filename,coord_bytes,hasher_factory,py_fn,native_name", SUITES,
                         ids=[s[0] for s in SUITES])
def test_backends_agree_on_wycheproof(filename, coord_bytes, hasher_factory, py_fn, native_name):
    native_fn = getattr(openssl, native_name)
    checked = 0
    for tc_id, comment, pk, sig, digest, expected in _wycheproof_cases(
            filename, coord_bytes, hasher_factory):
        native = native_fn(pk, sig, digest)
        assert native is py_fn(pk, sig, digest), (
            f"{filename} tcId {tc_id} ({comment}): libcrypto says {native}, "
            f"pure Python disagrees")
        assert native is expected, (
            f"{filename} tcId {tc_id} ({comment}): libcrypto says {native}, "
            f"Wycheproof expects {expected}")
        checked += 1
    assert checked > 100, f"only {checked} cases ran, the suite did not load"


def _verdict(case):
    """Validate one stored proof and reduce it to something comparable"""
    with open(os.path.join(CORPUS_DIR, case["proof_bin"]), "rb") as f:
        proof = f.read()
    try:
        verified = verify_rr_stream(parse_rr_stream(proof))
    except ValidationError as e:
        return ("error", e.error_type)
    txts = sorted(rr.data for rr in verified.resolve_name(Name(case["query_name"]))
                  if isinstance(rr, Txt))
    return ("ok", verified.valid_from, verified.expires, txts)


@pytest.mark.skipif(not CASES, reason="corpus not found")
@pytest.mark.parametrize("case", CASES, ids=[c["case"] for c in CASES])
def test_backends_agree_on_corpus(case, monkeypatch):
    """Every stored proof must get the same verdict from both backends

    validation.py binds the crypto functions at import, which is what the device does too, so the
    backend is swapped by rebinding those names rather than by re-importing the package.
    """
    import pydnssec_prover.validation as V

    monkeypatch.setattr(V, "validate_ecdsa_256r1", py_256r1)
    monkeypatch.setattr(V, "validate_ecdsa_384r1", py_384r1)
    pure = _verdict(case)

    monkeypatch.setattr(V, "validate_ecdsa_256r1", openssl.validate_ecdsa_256r1)
    monkeypatch.setattr(V, "validate_ecdsa_384r1", openssl.validate_ecdsa_384r1)
    native = _verdict(case)

    assert native == pure, f"{case['case']}: libcrypto gave {native}, pure Python gave {pure}"

"""
Validation tests against the BIP 353 appendix proofs checked in under tests/data/bip353

Every expected value was measured by running the same proof bytes through dnssec-prover 0.6.10.
These fixtures are required: a missing one is a failure, not a skip.

The proofs are snapshots and their RRSig windows have expired. That is fine, because neither this
port nor dnssec-prover looks at the clock inside verify_rr_stream. They report valid_from and
expires and leave the comparison to the caller, so both are asserted exactly.
"""

import json
import os

import pytest

from pydnssec_prover.rr import Name, Txt, parse_rr_stream
from pydnssec_prover.validation import verify_rr_stream, ValidationError

DATA_DIR = os.path.join(os.path.dirname(__file__), "data", "bip353")


def _load_cases():
    with open(os.path.join(DATA_DIR, "expected.json")) as f:
        return json.load(f)["cases"]


CASES = _load_cases()


def _read_proof(case):
    with open(os.path.join(DATA_DIR, case["proof"]), "rb") as f:
        return f.read()


def _run(case):
    rrs = parse_rr_stream(_read_proof(case))
    verified = verify_rr_stream(rrs)
    txts = [rr.data.decode("utf-8", "replace")
            for rr in verified.resolve_name(Name(case["query_name"]))
            if isinstance(rr, Txt)]
    return rrs, verified, txts


@pytest.mark.parametrize("case", CASES, ids=[c["case"] for c in CASES])
def test_matches_rust_oracle(case):
    """Each proof must give exactly the answer dnssec-prover 0.6.10 gave"""
    if not case["chain_valid"]:
        with pytest.raises(ValidationError):
            _run(case)
        return

    rrs, verified, txts = _run(case)

    assert len(rrs) == case["rr_count"]
    assert verified.valid_from == case["valid_from"]
    assert verified.expires == case["expires"]
    assert verified.max_cache_ttl == case["max_cache_ttl"]
    assert txts == case["records"]

    # NSEC and NSEC3 records are proof machinery and must never be handed back as answers
    assert all(rr.type_code not in (47, 50) for rr in verified.verified_rrs)


def test_wildcard_needs_its_nsec3():
    """
    Case 05 is case 03 with the wildcard's NSEC3 removed and must be refused

    Without that NSEC3 the resolver could be hiding a more specific record than the wildcard, so
    accepting the proof means paying an address the payee may not have published.
    """
    valid = next(c for c in CASES if c["case"] == "03-a-x-domain-cname-wild-valid")
    stripped = next(c for c in CASES if c["case"] == "05-missing-nsec3-wildcard-INVALID")
    assert valid["query_name"] == stripped["query_name"]

    _, verified, txts = _run(valid)
    assert len(txts) == 1
    assert txts[0].startswith("bitcoin:bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l?lno=")

    with pytest.raises(ValidationError) as excinfo:
        _run(stripped)
    assert excinfo.value.error_type == ValidationError.ErrorType.INVALID


@pytest.mark.parametrize("case", [c for c in CASES if c["chain_valid"]],
                         ids=[c["case"] for c in CASES if c["chain_valid"]])
def test_single_byte_corruption_is_fatal(case):
    """Flipping one byte of a valid proof must raise, never return a success object"""
    proof = bytearray(_read_proof(case))

    # The last byte of the stream is inside the final record's RDATA in every case here
    proof[-1] ^= 0x01

    with pytest.raises(Exception):
        verify_rr_stream(parse_rr_stream(bytes(proof)))

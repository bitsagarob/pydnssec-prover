"""
Differential tests against the recorded dnssec-prover 0.6.10 corpus

The corpus lives outside this repository. Every case is a stored RFC 9102 proof plus the answer
the Rust oracle gave for it, so these tests compare this port against measured behaviour rather
than against an assumption about it.

Proofs are snapshots and most of their RRSig windows have expired. That is fine: neither this port
nor dnssec-prover checks the clock inside verify_rr_stream, they report valid_from and expires and
leave the comparison to the caller. The recorded valid_from and expires are asserted exactly.
"""

import json
import os

import pytest

from pydnssec_prover.rr import Name, Txt, parse_rr_stream
from pydnssec_prover.validation import verify_rr_stream, ValidationError

CORPUS_DIR = os.environ.get(
    "PYDNSSEC_CORPUS",
    "/home/rob/apps/bitsaga/services/silentpayments/dnssec-verify/testdata")
INDEX_PATH = os.path.join(CORPUS_DIR, "INDEX.json")


def _load_cases():
    if not os.path.exists(INDEX_PATH):
        return []
    with open(INDEX_PATH) as f:
        index = json.load(f)
    # Some cases record a proof the oracle could not even build, so there are no bytes to feed us
    return [c for c in index["cases"] if c.get("proof_bin")]


CASES = _load_cases()

pytestmark = pytest.mark.skipif(not CASES, reason=f"corpus not found at {CORPUS_DIR}")


def _run(case):
    with open(os.path.join(CORPUS_DIR, case["proof_bin"]), "rb") as f:
        proof = f.read()
    rrs = parse_rr_stream(proof)
    verified = verify_rr_stream(rrs)
    txts = [rr.data.decode("utf-8", "replace")
            for rr in verified.resolve_name(Name(case["query_name"]))
            if isinstance(rr, Txt)]
    return rrs, verified, txts


@pytest.mark.parametrize("case", CASES, ids=[c["case"] for c in CASES])
def test_matches_rust_oracle(case):
    """Every stored proof must give exactly the answer dnssec-prover 0.6.10 gave"""
    oracle = case["oracle_chain_result"]

    if not oracle.get("chain_valid"):
        with pytest.raises(ValidationError):
            _run(case)
        return

    rrs, verified, txts = _run(case)

    assert len(rrs) == oracle["rr_count"]
    assert verified.valid_from == oracle["valid_from"]
    assert verified.expires == oracle["expires"]
    assert verified.max_cache_ttl == oracle["max_cache_ttl"]
    assert txts == oracle["records"]

    # NSEC and NSEC3 records are proof machinery and must never be handed back as answers
    assert all(rr.type_code not in (47, 50) for rr in verified.verified_rrs)


def test_bip353_case_05_is_rejected():
    """
    BIP 353 example 05 is case 03 with the NSEC3 removed and must be refused.

    Without that NSEC3 the resolver could be hiding a more specific record than the wildcard, so
    accepting the proof means paying an address the payee may not have published.
    """
    case = next(c for c in CASES if c["case"] == "bip353/05-missing-nsec3-wildcard-INVALID")
    with pytest.raises(ValidationError) as excinfo:
        _run(case)
    assert excinfo.value.error_type == ValidationError.ErrorType.INVALID


def test_bip353_case_03_resolves_to_one_txt():
    """BIP 353 example 03, the same proof with the NSEC3 present, must validate"""
    case = next(c for c in CASES if c["case"] == "bip353/03-a-x-domain-cname-wild-valid")
    rrs, verified, txts = _run(case)

    assert len(txts) == 1
    assert txts[0].startswith("bitcoin:bc1qztwy6xen3zdtt7z0vrgapmjtfz8acjkfp5fp7l?lno=")
    assert verified.valid_from == 1754461250
    assert verified.expires == 1754842932


@pytest.mark.parametrize("case", [c for c in CASES if c["oracle_chain_result"].get("chain_valid")],
                         ids=[c["case"] for c in CASES if c["oracle_chain_result"].get("chain_valid")])
def test_single_byte_corruption_is_fatal(case):
    """Flipping one byte of any valid proof must produce an error, never a success object"""
    with open(os.path.join(CORPUS_DIR, case["proof_bin"]), "rb") as f:
        proof = bytearray(f.read())

    # The last byte of the stream is inside the final record's RDATA in every corpus case
    proof[-1] ^= 0x01

    with pytest.raises(Exception):
        rrs = parse_rr_stream(bytes(proof))
        verify_rr_stream(rrs)

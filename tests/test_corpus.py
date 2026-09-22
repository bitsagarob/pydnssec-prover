"""
Differential tests against a larger recorded dnssec-prover corpus

Optional. Point PYDNSSEC_CORPUS at a directory holding an INDEX.json in the format written by
difftest/, and every stored proof in it is replayed here. Without it these tests skip; the proofs
that must always run are the checked-in ones in test_bip353.py.
"""

import json
import os

import pytest

from pydnssec_prover.rr import Name, Txt, parse_rr_stream
from pydnssec_prover.validation import verify_rr_stream, ValidationError

CORPUS_DIR = os.environ.get("PYDNSSEC_CORPUS")


def _load_cases():
    if not CORPUS_DIR:
        return []
    index_path = os.path.join(CORPUS_DIR, "INDEX.json")
    if not os.path.exists(index_path):
        return []
    with open(index_path) as f:
        index = json.load(f)
    # Some cases record a proof the oracle could not even build, so there are no bytes to feed us
    return [c for c in index["cases"] if c.get("proof_bin")]


CASES = _load_cases()

pytestmark = pytest.mark.skipif(not CASES, reason="set PYDNSSEC_CORPUS to a recorded corpus")


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
    """Every stored proof must give exactly the answer the oracle gave"""
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

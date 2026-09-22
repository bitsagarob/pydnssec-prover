"""Differential test suite: pydnssec-prover must agree with dnssec-prover 0.6.10, exactly.

    pytest difftest/                         # everything
    pytest difftest/ -k corpus               # just the corpus cases
    pytest difftest/ -m mutation             # just the mutated-bytes differential
    DIFFTEST_PORT_REV=HEAD pytest difftest/  # test a git revision, not the working tree

Every test compares the two implementations on identical bytes, never against the wall clock.
See the clock-pinning note in harness.py and in difftest/README.md.
"""

from __future__ import annotations

import os
import random
from typing import Any, Dict, List

import pytest

import harness
from harness import Case, compare, expected_dnssec_accept, run_case, run_python

try:
    _ALL_CASES = harness.load_cases()
except harness.CorpusMissing:
    _ALL_CASES = []

_WITH_PROOF = [c for c in _ALL_CASES if c.has_proof]
_NO_PROOF = [c for c in _ALL_CASES if not c.has_proof]

# A list, not a callable: pytest hands a callable its own sentinel when the parameter set is
# empty, which errors during collection before test_corpus_is_loaded can explain the problem.
_WITH_PROOF_IDS = [c.id for c in _WITH_PROOF]

needs_corpus = pytest.mark.skipif(
    not _ALL_CASES,
    reason="no corpus; set DIFFTEST_CORPUS or vendor one into difftest/corpus",
)

MUTANTS_PER_BASE = int(os.environ.get("DIFFTEST_MUTANTS", "50"))
MUTATION_SEED = int(os.environ.get("DIFFTEST_MUTATION_SEED", "20260902"))
MUTATION_BASES = [
    "bip353/01-simple-valid",
    "bip353/03-a-x-domain-cname-wild-valid",
    "live/satoshi.user._bitcoin-payment.twelve.cash",
    "live/a.nsec_tests.dnssec_proof_tests.bitcoin.ninja",
]


@needs_corpus
@pytest.mark.parametrize("case", _WITH_PROOF, ids=_WITH_PROOF_IDS)
def test_corpus_case_matches_reference(case: Case, oracle) -> None:
    """Same bytes in, same everything out"""
    res = run_case(case, oracle)
    if res.diffs:
        detail = "\n".join("  " + line for d in res.diffs for line in d.split("\n"))
        pytest.fail(
            "Rust and Python disagree on %s\n"
            "  input : %s\n"
            "  sha256: %s\n"
            "  name  : %s\n"
            "  pinned: %d (window %s..%s, source %s)\n"
            "%s\n"
            "  reduce: python3 difftest/reduce.py '%s'"
            % (
                case.id,
                case.proof_path,
                case.sha256(),
                case.query_name,
                case.pinned_time,
                case.window[0],
                case.window[1],
                case.pin_source,
                detail,
                case.id,
            ),
            pytrace=False,
        )


# The harness's own self-tests, proving it can see a divergence at all


def test_corpus_is_loaded() -> None:
    if not _ALL_CASES and os.environ.get("DIFFTEST_ALLOW_NO_CORPUS") == "1":
        pytest.skip("no corpus, and DIFFTEST_ALLOW_NO_CORPUS=1")
    assert _ALL_CASES, (
        "corpus did not load. Set DIFFTEST_CORPUS to a directory containing INDEX.json, live/ "
        "and bip353/, or vendor one into difftest/corpus."
    )
    assert len(_WITH_PROOF) >= 30, "corpus has suspiciously few replayable proofs"
    assert _NO_PROOF, "corpus should contain negative cases with no proof bytes"


@needs_corpus
@pytest.mark.parametrize("case", _WITH_PROOF, ids=_WITH_PROOF_IDS)
def test_corpus_blob_matches_its_recorded_digest(case: Case) -> None:
    """A proof blob that has changed on disk invalidates every result measured from it"""
    want = case.raw.get("proof_sha256")
    if not want:
        pytest.skip("case records no digest")
    assert case.sha256() == want, "%s has changed on disk" % case.id


@needs_corpus
def test_reference_rejects_the_missing_nsec3_case(oracle) -> None:
    """Pin the reference itself on the case the whole corpus turns on

    bip353/05 is bip353/03 with one NSEC3 deleted. A validator that checks every signature that
    is present accepts it, because the flaw is a record that is absent. dnssec-prover rejects it.
    """
    case = next(c for c in _WITH_PROOF if c.id.startswith("bip353/05"))
    rust = oracle.run(case.id, case.proof_bytes(), case.query_name)
    assert rust["result"] == "error", rust
    assert rust["error"] == "invalid", rust


@needs_corpus
def test_reference_accepts_the_bip353_layer_case(oracle) -> None:
    """bip353/04 is DNSSEC-sound and must be rejected one layer up, not by the chain validator"""
    case = next(c for c in _WITH_PROOF if c.id.startswith("bip353/04"))
    rust = oracle.run(case.id, case.proof_bytes(), case.query_name)
    assert rust["result"] == "valid", rust


@needs_corpus
@pytest.mark.parametrize("case", _WITH_PROOF, ids=_WITH_PROOF_IDS)
def test_reference_agrees_with_corpus_expectation(case: Case, oracle) -> None:
    """Cross-check the reference against what the corpus recorded, at the DNSSEC layer only"""
    want = expected_dnssec_accept(case)
    if want is None:
        pytest.skip("corpus does not state a chain-layer expectation")
    rust = oracle.run(case.id, case.proof_bytes(), case.query_name)
    assert (rust["result"] == "valid") is want, (
        "corpus says a chain validator should %s %s, reference said %s"
        % ("accept" if want else "reject", case.id, rust)
    )


@pytest.mark.parametrize(
    "field,bad",
    [
        ("result", "error"),
        ("error", "invalid"),
        ("valid_from", 1),
        ("expires", 1),
        ("max_cache_ttl", 999999),
        ("rr_count", 0),
    ],
)
def test_comparator_catches_an_injected_scalar_divergence(field: str, bad: Any) -> None:
    """The comparator must notice a single changed field

    Written against a synthetic result rather than the port's current bugs, so that fixing the
    port does not silently disarm the harness.
    """
    good: Dict[str, Any] = {
        "parsed": True,
        "rr_count": 3,
        "result": "valid",
        "valid_from": 100,
        "expires": 200,
        "max_cache_ttl": 30,
        "verified_rrs": [{"n": "a.", "t": 16, "w": "00"}],
        "resolved": [{"n": "a.", "t": 16, "w": "00"}],
    }
    assert compare(good, dict(good)) == []
    broken = dict(good)
    broken[field] = bad
    assert compare(good, broken), "comparator missed a divergence in %s" % field


def test_comparator_catches_record_content_order_and_count() -> None:
    base = {
        "parsed": True,
        "rr_count": 2,
        "result": "valid",
        "valid_from": 100,
        "expires": 200,
        "max_cache_ttl": 30,
        "verified_rrs": [
            {"n": "a.", "t": 16, "w": "aa"},
            {"n": "b.", "t": 16, "w": "bb"},
        ],
        "resolved": [],
    }
    assert compare(base, dict(base)) == []

    # one byte of rdata changed
    changed = dict(base, verified_rrs=[{"n": "a.", "t": 16, "w": "ab"}, {"n": "b.", "t": 16, "w": "bb"}])
    assert compare(base, changed)

    # a record dropped
    dropped = dict(base, verified_rrs=[{"n": "a.", "t": 16, "w": "aa"}])
    assert compare(base, dropped)

    # an extra record smuggled in
    extra = dict(base, verified_rrs=base["verified_rrs"] + [{"n": "c.", "t": 50, "w": "cc"}])
    assert compare(base, extra)

    # same records, different order
    reordered = dict(base, verified_rrs=list(reversed(base["verified_rrs"])))
    diffs = compare(base, reordered)
    assert diffs and "different order" in diffs[0]

    # a crash must never be folded into a plain rejection
    crashed = {"parsed": True, "rr_count": 2, "result": "crash", "error": "IndexError: x"}
    rejected = {"parsed": True, "rr_count": 2, "result": "error", "error": "invalid"}
    assert compare(rejected, crashed)


@needs_corpus
def test_clock_pinning_never_uses_now() -> None:
    """Every pinned time must sit inside its own case's recorded window, not near today"""
    for case in _WITH_PROOF:
        vf, ex = case.window
        if vf is None:
            assert case.pin_source == "fallback", case.id
            continue
        assert vf <= case.pinned_time <= ex, (
            "pinned time for %s fell outside its own recorded window" % case.id
        )


@needs_corpus
def test_expired_proofs_still_validate_on_both_sides(oracle) -> None:
    """A case that has merely aged must not be reported as a finding

    This is the property clock pinning rests on: the stream verifiers do not look at the clock, so
    a long-expired blob still validates. If it fails, the corpus needs recapturing.
    """
    import time as _time

    now = int(_time.time())
    expired = []
    for case in _WITH_PROOF:
        if expected_dnssec_accept(case) is not True:
            continue
        vf, ex = case.window
        if ex is not None and ex < now:
            expired.append(case)
    assert expired, "corpus has no expired-but-valid proof, so this property is untested"
    for case in expired:
        rust = oracle.run(case.id, case.proof_bytes(), case.query_name)
        assert rust["result"] == "valid", (
            "%s expired %d seconds ago and the reference now rejects it, which means the "
            "reference does apply a wall-clock check and the harness design is wrong"
            % (case.id, now - case.window[1])
        )


@needs_corpus
def test_negative_cases_have_no_bytes_to_replay() -> None:
    """The live negatives are build failures, not proof failures

    dnssec-prover emits a proof only when it can build one, so a plain NXDOMAIN or NODATA yields
    no file. Those cases have nothing to feed into a bytes-in differential.
    """
    assert _NO_PROOF, "corpus has no negative cases at all"
    for case in _NO_PROOF:
        assert case.expected == "invalid", case.id
        assert case.proof_path is None


# Mutated bytes: the same differential over inputs nobody wrote by hand


def _mutants(case: Case, count: int, seed: int) -> List[bytes]:
    rng = random.Random("%s:%d" % (case.id, seed))
    proof = case.proof_bytes()
    out: List[bytes] = []
    for _ in range(count):
        kind = rng.choice(["flip", "truncate", "extend"])
        if kind == "flip":
            buf = bytearray(proof)
            buf[rng.randrange(len(buf))] ^= 1 << rng.randrange(8)
            out.append(bytes(buf))
        elif kind == "truncate":
            out.append(proof[: rng.randrange(1, len(proof))])
        else:
            out.append(proof + bytes(rng.randrange(256) for _ in range(rng.randrange(1, 9))))
    return out


@needs_corpus
@pytest.mark.mutation
@pytest.mark.parametrize("case_id", MUTATION_BASES)
def test_mutated_proofs_match_reference(case_id: str, oracle) -> None:
    """Corrupt a known-good proof and require the two implementations to still agree

    This is where error handling gets tested, which the corpus barely touches: real proofs are
    either wholly good or wholly bad in one documented way. The direction that matters is the
    port accepting what the reference rejects.
    """
    case = next((c for c in _WITH_PROOF if c.id == case_id), None)
    if case is None:
        pytest.skip("base case %s not in corpus" % case_id)

    failures: List[str] = []
    for i, blob in enumerate(_mutants(case, MUTANTS_PER_BASE, MUTATION_SEED)):
        rust = oracle.run("%s#m%d" % (case.id, i), blob, case.query_name)
        py = run_python("%s#m%d" % (case.id, i), blob, case.query_name, case.pinned_time)
        diffs = compare(rust, py)
        if diffs:
            failures.append(
                "mutant %d (%d bytes, sha %s...): rust=%s/%s python=%s/%s  %s"
                % (
                    i,
                    len(blob),
                    __import__("hashlib").sha256(blob).hexdigest()[:16],
                    rust.get("result"),
                    rust.get("error"),
                    py.get("result"),
                    str(py.get("error"))[:40],
                    diffs[0].split("\n")[0],
                )
            )
    if failures:
        pytest.fail(
            "%d of %d mutants of %s diverged\nseed=%d, reproduce a single one with "
            "difftest/mutants.py\n%s"
            % (
                len(failures),
                MUTANTS_PER_BASE,
                case.id,
                MUTATION_SEED,
                "\n".join("  " + f for f in failures[:20]),
            ),
            pytrace=False,
        )

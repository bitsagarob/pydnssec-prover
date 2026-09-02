"""Differential test suite: pydnssec-prover must agree with dnssec-prover 0.6.10, exactly.

    pytest difftest/                       # everything
    pytest difftest/ -k corpus             # just the corpus cases
    pytest difftest/ -m mutation           # just the mutated-bytes differential
    DIFFTEST_PORT_REV=HEAD pytest difftest/  # test a git revision, not the working tree

Every test here compares two implementations on identical bytes. None of them compares anything
against the wall clock: see the clock-pinning note in harness.py and in difftest/README.md.
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

MUTANTS_PER_BASE = int(os.environ.get("DIFFTEST_MUTANTS", "50"))
MUTATION_SEED = int(os.environ.get("DIFFTEST_MUTATION_SEED", "20260902"))
MUTATION_BASES = [
    "bip353/01-simple-valid",
    "bip353/03-a-x-domain-cname-wild-valid",
    "live/rob.user._bitcoin-payment.silentpayments.net",
    "live/a.nsec_tests.dnssec_proof_tests.bitcoin.ninja",
]


# ------------------------------------------------------------------------------------------
# the gate
# ------------------------------------------------------------------------------------------


@pytest.mark.parametrize("case", _WITH_PROOF, ids=lambda c: c.id)
def test_corpus_case_matches_reference(case: Case, oracle) -> None:
    """The whole point: same bytes in, same everything out."""
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


# ------------------------------------------------------------------------------------------
# the harness's own self-tests: prove the harness can see a divergence at all
# ------------------------------------------------------------------------------------------


def test_corpus_is_loaded() -> None:
    if not _ALL_CASES and os.environ.get("DIFFTEST_ALLOW_NO_CORPUS") == "1":
        pytest.skip("no corpus, and DIFFTEST_ALLOW_NO_CORPUS=1")
    assert _ALL_CASES, (
        "corpus did not load. Set DIFFTEST_CORPUS to a directory containing INDEX.json, live/ "
        "and bip353/, or vendor one into difftest/corpus."
    )
    assert len(_WITH_PROOF) >= 30, "corpus has suspiciously few replayable proofs"
    assert _NO_PROOF, "corpus should contain negative cases with no proof bytes"


def test_reference_rejects_the_missing_nsec3_case(oracle) -> None:
    """The single most valuable case in the corpus, used here to pin the reference itself.

    bip353/05 is bip353/03 with one NSEC3 deleted. A validator that checks every signature that
    is present accepts it, because the flaw is a record that is ABSENT. dnssec-prover rejects it.
    If this ever stops holding, the Rust side of this harness is not what we think it is and no
    other result here means anything.
    """
    case = next(c for c in _WITH_PROOF if c.id.startswith("bip353/05"))
    rust = oracle.run(case.id, case.proof_bytes(), case.query_name)
    assert rust["result"] == "error", rust
    assert rust["error"] == "invalid", rust


def test_reference_accepts_the_bip353_layer_case(oracle) -> None:
    """bip353/04 is DNSSEC-sound and must be rejected one layer up, not by the chain validator.

    Conflating the two layers is the easy mistake. This asserts the reference does not make it.
    """
    case = next(c for c in _WITH_PROOF if c.id.startswith("bip353/04"))
    rust = oracle.run(case.id, case.proof_bytes(), case.query_name)
    assert rust["result"] == "valid", rust


@pytest.mark.parametrize("case", _WITH_PROOF, ids=lambda c: c.id)
def test_reference_agrees_with_corpus_expectation(case: Case, oracle) -> None:
    """Cross-check the reference against what the corpus recorded, at the DNSSEC layer only."""
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
    """If the comparator can be fooled, every green run above is worthless.

    Deliberately written against a synthetic result rather than against the port's current bugs,
    so that fixing the port does not silently disarm the harness.
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


def test_clock_pinning_never_uses_now() -> None:
    """Every pinned time must sit inside its own case's recorded window, not near today."""
    for case in _WITH_PROOF:
        vf, ex = case.window
        if vf is None:
            assert case.pin_source == "fallback", case.id
            continue
        assert vf <= case.pinned_time <= ex, (
            "pinned time for %s fell outside its own recorded window" % case.id
        )


def test_expired_proofs_still_validate_on_both_sides(oracle) -> None:
    """A case that has merely aged must not be reported as a finding.

    Proves the property the whole clock-pinning rule rests on: the stream verifiers do not look at
    the clock, so a long-expired blob still validates. If this ever fails, the corpus needs
    recapturing, not the port fixing.
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


def test_negative_cases_have_no_bytes_to_replay() -> None:
    """The 7 live negatives are build failures, not proof failures. Say so out loud.

    dnssec-prover emits NSEC/NSEC3 into a proof only when a wildcard has to be proved. A plain
    NXDOMAIN or NODATA yields no proof file at all. So these cases have nothing to feed into a
    bytes-in differential and are outside its scope, by construction rather than by neglect.
    """
    assert _NO_PROOF, "corpus has no negative cases at all"
    for case in _NO_PROOF:
        assert case.expected == "invalid", case.id
        assert case.proof_path is None


# ------------------------------------------------------------------------------------------
# mutated bytes: the same differential, over inputs nobody wrote by hand
# ------------------------------------------------------------------------------------------


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


@pytest.mark.mutation
@pytest.mark.parametrize("case_id", MUTATION_BASES)
def test_mutated_proofs_match_reference(case_id: str, oracle) -> None:
    """Corrupt a known-good proof and require the two implementations to still agree.

    This is where a port's error handling gets tested, which corpus cases barely touch: real
    proofs are either wholly good or wholly bad in one specific documented way. The interesting
    failure direction is the port ACCEPTING what the reference rejects.
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

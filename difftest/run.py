"""Run the whole differential corpus and print the report. Exit non-zero on any divergence.

    python3 difftest/run.py                # table plus a detail block per divergence
    python3 difftest/run.py --quiet        # table only
    python3 difftest/run.py --json         # machine readable, for CI artifacts
    python3 difftest/run.py --rev HEAD     # test src/ as of a git revision, not the working tree
    python3 difftest/run.py --repeat 5     # rerun every case N times in one process and flag any
                                           # case whose Python result is not identical every time

``--rev`` exists because a baseline that moves is not a baseline. It extracts ``src/`` at the
named commit into ``difftest/.portsnap/`` and tests that, so a recorded result stays reproducible
while somebody is editing the working tree.
"""

from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
from harness import (  # noqa: E402
    CaseResult,
    RustOracle,
    accepted_at,
    expected_dnssec_accept,
    find_corpus,
    load_cases,
    run_case,
)


def short(side: Dict[str, Any]) -> str:
    res = side.get("result")
    if res == "valid":
        nv = len(side.get("verified_rrs") or [])
        resolved = side.get("resolved")
        nr = "null" if resolved is None else str(len(resolved))
        return "valid %drr res=%s" % (nv, nr)
    if res == "crash":
        err = str(side.get("error", ""))
        return "CRASH %s" % err.split(":")[0]
    if res in ("error", "parse_error"):
        return "%s" % side.get("error")
    return str(res)


def _py_fingerprint(side: Dict[str, Any]) -> Any:
    """Everything about a Python result that must not change between identical runs."""
    def rrs(key: str) -> Any:
        v = side.get(key)
        if v is None:
            return None
        return tuple((r.get("n"), r.get("t"), r.get("w")) for r in v)

    return (
        side.get("result"),
        side.get("error"),
        side.get("rr_count"),
        side.get("valid_from"),
        side.get("expires"),
        side.get("max_cache_ttl"),
        rrs("verified_rrs"),
        rrs("resolved"),
    )


def run_all(repeat: int = 1) -> Dict[str, Any]:
    corpus = find_corpus()
    cases = load_cases(corpus)
    rows: List[Dict[str, Any]] = []
    results: List[CaseResult] = []
    skipped: List[Dict[str, Any]] = []
    unstable: List[Dict[str, Any]] = []

    with RustOracle() as oracle:
        for case in cases:
            if not case.has_proof:
                skipped.append(
                    {
                        "case": case.id,
                        "reason": "no proof bytes on disk. The reference failed to BUILD a proof "
                        "for this name over the network, which is what makes it a negative case. "
                        "There is nothing to replay offline, so it is outside the scope of a "
                        "bytes-in differential.",
                        "expected": case.expected,
                    }
                )
                continue
            t0 = time.time()
            res = run_case(case, oracle)
            results.append(res)
            if repeat > 1:
                seen = {_py_fingerprint(res.py)}
                for _ in range(repeat - 1):
                    again = run_case(case, oracle)
                    seen.add(_py_fingerprint(again.py))
                if len(seen) > 1:
                    unstable.append({"case": case.id, "distinct_results": len(seen)})
            rows.append(
                {
                    "case": case.id,
                    "source": case.source,
                    "status": "MATCH" if res.ok else "DIVERGE",
                    "rust": short(res.rust),
                    "python": short(res.py),
                    "pinned_time": case.pinned_time,
                    "pin_source": case.pin_source,
                    "accepted_at_pin": accepted_at(res.rust, case.pinned_time),
                    "expected_dnssec_accept": expected_dnssec_accept(case),
                    "reference_matches_corpus_expectation": (
                        expected_dnssec_accept(case) is None
                        or expected_dnssec_accept(case) == (res.rust.get("result") == "valid")
                    ),
                    "seconds": round(time.time() - t0, 3),
                    "diffs": res.diffs,
                    "notes": res.notes,
                }
            )

    return {
        "corpus": corpus,
        "port": harness.port_revision(),
        "rows": rows,
        "skipped": skipped,
        "results": results,
        "unstable": unstable,
        "repeat": repeat,
    }


def print_report(data: Dict[str, Any], quiet: bool = False) -> None:
    rows = data["rows"]
    skipped = data["skipped"]
    results: List[CaseResult] = data["results"]

    print("DNSSEC proof differential: dnssec-prover 0.6.10 (Rust) vs pydnssec-prover (Python)")
    print("corpus: %s" % data["corpus"])
    print("port  : %s" % data["port"])
    print(
        "clock: pinned per case inside its own recorded valid_from..expires window. "
        "Wall-clock now is never used to judge a case."
    )
    print()

    width = max(len(r["case"]) for r in rows) if rows else 20
    print("%-7s  %-*s  %-24s  %-24s  %s" % ("STATUS", width, "CASE", "RUST", "PYTHON", "PIN"))
    print("-" * (7 + 2 + width + 2 + 24 + 2 + 24 + 2 + 12))
    for r in rows:
        print(
            "%-7s  %-*s  %-24s  %-24s  %d"
            % (r["status"], width, r["case"], r["rust"], r["python"], r["pinned_time"])
        )
    for s in skipped:
        print("%-7s  %-*s  %s" % ("SKIP", width, s["case"], "no proof bytes, negative case"))

    n_match = sum(1 for r in rows if r["status"] == "MATCH")
    n_div = sum(1 for r in rows if r["status"] == "DIVERGE")
    print()
    print(
        "TOTAL: %d corpus cases, %d with proof bytes, %d MATCH, %d DIVERGE, %d SKIP"
        % (len(rows) + len(skipped), len(rows), n_match, n_div, len(skipped))
    )

    if data.get("repeat", 1) > 1:
        unstable = data.get("unstable") or []
        if unstable:
            print()
            print(
                "NON-DETERMINISM: these cases did not give the same Python answer on all %d runs "
                "in one process. A validator whose verdict depends on run order or on what ran "
                "before it is a bug in its own right:" % data["repeat"]
            )
            for u in unstable:
                print("  %s: %d distinct results" % (u["case"], u["distinct_results"]))
        else:
            print()
            print("stability: every case gave an identical Python answer on all %d runs" % data["repeat"])

    bad_ref = [r for r in rows if not r["reference_matches_corpus_expectation"]]
    if bad_ref:
        print()
        print("HARNESS SELF-CHECK FAILED: the Rust reference disagrees with the corpus's own")
        print("expected outcome on these cases, so the harness is not testing what it thinks:")
        for r in bad_ref:
            print("  %s: expected chain accept=%s, reference said %s" % (r["case"], r["expected_dnssec_accept"], r["rust"]))

    if quiet:
        return

    notes = [(r["case"], n) for r in rows for n in r["notes"] if "stale:" not in n]
    if notes:
        print()
        print("NOTES (informational, not divergences)")
        for case_id, note in notes:
            print("  %s: %s" % (case_id, note))

    stale = [r["case"] for r in rows for n in r["notes"] if n.startswith("stale:")]
    if stale:
        print()
        print(
            "%d of %d proofs are expired in wall-clock terms, which is expected for snapshots. "
            "Every case above was judged at its pinned time." % (len(stale), len(rows))
        )

    div = [r for r in results if not r.ok]
    if div:
        print()
        print("=" * 100)
        print("DIVERGENCES")
        print("=" * 100)
        for res in div:
            case = res.case
            print()
            print("CASE: %s" % case.id)
            print("  input      : %s" % case.proof_path)
            print("  sha256     : %s" % case.sha256())
            print("  bytes      : %d" % len(case.proof_bytes()))
            print("  query name : %s" % case.query_name)
            print("  pinned time: %d (source: %s, window %s..%s)" % (
                case.pinned_time, case.pin_source, case.window[0], case.window[1]))
            print("  corpus says: expected=%s layer=%s" % (case.expected, case.invalid_at_layer))
            print("  RUST   : %s" % json.dumps(_trim(res.rust), indent=None)[:400])
            print("  PYTHON : %s" % json.dumps(_trim(res.py), indent=None)[:400])
            print("  DIFFERENCES:")
            for d in res.diffs:
                for line in d.split("\n"):
                    print("    %s" % line)
            print("  REPRO, reference side:")
            print(
                "    difftest/oracle/target/release/difftest-oracle %s %s"
                % (case.proof_path, case.query_name)
            )
            print("  REPRO, port side:")
            print(
                "    python3 -c \"import sys,json; sys.path.insert(0,'difftest'); import pyside; "
                "print(json.dumps(pyside.run_one('x', open(r'%s','rb').read(), '%s'), indent=1))\""
                % (case.proof_path, case.query_name)
            )
            print("  SHRINK IT:")
            print("    python3 difftest/reduce.py '%s'" % case.id)


def _trim(side: Dict[str, Any]) -> Dict[str, Any]:
    out = dict(side)
    for key in ("verified_rrs", "resolved"):
        v = out.get(key)
        if isinstance(v, list):
            out[key] = ["%s/TYPE%s" % (r.get("n"), r.get("t")) for r in v]
    out.pop("traceback", None)
    return out


def _opt(argv: List[str], flag: str, default: str) -> str:
    if flag in argv:
        i = argv.index(flag)
        if i + 1 < len(argv):
            return argv[i + 1]
    return default


def main(argv: List[str]) -> int:
    if "--rev" in argv:
        rev = _opt(argv, "--rev", "HEAD")
        os.environ["DIFFTEST_PORT_SRC"] = harness.materialize_rev(rev)
    repeat = int(_opt(argv, "--repeat", "1"))

    data = run_all(repeat=repeat)
    if "--json" in argv:
        payload = {
            "corpus": data["corpus"],
            "port": data["port"],
            "generated_unix": int(time.time()),
            "repeat": data["repeat"],
            "rows": data["rows"],
            "skipped": data["skipped"],
            "unstable": data["unstable"],
        }
        print(json.dumps(payload, indent=1))
    else:
        print_report(data, quiet="--quiet" in argv)
    n_div = sum(1 for r in data["rows"] if r["status"] == "DIVERGE")
    bad_ref = sum(1 for r in data["rows"] if not r["reference_matches_corpus_expectation"])
    n_unstable = len(data.get("unstable") or [])
    return 1 if (n_div or bad_ref or n_unstable) else 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

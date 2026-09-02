"""Record-level delta debugging: shrink a diverging proof to the smallest one that still diverges.

A proof blob is a flat concatenation of RFC 1035 wire records. This walks the blob to find each
record's byte span, then greedily drops records for as long as the divergence SIGNATURE survives.
What comes out is a proof with the fewest records that still makes the Python port disagree with
dnssec-prover, which is a far better bug report than "here are 5747 bytes".

The signature that must survive is the pair of (rust result, python result) plus, when both accept,
whether the verified-record sets and the resolved-record sets differ.

Read the result carefully. That signature is coarse on purpose, so a reduction can land on a MORE
GENERAL bug than the one you started from rather than on the specific one. When it does, that is
the useful answer and not a defect of the reducer, but the reduced blob is then a repro for the
general bug, and the original case is still the repro for the specific one. Both belong in a
report.

Cases where nothing can be dropped are also a result: it means every record in the chain is load
bearing for that divergence, and the corpus case itself is already the minimal input.

Usage:
    python3 difftest/reduce.py <case-id-substring> [...]
    python3 difftest/reduce.py --all
"""

from __future__ import annotations

import os
import struct
import sys
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
from harness import Case, RustOracle, compare, load_cases, run_python  # noqa: E402


def record_spans(proof: bytes) -> Optional[List[Tuple[int, int]]]:
    """Byte spans of each top-level record, or None if the blob does not walk cleanly.

    An independent reader, on purpose. It must not share code with either implementation under
    test, or a framing bug would hide itself.
    """
    spans: List[Tuple[int, int]] = []
    off = 0
    n = len(proof)
    while off < n:
        start = off
        # name: sequence of length-prefixed labels ending in a zero byte. No compression pointers
        # are legal at the top level of an RFC 9102 chain.
        while True:
            if off >= n:
                return None
            ln = proof[off]
            if ln & 0xC0:
                return None
            off += 1
            if ln == 0:
                break
            off += ln
        if off + 10 > n:
            return None
        off += 8  # type, class, ttl
        rdlen = struct.unpack(">H", proof[off : off + 2])[0]
        off += 2
        off += rdlen
        if off > n:
            return None
        spans.append((start, off))
    return spans


def signature(rust: Dict[str, Any], py: Dict[str, Any]) -> Tuple:
    """Coarse fingerprint of a divergence, stable enough to reduce against."""
    def rrkeys(side: Dict[str, Any], key: str):
        v = side.get(key)
        if v is None:
            return None
        return tuple(sorted((r.get("n"), r.get("t"), r.get("w")) for r in v))

    return (
        rust.get("result"),
        rust.get("error"),
        py.get("result"),
        py.get("error", "").split(":")[0] if isinstance(py.get("error"), str) else py.get("error"),
        rrkeys(rust, "verified_rrs") == rrkeys(py, "verified_rrs"),
        rrkeys(rust, "resolved") == rrkeys(py, "resolved"),
    )


def reduce_case(case: Case, oracle: RustOracle, max_rounds: int = 12) -> Dict[str, Any]:
    proof = case.proof_bytes()
    name = case.query_name
    pinned = case.pinned_time

    rust0 = oracle.run(case.id, proof, name)
    py0 = run_python(case.id, proof, name, pinned)
    diffs0 = compare(rust0, py0)
    if not diffs0:
        return {"case": case.id, "reduced": False, "reason": "no divergence to reduce"}
    target = signature(rust0, py0)

    spans = record_spans(proof)
    if spans is None:
        return {
            "case": case.id,
            "reduced": False,
            "reason": "blob does not walk cleanly as a record stream, cannot reduce by record",
            "original_bytes": len(proof),
        }

    keep = list(range(len(spans)))

    def build(idxs: List[int]) -> bytes:
        return b"".join(proof[spans[i][0] : spans[i][1]] for i in idxs)

    def still_diverges(idxs: List[int]) -> bool:
        blob = build(idxs)
        if not blob:
            return False
        r = oracle.run(case.id + "#red", blob, name)
        p = run_python(case.id + "#red", blob, name, pinned)
        return bool(compare(r, p)) and signature(r, p) == target

    changed = True
    rounds = 0
    while changed and rounds < max_rounds:
        changed = False
        rounds += 1
        i = 0
        while i < len(keep):
            trial = keep[:i] + keep[i + 1 :]
            if still_diverges(trial):
                keep = trial
                changed = True
            else:
                i += 1

    reduced = build(keep)
    r = oracle.run(case.id + "#red", reduced, name)
    p = run_python(case.id + "#red", reduced, name, pinned)
    return {
        "case": case.id,
        "reduced": True,
        "original_bytes": len(proof),
        "original_records": len(spans),
        "reduced_bytes": len(reduced),
        "reduced_records": len(keep),
        "kept_record_indices": keep,
        "dropped_record_indices": [i for i in range(len(spans)) if i not in keep],
        "reduced_hex": reduced.hex(),
        "rust": r,
        "python": p,
        "diffs": compare(r, p),
    }


def _label(proof: bytes, span: Tuple[int, int]) -> str:
    """Human label for one record span, from the independent reader."""
    blob = proof[span[0] : span[1]]
    off = 0
    labels = []
    while True:
        ln = blob[off]
        off += 1
        if ln == 0:
            break
        labels.append(blob[off : off + ln].decode("ascii", "replace"))
        off += ln
    ty = struct.unpack(">H", blob[off : off + 2])[0]
    names = {
        1: "A", 2: "NS", 5: "CNAME", 16: "TXT", 28: "AAAA", 39: "DNAME",
        43: "DS", 46: "RRSIG", 47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 52: "TLSA",
    }
    return "%s %s" % (".".join(labels) + ".", names.get(ty, "TYPE%d" % ty))


def main(argv: List[str]) -> int:
    if "--rev" in argv:
        rev = argv[argv.index("--rev") + 1]
        os.environ["DIFFTEST_PORT_SRC"] = harness.materialize_rev(rev)
    cases = load_cases()
    if "--all" in argv:
        wanted = cases
    else:
        skip = {argv[argv.index("--rev") + 1]} if "--rev" in argv else set()
        pats = [a for a in argv if not a.startswith("-") and a not in skip]
        if not pats:
            print(__doc__)
            return 2
        wanted = [c for c in cases if any(p in c.id for p in pats)]
    wanted = [c for c in wanted if c.has_proof]
    if not wanted:
        print("no matching cases with proof bytes")
        return 2

    with RustOracle() as oracle:
        for case in wanted:
            res = reduce_case(case, oracle)
            print("=" * 100)
            print("case: %s" % case.id)
            if not res.get("reduced"):
                print("  %s" % res.get("reason"))
                continue
            proof = case.proof_bytes()
            spans = record_spans(proof) or []
            print(
                "  %d records / %d bytes  ->  %d records / %d bytes"
                % (res["original_records"], res["original_bytes"], res["reduced_records"], res["reduced_bytes"])
            )
            print("  kept records:")
            for i in res["kept_record_indices"]:
                print("    [%2d] %s" % (i, _label(proof, spans[i])))
            print("  rust  : %s" % {k: v for k, v in res["rust"].items() if k in ("result", "error", "valid_from", "expires", "max_cache_ttl")})
            print("  python: %s" % {k: v for k, v in res["python"].items() if k in ("result", "error", "valid_from", "expires", "max_cache_ttl")})
            print("  divergence still present:")
            for d in res["diffs"]:
                print("    %s" % d)
            out = os.path.join(harness.HERE, "repro")
            os.makedirs(out, exist_ok=True)
            path = os.path.join(out, case.id.replace("/", "_") + ".minimal.bin")
            with open(path, "wb") as fh:
                fh.write(bytes.fromhex(res["reduced_hex"]))
            print("  minimal blob written to: %s" % path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

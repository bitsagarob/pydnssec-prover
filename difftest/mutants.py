"""Generate the mutated proofs the mutation test uses, and dump the diverging ones to disk.

The mutants are a deterministic function of (case id, seed), so a failure reported by
``test_mutated_proofs_match_reference`` can always be reproduced byte for byte.

    python3 difftest/mutants.py                       # summarise every base case
    python3 difftest/mutants.py --write               # also write diverging mutants to repro/
    python3 difftest/mutants.py --case bip353/01-simple-valid --index 7
"""

from __future__ import annotations

import hashlib
import os
import sys
from typing import List

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import harness  # noqa: E402
from harness import RustOracle, compare, load_cases, run_python  # noqa: E402
from test_difftest import MUTANTS_PER_BASE, MUTATION_BASES, MUTATION_SEED, _mutants  # noqa: E402


def main(argv: List[str]) -> int:
    if "--rev" in argv:
        os.environ["DIFFTEST_PORT_SRC"] = harness.materialize_rev(argv[argv.index("--rev") + 1])
    write = "--write" in argv
    only = None
    if "--case" in argv:
        only = argv[argv.index("--case") + 1]
    index = None
    if "--index" in argv:
        index = int(argv[argv.index("--index") + 1])

    cases = {c.id: c for c in load_cases() if c.has_proof}
    bases = [only] if only else MUTATION_BASES
    out_dir = os.path.join(harness.HERE, "repro")

    rc = 0
    with RustOracle() as oracle:
        for base_id in bases:
            case = cases.get(base_id)
            if case is None:
                print("skip %s: not in corpus" % base_id)
                continue
            mutants = _mutants(case, MUTANTS_PER_BASE, MUTATION_SEED)
            todo = [index] if index is not None else range(len(mutants))
            n_div = 0
            classes = {}
            for i in todo:
                blob = mutants[i]
                rust = oracle.run("m%d" % i, blob, case.query_name)
                py = run_python("m%d" % i, blob, case.query_name, case.pinned_time)
                diffs = compare(rust, py)
                if not diffs:
                    continue
                n_div += 1
                rc = 1
                key = (rust.get("result"), rust.get("error"), py.get("result"))
                classes[key] = classes.get(key, 0) + 1
                if index is not None or write:
                    sha = hashlib.sha256(blob).hexdigest()
                    print("-" * 90)
                    print("%s mutant %d: %d bytes, sha256 %s" % (base_id, i, len(blob), sha))
                    print("  rust  : %s %s" % (rust.get("result"), rust.get("error") or ""))
                    print(
                        "  python: %s %s (%d verified records)"
                        % (
                            py.get("result"),
                            py.get("error") or "",
                            len(py.get("verified_rrs") or []),
                        )
                    )
                    for d in diffs:
                        print("  %s" % d.split("\n")[0])
                    if write:
                        os.makedirs(out_dir, exist_ok=True)
                        path = os.path.join(
                            out_dir, "%s.mutant%d.bin" % (base_id.replace("/", "_"), i)
                        )
                        with open(path, "wb") as fh:
                            fh.write(blob)
                        print("  written: %s" % path)
            print(
                "%s: %d of %d mutants diverge  %s"
                % (base_id, n_div, len(list(todo)), dict(classes))
            )
    return rc


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))

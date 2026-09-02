"""Differential harness: same proof bytes into the Rust reference and the Python port.

The contract this enforces is narrow and total: for every proof blob in the corpus, the Python
port must produce exactly what dnssec-prover 0.6.10 produces. Same accept/reject decision, same
error, same ``valid_from`` / ``expires`` / ``max_cache_ttl``, same verified records byte for byte,
same ``resolve_name`` output. Any difference is a failure.

CLOCK PINNING
-------------
The live half of the corpus is a set of snapshots. Cloudflare-signed chains in it go stale in
about 1.3 days. So no part of this harness compares anything against ``now``.

Neither implementation looks at the clock inside its stream verifier: ``verify_rr_stream`` in both
returns the signature window and leaves the wall-clock check to the caller. That is exactly why
these expired blobs still validate on both sides. This harness therefore:

* takes each case's pinned time from the case's OWN recorded window in ``INDEX.json``
  (midpoint of ``valid_from .. expires``), never from the system clock,
* applies the wall-clock acceptance check itself, at the pinned time, identically to both sides,
* additionally pins ``time.time()`` for the duration of the Python run, so that if the port ever
  grows an internal clock check the harness stays honest instead of silently going red on a
  Tuesday,
* reports staleness relative to now as information only, never as a failure.

A case that fails only because it aged is not a finding and this harness will not report one.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
if HERE not in sys.path:
    sys.path.insert(0, HERE)

# The corpus is an artifact of the dnssec-verify repo, with its own capture.sh / extract_bip353.py
# / analyze.py regeneration scripts. It is not vendored here. Point at it explicitly, or vendor it
# into difftest/corpus, or leave the default in place on this box.
DEFAULT_CORPUS_CANDIDATES = [
    os.environ.get("DIFFTEST_CORPUS", ""),
    os.path.join(HERE, "corpus"),
    "/home/rob/apps/bitsaga/services/silentpayments/dnssec-verify/testdata",
]

ORACLE_DIR = os.path.join(HERE, "oracle")
ORACLE_BIN = os.path.join(ORACLE_DIR, "target", "release", "difftest-oracle")

# Used only for cases with no recorded signature window at all (the deliberately DNSSEC-invalid
# BIP 353 example, which never produces a window on either side). 2025-08-08, when the BIP 353
# example proofs were live.
FALLBACK_PIN = 1754650000


def materialize_rev(rev: str) -> str:
    """Extract ``src/`` at a git revision into difftest/.portsnap/<rev>/ and return that path.

    The point is a baseline that cannot move under you. The working tree is fair game for whoever
    is fixing the port; a recorded baseline has to name a commit.
    """
    import tarfile
    import io

    proc = subprocess.run(
        ["git", "-C", REPO, "rev-parse", rev], capture_output=True, text=True
    )
    if proc.returncode != 0:
        raise RuntimeError("not a git revision: %s" % rev)
    sha = proc.stdout.strip()
    dest = os.path.join(HERE, ".portsnap", sha)
    marker = os.path.join(dest, ".complete")
    if not os.path.isfile(marker):
        if os.path.isdir(dest):
            shutil.rmtree(dest)
        os.makedirs(dest, exist_ok=True)
        arc = subprocess.run(
            ["git", "-C", REPO, "archive", sha, "src"], capture_output=True
        )
        if arc.returncode != 0:
            raise RuntimeError("git archive %s failed: %s" % (sha, arc.stderr.decode()))
        with tarfile.open(fileobj=io.BytesIO(arc.stdout)) as tar:
            tar.extractall(dest)
        with open(marker, "w") as fh:
            fh.write(sha + "\n")
    return os.path.join(dest, "src")


def port_revision() -> str:
    """A short description of exactly which port is under test, for the report header."""
    src = os.environ.get("DIFFTEST_PORT_SRC")
    if src:
        return "pinned tree %s" % os.path.abspath(src)
    proc = subprocess.run(
        ["git", "-C", REPO, "rev-parse", "--short", "HEAD"], capture_output=True, text=True
    )
    head = proc.stdout.strip() if proc.returncode == 0 else "?"
    dirty = subprocess.run(
        ["git", "-C", REPO, "status", "--porcelain", "--", "src"], capture_output=True, text=True
    ).stdout.strip()
    return "working tree at %s%s" % (head, " PLUS UNCOMMITTED CHANGES" if dirty else "")


class CorpusMissing(Exception):
    pass


class OracleMissing(Exception):
    pass


def find_corpus() -> str:
    for cand in DEFAULT_CORPUS_CANDIDATES:
        if cand and os.path.isfile(os.path.join(cand, "INDEX.json")):
            return os.path.abspath(cand)
    raise CorpusMissing(
        "no DNSSEC proof corpus found. Set DIFFTEST_CORPUS to a directory containing "
        "INDEX.json, live/ and bip353/, or vendor one into difftest/corpus. Tried: "
        + ", ".join(c for c in DEFAULT_CORPUS_CANDIDATES if c)
    )


def ensure_oracle(autobuild: bool = True) -> str:
    """Return the path to the Rust reference binary, building it if needed."""
    if os.path.isfile(ORACLE_BIN) and os.access(ORACLE_BIN, os.X_OK):
        return ORACLE_BIN
    if not autobuild or os.environ.get("DIFFTEST_AUTOBUILD") == "0":
        raise OracleMissing(
            "Rust reference oracle not built. Run: (cd %s && cargo build --release)" % ORACLE_DIR
        )
    cargo = shutil.which("cargo") or os.path.expanduser("~/.cargo/bin/cargo")
    if not os.path.isfile(cargo):
        raise OracleMissing(
            "cargo not found, cannot build the Rust reference oracle. Install a Rust toolchain "
            "or set DIFFTEST_AUTOBUILD=0 and build %s by hand." % ORACLE_DIR
        )
    cmd = [cargo, "build", "--release"]
    if os.environ.get("DIFFTEST_OFFLINE", "1") != "0":
        cmd.append("--offline")
    proc = subprocess.run(cmd, cwd=ORACLE_DIR, capture_output=True, text=True)
    if proc.returncode != 0:
        raise OracleMissing(
            "building the Rust reference oracle failed:\n%s\n%s" % (proc.stdout, proc.stderr)
        )
    if not os.path.isfile(ORACLE_BIN):
        raise OracleMissing("cargo reported success but %s does not exist" % ORACLE_BIN)
    return ORACLE_BIN


# ---------------------------------------------------------------------------------------------
# corpus
# ---------------------------------------------------------------------------------------------


@dataclass
class Case:
    id: str
    source: str
    query_name: Optional[str]
    expected: str
    invalid_at_layer: Optional[str]
    proof_path: Optional[str]
    index_valid_from: Optional[int]
    index_expires: Optional[int]
    oracle_chain_result: Dict[str, Any]
    raw: Dict[str, Any] = field(repr=False, default_factory=dict)

    # ---- clock pinning ----
    @property
    def window(self) -> Tuple[Optional[int], Optional[int]]:
        """The signature window this case was recorded with, from the corpus, never from now."""
        if self.index_valid_from is not None and self.index_expires is not None:
            return self.index_valid_from, self.index_expires
        ocr = self.oracle_chain_result or {}
        if ocr.get("valid_from") is not None and ocr.get("expires") is not None:
            return int(ocr["valid_from"]), int(ocr["expires"])
        return None, None

    @property
    def pin_source(self) -> str:
        vf, ex = self.window
        if vf is None:
            return "fallback"
        if self.index_valid_from is not None:
            return "index"
        return "oracle_chain_result"

    @property
    def pinned_time(self) -> int:
        """A UNIX time inside this case's own recorded validity window."""
        vf, ex = self.window
        if vf is None or ex is None:
            return FALLBACK_PIN
        return vf + (ex - vf) // 2

    @property
    def has_proof(self) -> bool:
        return self.proof_path is not None

    def proof_bytes(self) -> bytes:
        assert self.proof_path is not None
        with open(self.proof_path, "rb") as fh:
            return fh.read()

    def sha256(self) -> str:
        return hashlib.sha256(self.proof_bytes()).hexdigest()


def load_cases(corpus: Optional[str] = None) -> List[Case]:
    corpus = corpus or find_corpus()
    with open(os.path.join(corpus, "INDEX.json")) as fh:
        index = json.load(fh)
    cases: List[Case] = []
    for entry in index["cases"]:
        proof_rel = entry.get("proof_bin")
        proof_path = os.path.join(corpus, proof_rel) if proof_rel else None
        if proof_path and not os.path.isfile(proof_path):
            proof_path = None
        cases.append(
            Case(
                id=entry["case"],
                source=entry.get("source", "?"),
                query_name=entry.get("query_name"),
                expected=entry.get("expected", "?"),
                invalid_at_layer=entry.get("invalid_at_layer"),
                proof_path=proof_path,
                index_valid_from=entry.get("valid_from"),
                index_expires=entry.get("expires"),
                oracle_chain_result=entry.get("oracle_chain_result") or {},
                raw=entry,
            )
        )
    return cases


# ---------------------------------------------------------------------------------------------
# the two sides
# ---------------------------------------------------------------------------------------------


class RustOracle:
    """One long-lived dnssec-prover 0.6.10 process speaking the batch line protocol."""

    def __init__(self, binary: Optional[str] = None):
        self.binary = binary or ensure_oracle()
        self.proc = subprocess.Popen(
            [self.binary],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

    def run(self, case_id: str, proof: bytes, name: Optional[str]) -> Dict[str, Any]:
        assert self.proc.stdin is not None and self.proc.stdout is not None
        line = "%s\t%s\t%s\n" % (case_id.replace("\t", " "), proof.hex(), name or "-")
        self.proc.stdin.write(line)
        self.proc.stdin.flush()
        out = self.proc.stdout.readline()
        if not out:
            err = self.proc.stderr.read() if self.proc.stderr else ""
            raise RuntimeError("Rust oracle died on %s: %s" % (case_id, err))
        return json.loads(out)

    def close(self) -> None:
        try:
            if self.proc.stdin:
                self.proc.stdin.close()
            self.proc.wait(timeout=5)
        except Exception:
            self.proc.kill()

    def __enter__(self) -> "RustOracle":
        return self

    def __exit__(self, *exc: Any) -> None:
        self.close()


def run_python(case_id: str, proof: bytes, name: Optional[str], pinned_time: int) -> Dict[str, Any]:
    """Run the port under test with the clock pinned to ``pinned_time``.

    The port does not read the clock today. Pinning anyway is cheap insurance: it means a future
    internal wall-clock check cannot turn this suite red purely because the corpus aged.
    """
    import pyside

    real_time = time.time
    try:
        time.time = lambda: float(pinned_time)  # type: ignore[assignment]
        return pyside.run_one(case_id, proof, name)
    finally:
        time.time = real_time  # type: ignore[assignment]


# ---------------------------------------------------------------------------------------------
# comparison
# ---------------------------------------------------------------------------------------------

SCALARS = ("parsed", "rr_count", "result", "error", "valid_from", "expires", "max_cache_ttl")


def _rr_key(rr: Dict[str, Any]) -> Tuple[str, int, str]:
    return (rr.get("n", ""), int(rr.get("t", -1)), rr.get("w", ""))


def _describe_rr(rr: Dict[str, Any]) -> str:
    return "%s TYPE%s %s" % (rr.get("n"), rr.get("t"), rr.get("w"))


def _compare_rr_lists(label: str, a: Any, b: Any) -> List[str]:
    """Compare a verified-record list. Distinguishes content differences from order differences."""
    if a is None and b is None:
        return []
    if (a is None) != (b is None):
        return ["%s: rust=%s python=%s" % (label, "null" if a is None else "list", "null" if b is None else "list")]
    ka = [_rr_key(r) for r in a]
    kb = [_rr_key(r) for r in b]
    if ka == kb:
        return []
    diffs: List[str] = []
    sa, sb = sorted(ka), sorted(kb)
    if sa == sb:
        diffs.append(
            "%s: same %d records but different order\n    rust  : %s\n    python: %s"
            % (label, len(ka), [k[0] + "/" + str(k[1]) for k in ka], [k[0] + "/" + str(k[1]) for k in kb])
        )
        return diffs
    only_rust = [r for r in a if _rr_key(r) not in set(kb)]
    only_py = [r for r in b if _rr_key(r) not in set(ka)]
    diffs.append("%s: rust has %d records, python has %d" % (label, len(a), len(b)))
    for rr in only_rust:
        diffs.append("    only rust  : %s" % _describe_rr(rr))
    for rr in only_py:
        diffs.append("    only python: %s" % _describe_rr(rr))
    return diffs


def compare(rust: Dict[str, Any], py: Dict[str, Any]) -> List[str]:
    """Return a list of divergences. Empty list means the two sides agree exactly."""
    diffs: List[str] = []

    if py.get("result") == "crash":
        diffs.append(
            "python CRASHED where rust returned %s: %s"
            % (rust.get("result"), py.get("error"))
        )

    for key in SCALARS:
        ra, pa = rust.get(key), py.get(key)
        if key in ("valid_from", "expires", "max_cache_ttl") and rust.get("result") != "valid":
            continue
        if ra != pa:
            diffs.append("%s: rust=%r python=%r" % (key, ra, pa))

    if rust.get("result") == "valid" and py.get("result") == "valid":
        diffs.extend(_compare_rr_lists("verified_rrs", rust.get("verified_rrs"), py.get("verified_rrs")))
        diffs.extend(_compare_rr_lists("resolved", rust.get("resolved"), py.get("resolved")))

    if py.get("resolve_crash"):
        diffs.append("python resolve_name raised: %s" % py["resolve_crash"])

    return diffs


# ---------------------------------------------------------------------------------------------
# per-case execution, including the harness's own wall-clock layer
# ---------------------------------------------------------------------------------------------


@dataclass
class CaseResult:
    case: Case
    rust: Dict[str, Any]
    py: Dict[str, Any]
    diffs: List[str]
    # informational, never a Rust-vs-Python divergence
    notes: List[str]

    @property
    def ok(self) -> bool:
        return not self.diffs


def accepted_at(side: Dict[str, Any], pinned: int) -> bool:
    """The wall-clock layer that both implementations deliberately leave to the caller."""
    if side.get("result") != "valid":
        return False
    return int(side["valid_from"]) <= pinned <= int(side["expires"])


def run_case(case: Case, oracle: RustOracle) -> CaseResult:
    proof = case.proof_bytes()
    name = case.query_name
    pinned = case.pinned_time
    rust = oracle.run(case.id, proof, name)
    py = run_python(case.id, proof, name, pinned)
    diffs = compare(rust, py)
    notes: List[str] = []

    # Clock layer, applied at the pinned time to both sides identically.
    r_acc, p_acc = accepted_at(rust, pinned), accepted_at(py, pinned)
    if r_acc != p_acc:
        diffs.append(
            "accepted at pinned time %d: rust=%s python=%s" % (pinned, r_acc, p_acc)
        )
    if rust.get("result") == "valid" and not r_acc:
        notes.append(
            "pinned time %d is outside the reference window %s..%s, pin source %s: the corpus "
            "index and the proof disagree" % (pinned, rust.get("valid_from"), rust.get("expires"), case.pin_source)
        )

    # Corpus drift: does the reference still say what INDEX.json recorded? Informational.
    ocr = case.oracle_chain_result or {}
    if ocr:
        if bool(ocr.get("chain_valid")) != (rust.get("result") == "valid"):
            notes.append(
                "corpus drift: INDEX recorded chain_valid=%s, reference now says result=%s"
                % (ocr.get("chain_valid"), rust.get("result"))
            )
        for key in ("valid_from", "expires", "max_cache_ttl"):
            if key in ocr and rust.get("result") == "valid" and ocr[key] != rust.get(key):
                notes.append(
                    "corpus drift: INDEX recorded %s=%s, reference now says %s"
                    % (key, ocr[key], rust.get(key))
                )

    # Staleness, information only. Never a failure.
    if rust.get("result") == "valid":
        now = int(time.time())
        if now > int(rust["expires"]):
            notes.append(
                "stale: expired %.1f days ago in wall-clock terms, which is expected for a "
                "snapshot and is NOT a finding" % ((now - int(rust["expires"])) / 86400.0)
            )

    return CaseResult(case=case, rust=rust, py=py, diffs=diffs, notes=notes)


# ---------------------------------------------------------------------------------------------
# corpus-expectation cross-check (a self-test of the harness, not of the port)
# ---------------------------------------------------------------------------------------------


def expected_dnssec_accept(case: Case) -> Optional[bool]:
    """What the corpus says a pure chain validator should decide, or None if unspecified.

    ``expected=invalid`` with ``invalid_at_layer=bip353`` means the chain is sound and a chain
    validator is expected to ACCEPT. Conflating that with a DNSSEC rejection is the classic
    mistake and the corpus separates the two on purpose.
    """
    if case.expected == "valid":
        return True
    if case.expected == "invalid":
        if case.invalid_at_layer == "bip353":
            return True
        if case.invalid_at_layer == "dnssec":
            return False
    return None

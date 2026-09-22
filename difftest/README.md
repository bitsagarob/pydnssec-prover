# difftest: differential harness against the Rust reference

Runs the same DNSSEC proof bytes through both implementations and requires them to agree exactly:

* `dnssec-prover` 0.6.10, Matt Corallo's Rust crate, the reference,
* `pydnssec_prover`, the Python port in this repo, the thing under test.

Compared, per proof: the accept or reject decision, the specific error on reject, `valid_from`,
`expires`, `max_cache_ttl`, the full set of verified records including name, type and rdata byte
for byte, and the output of `resolve_name`. Any difference is a failure.

It is a hard oracle rather than a reading of the RFCs. That matters for DNSSEC, where the
dangerous bugs are not "the signature check is wrong" but "a record that had to be present was
absent and nobody noticed".

## Running it

```
pytest difftest/                          # the whole suite, exits non-zero on any divergence
pytest difftest/ -k corpus                # only the corpus cases
pytest difftest/ -m mutation              # only the mutated-bytes differential
python3 difftest/run.py                   # the same comparison as a report, table plus details
python3 difftest/run.py --quiet           # table only
python3 difftest/run.py --json            # machine readable, for CI artifacts
python3 difftest/run.py --repeat 5        # flag any case that is not deterministic across runs
python3 difftest/reduce.py <case>         # shrink a diverging proof to a minimal one
python3 difftest/mutants.py --write       # dump diverging mutated proofs to difftest/repro/
```

Dependencies: pytest and the standard library on the Python side, a Rust toolchain on the
reference side. Nothing else. `run.py` and `pytest` build the reference binary on first use with
`cargo build --release`, online, since a fresh cargo cache has none of the locked dependencies.
Set `DIFFTEST_OFFLINE=1` to add `--offline` once they are cached, or `DIFFTEST_AUTOBUILD=0` to
require a hand build.

`pyproject.toml` sets `testpaths = ["tests"]`, so a bare `pytest` will not pick this up. To adopt
it as CI, add `"difftest"` to `testpaths`.

### Pinning the port under test

A baseline that moves is not a baseline. To measure a specific commit rather than whatever is in
the working tree:

```
python3 difftest/run.py --rev HEAD
DIFFTEST_PORT_REV=HEAD pytest difftest/
DIFFTEST_PORT_SRC=/some/other/src pytest difftest/
```

`--rev` extracts `src/` at that commit into `difftest/.portsnap/<sha>/` and tests that copy. The
report header states which tree it measured, and says so when the working tree is dirty.

## The corpus

The proofs come from the `dnssec-verify` test corpus: 44 cases, 32 live proofs, 7 live negatives,
and BIP 353's own 5 example proofs. It is not vendored here, because it belongs to another repo
along with its regeneration scripts. Point at it with:

```
DIFFTEST_CORPUS=/path/to/dnssec-verify/testdata pytest difftest/
```

or vendor a copy into `difftest/corpus/`. With neither, the suite fails with that message rather
than skipping quietly; set `DIFFTEST_ALLOW_NO_CORPUS=1` for a skip instead.

The five BIP 353 proofs are also checked into `tests/data/bip353` and run without any of this,
from `tests/test_bip353.py`.

Seven of the 44 cases carry no proof bytes. They are names for which the reference could not
*build* a proof at all: NXDOMAIN, NODATA, Cloudflare NSEC black lies. There is nothing to replay
offline, so a bytes-in differential cannot cover them.

## The clock-pinning rule

Read this before filing a bug against a failing case.

Live proofs expire. Cloudflare-signed chains in this corpus are stale within about 1.3 days, the
rest within about two weeks, and all five BIP 353 example proofs expired in August 2025.

Nothing in this harness is judged against `now`. Each case is judged at a time pinned inside its
own recorded `valid_from .. expires` window from `INDEX.json`, specifically the midpoint. This is
safe because `verify_rr_stream` in both implementations deliberately does not apply a wall-clock
check: it returns the signature window and leaves the decision to the caller. The harness applies
that layer itself, at the pinned time, identically to both sides, and pins `time.time()` for the
duration of each Python run so a future internal clock check cannot turn the suite red on a date
that has nothing to do with the port. `test_expired_proofs_still_validate_on_both_sides` asserts
the property directly.

A case failing only because it aged is not a finding. The report prints staleness as a note. If
you are about to re-capture the corpus to make something go green, check first whether the only
thing wrong is the date.

## What is in here

```
oracle/               the Rust reference side, links dnssec-prover 0.6.10
  src/main.rs           batch line protocol on stdin, one JSON result per line
pyside.py             the Python side, same JSON schema, so the two are directly comparable
harness.py            corpus loading, clock pinning, the comparator, the wall-clock layer
run.py                the report and the exit code
test_difftest.py      the pytest suite, including the harness's own self-tests
conftest.py           fixtures, and the DIFFTEST_PORT_REV pin
reduce.py             record-level delta debugging, shrinks a diverging proof
mutants.py            deterministic mutated proofs, and dumps the diverging ones
```

Records are compared by their canonical wire encoding, produced by each implementation's own
`write_rr(rr, 0, out)` with the TTL zeroed, plus the name and numeric type as that implementation
stores them. Comparing rendered JSON or `str()` would hide encoding bugs, which is the whole
reason this exists.

A Python exception is reported as `result="crash"` and is never folded into a plain `"invalid"`.
A port that raises `IndexError` where the reference returns `Err(Invalid)` has a real bug even
though both reject the proof.

The comparator self-tests are written against synthetic results rather than the port's current
bugs, so fixing the port cannot silently blind them.

## Baseline

Against the validator branch, reference `dnssec-prover` 0.6.10, corpus captured 2026-09-02:

```
44 corpus cases: 37 with proof bytes, 7 negatives with nothing to replay
37 MATCH   0 DIVERGE   7 SKIP
```

Mutated-bytes differential, 50 mutants each of four base proofs: 200 of 200 match. Against
upstream `main` the same run gives 26 match and 11 diverge on the corpus, 69 of 200 mutants
diverging, which is what this harness was built to find.

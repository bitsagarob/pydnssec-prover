# difftest: differential harness against the Rust reference

This runs the same DNSSEC proof bytes through **both** implementations and requires them to agree
exactly:

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
reference side. Nothing else. `run.py` and `pytest` build the reference binary on first use
(`cargo build --release --offline`); set `DIFFTEST_AUTOBUILD=0` to require a hand build, or
`DIFFTEST_OFFLINE=0` to let cargo reach the network.

`pyproject.toml` sets `testpaths = ["tests"]`, so a bare `pytest` will not pick this up. Naming
the directory is deliberate for now. To adopt this as CI, add `"difftest"` to `testpaths`.

### Pinning the port under test

A baseline that moves is not a baseline. To measure a specific commit rather than whatever is in
the working tree:

```
python3 difftest/run.py --rev HEAD
DIFFTEST_PORT_REV=HEAD pytest difftest/
DIFFTEST_PORT_SRC=/some/other/src pytest difftest/
```

`--rev` extracts `src/` at that commit into `difftest/.portsnap/<sha>/` and tests that copy. The
report header always states which tree it measured, and says so loudly when the working tree has
uncommitted changes.

## The corpus

The proofs come from the `dnssec-verify` test corpus: 44 cases, 32 live proofs, 7 live negatives,
and BIP 353's own 5 example proofs. It is **not vendored here**, because it belongs to another
repo along with its regeneration scripts. Point at it with:

```
DIFFTEST_CORPUS=/path/to/dnssec-verify/testdata pytest difftest/
```

or vendor a copy into `difftest/corpus/`. With neither, the suite fails loudly rather than
skipping quietly; set `DIFFTEST_ALLOW_NO_CORPUS=1` if you really want a skip.

Regenerating it, in the corpus directory:

```
./capture.sh                                  # re-queries live DNS, rewrites live/, ~1 minute
curl -sS -o bip-0353.mediawiki \
  https://raw.githubusercontent.com/bitcoin/bips/master/bip-0353.mediawiki
python3 extract_bip353.py bip-0353.mediawiki  # deterministic, rewrites bip353/
python3 analyze.py                            # rebuilds INDEX.json
```

`capture.sh` produces different bytes every time, because it re-queries and signature windows
move. Read that corpus's own README before regenerating: the BIP 353 half is deterministic and
must not change, and `extract_bip353.py` aborts on purpose if the BIP's example section changes.

Seven of the 44 cases carry no proof bytes. They are names for which the reference could not
**build** a proof at all: NXDOMAIN, NODATA, Cloudflare NSEC black lies. That is what makes them
negatives. There is nothing to replay offline, so a bytes-in differential cannot cover them, and
the suite says so explicitly instead of pretending otherwise.

## The clock-pinning rule

**Read this before you file a bug against a failing case.**

Live proofs expire. Cloudflare-signed chains in this corpus are stale within about 1.3 days, the
rest within about two weeks, and all five BIP 353 example proofs expired in August 2025. So:

**Nothing in this harness is judged against `now`.** Each case is judged at a time pinned inside
its own recorded `valid_from .. expires` window from `INDEX.json`, specifically the midpoint. The
one case with no recorded window at all, the deliberately DNSSEC-invalid `bip353/05`, uses a fixed
constant from the BIP 353 era; it never validates on either side, so the pin never decides
anything for it.

This is safe because `verify_rr_stream` in both implementations deliberately does **not** apply a
wall-clock check. It returns the signature window and leaves the decision to the caller. So an
expired blob still validates cryptographically on both sides, and the harness applies the
wall-clock layer itself, at the pinned time, identically to both. `run.py` also pins `time.time()`
for the duration of each Python run, so that if the port ever grows an internal clock check this
suite stays honest instead of going red on an arbitrary Tuesday.

`test_expired_proofs_still_validate_on_both_sides` asserts that property directly. If it ever
fails, the corpus needs recapturing and the harness design needs revisiting; it does not mean the
port is broken.

**A case failing only because it aged is not a finding.** The report prints staleness as a note
and never as a failure. If you are about to re-capture the corpus to make something go green, stop
and check whether the only thing wrong is the date.

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
though both "reject" the proof.

## Self-tests

A differential harness that cannot see a difference is worse than no harness, so the suite tests
itself, in a way that will not disarm when the port is fixed:

* `test_reference_rejects_the_missing_nsec3_case` pins the reference on `bip353/05`, the corpus's
  most valuable case: `bip353/03` with exactly one NSEC3 record deleted. A validator that checks
  every signature that is *present* accepts it, because the flaw is a record that is *absent*.
* `test_reference_accepts_the_bip353_layer_case` pins the other half of that trap. `bip353/04` is
  cryptographically sound and must be rejected one layer up, by BIP 353 rules, not by the chain
  validator. Conflating the two layers is the easy mistake.
* `test_comparator_catches_an_injected_scalar_divergence` and
  `test_comparator_catches_record_content_order_and_count` feed the comparator synthetic results
  that differ in one field, one rdata byte, one record, or only in order, and require it to
  notice each. These are written against synthetic data, not against the port's current bugs, so
  fixing the port cannot silently blind them.
* `test_clock_pinning_never_uses_now` asserts every pinned time lies inside its own case's window.

## Recorded baseline

Measured 2026-09-02 against port revision `3a3bda4` (`--rev HEAD`), reference `dnssec-prover`
0.6.10, corpus captured 2026-09-02.

```
44 corpus cases: 37 with proof bytes, 7 negatives with nothing to replay
26 MATCH   11 DIVERGE   7 SKIP
```

Diverging cases, and what differs:

| case | difference |
| --- | --- |
| `bip353/05-missing-nsec3-wildcard-INVALID` | reference rejects (`Invalid`), port **accepts** |
| `bip353/03-a-x-domain-cname-wild-valid` | port returns an NSEC3 as a verified record instead of the CNAME, `resolve_name` returns nothing, `max_cache_ttl` 60 not 30 |
| `live/a.x_domain_cname_wild.user._bitcoin-payment.dnssec_proof_tests.bitcoin.ninja` | same shape as `bip353/03` |
| `live/wildcard.x_domain_cname_wild.dnssec_proof_tests.bitcoin.ninja` | same shape as `bip353/03` |
| `live/asdf.cname_wildcard_test.dnssec_proof_tests.bitcoin.ninja` | NSEC3s returned instead of the CNAME and TXT, `expires` too late, `max_cache_ttl` 60 not 30 |
| `live/asdf.wildcard_test.dnssec_proof_tests.bitcoin.ninja` | NSEC3 returned instead of the TXT, `expires` too late, `max_cache_ttl` 60 not 30 |
| `live/cname.wildcard_test.dnssec_proof_tests.bitcoin.ninja` | NSEC3 returned instead of the TXT, `expires` too late, `max_cache_ttl` 60 not 30 |
| `live/wildcard_a.wildcard_b.dname_test.dnssec_proof_tests.bitcoin.ninja` | NSEC3s returned instead of the CNAME and TXT |
| `live/zzz9.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja` | an NSEC returned instead of the TXT |
| `live/asdf.wildcard_test.nsec_tests.dnssec_proof_tests.bitcoin.ninja` | no verified records at all, still reports valid, `expires` too late |
| `live/iis.se` | no verified records at all, still reports valid, window matches |

Mutated-bytes differential at the same revision, seed `20260902`, 50 mutants each of four base
proofs: **69 of 200 diverge**. 64 are the reference returning `Invalid` while the port accepts.
4 more are blobs the reference cannot even parse while the port accepts. The remaining 1 is a
both-accept content difference inherited from `bip353/03`. No crash on either side, in either
direction.

The reduced form of that whole accept-anything class is 290 bytes. `python3 difftest/reduce.py
bip353/05` shrinks the 34-record proof to a single `com. RRSIG` record, with no DNSKEY and no
trust anchor anywhere in the stream, which the port reports as valid with `valid_from=0,
expires=0, max_cache_ttl=0` and zero verified records. That is a more general bug than the
missing-NSEC3 one it started from, and both are worth fixing: the full `bip353/05` case is the
repro for the specific one, the 290-byte blob for the general one.

Determinism: `run.py --rev HEAD --repeat 5` reports every case identical across all five runs.

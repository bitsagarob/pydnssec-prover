"""The Python side of the differential harness.

Runs a proof blob through the pydnssec-prover port under test and returns a result dict in
exactly the schema that ``difftest/oracle`` (the Rust reference) emits, so the two can be
compared field for field.

Deliberate choices:

* Records are compared by their canonical wire encoding, produced by the port's own
  ``write_rr(record, 0, out)`` with the TTL forced to 0, plus the name and numeric type as the
  port stores them. Comparing rendered JSON or ``str()`` would hide encoding bugs.
* An unexpected exception is reported as ``result="crash"``, never folded into ``"invalid"``.
  A port that raises ``IndexError`` where the reference returns ``Err(Invalid)`` has a real bug
  even though both "reject" the proof, and CI must see the difference.
* Nothing here consults the wall clock. Clock pinning is applied by ``harness.py``.
"""

from __future__ import annotations

import os
import sys
import traceback
from io import BytesIO
from typing import Any, Dict, List, Optional

_HERE = os.path.dirname(os.path.abspath(__file__))
# Which copy of the port to test. Defaults to the working tree. Set DIFFTEST_PORT_SRC to a
# directory containing pydnssec_prover/ to test a different one, which is how ``run.py --rev``
# pins a baseline to a git revision while somebody else is editing the working tree.
_SRC = os.environ.get("DIFFTEST_PORT_SRC") or os.path.join(os.path.dirname(_HERE), "src")
_SRC = os.path.abspath(_SRC)
if _SRC not in sys.path:
    sys.path.insert(0, _SRC)

import pydnssec_prover as pdp  # noqa: E402

PORT_SRC = _SRC
PORT_FILE = getattr(pdp, "__file__", "?")


def _rr_dict(record: Any) -> Dict[str, Any]:
    """Canonical, comparable encoding of one verified record."""
    buf = BytesIO()
    pdp.write_rr(record, 0, buf)
    return {
        "n": str(record.name),
        "t": int(record.type_code),
        "w": buf.getvalue().hex(),
    }


def _rr_dict_safe(record: Any) -> Dict[str, Any]:
    try:
        return _rr_dict(record)
    except Exception as exc:  # a record the port cannot re-serialize is itself a divergence
        return {
            "n": str(getattr(record, "name", "?")),
            "t": int(getattr(record, "type_code", -1) or -1),
            "w": "SERIALIZE_ERROR:%s: %s" % (type(exc).__name__, exc),
        }


def _error_name(exc: BaseException) -> str:
    etype = getattr(exc, "error_type", None)
    value = getattr(etype, "value", None)
    if isinstance(value, str):
        return value
    return str(exc)


def run_one(case_id: str, proof: bytes, name: Optional[str]) -> Dict[str, Any]:
    """Run one proof through the port. Never raises."""
    out: Dict[str, Any] = {"id": case_id}

    # --- parse -------------------------------------------------------------------------
    try:
        rrs = pdp.parse_rr_stream(proof)
    except Exception as exc:
        out.update(
            parsed=False,
            result="parse_error",
            error="parse_error",
            detail="%s: %s" % (type(exc).__name__, exc),
        )
        return out

    out["parsed"] = True
    out["rr_count"] = len(rrs)

    # --- verify ------------------------------------------------------------------------
    try:
        verified = pdp.verify_rr_stream(rrs)
    except pdp.ValidationError as exc:
        out.update(result="error", error=_error_name(exc))
        return out
    except Exception as exc:
        out.update(
            result="crash",
            error="%s: %s" % (type(exc).__name__, exc),
            traceback=traceback.format_exc(limit=6),
        )
        return out

    out["result"] = "valid"
    try:
        out["valid_from"] = int(verified.valid_from)
        out["expires"] = int(verified.expires)
        out["max_cache_ttl"] = int(verified.max_cache_ttl)
    except Exception as exc:
        out.update(result="crash", error="bad window fields: %s: %s" % (type(exc).__name__, exc))
        return out

    out["verified_rrs"] = [_rr_dict_safe(r) for r in verified.verified_rrs]

    # --- resolve_name ------------------------------------------------------------------
    if name is None:
        out["resolved"] = None
        return out

    dotted = name if name.endswith(".") else name + "."
    try:
        target = pdp.Name(dotted)
    except Exception:
        out["resolved"] = None
        return out
    try:
        resolved: List[Any] = verified.resolve_name(target)
    except Exception as exc:
        out["resolved"] = None
        out["resolve_crash"] = "%s: %s" % (type(exc).__name__, exc)
        return out
    out["resolved"] = [_rr_dict_safe(r) for r in resolved]
    return out


def _main() -> int:
    """Batch mode, same line protocol as the Rust oracle. Used for cross-checking only."""
    import json

    for line in sys.stdin:
        line = line.rstrip("\n")
        if not line.strip():
            continue
        parts = line.split("\t")
        if len(parts) < 2:
            print(json.dumps({"id": "?", "parsed": False, "result": "bad_request"}))
            continue
        case_id, proof_hex = parts[0], parts[1]
        name = parts[2] if len(parts) > 2 and parts[2] not in ("", "-") else None
        try:
            proof = bytes.fromhex(proof_hex)
        except ValueError:
            print(json.dumps({"id": case_id, "parsed": False, "result": "bad_request"}))
            continue
        print(json.dumps(run_one(case_id, proof, name)))
        sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(_main())

"""Finite held-resource protocol and exclusive persistent synthetic ledger.

This is executable protocol source, not a qualified Windows backend. File
reservations survive reopening, but filesystem crash durability/ACL/ancestry
and OS handle semantics require independent platform qualification.
"""
import os
from pathlib import Path
import time
from types import SimpleNamespace
import math
from dataclasses import dataclass
from infra.evidence_release_schemas import Refused, require, hexadecimal, canonical, GATES, FINALIZERS, digest
from infra.evidence_release_bridge import ModelAdmission

class ModelFileLedger:
    def __init__(self, synthetic_directory):
        self.directory = Path(synthetic_directory)
    def consume(self, admission):
        require(type(admission) is ModelAdmission and admission.production_eligible is False)
        hexadecimal(admission.nonce,32)
        hexadecimal(admission.authorization_sha256)
        require(admission.operation in ("FRESH_PREFLIGHT","ONE_COMPARISON"))
        raw=canonical({"schema":2,"nonce":admission.nonce,"operation":admission.operation,"authorization_sha256":admission.authorization_sha256})
        fd=None; failed=False
        try:
            fd=os.open(self.directory/(admission.nonce+".reservation"), os.O_WRONLY|os.O_CREAT|os.O_EXCL|getattr(os,"O_NOFOLLOW",0),0o600)
            written=os.write(fd,raw); require(type(written) is int and written == len(raw))
            require(os.fsync(fd) is None)
        except BaseException: failed=True
        finally:
            if fd is not None:
                try: require(os.close(fd) is None)
                except BaseException: failed=True
        if failed: raise Refused()

@dataclass(frozen=True)
class ModelOutcome:
    operation: str
    create_attempted: bool
    original_cid: str | None
    gates: tuple
    finalizers: tuple
    production_eligible: bool = False

def drive_model(admission, ledger, backend, *, clock=time.monotonic):
    failed=False; result=None
    try: result=_drive_model(admission,ledger,backend,clock=clock)
    except BaseException: failed=True
    if failed: raise Refused()
    return result

def _drive_model(admission, ledger, backend, *, clock):
    """Run the full injected held-resource protocol, without creating OS objects.

    backend owns held parents/executing bytes/lock/engine/guards and must expose
    closed typed observations. An injected object is never production authority.
    All five finalizers run even after interruption; any uncertainty is sticky.
    """
    require(type(admission) is ModelAdmission and admission.production_eligible is False and admission.operation in ("FRESH_PREFLIGHT","ONE_COMPARISON"))
    ledger.consume(admission)  # Never erase or recycle this reservation.
    # Capture original bound callbacks once, before work can replace backend
    # attributes. Cleanup never adopts a later replacement callback.
    failed_capture=False
    try: backend=SimpleNamespace(**{name:getattr(backend,name) for name in ("hold","observe","reserve_guard","repeat_live_gates","mark_create_attempted","create_original","record_original","start_original","attach_original","postflight","save_candidate","cleanup_original","finalize","close_candidate","commit_original_guard","confirm_guard_absent","finish_model","retain_refusal_guard")})
    except BaseException: failed_capture=True
    if failed_capture: raise Refused()
    source_clock=clock; last=[None]
    def clock():
        value=source_clock()
        require(type(value) in (int,float) and math.isfinite(value) and (last[0] is None or value>=last[0]))
        last[0]=value
        return value
    start=clock(); deadline=start+300; attempted=False; cid=None; failed=False; gates=[]; finalizers=[]
    def remaining(cap=15):
        value=deadline-clock(); require(value>0); return min(cap,value)
    def exact_none(value): require(value is None)
    def close_budget():
        nonlocal failed
        try: return max(0,min(15,deadline-clock()))
        except BaseException:
            failed=True
            return 0
    try:
        exact_none(backend.hold(admission,remaining()))
        # These are held live observations, not saved receipt substitutions.
        for gate in GATES:
            row=backend.observe(gate,remaining())
            require(type(row) is dict and set(row)=={"gate","confirmed"} and row["gate"]==gate and row["confirmed"] is True)
            remaining(); gates.append(gate)
        exact_none(backend.reserve_guard(remaining()))
        if admission.operation == "ONE_COMPARISON":
            # Repeat currentness immediately before the only create.
            exact_none(backend.repeat_live_gates(tuple(GATES),remaining()))
            exact_none(backend.mark_create_attempted(remaining())); attempted=True
            result=backend.create_original(remaining())
            require(type(result) is dict)
            hexadecimal(result.get("cid")); cid=result["cid"]
            exact_none(backend.record_original(cid,remaining()))  # CID before start.
            require(set(result)=={"cid","returncode"})
            require(type(result["returncode"]) is int and result["returncode"]==0)
            exact_none(backend.start_original(cid,remaining()))
            observation=backend.attach_original(cid,remaining(180))
            remaining()
            require(type(observation) is dict and set(observation)=={"returncode","stdout","stderr_bytes","closed"} and observation["closed"] is True)
            require(type(observation["returncode"]) is int and observation["returncode"]==0 and type(observation["stdout"]) is bytes and 1<=len(observation["stdout"])<=4096 and type(observation["stderr_bytes"]) is int and 0<=observation["stderr_bytes"]<=16384)
            # Frozen parser, imported only after transport has closed.
            from infra.evidence_detection_controls import parse_detection_controls
            parse_detection_controls(observation["stdout"],observation["returncode"])
    except BaseException: failed=True
    finally:
        if attempted:
            try:
                # Unknown CID is not permission to adopt a name/other object.
                # At zero remaining budget this is a close-only request; the
                # backend must not issue a new external cleanup command.
                budget=close_budget()
                exact_none(backend.cleanup_original(cid,budget,8))
                remaining()
            except BaseException: failed=True
        if not failed:
            try:
                exact_none(backend.postflight(cid,29 if cid else 28,116 if cid else 112,remaining()))
                exact_none(backend.save_candidate(remaining()))
            except BaseException: failed=True
        for finalizer in FINALIZERS:
            try:
                exact_none(backend.finalize(finalizer,close_budget()))
                remaining(); finalizers.append(finalizer)
            except BaseException: failed=True
        if not failed:
            try:
                exact_none(backend.close_candidate(remaining()))
                exact_none(backend.commit_original_guard(remaining()))
                require(backend.confirm_guard_absent(remaining()) is True)
                # External holder proof is a separately authenticated obligation;
                # model backend cannot self-issue a production witness.
                exact_none(backend.finish_model(remaining()))
                remaining()
            except BaseException: failed=True
        if failed:
            try: backend.retain_refusal_guard()
            except BaseException: pass
    if failed: raise Refused()
    return ModelOutcome(admission.operation,attempted,cid,tuple(gates),tuple(finalizers))

"""Pure, skip-aware C16 summaries of supplied evidence, never execution authority.

No command, file, clock, model, network or database is accessed. Metadata marked
ACTUAL remains a caller claim. Source hashes are comparisons, not authentication;
age is a declared reporting window, not live currentness. This module cannot
grant M4 acceptance or native/private execution. It does not run quality.py.
"""
from __future__ import annotations

import re
from types import MappingProxyType


# Kept explicit rather than importing the command runner or Django management
# command. A reviewed source change is required to change required checks.
CHECK_KINDS = MappingProxyType({
    "tools-unit": "TEST", "skills-structure": "COMMAND",
    "agents-structure": "COMMAND", "project-structure": "COMMAND",
    "quality-unit": "TEST", "recovery-unit": "TEST",
    "retention-unit": "TEST", "evidence-unit": "TEST",
    "sanitizer-unit": "TEST", "retention-policy-unit": "TEST",
    "restore-rehearsal-unit": "TEST", "live-recovery-guards": "TEST",
    "native-ownership-unit": "TEST", "web-protocol-unit": "TEST",
    "detector-runner-unit": "TEST", "web-typecheck": "COMMAND",
    "web-build": "COMMAND", "web-protocol-browser": "TEST",
    "android-jvm-build-device": "TEST", "isolated-postgresql": "TEST",
    "serialized-live-browser": "TEST", "restore-reconciliation": "TEST",
    "synthetic-load-faults": "TEST",
    "dependency-license-secret-config-review": "REVIEW",
    "independent-security-review": "REVIEW", "human-acceptance": "HUMAN",
})
REQUIRED_CHECKS = tuple(CHECK_KINDS)
_STATUSES = ("PASSED", "FAILED", "TIMEOUT", "UNAVAILABLE", "NOT_RUN")
_FIELDS = {"id", "mode", "status", "exit_code", "counts", "observed_at", "source_sha256"}
_COUNT_FIELDS = {"total", "passed", "failed", "errors", "skipped"}
_MAX_COUNT = 10**9
_MAX_TIME = 2**53 - 1


class InvalidEvidence(ValueError):
    """Fixed diagnostic; untrusted values and exception context are not emitted."""


def _require(condition):
    if not condition:
        raise InvalidEvidence("INVALID_EVIDENCE")


def _number(value, maximum=_MAX_COUNT):
    return type(value) is int and 0 <= value <= maximum


def _hash(value):
    return type(value) is str and re.fullmatch(r"[0-9a-f]{64}", value) is not None


def _metadata(observed_at, evaluated_at, max_age_seconds, mode):
    _require(_number(observed_at, _MAX_TIME) and _number(evaluated_at, _MAX_TIME))
    _require(type(max_age_seconds) is int and 1 <= max_age_seconds <= 31_536_000)
    _require(type(mode) is str and mode in ("ACTUAL", "MODEL"))
    if observed_at > evaluated_at:
        return "FUTURE"
    return "WITHIN_DECLARED_WINDOW" if evaluated_at - observed_at <= max_age_seconds else "STALE"


def _counts(value):
    if value is None:
        return None
    _require(type(value) is dict and set(value) == _COUNT_FIELDS)
    _require(all(_number(item) for item in value.values()))
    _require(value["total"] == sum(value[key] for key in ("passed", "failed", "errors", "skipped")))
    return dict(value)


def summarize_required(records, *, evaluated_at, expected_source_sha256, max_age_seconds):
    """Summarize the fixed required set without running or authenticating it.

    Exact built-in JSON types only; malformed/unknown/duplicate records raise a
    fixed InvalidEvidence. Missing records become MISSING. Test PASSED requires
    known counts, positive execution, and zero skips/errors/failures. Commands
    use counts=None and mean command completion only. Reviews/human acceptance
    remain unadmitted regardless of supplied metadata. UTC epoch seconds and a
    bounded explicit age window are comparison inputs, never clock authority.
    """
    _require(type(records) is list and len(records) <= len(REQUIRED_CHECKS))
    _require(_number(evaluated_at, _MAX_TIME) and _hash(expected_source_sha256))
    _require(type(max_age_seconds) is int and 1 <= max_age_seconds <= 31_536_000)
    by_id = {}
    for record in records:
        _require(type(record) is dict and set(record) == _FIELDS)
        name = record["id"]
        _require(type(name) is str and name in CHECK_KINDS and name not in by_id)
        _require(type(record["status"]) is str and record["status"] in _STATUSES)
        _require(record["exit_code"] is None or (type(record["exit_code"]) is int and -2**31 <= record["exit_code"] < 2**31))
        _require(_hash(record["source_sha256"]))
        freshness = _metadata(record["observed_at"], evaluated_at, max_age_seconds, record["mode"])
        counts = _counts(record["counts"])
        kind = CHECK_KINDS[name]
        if kind == "COMMAND":
            _require(counts is None)
        state = record["status"]
        if state in ("FAILED", "TIMEOUT") or record["exit_code"] not in (None, 0) or (counts and (counts["failed"] or counts["errors"])):
            state = "FAILED"
        elif kind in ("HUMAN", "REVIEW"):
            state = "HUMAN_REVIEW_REQUIRED" if kind == "HUMAN" else "REVIEW_UNADMITTED"
        elif state != "PASSED":
            pass
        elif freshness != "WITHIN_DECLARED_WINDOW":
            state = freshness
        elif record["source_sha256"] != expected_source_sha256:
            state = "SOURCE_MISMATCH"
        elif record["mode"] != "ACTUAL":
            state = "MODEL_ONLY"
        elif record["exit_code"] is None:
            state = "UNKNOWN_EXIT"
        elif kind == "TEST" and counts is None:
            state = "UNKNOWN_COUNTS"
        elif kind == "TEST" and counts["skipped"]:
            state = "SKIPPED_REQUIRED"
        elif kind == "TEST" and counts["passed"] == 0:
            state = "NO_EXECUTED_TESTS"
        else:
            state = "REPORTED_TEST_PASS" if kind == "TEST" else "REPORTED_COMMAND_COMPLETION"
        by_id[name] = {"id": name, "kind": kind, "state": state, "mode": record["mode"],
                       "counts": counts, "age_status": freshness,
                       "source_matches": record["source_sha256"] == expected_source_sha256}
    results = [by_id.get(name, {"id": name, "kind": kind, "state": "MISSING"})
               for name, kind in CHECK_KINDS.items()]
    command_checks = [item for item in results if item["kind"] in ("TEST", "COMMAND")]
    complete = all(item["state"] in ("REPORTED_TEST_PASS", "REPORTED_COMMAND_COMPLETION") for item in command_checks)
    status = "FAILED" if any(item["state"] == "FAILED" for item in results) else ("CHECK_EVIDENCE_COMPLETE" if complete else "INCOMPLETE")
    return {"schema_version": 1, "status": status, "checks": results,
            "authority": "NONE", "provenance": "UNAUTHENTICATED_CALLER_METADATA",
            "freshness_basis": "DECLARED_WINDOW_NOT_LIVE_CURRENTNESS",
            "m4_acceptance": "NOT_GRANTED", "native_execution": "NOT_GRANTED"}


_JOB_STATUSES = ("PENDING", "PROCESSING", "DONE", "FAILED")
_POISON_CODES = ("RULE_PROCESSING_FAILED", "ATTEMPTS_EXHAUSTED", "STALE_CONTEXT")
_HEALTH_FIELDS = {"schema_version", "completeness", "status", "job_status_counts", "unknown_status_count",
                  "expired_lease_count", "missing_lease_count", "oldest_pending_age_seconds",
                  "pending_creation_age_status", "oldest_pending_available_age_seconds", "available_age_basis",
                  "poison_code_counts", "unclassified_failure_count"}


def summarize_health(payload, *, observed_at, evaluated_at, max_age_seconds, mode):
    """Validate the operator command's safe aggregate shape, without DB access.

    Pending age is unavailable because the collector has no creation timestamp;
    available_at is retry scheduling time, never queue creation or latency/SLA.
    Counts cannot prove worker liveness, restart/retry behavior or no lost jobs.
    """
    age_status = _metadata(observed_at, evaluated_at, max_age_seconds, mode)
    _require(type(payload) is dict)
    if set(payload) == {"schema_version", "completeness", "status"}:
        _require(type(payload["schema_version"]) is int and payload["schema_version"] == 1)
        _require(type(payload["completeness"]) is str and type(payload["status"]) is str)
        _require(payload["completeness"] == "PARTIAL" and payload["status"] == "SCHEMA_UNAVAILABLE")
        return {"schema_version": 1, "status": "UNAVAILABLE", "authority": "NONE", "mode": mode,
                "age_status": age_status, "freshness_basis": "DECLARED_WINDOW_NOT_LIVE_CURRENTNESS"}
    _require(set(payload) == _HEALTH_FIELDS)
    _require(type(payload["schema_version"]) is int and payload["schema_version"] == 1)
    _require(all(type(payload[key]) is str for key in ("status", "completeness", "pending_creation_age_status", "available_age_basis")))
    _require(payload["status"] == "AGGREGATE_ONLY")
    jobs, poison = payload["job_status_counts"], payload["poison_code_counts"]
    _require(type(jobs) is dict and set(jobs) == set(_JOB_STATUSES))
    _require(type(poison) is dict and set(poison) == set(_POISON_CODES))
    _require(all(_number(value) for value in (*jobs.values(), *poison.values())))
    for key in ("unknown_status_count", "expired_lease_count", "missing_lease_count", "unclassified_failure_count"):
        _require(_number(payload[key]))
    _require(payload["expired_lease_count"] + payload["missing_lease_count"] <= jobs["PROCESSING"])
    _require(sum(poison.values()) + payload["unclassified_failure_count"] == jobs["FAILED"])
    _require(payload["oldest_pending_age_seconds"] is None)
    _require(payload["available_age_basis"] == "AVAILABLE_AT_NOT_CREATION_TIME")
    available_age = payload["oldest_pending_available_age_seconds"]
    if jobs["PENDING"]:
        _require(payload["pending_creation_age_status"] == "CREATION_TIME_UNAVAILABLE")
        _require(_number(available_age, _MAX_TIME))
    else:
        _require(payload["pending_creation_age_status"] == "NO_PENDING" and available_age is None)
    partial = bool(payload["unknown_status_count"] or payload["missing_lease_count"] or payload["unclassified_failure_count"] or jobs["PENDING"])
    _require(payload["completeness"] == ("PARTIAL" if partial else "COMPLETE"))
    issues = []
    for key, code in (("unknown_status_count", "UNKNOWN_JOB_STATUS"), ("expired_lease_count", "EXPIRED_LEASE"),
                      ("missing_lease_count", "MISSING_LEASE"), ("unclassified_failure_count", "UNCLASSIFIED_FAILURE")):
        if payload[key]:
            issues.append(code)
    if jobs["FAILED"]:
        issues.append("FAILED_JOBS")
    if jobs["PENDING"]:
        issues.append("PENDING_CREATION_AGE_UNAVAILABLE")
    status = "ATTENTION_REQUIRED" if issues else "AGGREGATE_OBSERVED"
    if age_status != "WITHIN_DECLARED_WINDOW":
        status = age_status
    elif mode == "MODEL":
        status = "MODEL_ONLY"
    return {"schema_version": 1, "status": status, "authority": "NONE", "mode": mode,
            "age_status": age_status, "freshness_basis": "DECLARED_WINDOW_NOT_LIVE_CURRENTNESS",
            "job_status_counts": dict(jobs), "unknown_status_count": payload["unknown_status_count"],
            "expired_lease_count": payload["expired_lease_count"], "missing_lease_count": payload["missing_lease_count"],
            "poison_code_counts": dict(poison), "unclassified_failure_count": payload["unclassified_failure_count"],
            "pending_creation_age_status": payload["pending_creation_age_status"],
            "oldest_pending_age_seconds": None, "oldest_pending_available_age_seconds": available_age,
            "available_age_basis": "AVAILABLE_AT_NOT_CREATION_TIME", "issues": issues,
            "worker_liveness": "UNVERIFIED", "latency_sla": "UNVERIFIED",
            "provenance": "UNAUTHENTICATED_CALLER_METADATA"}

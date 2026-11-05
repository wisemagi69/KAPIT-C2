"""Closed, bounded observations appended only to a failed PostgreSQL phase."""
import importlib
import json

MAX_BYTES = 4096
UNAVAILABLE = "POSTGRES_FAILURE_OBSERVATION: UNAVAILABLE"
PREFIX = "POSTGRES_FAILURE_OBSERVATION: "
ENUMS = {
    "ownership": ("UNAVAILABLE", "ABSENT", "INVALID", "VERIFIED"),
    "initialization": ("UNKNOWN", "INCOMPLETE", "READY"),
    "pid_file": ("NOT_INSPECTED", "ABSENT", "OVERSIZED", "UNAVAILABLE", "INVALID",
                 "PRESENT_VALIDATED_PROCESS_UNVERIFIED"),
    "log": ("NOT_INSPECTED", "ABSENT", "OVERSIZED", "UNAVAILABLE", "OBSERVED"),
    "log_attribution": ("EXISTING_LOG_NOT_BOUND_TO_FAILED_ATTEMPT",),
    "current_token": ("UNAVAILABLE", "NOT_SUPPORTED", "RESTRICTED", "NOT_RESTRICTED"),
    "cause": ("UNCONFIRMED",),
    "readiness": ("UNVERIFIED",),
}
CONDITIONS = ("TOKEN_RESTRICTION", "PERMISSION_DENIED", "PORT_UNAVAILABLE",
              "PID_LOCK_PRESENT", "SHUTDOWN_RECORDED", "READY_RECORDED")
ACTION = "SHARE_FINITE_DIAGNOSTIC_FOR_REVIEW"


def collect():
    # Optional diagnostic import failure must not replace the primary error.
    return importlib.import_module("infra.postgres_diagnostics").diagnose()


def validate(report):
    """Return a fresh finite projection; never retain arbitrary input strings."""
    keys = {"schema_version", "log_conditions", "next_actions", *ENUMS}
    if type(report) is not dict or len(report) != len(keys):
        raise ValueError
    if any(type(key) is not str for key in report) or set(report) != keys:
        raise ValueError
    if type(report["schema_version"]) is not int or report["schema_version"] != 1:
        raise ValueError
    safe = {"schema_version": 1}
    for key, values in ENUMS.items():
        value = report[key]
        if type(value) is not str or value not in values:
            raise ValueError
        safe[key] = values[values.index(value)]
    conditions = report["log_conditions"]
    if type(conditions) is not list or len(conditions) > len(CONDITIONS):
        raise ValueError
    if any(type(value) is not str or value not in CONDITIONS for value in conditions):
        raise ValueError
    canonical = [value for value in CONDITIONS if value in conditions]
    if conditions != canonical:
        raise ValueError
    safe["log_conditions"] = canonical
    actions = report["next_actions"]
    if (type(actions) is not list or len(actions) != 1
            or type(actions[0]) is not str or actions[0] != ACTION):
        raise ValueError
    safe["next_actions"] = [ACTION]
    # Preserve the collector's authentication/inspection sequencing as well.
    if safe["ownership"] != "VERIFIED" and safe["initialization"] != "UNKNOWN":
        raise ValueError
    if safe["initialization"] != "READY":
        if safe["pid_file"] != "NOT_INSPECTED" or safe["log"] != "NOT_INSPECTED":
            raise ValueError
    elif safe["pid_file"] == "NOT_INSPECTED" or safe["log"] == "NOT_INSPECTED":
        raise ValueError
    if safe["log"] != "OBSERVED" and canonical:
        raise ValueError
    return safe


def failure_observation():
    """Collect once; secondary failures cannot replace the startup error.

    KeyboardInterrupt deliberately propagates; collector SystemExit is secondary.
    """
    try:
        safe = validate(collect())
        serialized = json.dumps(safe, ensure_ascii=True, allow_nan=False, separators=(",", ":"))
        if type(serialized) is not str:
            raise ValueError
        result = PREFIX + serialized
        if len(result.encode("utf-8")) > MAX_BYTES:
            raise ValueError
        return result
    except (Exception, SystemExit):
        return UNAVAILABLE

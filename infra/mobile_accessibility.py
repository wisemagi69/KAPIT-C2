"""TASK093: actual TalkBack keyboard scenarios on a new, owned API36 emulator.

No server, database, PIN, reverse tunnel, phone or existing AVD is needed for
TASK092's synthetic presentation. Requires reviewed APKs and the heavy slot.
All raw Android dumps/instrumentation stay in bounded memory, never in reports.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from infra import mobile_emulator as base

PACKAGE, TEST_PACKAGE, RUNNER = base.PACKAGE, base.TEST_PACKAGE, base.RUNNER
TALKBACK_PACKAGE = "com.google.android.marvin.talkback"
COMPONENT = TALKBACK_PACKAGE + "/" + TALKBACK_PACKAGE + ".TalkBackService"
SHORT_COMPONENT = TALKBACK_PACKAGE + "/.TalkBackService"
TEST_CLASS = "org.kapit.c2.mobile.ui.MobileAccessibilityTest"
METHODS = (
    "talkBackSignInPasswordErrorsAndActivation",
    "talkBackEditorValidationAndFieldNavigation",
    "talkBackConfirmationRequiresExplicitQueueAndKeepsLockAvailable",
    "talkBackOfflineOutboxDistinguishesReceiptAndDisabledRetry",
    "talkBackLockedAndExpiredAccessExposeRecoveryActionsOnly",
)
SETTINGS = ("enabled_accessibility_services", "accessibility_enabled", "touch_exploration_enabled")
LIBRARIES = ("infra/mobile_emulator.py", "infra/mobile_integration.py", "infra/mobile_device.py",
             "android/tools/owned_process.py")
require = base.require
AccessibilityError = base.EmulatorError
RETRYABLE_STATE_ERRORS = frozenset({
    "A11Y_SERVICE_NOT_STABLE", "A11Y_ACTIVITY_SERVICE_INVALID", "A11Y_BINDER_MISSING",
    "A11Y_BINDING_NOT_RECEIVED", "A11Y_SYSTEM_CLIENT_MISSING", "A11Y_ACTIVITY_PROCESS_INVALID",
})
DIAGNOSTIC_ERRORS = RETRYABLE_STATE_ERRORS | frozenset({
    "A11Y_CURRENT_USER_DENIED", "A11Y_USER_STATE_INVALID", "A11Y_ATTRIBUTES_INVALID",
    "A11Y_SERVICE_STATE_INVALID", "A11Y_PREEXISTING_SERVICE_DENIED", "A11Y_BOUND_FORMAT_INVALID",
    "A11Y_BOUND_NOT_SPOKEN", "A11Y_BOUND_IDENTITY_INCONSISTENT", "A11Y_USER_ZERO_MISSING",
    "A11Y_ACTIVITY_USER_DENIED", "A11Y_ACTIVITY_PERMISSION_INVALID", "A11Y_BINDING_RECORD_INVALID",
    "A11Y_BINDING_INTENT_INVALID", "A11Y_UNEXPECTED_BINDING_CLIENT", "A11Y_COMPONENT_DENIED",
    "A11Y_DUMP_BOUND", "A11Y_ACTIVITY_DUMP_BOUND", "EMULATOR_TRANSPORT_CHANGED", "EMULATOR_COMMAND_TIMEOUT",
})
WAIT_PHASES = frozenset({"setup_service_readiness", "restore_original_service"})
DIAGNOSTIC_SCHEMA = 2
GUARDED_OPERATIONS = frozenset({"current_user_guard", "accessibility_dump", "talkback_binding_dump", "other"})
DIAGNOSTIC_STAGES = WAIT_PHASES | frozenset({
    "created", "installing_apks", "installed_service_query", "installed_identity", "original_settings",
    "original_service_state", "enable_service", "enable_accessibility", "verify_bound_service", "native_scenario",
    "restore_not_needed", "restore_stop_fixture", "restore_service_setting", "restore_accessibility_setting",
    "restore_touch_setting", "restore_verify", "restored",
})
# Android 16 r2 AccessibilityEvent constants, in ascending bit order (0..26).
# eventTypeToString emits an all-mask token, one bare name, or a canonical list.
# Zero/unknown-bit masks intentionally remain outside this supported subset.
EVENT_TYPES = (
    "TYPE_VIEW_CLICKED", "TYPE_VIEW_LONG_CLICKED", "TYPE_VIEW_SELECTED", "TYPE_VIEW_FOCUSED",
    "TYPE_VIEW_TEXT_CHANGED", "TYPE_WINDOW_STATE_CHANGED", "TYPE_NOTIFICATION_STATE_CHANGED",
    "TYPE_VIEW_HOVER_ENTER", "TYPE_VIEW_HOVER_EXIT", "TYPE_TOUCH_EXPLORATION_GESTURE_START",
    "TYPE_TOUCH_EXPLORATION_GESTURE_END", "TYPE_WINDOW_CONTENT_CHANGED", "TYPE_VIEW_SCROLLED",
    "TYPE_VIEW_TEXT_SELECTION_CHANGED", "TYPE_ANNOUNCEMENT", "TYPE_VIEW_ACCESSIBILITY_FOCUSED",
    "TYPE_VIEW_ACCESSIBILITY_FOCUS_CLEARED", "TYPE_VIEW_TEXT_TRAVERSED_AT_MOVEMENT_GRANULARITY",
    "TYPE_GESTURE_DETECTION_START", "TYPE_GESTURE_DETECTION_END", "TYPE_TOUCH_INTERACTION_START",
    "TYPE_TOUCH_INTERACTION_END", "TYPE_WINDOWS_CHANGED", "TYPE_VIEW_CONTEXT_CLICKED",
    "TYPE_ASSIST_READING_CONTEXT", "TYPE_SPEECH_STATE_CHANGE", "TYPE_VIEW_TARGETED_BY_SCROLL",
)
EVENT_RANK = {name: rank for rank, name in enumerate(EVENT_TYPES)}
EVENT_SHAPES = frozenset({"all_mask", "single_known", "list_known", "empty", "missing_or_duplicate", "other"})
BOUND_BOOLEAN_FIELDS = frozenset({"envelope_valid", "label_valid", "feedback_shape_valid", "numeric_fields_valid"})
BOUND_COUNT_FIELDS = frozenset({"service_records", "event_fields"})
BOUND_PATTERN = re.compile(
    r"Service\[label=[^\[\]\r\n]{1,160}, feedbackType\[([A-Z_, ]+)\], "
    r"capabilities=[0-9]{1,6}, eventTypes=(?P<events>[^\r\n]{0,2048}), notificationTimeout=[0-9]{1,12}, "
    r"requestA11yBtn=(?:true|false)\]")


def event_shape(value):
    if not isinstance(value, str) or len(value) > 2048:
        return "other"
    if value == "TYPES_ALL_MASK":
        return "all_mask"
    if value in EVENT_RANK:
        return "single_known"
    if value == "":
        return "empty"
    if value.startswith("[") and value.endswith("]"):
        names = value[1:-1].split(", ")
        if 2 <= len(names) <= len(EVENT_TYPES) and all(name in EVENT_RANK for name in names):
            ranks = [EVENT_RANK[name] for name in names]
            if all(left < right for left, right in zip(ranks, ranks[1:])):
                return "list_known"
    return "other"


def bound_structure(bound):
    """Fixed structure only, from the already bounded capture; never retain values."""
    fields = ("Service[", "feedbackType[", ", capabilities=", ", eventTypes=",
              ", notificationTimeout=", ", requestA11yBtn=")
    counts = {field: min(2, bound.count(field)) for field in fields}
    envelope = BOUND_PATTERN.fullmatch(bound)
    # Extract an event value only between unique, fixed separators. A full finite
    # grammar check is still mandatory; this extraction grants no acceptance.
    shape = "missing_or_duplicate"
    if counts[", eventTypes="] == counts[", notificationTimeout="] == 1:
        value = bound.partition(", eventTypes=")[2].partition(", notificationTimeout=")[0]
        shape = event_shape(value)
    return {
        "schema": 1,
        "service_records": counts["Service["], "event_fields": counts[", eventTypes="],
        "envelope_valid": envelope is not None and all(count == 1 for count in counts.values()),
        "label_valid": re.match(r"\AService\[label=[^\[\]\r\n]{1,160}, feedbackType\[", bound) is not None,
        "feedback_shape_valid": counts["feedbackType["] == 1 and
            re.search(r", feedbackType\[[A-Z_, ]+\], capabilities=", bound) is not None,
        "numeric_fields_valid": counts[", capabilities="] == counts[", notificationTimeout="] == 1 and
            re.search(r", capabilities=[0-9]{1,6}, eventTypes=", bound) is not None and
            re.search(r", notificationTimeout=[0-9]{1,12}, requestA11yBtn=", bound) is not None,
        "event_shape": shape,
    }


def valid_bound_structure(value):
    return (isinstance(value, dict) and set(value) ==
            {"schema", "event_shape"} | BOUND_BOOLEAN_FIELDS | BOUND_COUNT_FIELDS and
            type(value["schema"]) is int and value["schema"] == 1 and
            isinstance(value["event_shape"], str) and value["event_shape"] in EVENT_SHAPES and
            all(type(value[name]) is bool for name in BOUND_BOOLEAN_FIELDS) and
            all(type(value[name]) is int and value[name] in {0, 1, 2} for name in BOUND_COUNT_FIELDS))


def diagnostic_observation(kind, value, structure, operation=None):
    result = {"kind": kind, "state" if kind == "parsed_state" else "code":
              dict(value) if kind == "parsed_state" else value}
    if structure:
        result["bound_structure"] = dict(structure)
    if operation is not None:
        result["guarded_operation"] = operation
    return result


def guarded_operation(parts):
    # Fixed authored tuples only. This labels the guarded call, not proof that
    # its payload ran: inherited emulator identity checks can fail first.
    if parts == ("shell", "am", "get-current-user"):
        return "current_user_guard"
    if parts == ("shell", "dumpsys", "accessibility"):
        return "accessibility_dump"
    if parts == ("shell", "dumpsys", "activity", "services", COMPONENT):
        return "talkback_binding_dump"
    return "other"


def valid_diagnostic_observation(observation, *, previous=False):
    if type(observation) is not dict:
        return False
    kind = observation.get("kind")
    if type(kind) is not str or kind not in {"parsed_state", "retryable_error", "fatal_error"}:
        return False
    if previous and kind == "fatal_error":
        return False
    optional = set(observation) & {"bound_structure", "guarded_operation"}
    if "bound_structure" in optional and not valid_bound_structure(observation["bound_structure"]):
        return False
    if "guarded_operation" in optional and not (
            kind == "fatal_error" and type(observation["guarded_operation"]) is str and
            observation["guarded_operation"] in GUARDED_OPERATIONS):
        return False
    if kind == "parsed_state":
        if set(observation) != {"kind", "state"} | optional:
            return False
        state = observation["state"]
        return (type(state) is dict and set(state) == {"enabled_component", "bound_count", "touch_exploration"} and
                (state["enabled_component"] is None or
                 type(state["enabled_component"]) is str and state["enabled_component"] == COMPONENT) and
                type(state["bound_count"]) is int and state["bound_count"] in {0, 1} and
                type(state["touch_exploration"]) is bool)
    return (set(observation) == {"kind", "code"} | optional and type(observation["code"]) is str and
            observation["code"] in DIAGNOSTIC_ERRORS | {"A11Y_DIAGNOSTIC_OTHER"} and
            (kind != "retryable_error" or observation["code"] in RETRYABLE_STATE_ERRORS))


def preceding_observation(observation):
    if observation is None:
        return None
    try:
        if valid_diagnostic_observation(observation, previous=True):
            return diagnostic_observation(observation["kind"], observation.get("state", observation.get("code")),
                                          observation.get("bound_structure"))
    except Exception:
        pass
    # Invalid evidence must produce the fixed snapshot failure marker without
    # retaining its values or replacing the original runtime exception.
    return {}


def diagnostic_error(error):
    # Never export an arbitrary exception message/class or an uppercase-looking token.
    try:
        code = str(error) if isinstance(error, AccessibilityError) else None
        return code if code in DIAGNOSTIC_ERRORS else "A11Y_DIAGNOSTIC_OTHER"
    except Exception:
        return "A11Y_DIAGNOSTIC_OTHER"


def diagnostic_stage(value):
    return value if isinstance(value, str) and value in DIAGNOSTIC_STAGES else "unknown"


def diagnostic_snapshot(session):
    """Bounded metadata only; formatting must not interfere with existing cleanup."""
    try:
        identity = session.installed_identity
        if identity is not None:
            if not (isinstance(identity, dict) and set(identity) ==
                    {"talkback_version_code", "talkback_version_name", "android_api", "android_build"} and
                    type(identity["talkback_version_code"]) is int and 0 < identity["talkback_version_code"] <= 9223372036854775807 and
                    type(identity["android_api"]) is int and identity["android_api"] == 36 and
                    all(isinstance(identity[key], str) and 1 <= len(identity[key]) <= maximum and
                        all(32 <= ord(char) <= 126 for char in identity[key])
                        for key, maximum in (("talkback_version_name", 80), ("android_build", 256)))):
                raise ValueError("identity")
        if not isinstance(session.wait_observations, dict) or not set(session.wait_observations) <= WAIT_PHASES:
            raise ValueError("waits")
        for value in session.wait_observations.values():
            if not (isinstance(value, dict) and set(value) ==
                    {"budget_seconds", "attempts", "outcome", "last_observation", "previous_observation"} and
                    type(value["budget_seconds"]) in (int, float) and 0 <= value["budget_seconds"] <= 3600 and
                    type(value["attempts"]) is int and 0 <= value["attempts"] <= 100000 and
                    type(value["outcome"]) is str and
                    value["outcome"] in {"waiting", "target_reached", "timeout", "fatal_error"}):
                raise ValueError("wait")
            observation = value["last_observation"]
            if observation is not None and not valid_diagnostic_observation(observation):
                raise ValueError("observation")
            previous = value["previous_observation"]
            if previous is not None and not (value["outcome"] == "fatal_error" and value["attempts"] >= 2 and
                    observation is not None and observation["kind"] == "fatal_error" and
                    valid_diagnostic_observation(previous, previous=True)):
                raise ValueError("previous")
        result = {"schema": DIAGNOSTIC_SCHEMA, "stage": diagnostic_stage(session.stage), "installed_identity": identity,
                  "waits": session.wait_observations}
        encoded = json.dumps(result, separators=(",", ":"))
        if len(encoded.encode("utf-8")) > 4096:
            return {"schema": DIAGNOSTIC_SCHEMA, "code": "A11Y_DIAGNOSTICS_BOUND"}
        return json.loads(encoded)  # Freeze the final evidence independently of the mutable session.
    except Exception:
        return {"schema": DIAGNOSTIC_SCHEMA, "code": "A11Y_DIAGNOSTICS_UNAVAILABLE"}


def failure_code(error):
    value = str(error)
    return value if isinstance(error, AccessibilityError) and re.fullmatch(r"(?:A11Y|EMULATOR)_[A-Z_]{1,80}", value) else "A11Y_RUN_FAILED"


def bounded_text(raw, limit, code):
    require(isinstance(raw, str) and len(raw.encode("utf-8")) <= limit and "\x00" not in raw
            and "\ufffd" not in raw, code)
    return raw


def exact_component(value):
    require(value in {COMPONENT, SHORT_COMPONENT}, "A11Y_COMPONENT_DENIED")
    return COMPONENT


def settings_snapshot(raw):
    """List, not get: get conflates an absent entry with a literal null value."""
    bounded_text(raw, 65536, "A11Y_SETTINGS_BOUND")
    result = {name: None for name in SETTINGS}
    seen = set()
    for line in raw.splitlines():
        name, separator, value = line.partition("=")
        if name not in result:
            continue
        require(separator and name not in seen, "A11Y_SETTINGS_INVALID")
        seen.add(name)
        if name == SETTINGS[0]:
            require(value in {"", COMPONENT, SHORT_COMPONENT}, "A11Y_PREEXISTING_SERVICE_DENIED")
        else:
            require(value in {"", "0", "1"}, "A11Y_SETTINGS_INVALID")
        result[name] = value
    return result


def setting_script(name, value):
    require(name in SETTINGS, "A11Y_SETTING_DENIED")
    # The only permitted values contain no shell metacharacters; quotes preserve empty.
    require(value is None or isinstance(value, str), "A11Y_SETTING_DENIED")
    if value is not None:
        allowed = {"", COMPONENT, SHORT_COMPONENT} if name == SETTINGS[0] else {"", "0", "1"}
        require(value in allowed, "A11Y_SETTING_DENIED")
    if value is None:
        return f"settings --user 0 delete secure {name}\n".encode("ascii")
    return f"settings --user 0 put secure {name} '{value}'\n".encode("ascii")


def single(pattern, value, code):
    found = re.findall(pattern, value, re.MULTILINE)
    require(len(found) == 1, code)
    return found[0]


def accessibility_state(raw, *, structure=None):
    """Android16 AccessibilityUserState.dump; labels never establish identity.

    Bound services intentionally omit component IDs in AOSP. Require one spoken
    bound service AND the sole exact enabled component, then independently bind
    that identity to ActivityManager's live system-client ServiceRecord.
    """
    bounded_text(raw, 262144, "A11Y_DUMP_BOUND")
    starts = list(re.finditer(r"^User state\[\s*$", raw, re.MULTILINE))
    require(1 <= len(starts) <= 8, "A11Y_USER_STATE_INVALID")
    states = {}
    for index, start in enumerate(starts):
        block = raw[start.end():starts[index + 1].start() if index + 1 < len(starts) else len(raw)]
        attrs = single(r"^     attributes:\{(.*)\}\s*$", block, "A11Y_ATTRIBUTES_INVALID")
        user = single(r"(?:^|, )id=([0-9]{1,5})(?=,|$)", attrs, "A11Y_USER_STATE_INVALID")
        require(user not in states, "A11Y_USER_STATE_INVALID")
        touch = single(r"(?:^|, )touchExplorationEnabled=(true|false)(?=,|$)", attrs, "A11Y_ATTRIBUTES_INVALID")
        fields = {}
        for name in ("Bound", "Enabled", "Binding", "Crashed"):
            # A Bound block may span lines; stop at the next exact service field.
            fields[name] = single(r"^     " + name + r" services:\{([\s\S]*?)\}\s*$", block,
                                  "A11Y_SERVICE_STATE_INVALID")
        require(not fields["Binding"] and not fields["Crashed"], "A11Y_SERVICE_NOT_STABLE")
        enabled = fields["Enabled"]
        if enabled:
            require(re.fullmatch(r"\{[^{}]+\}", enabled) is not None, "A11Y_PREEXISTING_SERVICE_DENIED")
            enabled = exact_component(enabled[1:-1])
        bound = fields["Bound"]
        count = 0
        format_state = bound_structure(bound)
        if structure is not None and user == "0":
            structure.update(format_state)
        if bound:
            require(format_state["envelope_valid"] and format_state["event_shape"] in
                    {"all_mask", "single_known", "list_known"}, "A11Y_BOUND_FORMAT_INVALID")
            feedback = single(r"feedbackType\[([^\]]+)\]", bound, "A11Y_BOUND_FORMAT_INVALID")
            require("FEEDBACK_SPOKEN" in feedback.split(", "), "A11Y_BOUND_NOT_SPOKEN")
            require(enabled == COMPONENT, "A11Y_BOUND_IDENTITY_INCONSISTENT")
            count = 1
        states[user] = {"enabled_component": enabled or None, "bound_count": count,
                        "touch_exploration": touch == "true"}
    require("0" in states, "A11Y_USER_ZERO_MISSING")
    # Other Android users cannot supply the selected user's evidence.
    return states["0"]


def activity_binding(raw):
    """Exact user0 service + actual received binder + its system/1000 client.

    See Android16 ServiceRecord.dump and IntentBindRecord.dumpInService. No
    component mentioned in an intent/connection elsewhere can satisfy this.
    """
    bounded_text(raw, 131072, "A11Y_ACTIVITY_DUMP_BOUND")
    headers = list(re.finditer(r"^([ ]*)\* ServiceRecord\{[0-9a-f]+ u([0-9]+) ([^ }]+)(?: c:[A-Za-z0-9_.]+)?\}\s*$", raw, re.MULTILINE))
    require(len(headers) == 1, "A11Y_ACTIVITY_SERVICE_INVALID")
    header = headers[0]
    require(header[2] == "0", "A11Y_ACTIVITY_USER_DENIED")
    exact_component(header[3])
    indent = len(header[1])
    lines = raw[header.end():].splitlines()
    selected = []
    for line in lines:
        if line.strip() and len(line) - len(line.lstrip()) <= indent:
            break
        selected.append(line)
    block = "\n".join(selected)
    require(single(r"^\s+packageName=([^\s]+)\s*$", block, "A11Y_ACTIVITY_SERVICE_INVALID") == TALKBACK_PACKAGE,
            "A11Y_ACTIVITY_SERVICE_INVALID")
    require(single(r"^\s+permission=([^\s]+)\s*$", block, "A11Y_ACTIVITY_PERMISSION_INVALID") ==
            "android.permission.BIND_ACCESSIBILITY_SERVICE", "A11Y_ACTIVITY_PERMISSION_INVALID")
    app = single(r"^\s+app=ProcessRecord\{([0-9a-f]+ [1-9][0-9]*:[^ }]+)\}\s*$", block,
                 "A11Y_ACTIVITY_PROCESS_INVALID")
    require(re.fullmatch(r"[0-9a-f]+ [1-9][0-9]*:" + re.escape(TALKBACK_PACKAGE) + r"(?:[:][A-Za-z0-9_.]+)?/u0a[0-9]+", app)
            is not None, "A11Y_ACTIVITY_PROCESS_INVALID")
    binds = list(re.finditer(r"^([ ]*)\* IntentBindRecord\{[0-9a-f]+ CREATE\}:\s*$", block, re.MULTILINE))
    require(len(binds) == 1, "A11Y_BINDING_RECORD_INVALID")
    bind = binds[0]
    contents = []
    for line in block[bind.end():].splitlines():
        if line.strip() and len(line) - len(line.lstrip()) <= len(bind[1]):
            break
        contents.append(line)
    binding = "\n".join(contents)
    # AccessibilityServiceConnection constructs new Intent().setComponent(...)
    # without an action. Its extras are deliberately suppressed in this dump.
    intent = single(r"^\s+intent=\{cmp=([^ }]+)\}\s*$",
                    binding, "A11Y_BINDING_INTENT_INVALID")
    exact_component(intent)
    single(r"^\s+binder=android\.os\.BinderProxy@[0-9a-f]+\s*$", binding, "A11Y_BINDER_MISSING")
    single(r"^\s+requested=true received=true hasBound=true doRebind=false\s*$", binding,
           "A11Y_BINDING_NOT_RECEIVED")
    single(r"^\s+\* Client AppBindRecord\{[0-9a-f]+ ProcessRecord\{[0-9a-f]+ [1-9][0-9]*:system/1000\}\}\s*$",
           binding, "A11Y_SYSTEM_CLIENT_MISSING")
    require(len(re.findall(r"^\s+\* Client AppBindRecord", binding, re.MULTILINE)) == 1,
            "A11Y_UNEXPECTED_BINDING_CLIENT")
    return True


def package_version(raw):
    bounded_text(raw, 262144, "A11Y_PACKAGE_DUMP_BOUND")
    # Hidden system/update package records must not satisfy active-package fields.
    section = single(r"^Packages:\s*\n([\s\S]*?)(?=^\S|\Z)", raw, "A11Y_PACKAGE_RECORD_INVALID")
    headers = re.findall(r"^  Package \[([^\]]+)\] \([0-9a-f]+\):\s*$", section, re.MULTILINE)
    require(headers == [TALKBACK_PACKAGE], "A11Y_PACKAGE_RECORD_INVALID")
    code = single(r"^    versionCode=([1-9][0-9]{0,18})(?: minSdk=[0-9]+)?(?: targetSdk=[0-9]+)?\s*$", section,
                  "A11Y_VERSION_INVALID")
    name = single(r"^    versionName=([^\r\n]+)$", section, "A11Y_VERSION_INVALID")
    require(int(code) <= 9223372036854775807 and 1 <= len(name) <= 80
            and all(32 <= ord(char) <= 126 for char in name), "A11Y_VERSION_INVALID")
    user = single(r"^    User 0: ([^\r\n]+)$", section, "A11Y_PACKAGE_USER_INVALID")
    require(re.findall(r"(?:^| )installed=(true|false)(?= |$)", user) == ["true"], "A11Y_PACKAGE_USER_INVALID")
    return {"talkback_version_code": int(code), "talkback_version_name": name}


def native_result(raw, method):
    """TASK088's exact raw status algorithm, with a separate fixed TASK092 allowlist."""
    require(method in METHODS, "A11Y_METHOD_DENIED")
    bounded_text(raw, 262144, "A11Y_INSTRUMENTATION_BOUND")
    codes = re.findall(r"^INSTRUMENTATION_CODE: (-?\d{1,3})\s*$", raw, re.MULTILINE)
    records, current = [], {}
    for line in raw.splitlines():
        field = re.fullmatch(r"INSTRUMENTATION_STATUS: (class|test|current|numtests)=(.*)", line)
        if field:
            current.setdefault(field[1], []).append(field[2])
        status = re.fullmatch(r"INSTRUMENTATION_STATUS_CODE: (-?\d{1,3})", line)
        if status:
            records.append((int(status[1]), current))
            current = {}
    expected = {"class": [TEST_CLASS], "test": [method], "current": ["1"], "numtests": ["1"]}
    exact = (not current and len(records) == 2 and all(fields == expected for _, fields in records)
             and len(re.findall(r"^INSTRUMENTATION_STATUS_CODE:", raw, re.MULTILINE)) == 2)
    statuses = [code for code, _ in records]
    completed = (exact and statuses[0] == 1 and statuses[1] in {0, -1, -2, -3, -4}
                 and codes == ["-1"] and len(re.findall(r"^INSTRUMENTATION_CODE:", raw, re.MULTILINE)) == 1)
    passed = (completed and statuses == [1, 0] and codes == ["-1"]
        and len(re.findall(r"^INSTRUMENTATION_CODE:", raw, re.MULTILINE)) == 1
        and len(re.findall(r"^OK \(1 test\)\s*$", raw, re.MULTILINE)) == 1
        and not any(value in raw for value in ("FAILURES", "INSTRUMENTATION_FAILED", "shortMsg=", "stack="))
        and not re.search(r"^(?:[A-Za-z_$][A-Za-z0-9_$]*\.){1,12}[A-Za-z_$][A-Za-z0-9_$]*(?:Error|Exception|Failure)(?::|\s*$)",
                          raw, re.MULTILINE))
    # Retain only fixed fixture diagnostics, not arbitrary exception/message text.
    diagnostics = sorted(set(re.findall(r"\b(A11Y_[A-Z_]{1,64})\b", raw)))
    allowed = {"A11Y_SERVICE_UNAVAILABLE", "A11Y_SERVICE_LOST", "A11Y_VERSION_MISMATCH", "A11Y_APP_WINDOW_UNAVAILABLE",
               "A11Y_FIRST_FOCUS_UNAVAILABLE", "A11Y_SERVICE_FOCUS_DID_NOT_MOVE", "A11Y_TARGET_NOT_REACHED",
               "A11Y_NAVIGATION_BUDGET", "A11Y_ACTIVATION_NO_EFFECT", "A11Y_PASSWORD_ROLE", "A11Y_TEXT_FIXTURE_SETUP"}
    return {"passed": bool(passed), "outcome": "passed" if passed else "failed" if completed else "incomplete",
            "method_completed_count": int(completed), "status_codes": statuses[:4],
            "instrumentation_codes": [int(code) for code in codes[:4]],
            "fixture_codes": [code for code in diagnostics if code in allowed][:4]}


def scenario_evidence(raw, method, identity):
    require(method in METHODS, "A11Y_METHOD_DENIED")
    bounded_text(raw, 2048, "A11Y_EVIDENCE_BOUND")
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "A11Y_EVIDENCE_DUPLICATE")
            result[key] = value
        return result
    try:
        value = json.loads(raw, object_pairs_hook=pairs,
                           parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (ValueError, TypeError, RecursionError):
        raise AccessibilityError("A11Y_EVIDENCE_INVALID") from None
    fixed = {"schema": 1, "method": method, "talkback_component": COMPONENT,
             "keymap_prerequisite": "default-alt", "native_enabled_spoken_service": True,
             "native_touch_exploration": True, "platform_assertions_passed": True, "scenario_passed": True,
             "synthetic_presentation": True, "actual_authentication": False, "touch_gestures": False,
             "human_listening": False, **identity}
    counters = ("next_focus_moves", "previous_focus_moves", "observed_app_accessibility_focus_events", "verified_activations")
    require(isinstance(value, dict) and set(value) == set(fixed) | set(counters), "A11Y_EVIDENCE_SCHEMA")
    for key, expected in fixed.items():
        require(type(value[key]) is type(expected) and value[key] == expected, "A11Y_EVIDENCE_MISMATCH")
    for key in counters:
        minimum = 0 if key == "previous_focus_moves" and method not in METHODS[:2] else 1
        require(type(value[key]) is int and minimum <= value[key] <= 100000, "A11Y_EVIDENCE_COUNTER")
    return value


class RunLease:
    """The no-database equivalent of MobileHarness.assert_owned for this fixture.

    A retained fresh directory/held marker identity is checked on every inherited
    emulator identity check. Emulator process/AVD/transport checks stay unchanged.
    """
    def __init__(self, run):
        self.run = base.checked_path(run)
        parent = ROOT / ".cache/m1-runtime/mobile-accessibility"
        require(self.run.parent == parent and re.fullmatch(r"[0-9a-f]{24}", self.run.name), "A11Y_RUN_PATH_DENIED")
        self.file = None

    def __enter__(self):
        require(not self.run.exists(), "A11Y_RUN_PREEXISTING")
        self.run.mkdir(exist_ok=False)
        self.directory = self.run.stat()
        self.pid = os.getpid()
        self.token = secrets.token_hex(24).encode("ascii")
        self.path = self.run / "owner"
        self.file = self.path.open("x+b")
        self.file.write(self.token)
        self.file.flush()
        os.fsync(self.file.fileno())
        self.identity = os.fstat(self.file.fileno())
        self.assert_owned()
        return self

    def assert_owned(self):
        require(self.file is not None and not self.file.closed and os.getpid() == self.pid, "A11Y_RUN_OWNERSHIP_LOST")
        base.checked_path(self.path)
        actual, directory = self.path.stat(), self.run.stat()
        require((actual.st_dev, actual.st_ino, actual.st_size) ==
                (self.identity.st_dev, self.identity.st_ino, len(self.token)) and
                (directory.st_dev, directory.st_ino) == (self.directory.st_dev, self.directory.st_ino),
                "A11Y_RUN_OWNERSHIP_LOST")
        self.file.seek(0)
        require(self.file.read(49) == self.token, "A11Y_RUN_OWNERSHIP_LOST")

    def __exit__(self, *args):
        if self.file is not None:
            self.file.close()
        # Preserve AVD/result/owner evidence. No directory deletion here.


class TalkBackSession:
    def __init__(self, emulator, clock=time.monotonic, sleep=time.sleep):
        self.emulator, self.clock, self.sleep = emulator, clock, sleep
        self.original = self.original_state = None
        self.mutated = False
        self.restored = False
        self.stage = "created"
        self.installed_identity = None
        self.wait_observations = {}
        self.bound_structure = {}
        self.failed_guarded_operation = None

    def command(self, *parts, **kwargs):
        self.failed_guarded_operation = None
        try:
            require(self.emulator.command("shell", "am", "get-current-user", timeout=5, maximum=64).strip() == "0",
                    "A11Y_CURRENT_USER_DENIED")
        except BaseException:
            self.failed_guarded_operation = "current_user_guard"
            raise
        try:
            return self.emulator.command(*parts, **kwargs)
        except BaseException:
            self.failed_guarded_operation = guarded_operation(parts)
            raise

    def settings(self):
        return settings_snapshot(self.command("shell", "settings", "--user", "0", "list", "secure", maximum=65536))

    def put(self, name, value):
        self.command("shell", stdin=setting_script(name, value), maximum=1024)

    def state(self):
        self.bound_structure = {}
        self.failed_guarded_operation = None
        state = accessibility_state(self.command("shell", "dumpsys", "accessibility", timeout=5),
                                    structure=self.bound_structure)
        if state["bound_count"]:
            activity_binding(self.command("shell", "dumpsys", "activity", "services", COMPONENT, timeout=5, maximum=131072))
        return state

    def version(self):
        return package_version(self.command("shell", "dumpsys", "package", TALKBACK_PACKAGE))

    def observed_identity(self):
        version = self.version()
        fingerprint = self.command("shell", "getprop", "ro.build.fingerprint", maximum=512).strip()
        require(1 <= len(fingerprint) <= 256 and all(32 <= ord(char) <= 126 for char in fingerprint), "A11Y_BUILD_INVALID")
        require(self.command("shell", "getprop", "ro.build.version.sdk", maximum=64).strip() == "36", "A11Y_API_INVALID")
        return {**version, "android_api": 36, "android_build": fingerprint}

    def require_bound(self, identity):
        require(self.observed_identity() == identity, "A11Y_INSTALLED_IDENTITY_CHANGED")
        require(self.state() == {"enabled_component": COMPONENT, "bound_count": 1, "touch_exploration": True},
                "A11Y_SERVICE_NOT_BOUND")
        settings = self.settings()
        require(settings[SETTINGS[0]] in {COMPONENT, SHORT_COMPONENT} and settings[SETTINGS[1]] == "1"
                and settings[SETTINGS[2]] == "1", "A11Y_ENABLED_STATE_MISMATCH")
        return {"user": 0, "exact_component_bound": True, "system_client_received_binder": True,
                "touch_exploration": True, **identity}

    def wait_state(self, target, seconds=20, *, phase="setup_service_readiness"):
        deadline = self.clock() + seconds
        observation = {"budget_seconds": seconds, "attempts": 0, "outcome": "waiting", "last_observation": None,
                       "previous_observation": None}
        if phase in WAIT_PHASES:
            self.stage = phase
            self.wait_observations[phase] = observation
        try:
            while True:
                observation["attempts"] = min(100000, observation["attempts"] + 1)
                self.bound_structure = {}
                self.failed_guarded_operation = None
                try:
                    state = self.state()
                    observation["last_observation"] = diagnostic_observation("parsed_state", state, self.bound_structure)
                    if state == target:
                        observation["outcome"] = "target_reached"
                        return
                except AccessibilityError as error:
                    if str(error) not in RETRYABLE_STATE_ERRORS:
                        raise
                    observation["last_observation"] = diagnostic_observation("retryable_error", diagnostic_error(error), self.bound_structure)
                within_budget = self.clock() < deadline
                if not within_budget:
                    observation["outcome"] = "timeout"
                require(within_budget, "A11Y_SERVICE_WAIT_TIMEOUT")
                self.sleep(0.25)
        except BaseException as error:
            if observation["outcome"] != "timeout":
                observation["outcome"] = "fatal_error"
                observation["previous_observation"] = preceding_observation(observation["last_observation"])
                observation["last_observation"] = diagnostic_observation(
                    "fatal_error", diagnostic_error(error), self.bound_structure, self.failed_guarded_operation)
            raise

    def install(self, artifacts, hashes):
        for package in (PACKAGE, TEST_PACKAGE):
            require(not self.command("shell", "pm", "list", "packages", "--user", "0", "-u", package).strip(),
                    "A11Y_PACKAGE_PREEXISTING")
        # UI-only: no backend reverse, synthetic credential or screen-timeout mutation.
        require(not base.parse_reverse(self.command("reverse", "--list")), "A11Y_REVERSE_PREEXISTING")
        for path, expected in zip(artifacts, hashes, strict=True):
            require(base.digest(path) == expected, "A11Y_APK_CHANGED")
            require(self.command("install", "--user", "0", str(path), timeout=120).splitlines() in
                    (["Success"], ["Performing Streamed Install", "Success"]),
                    "A11Y_INSTALL_FAILED")
            require(base.digest(path) == expected, "A11Y_APK_CHANGED")
        require(self.command("shell", "pm", "list", "instrumentation").splitlines() ==
                [f"instrumentation:{TEST_PACKAGE}/{RUNNER} (target={PACKAGE})"], "A11Y_INSTALLED_RUNNER_DENIED")
        for name in (*[f"m2-accessibility-{method}.json" for method in METHODS], "m2-live-phase"):
            self.require_absent(name)

    def require_absent(self, name):
        require(name in {f"m2-accessibility-{method}.json" for method in METHODS} | {"m2-live-phase"}, "A11Y_FILE_DENIED")
        script = f"if [ -e no_backup/{name} ]; then printf present; else printf absent; fi\n"
        require(self.command("shell", "run-as", PACKAGE, "sh", stdin=script.encode("ascii"), maximum=64) == "absent",
                "A11Y_EVIDENCE_PREEXISTING")

    def setup(self):
        self.stage = "installed_service_query"
        services = self.command("shell", "cmd", "package", "query-services", "--components", "--user", "0",
                                "-a", "android.accessibilityservice.AccessibilityService", "-n", COMPONENT,
                                maximum=4096).splitlines()
        require(len(services) == 1, "A11Y_INSTALLED_SERVICE_INVALID")
        exact_component(services[0])
        self.stage = "installed_identity"
        identity = self.observed_identity()
        self.installed_identity = dict(identity)
        self.stage = "original_settings"
        original = self.settings()
        self.stage = "original_service_state"
        original_state = self.state()
        require(original_state["enabled_component"] == (COMPONENT if original[SETTINGS[0]] else None),
                "A11Y_INITIAL_STATE_INCONSISTENT")
        require(original_state["bound_count"] == int(original_state["enabled_component"] is not None),
                "A11Y_INITIAL_STATE_INCONSISTENT")
        require(original_state["touch_exploration"] == (original[SETTINGS[2]] == "1"), "A11Y_INITIAL_STATE_INCONSISTENT")
        require(original_state["touch_exploration"] == bool(original_state["bound_count"]) and
                (original[SETTINGS[1]] == "1") == bool(original_state["bound_count"]), "A11Y_INITIAL_STATE_INCONSISTENT")
        self.original, self.original_state = original, original_state
        # Set this before the first command: even an ambiguous command failure must restore.
        self.mutated = True
        self.stage = "enable_service"
        self.put(SETTINGS[0], original[SETTINGS[0]] or COMPONENT)
        self.stage = "enable_accessibility"
        self.put(SETTINGS[1], "1")
        # TalkBack itself must request touch exploration; never set it to fabricate readiness.
        self.wait_state({"enabled_component": COMPONENT, "bound_count": 1, "touch_exploration": True})
        self.stage = "verify_bound_service"
        self.require_bound(identity)
        return identity

    def restore(self):
        if not self.mutated:
            self.stage = "restore_not_needed"
            self.restored = True
            return
        # Stop only the fixture instrumentation/app before returning service settings.
        self.stage = "restore_stop_fixture"
        self.command("shell", "am", "force-stop", "--user", "0", PACKAGE)
        self.stage = "restore_service_setting"
        self.put(SETTINGS[0], self.original[SETTINGS[0]])
        # Observe actual service settling before the last exact scalar restoration.
        self.wait_state(self.original_state, phase="restore_original_service")
        self.stage = "restore_accessibility_setting"
        self.put(SETTINGS[1], self.original[SETTINGS[1]])
        self.stage = "restore_touch_setting"
        self.put(SETTINGS[2], self.original[SETTINGS[2]])
        self.stage = "restore_verify"
        require(self.settings() == self.original and self.state() == self.original_state, "A11Y_RESTORE_MISMATCH")
        self.restored = True
        self.stage = "restored"

    def method(self, method, identity, outcome):
        self.stage = "native_scenario"
        require(method in METHODS, "A11Y_METHOD_DENIED")
        outcome.update(method=method, passed=False)
        outcome["binding_before"] = self.require_bound(identity)
        self.require_absent(f"m2-accessibility-{method}.json")
        self.require_absent("m2-live-phase")
        self.command("shell", "input", "keyevent", "KEYCODE_WAKEUP")
        # Fresh UI-only AVD has no configured PIN. This command never guesses a credential.
        self.command("shell", "wm", "dismiss-keyguard")
        require(base.device_unlocked(self.command("shell", "dumpsys", "trust")), "A11Y_KEYGUARD_NOT_DISMISSED")
        outcome["native"] = {"passed": False, "outcome": "incomplete", "method_completed_count": 0}
        try:
            raw = self.command("shell", "am", "instrument", "--user", "0", "-w", "-r", "-e", "class",
                TEST_CLASS + "#" + method, "-e", "ownedEmulator", "true", "-e", "talkbackKeymap", "default-alt",
                "-e", "talkbackVersionCode", str(identity["talkback_version_code"]), f"{TEST_PACKAGE}/{RUNNER}", timeout=180)
            outcome["native"] = native_result(raw, method)
        except AccessibilityError as error:
            outcome["native"]["code"] = failure_code(error)
            raise
        finally:
            # A post-check is attempted even after native timeout/failure; it cannot grant success.
            outcome["binding_after"] = self.require_bound(identity)
        require(outcome["native"]["passed"], "A11Y_NATIVE_SCENARIO_FAILED")
        raw = self.command("shell", "run-as", PACKAGE, "head", "-c", "2049",
                           f"no_backup/m2-accessibility-{method}.json", maximum=2049)
        outcome["scenario"] = scenario_evidence(raw, method, identity)
        outcome["scenario_sha256"] = hashlib.sha256(raw.encode("utf-8")).hexdigest()
        outcome["passed"] = True


def run_scenarios(emulator, artifacts, hashes, evidence):
    session = TalkBackSession(emulator)
    try:
        session.stage = "installing_apks"
        session.install(artifacts, hashes)
        identity = session.setup()
        evidence["observed_identity"] = identity
        for method in METHODS:
            outcome = {"method": method, "passed": False}
            evidence["scenarios"].append(outcome)
            session.method(method, identity, outcome)
            print(json.dumps({"method": method, "passed": True}), flush=True)
    except BaseException as error:
        evidence["scenario_failure_code"] = failure_code(error)
        evidence["scenario_failure_stage"] = diagnostic_stage(session.stage)
        raise
    finally:
        evidence["original_secure_settings"] = session.original
        evidence["original_service_state"] = session.original_state
        try:
            session.restore()
        except BaseException as error:
            evidence["restoration_failure_code"] = failure_code(error)
            evidence["restoration_failure_stage"] = diagnostic_stage(session.stage)
            raise
        finally:
            evidence["secure_settings_restored"] = session.restored
            evidence["service_diagnostics"] = diagnostic_snapshot(session)


def execute(app, app_sha256, test, test_sha256):
    require(os.name == "nt", "A11Y_WINDOWS_HOST_REQUIRED")
    require(shutil.disk_usage(ROOT).free >= 12 * 1024**3, "A11Y_DISK_SPACE_REQUIRED")
    tools = base.AndroidTools()
    artifacts, proof = base.verify_artifacts(tools, app, app_sha256, test, test_sha256)
    parent = base.checked_path(ROOT / ".cache/m1-runtime/mobile-accessibility")
    parent.mkdir(parents=True, exist_ok=True)
    run = base.checked_path(parent / secrets.token_hex(12))
    evidence = {"task": "TASK-093", "ok": False, "physical_phone": False, "database_started": False,
                "artifacts": proof, "scenarios": [], "secure_settings_restored": False,
                "libraries": {name: base.digest(ROOT / name) for name in LIBRARIES},
                "evidence_categories": {"actual_service_keyboard": False, "synthetic_platform_assertions": False,
                    "touch_gestures": False, "human_listening": False, "actual_authentication": False}}
    # No MobileHarness.__enter__: it would unnecessarily create PostgreSQL and HTTP children.
    with RunLease(run) as lease:
        emulator = base.OwnedEmulator(tools, lease, run)
        emulator.evidence.update(owned_emulator_stopped=False, owned_emulator_ports_closed=False)
        try:
            try:
                with emulator:
                    run_scenarios(emulator, artifacts, (app_sha256, test_sha256), evidence)
            finally:
                evidence["emulator"] = emulator.evidence
            require(emulator.evidence.get("owned_emulator_stopped") is True and
                    emulator.evidence.get("owned_emulator_ports_closed") is True and
                    evidence["secure_settings_restored"] is True, "A11Y_CLEANUP_INCOMPLETE")
            require([row.get("method") for row in evidence["scenarios"]] == list(METHODS) and
                    all(row.get("passed") is True for row in evidence["scenarios"]), "A11Y_SCENARIOS_INCOMPLETE")
            require(evidence["libraries"] == {name: base.digest(ROOT / name) for name in LIBRARIES}, "A11Y_HELPER_CHANGED")
            require([base.digest(path) for path in artifacts] == [app_sha256, test_sha256], "A11Y_APK_CHANGED")
            evidence["evidence_categories"].update(actual_service_keyboard=True, synthetic_platform_assertions=True)
            evidence["ok"] = True
        except BaseException as error:
            evidence["code"] = failure_code(error)
            if emulator.evidence.get("owned_emulator_stopped") is not True or emulator.evidence.get("owned_emulator_ports_closed") is not True:
                # The inherited uncertain-cleanup path may fail importing its DB
                # preservation hook. No database exists here; retain a fixed
                # failed cleanup gate, never attempt unrelated cleanup/startup.
                evidence["cleanup_failure_code"] = "A11Y_OWNED_CLEANUP_UNCERTAIN"
            raise
        finally:
            lease.assert_owned()
            # Exclusive creation, small allowlisted metadata only. Retain failed run evidence.
            result = base.checked_path(run / "result.json")
            with result.open("x", encoding="utf-8") as stream:
                json.dump(evidence, stream, indent=2)
                stream.write("\n")
            print(json.dumps({"result": str(result.relative_to(ROOT)), "ok": evidence["ok"]}), flush=True)
    return evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--app", type=Path, required=True)
    parser.add_argument("--app-sha256", required=True)
    parser.add_argument("--test", type=Path, required=True)
    parser.add_argument("--test-sha256", required=True)
    args = parser.parse_args()
    try:
        execute(args.app, args.app_sha256, args.test, args.test_sha256)
        return 0
    except BaseException as error:
        print(json.dumps({"ok": False, "code": failure_code(error)}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

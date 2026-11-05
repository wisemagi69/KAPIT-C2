"""Pure TASK093 host guards; no ADB, emulator, PostgreSQL or file cleanup."""
import io
import json
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, Mock, call, patch

from infra import mobile_accessibility as host

METHOD = host.METHODS[0]
IDENTITY = {"talkback_version_code": 60149353, "talkback_version_name": "16.0.1",
            "android_api": 36, "android_build": "google/sdk_gphone64_x86_64/emulator:16/test/userdebug"}
EMPTY = {"enabled_component": None, "bound_count": 0, "touch_exploration": False}
BOUND = {"enabled_component": host.COMPONENT, "bound_count": 1, "touch_exploration": True}


def dump_state(*, user=0, enabled=True, bound=True, touch=True, binding="", crashed=""):
    service = ("Service[label=TalkBack, feedbackType[FEEDBACK_SPOKEN, FEEDBACK_HAPTIC], capabilities=15, "
               "eventTypes=[TYPE_VIEW_CLICKED, TYPE_VIEW_ACCESSIBILITY_FOCUSED], notificationTimeout=0, requestA11yBtn=false]")
    return (f"User state[\n     attributes:{{id={user}, touchExplorationEnabled={str(touch).lower()}, installedServiceCount=2}}\n"
            f"     Bound services:{{{service if bound else ''}}}\n"
            f"     Enabled services:{{{'{' + host.SHORT_COMPONENT + '}' if enabled else ''}}}\n"
            f"     Binding services:{{{binding}}}\n     Crashed services:{{{crashed}}}\n"
            "     Client list info:{\n          Client list callbacks: 1\n}]\n")


def dump_activity():
    return ("ACTIVITY MANAGER SERVICES (dumpsys activity services)\n  User 0 active services:\n"
        f"  * ServiceRecord{{abc u0 {host.SHORT_COMPONENT}}}\n"
        f"    intent={{cmp={host.SHORT_COMPONENT}}}\n"
        f"    packageName={host.TALKBACK_PACKAGE}\n    permission=android.permission.BIND_ACCESSIBILITY_SERVICE\n"
        f"    app=ProcessRecord{{def 2222:{host.TALKBACK_PACKAGE}/u0a42}}\n"
        "    Bindings:\n    * IntentBindRecord{123 CREATE}:\n"
        f"      intent={{cmp={host.SHORT_COMPONENT}}}\n"
        "      binder=android.os.BinderProxy@abc\n      requested=true received=true hasBound=true doRebind=false\n"
        "      * Client AppBindRecord{456 ProcessRecord{789 1234:system/1000}}\n"
        "        Per-process Connections:\n          ConnectionRecord{abc}\n    All Connections:\n      ConnectionRecord{abc}\n")


def dump_package():
    return (f"Packages:\n  Package [{host.TALKBACK_PACKAGE}] (abc):\n"
        "    versionCode=60149353 minSdk=26 targetSdk=35\n    versionName=16.0.1\n"
        "    User 0: ceDataInode=123 installed=true hidden=false suspended=false stopped=false\n"
        "Queries:\n  irrelevant package information\n")


def status(code, method=METHOD, klass=host.TEST_CLASS):
    return (f"INSTRUMENTATION_STATUS: class={klass}\nINSTRUMENTATION_STATUS: test={method}\n"
            f"INSTRUMENTATION_STATUS: current=1\nINSTRUMENTATION_STATUS: numtests=1\nINSTRUMENTATION_STATUS_CODE: {code}\n")


def native(method=METHOD):
    return status(1, method) + status(0, method) + "OK (1 test)\nINSTRUMENTATION_CODE: -1\n"


def scenario(method=METHOD):
    return {"schema": 1, "method": method, "talkback_component": host.COMPONENT, **IDENTITY,
            "native_enabled_spoken_service": True, "native_touch_exploration": True, "keymap_prerequisite": "default-alt",
            "next_focus_moves": 8, "previous_focus_moves": 1, "observed_app_accessibility_focus_events": 14,
            "verified_activations": 2, "platform_assertions_passed": True, "scenario_passed": True,
            "synthetic_presentation": True, "actual_authentication": False, "touch_gestures": False, "human_listening": False}


class ParserTests(unittest.TestCase):
    def test_settings_distinguish_absent_empty_zero_and_exact_component(self):
        found = host.settings_snapshot("other_private_value=NEVER_RETAIN\naccessibility_enabled=\ntouch_exploration_enabled=0\n")
        self.assertEqual(found, dict(zip(host.SETTINGS, (None, "", "0"))))
        self.assertNotIn("NEVER_RETAIN", str(found))
        self.assertEqual(host.settings_snapshot(f"enabled_accessibility_services={host.SHORT_COMPONENT}\n")[host.SETTINGS[0]], host.SHORT_COMPONENT)

    def test_unexpected_or_duplicate_services_and_literal_null_are_rejected(self):
        for raw in ("enabled_accessibility_services=other/.Service", f"enabled_accessibility_services={host.COMPONENT}:other/.Service",
                    f"enabled_accessibility_services={host.COMPONENT}:{host.COMPONENT}", "accessibility_enabled=null",
                    "enabled_accessibility_services=\nenabled_accessibility_services=", "touch_exploration_enabled=2"):
            with self.subTest(raw=raw), self.assertRaises(host.AccessibilityError):
                host.settings_snapshot(raw)

    def test_setting_commands_keep_user_zero_and_preserve_empty(self):
        self.assertEqual(host.setting_script(host.SETTINGS[1], ""), b"settings --user 0 put secure accessibility_enabled ''\n")
        self.assertEqual(host.setting_script(host.SETTINGS[1], None), b"settings --user 0 delete secure accessibility_enabled\n")
        for key, value in (("other", "1"), (host.SETTINGS[1], "1;echo secret"), (host.SETTINGS[0], "$(secret)")):
            with self.assertRaises(host.AccessibilityError):
                host.setting_script(key, value)

    def test_exact_bound_spoken_user_zero_shape(self):
        self.assertEqual(host.accessibility_state(dump_state()), BOUND)
        self.assertEqual(host.accessibility_state(dump_state(enabled=False, bound=False, touch=False)), EMPTY)

    def test_enabled_alone_is_not_bound(self):
        self.assertEqual(host.accessibility_state(dump_state(bound=False))["bound_count"], 0)

    def test_other_user_cannot_supply_bound_membership(self):
        raw = dump_state(enabled=False, bound=False, touch=False) + dump_state(user=10)
        self.assertEqual(host.accessibility_state(raw), EMPTY)
        with self.assertRaisesRegex(host.AccessibilityError, "A11Y_USER_ZERO_MISSING"):
            host.accessibility_state(dump_state(user=10))

    def test_duplicates_missing_fields_binding_crashed_wrong_component_fail(self):
        for raw in (dump_state() + dump_state(), dump_state().replace("     Bound services:", "     Ignored services:"),
                    dump_state(binding="{" + host.SHORT_COMPONENT + "}"), dump_state(crashed="{" + host.SHORT_COMPONENT + "}"),
                    dump_state().replace(host.SHORT_COMPONENT, "other/.TalkBackService"),
                    dump_state().replace("FEEDBACK_SPOKEN", "FEEDBACK_GENERIC"),
                    dump_state().replace("     Crashed services:{}", "     Crashed services:{}\n     Crashed services:{}")):
            with self.subTest(raw=raw[:70]), self.assertRaises(host.AccessibilityError):
                host.accessibility_state(raw)

    def test_label_and_installed_identity_do_not_prove_binding(self):
        raw = dump_state(bound=False).replace("Client list info:{", f"Client list info:{{TalkBack {host.COMPONENT}")
        self.assertEqual(host.accessibility_state(raw)["bound_count"], 0)
        with self.assertRaises(host.AccessibilityError):
            host.accessibility_state(dump_state(enabled=False))

    def test_exact_activity_system_binding(self):
        self.assertTrue(host.activity_binding(dump_activity()))
        self.assertTrue(host.activity_binding(dump_activity().replace("u0 " + host.SHORT_COMPONENT + "}",
                                                                    "u0 " + host.SHORT_COMPONENT + " c:android}")))

    def test_activity_binding_rejects_other_user_component_process_client_or_permission(self):
        for raw in (dump_activity().replace(" u0 ", " u10 "), dump_activity().replace(host.SHORT_COMPONENT, "other/.Service"),
                    dump_activity().replace("/u0a42", "/u10a42"), dump_activity().replace("system/1000", "app/10001"),
                    dump_activity().replace("android.permission.BIND_ACCESSIBILITY_SERVICE", "other.permission"),
                    dump_activity().replace("received=true", "received=false"),
                    dump_activity().replace("hasBound=true", "hasBound=false"),
                    dump_activity().replace("intent={cmp=", "intent={act=other.action cmp="),
                    dump_activity().replace("binder=android.os.BinderProxy@abc", "binder=null")):
            with self.subTest(raw=raw[:70]), self.assertRaises(host.AccessibilityError):
                host.activity_binding(raw)

    def test_activity_cannot_combine_fields_from_other_records(self):
        for raw in (dump_activity() + dump_activity(),
                    dump_activity().replace("    All Connections:", "    * IntentBindRecord{999 CREATE}:\n      requested=true received=true hasBound=true doRebind=false\n    All Connections:"),
                    dump_activity().replace("      * Client AppBindRecord", "    All Connections:\n      * Client AppBindRecord"),
                    dump_activity().replace("      requested=true received=true hasBound=true doRebind=false", "    All Connections:\n      requested=true received=true hasBound=true doRebind=false")):
            with self.assertRaises(host.AccessibilityError):
                host.activity_binding(raw)

    def test_active_package_version_and_user_are_exact(self):
        self.assertEqual(host.package_version(dump_package()), {key: IDENTITY[key] for key in ("talkback_version_code", "talkback_version_name")})
        for raw in (dump_package().replace("installed=true", "installed=false"), dump_package().replace("User 0:", "User 10:"),
                    dump_package().replace(host.TALKBACK_PACKAGE, "other.package"), dump_package().replace("Packages:", "Hidden system packages:"),
                    dump_package().replace("    versionName=", "    versionCode=12\n    versionName=")):
            with self.assertRaises(host.AccessibilityError):
                host.package_version(raw)

    def test_raw_dump_bounds_and_invalid_decoding_are_not_silently_accepted(self):
        for parser, raw in ((host.settings_snapshot, "x" * 65537), (host.accessibility_state, "x" * 262145),
                            (host.activity_binding, "x" * 131073), (host.package_version, dump_package() + "\ufffd")):
            with self.assertRaises(host.AccessibilityError):
                parser(raw)


class BoundFormatTests(unittest.TestCase):
    @staticmethod
    def events(value, **kwargs):
        return dump_state(**kwargs).replace("[TYPE_VIEW_CLICKED, TYPE_VIEW_ACCESSIBILITY_FOCUSED]", value)

    def test_android_all_mask_single_and_complete_known_list_parse_without_bracket_assumption(self):
        values = ("TYPES_ALL_MASK", "TYPE_VIEW_CLICKED", "TYPE_VIEW_TARGETED_BY_SCROLL",
                  "[" + ", ".join(host.EVENT_TYPES) + "]")
        for value, expected in zip(values, ("all_mask", "single_known", "single_known", "list_known")):
            with self.subTest(shape=expected):
                structure = {}
                self.assertEqual(host.accessibility_state(self.events(value), structure=structure), BOUND)
                self.assertTrue(host.valid_bound_structure(structure))
                self.assertEqual(structure["event_shape"], expected)
                self.assertTrue(structure["envelope_valid"])
                self.assertEqual(structure["service_records"], 1)
                self.assertEqual(structure["event_fields"], 1)

    def test_list_order_tracks_android_bits_not_switch_statement_order(self):
        for left, right in (("TYPE_NOTIFICATION_STATE_CHANGED", "TYPE_VIEW_HOVER_ENTER"),
                            ("TYPE_VIEW_SCROLLED", "TYPE_VIEW_TEXT_SELECTION_CHANGED")):
            self.assertEqual(host.accessibility_state(self.events(f"[{left}, {right}]")), BOUND)
            with self.assertRaisesRegex(host.AccessibilityError, "^A11Y_BOUND_FORMAT_INVALID$"):
                host.accessibility_state(self.events(f"[{right}, {left}]"))

    def test_unsupported_empty_hex_invented_duplicate_and_noncanonical_events_fail(self):
        cases = ("", "0", "40000000", "ffffffff", "TYPE_PRIVATE_CANARY", "[]", "[TYPES_ALL_MASK]",
                 "[TYPE_VIEW_CLICKED]", "[TYPE_VIEW_CLICKED, TYPE_VIEW_CLICKED]",
                 "[TYPE_VIEW_CLICKED,TYPE_VIEW_SELECTED]", "[TYPE_VIEW_CLICKED,  TYPE_VIEW_SELECTED]",
                 "[TYPE_VIEW_CLICKED, TYPE_PRIVATE_CANARY]", "[TYPE_VIEW_CLICKED, 40000000]",
                 "[TYPE_VIEW_CLICKED, TYPE_VIEW_SELECTED, ]", "[[TYPE_VIEW_CLICKED, TYPE_VIEW_SELECTED]]",
                 " TYPES_ALL_MASK", "TYPES_ALL_MASK ", "TYPE_VIEW_CLICKED\n", "A" * 2049,
                 "[" + ", ".join(["TYPE_VIEW_CLICKED"] * 28) + "]")
        for value in cases:
            with self.subTest(value=value[:50]), self.assertRaisesRegex(host.AccessibilityError, "^A11Y_BOUND_FORMAT_INVALID$"):
                host.accessibility_state(self.events(value))

    def test_duplicate_fields_extra_data_and_multiple_records_cannot_use_valid_event_token(self):
        raw = self.events("TYPES_ALL_MASK")
        service = raw.split("Bound services:{", 1)[1].split("}\n", 1)[0]
        cases = (raw.replace(", eventTypes=", ", eventTypes=TYPES_ALL_MASK, eventTypes="),
                 raw.replace("label=TalkBack", "label=TalkBack, eventTypes=TYPES_ALL_MASK"),
                 raw.replace("label=TalkBack", "label=TalkBack, capabilities=7"),
                 raw.replace("label=TalkBack", "label=TalkBack, notificationTimeout=1"),
                 raw.replace("label=TalkBack", "label=TalkBack, requestA11yBtn=false"),
                 raw.replace("capabilities=15", "capabilities=15, extra=PRIVATE_CANARY"),
                 raw.replace(service, service + ",\n" + service),
                 raw.replace("requestA11yBtn=false]", "requestA11yBtn=false] trailing"))
        for value in cases:
            with self.subTest(case=value[:30]), self.assertRaisesRegex(host.AccessibilityError, "^A11Y_BOUND_FORMAT_INVALID$"):
                host.accessibility_state(value)

    def test_documented_event_format_does_not_replace_user_component_or_spoken_proof(self):
        raw = self.events("TYPES_ALL_MASK")
        for value, code in ((raw.replace(host.SHORT_COMPONENT, "other/.Service"), "A11Y_COMPONENT_DENIED"),
                            (self.events("TYPES_ALL_MASK", enabled=False), "A11Y_BOUND_IDENTITY_INCONSISTENT"),
                            (raw.replace("FEEDBACK_SPOKEN", "FEEDBACK_GENERIC"), "A11Y_BOUND_NOT_SPOKEN"),
                            (raw + raw, "A11Y_USER_STATE_INVALID"),
                            (self.events("TYPES_ALL_MASK", user=10), "A11Y_USER_ZERO_MISSING")):
            with self.subTest(code=code), self.assertRaisesRegex(host.AccessibilityError, "^" + code + "$"):
                host.accessibility_state(value)

    def test_known_event_format_still_requires_received_system_binder(self):
        for binding in (dump_activity().replace("received=true", "received=false"),
                        dump_activity().replace("system/1000", "app/10001")):
            session = host.TalkBackSession(Mock())
            session.command = Mock(side_effect=[self.events("TYPES_ALL_MASK"), binding])
            with self.assertRaises(host.AccessibilityError):
                session.state()
            self.assertEqual([call.args for call in session.command.call_args_list],
                             [("shell", "dumpsys", "accessibility"),
                              ("shell", "dumpsys", "activity", "services", host.COMPONENT)])

    def test_known_event_format_cannot_supply_missing_touch_readiness(self):
        session = host.TalkBackSession(Mock(), clock=Mock(side_effect=[0, 0, 21]), sleep=Mock())
        session.command = Mock(side_effect=[self.events("TYPES_ALL_MASK", touch=False), dump_activity()] * 2)
        with self.assertRaisesRegex(host.AccessibilityError, "^A11Y_SERVICE_WAIT_TIMEOUT$"):
            session.wait_state(BOUND)
        observation = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]
        self.assertEqual(observation["outcome"], "timeout")
        self.assertFalse(observation["last_observation"]["state"]["touch_exploration"])
        self.assertEqual(session.command.call_count, 4)
        session.sleep.assert_called_once_with(0.25)

    def test_structural_observation_is_only_selected_user_zero(self):
        empty = dump_state(enabled=False, bound=False, touch=False)
        other = self.events("TYPES_ALL_MASK", user=10)
        for raw in (empty + other, other + empty):
            structure = {}
            self.assertEqual(host.accessibility_state(raw, structure=structure), EMPTY)
            self.assertEqual(structure["service_records"], 0)
            self.assertEqual(structure["event_shape"], "missing_or_duplicate")
        structure = {}
        with self.assertRaises(host.AccessibilityError):
            host.accessibility_state(other, structure=structure)
        self.assertEqual(structure, {})

    def test_successful_wait_uses_existing_capture_and_retains_only_fixed_shape(self):
        session = host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())
        session.command = Mock(side_effect=[self.events("TYPES_ALL_MASK").replace("label=TalkBack", "label=PRIVATE_LABEL"), dump_activity()])
        session.wait_state(BOUND)
        observation = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]["last_observation"]
        self.assertEqual(observation["state"], BOUND)
        self.assertEqual(observation["bound_structure"]["event_shape"], "all_mask")
        self.assertNotIn("PRIVATE_LABEL", json.dumps(observation))
        self.assertEqual(session.command.call_count, 2)
        session.sleep.assert_not_called()

    def test_fatal_format_keeps_original_code_without_retry_or_private_values(self):
        for raw, expected in ((self.events("TYPE_PRIVATE_CANARY"), "other"),
                              (self.events(""), "empty"),
                              (self.events("TYPES_ALL_MASK").replace(", eventTypes=", ", eventTypes=PRIVATE_CANARY, eventTypes="), "missing_or_duplicate")):
            session = host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())
            session.command = Mock(return_value=raw.replace("label=TalkBack", "label=PRIVATE_LABEL"))
            with self.assertRaisesRegex(host.AccessibilityError, "^A11Y_BOUND_FORMAT_INVALID$"):
                session.wait_state(BOUND)
            wait = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]
            self.assertEqual((wait["attempts"], wait["outcome"]), (1, "fatal_error"))
            self.assertEqual(wait["last_observation"]["code"], "A11Y_BOUND_FORMAT_INVALID")
            self.assertEqual(wait["last_observation"]["bound_structure"]["event_shape"], expected)
            self.assertNotIn("PRIVATE", json.dumps(wait))
            session.command.assert_called_once_with("shell", "dumpsys", "accessibility", timeout=5)
            session.sleep.assert_not_called()

    def test_failed_later_capture_cannot_reuse_prior_format_evidence(self):
        session = host.TalkBackSession(Mock(), clock=Mock(side_effect=[0, 0]), sleep=Mock())
        session.command = Mock(side_effect=[self.events("TYPES_ALL_MASK", touch=False), dump_activity(),
                                            host.AccessibilityError("A11Y_CURRENT_USER_DENIED")])
        with self.assertRaisesRegex(host.AccessibilityError, "^A11Y_CURRENT_USER_DENIED$"):
            session.wait_state(BOUND)
        observation = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]["last_observation"]
        self.assertEqual(observation, {"kind": "fatal_error", "code": "A11Y_CURRENT_USER_DENIED"})

    def test_structural_schema_rejects_arbitrary_values_extras_and_invalid_scalar_types(self):
        session = host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())
        session.command = Mock(side_effect=[self.events("TYPES_ALL_MASK"), dump_activity()])
        session.wait_state(BOUND)
        observation = session.wait_observations["setup_service_readiness"]["last_observation"]
        original = observation["bound_structure"]
        for changes in ({"raw": "PRIVATE_CANARY"}, {"event_shape": "PRIVATE_CANARY"},
                        {"schema": True}, {"event_fields": True}, {"event_fields": 3},
                        {"service_records": -1}, {"label_valid": "PRIVATE_CANARY"}):
            observation["bound_structure"] = {**original, **changes}
            evidence = host.diagnostic_snapshot(session)
            self.assertEqual(evidence, {"schema": 2, "code": "A11Y_DIAGNOSTICS_UNAVAILABLE"})
            self.assertNotIn("PRIVATE", json.dumps(evidence))

    def test_structural_counts_are_capped_and_snapshot_remains_detached_and_bounded(self):
        structure = host.bound_structure("Service[" * 1000 + ", eventTypes=" * 1000)
        self.assertTrue(host.valid_bound_structure(structure))
        self.assertEqual((structure["service_records"], structure["event_fields"]), (2, 2))
        session = host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())
        session.command = Mock(side_effect=[self.events("TYPES_ALL_MASK"), dump_activity()] * 2)
        for phase in sorted(host.WAIT_PHASES):
            session.wait_state(BOUND, phase=phase)
        snapshot = host.diagnostic_snapshot(session)
        session.wait_observations["setup_service_readiness"]["last_observation"]["bound_structure"]["event_shape"] = "other"
        self.assertEqual(snapshot["waits"]["setup_service_readiness"]["last_observation"]["bound_structure"]["event_shape"], "all_mask")
        self.assertEqual(len(snapshot["waits"]), 2)
        self.assertLessEqual(len(json.dumps(snapshot).encode()), 4096)

    def test_malformed_envelope_reports_only_structure_even_with_adversarial_label(self):
        for replacement in ("label=PRIVATE[CANARY]", "label=" + "PRIVATE_CANARY" * 20,
                            "label=PRIVATE\nCANARY", "label=PRIVATE, eventTypes=CANARY"):
            raw = self.events("TYPES_ALL_MASK").replace("label=TalkBack", replacement)
            structure = {}
            with self.assertRaises(host.AccessibilityError):
                host.accessibility_state(raw, structure=structure)
            self.assertTrue(host.valid_bound_structure(structure))
            self.assertFalse(structure["envelope_valid"])
            self.assertNotIn("PRIVATE", json.dumps(structure))
            self.assertNotIn("CANARY", json.dumps(structure))

    def test_format_failure_keeps_actual_restoration_and_separate_wait_observations(self):
        session = host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())
        session.install = Mock()
        empty = dump_state(enabled=False, bound=False, touch=False)
        session.command = Mock(side_effect=[host.SHORT_COMPONENT, empty, self.events("TYPE_PRIVATE_CANARY"), "", empty, empty])
        session.observed_identity = Mock(return_value=IDENTITY)
        original = dict(zip(host.SETTINGS, (None, "0", "0")))
        session.settings = Mock(return_value=original)
        session.put = Mock()
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session):
            with self.assertRaisesRegex(host.AccessibilityError, "^A11Y_BOUND_FORMAT_INVALID$"):
                host.run_scenarios(Mock(), [], [], evidence)
        self.assertTrue(evidence["secure_settings_restored"])
        self.assertEqual(evidence["scenario_failure_stage"], "setup_service_readiness")
        waits = evidence["service_diagnostics"]["waits"]
        self.assertEqual(waits["setup_service_readiness"]["last_observation"]["bound_structure"]["event_shape"], "other")
        self.assertEqual(waits["restore_original_service"]["last_observation"]["state"], EMPTY)
        self.assertEqual(waits["restore_original_service"]["last_observation"]["bound_structure"]["service_records"], 0)
        self.assertEqual([call.args for call in session.put.call_args_list],
                         [(host.SETTINGS[0], host.COMPONENT), (host.SETTINGS[1], "1"), *original.items()])
        self.assertEqual(evidence["scenarios"], [])
        self.assertNotIn("PRIVATE", json.dumps(evidence))


class NativeEvidenceTests(unittest.TestCase):
    def test_each_exact_single_method_has_independent_completion(self):
        for method in host.METHODS:
            result = host.native_result(native(method), method)
            self.assertTrue(result["passed"])
            self.assertEqual(result["method_completed_count"], 1)
        with self.assertRaises(host.AccessibilityError):
            host.native_result(native(), "otherMethod")

    def test_missing_duplicate_wrong_method_class_or_count_cannot_pass(self):
        for raw in ("OK (1 test)\nINSTRUMENTATION_CODE: -1\n", native().replace("numtests=1", "numtests=2"),
                    native().replace(host.TEST_CLASS, "other.Class"), native().replace(METHOD, "otherMethod"),
                    native() + status(0), native() + "INSTRUMENTATION_CODE: -1\n", native() + "INSTRUMENTATION_STATUS_CODE: nonsense\n",
                    native() + "INSTRUMENTATION_STATUS: test=orphan\n", native() + "INSTRUMENTATION_CODE: nonsense\n"):
            self.assertFalse(host.native_result(raw, METHOD)["passed"])

    def test_failure_marker_and_exception_always_win_over_ok(self):
        for suffix in ("FAILURES!!!", "INSTRUMENTATION_FAILED: canary", "INSTRUMENTATION_RESULT: shortMsg=canary",
                       "INSTRUMENTATION_STATUS: stack=canary", "java.lang.IllegalStateException: PRIVATE_CANARY"):
            result = host.native_result(native() + suffix + "\n", METHOD)
            self.assertFalse(result["passed"])
            self.assertNotIn("CANARY", str(result))

    def test_native_failure_and_interruption_are_distinct(self):
        failed = status(1) + status(-2) + "INSTRUMENTATION_CODE: -1\n"
        self.assertEqual(host.native_result(failed, METHOD)["outcome"], "failed")
        self.assertEqual(host.native_result(status(1), METHOD)["outcome"], "incomplete")
        self.assertEqual(host.native_result(status(1) + status(0), METHOD)["method_completed_count"], 0)
        self.assertEqual(host.native_result(status(1) + status(-2), METHOD)["outcome"], "incomplete")

    def test_only_allowlisted_fixture_diagnostics_survive(self):
        result = host.native_result(status(1) + status(-2) + "A11Y_TARGET_NOT_REACHED A11Y_PRIVATE_CANARY\nINSTRUMENTATION_CODE: -1\n", METHOD)
        self.assertEqual(result["fixture_codes"], ["A11Y_TARGET_NOT_REACHED"])
        self.assertNotIn("CANARY", str(result))

    def test_evidence_has_exact_schema_types_and_independent_identity(self):
        value = scenario()
        self.assertEqual(host.scenario_evidence(json.dumps(value), METHOD, IDENTITY), value)
        for key, replacement in (("schema", True), ("native_touch_exploration", 1), ("next_focus_moves", True),
                                 ("talkback_version_code", 60149354), ("talkback_version_name", "other"),
                                 ("android_build", "other"), ("method", host.METHODS[1]), ("talkback_component", host.SHORT_COMPONENT),
                                 ("actual_authentication", True), ("touch_gestures", True), ("human_listening", True),
                                 ("scenario_passed", False), ("previous_focus_moves", 0)):
            changed = {**value, key: replacement}
            with self.subTest(key=key), self.assertRaises(host.AccessibilityError):
                host.scenario_evidence(json.dumps(changed), METHOD, IDENTITY)

    def test_duplicate_unknown_missing_oversize_non_json_nested_evidence_rejected(self):
        valid = json.dumps(scenario())
        missing = scenario(); missing.pop("synthetic_presentation")
        for raw in (valid[:-1] + ', "schema": 1}', json.dumps({**scenario(), "extra": "PRIVATE_CANARY"}), json.dumps(missing),
                    valid + " " * 2049, "[1]", "{", "[" * 1500, valid.replace('"next_focus_moves": 8', '"next_focus_moves": NaN')):
            with self.assertRaises(host.AccessibilityError):
                host.scenario_evidence(raw, METHOD, IDENTITY)

    def test_reverse_focus_required_only_for_first_two_scenarios(self):
        for method in host.METHODS:
            value = {**scenario(method), "previous_focus_moves": 0}
            if method in host.METHODS[:2]:
                with self.assertRaises(host.AccessibilityError):
                    host.scenario_evidence(json.dumps(value), method, IDENTITY)
            else:
                host.scenario_evidence(json.dumps(value), method, IDENTITY)


class SessionTests(unittest.TestCase):
    def test_install_accepts_only_reviewed_success_variants_without_pin_or_reverse(self):
        for output in ("Success\n", "Performing Streamed Install\nSuccess\n"):
            session = host.TalkBackSession(Mock())
            session.command = Mock(side_effect=["", "", "", output, output,
                f"instrumentation:{host.TEST_PACKAGE}/{host.RUNNER} (target={host.PACKAGE})\n"])
            session.require_absent = Mock()
            with patch.object(host.base, "digest", return_value="hash"):
                session.install(("app.apk", "test.apk"), ("hash", "hash"))
            calls = [call.args for call in session.command.call_args_list]
            self.assertEqual([call for call in calls if call[0] == "reverse"], [("reverse", "--list")])
            self.assertFalse(any("locksettings" in call or "settings" in call for call in calls))
            self.assertEqual(session.require_absent.call_count, 6)

    def test_install_failure_or_unknown_banner_never_accepted(self):
        for output in ("Performing Streamed Install\nFailure [INSTALL_FAILED]\n", "Success\nPRIVATE_CANARY\n", "Performing Other Install\nSuccess\n"):
            session = host.TalkBackSession(Mock())
            session.command = Mock(side_effect=["", "", "", output])
            with patch.object(host.base, "digest", return_value="hash"), self.assertRaisesRegex(host.AccessibilityError, "A11Y_INSTALL_FAILED"):
                session.install(("app.apk", "test.apk"), ("hash", "hash"))

    def test_existing_package_or_reverse_blocks_installation(self):
        for replies in (["package:existing"], ["", "", "emulator tcp:18082 tcp:18082"]):
            session = host.TalkBackSession(Mock())
            session.command = Mock(side_effect=replies)
            with self.assertRaises(host.AccessibilityError):
                session.install(("app.apk", "test.apk"), ("hash", "hash"))
            self.assertFalse(any(call.args[0] == "install" for call in session.command.call_args_list))

    def test_changed_apk_blocks_installation(self):
        session = host.TalkBackSession(Mock())
        session.command = Mock(side_effect=["", "", ""])
        with patch.object(host.base, "digest", return_value="changed"), self.assertRaisesRegex(host.AccessibilityError, "A11Y_APK_CHANGED"):
            session.install(("app.apk", "test.apk"), ("hash", "hash"))
        self.assertFalse(any(call.args[0] == "install" for call in session.command.call_args_list))

    def test_each_session_command_checks_current_user_and_held_emulator(self):
        emulator = Mock()
        emulator.command.side_effect = ["0\n", "done"]
        session = host.TalkBackSession(emulator)
        self.assertEqual(session.command("shell", "fixed-command"), "done")
        self.assertEqual(emulator.command.call_args_list[0].args, ("shell", "am", "get-current-user"))
        self.assertEqual(emulator.command.call_args_list[1].args, ("shell", "fixed-command"))
        emulator.command.side_effect = ["10\n"]
        emulator.reset_mock()
        with self.assertRaisesRegex(host.AccessibilityError, "A11Y_CURRENT_USER_DENIED"):
            session.command("shell", "must-not-run")
        self.assertEqual(emulator.command.call_count, 1)

    def test_lost_owned_transport_blocks_commands_and_settings(self):
        emulator = Mock()
        emulator.command.side_effect = host.AccessibilityError("EMULATOR_TRANSPORT_CHANGED")
        session = host.TalkBackSession(emulator)
        with self.assertRaises(host.AccessibilityError):
            session.put(host.SETTINGS[0], host.COMPONENT)
        self.assertEqual(emulator.command.call_count, 1)

    def test_binding_checks_activity_record_in_addition_to_accessibility(self):
        session = host.TalkBackSession(Mock())
        session.command = Mock(side_effect=[dump_state(), dump_activity()])
        self.assertEqual(session.state(), BOUND)
        self.assertIn(host.COMPONENT, session.command.call_args_list[1].args)
        session.command.side_effect = [dump_state(), dump_activity().replace("received=true", "received=false")]
        with self.assertRaises(host.AccessibilityError):
            session.state()

    def test_setup_captures_before_first_mutation_and_never_forces_touch_exploration(self):
        session = host.TalkBackSession(Mock())
        session.command = Mock(return_value=host.SHORT_COMPONENT)
        session.observed_identity = Mock(return_value=IDENTITY)
        session.settings = Mock(return_value=dict(zip(host.SETTINGS, (None, "", "0"))))
        session.state = Mock(return_value=EMPTY)
        session.put = Mock()
        session.wait_state = Mock()
        session.require_bound = Mock()
        self.assertEqual(session.setup(), IDENTITY)
        self.assertEqual(session.put.call_args_list[0].args, (host.SETTINGS[0], host.COMPONENT))
        self.assertEqual(session.put.call_args_list[1].args, (host.SETTINGS[1], "1"))
        self.assertEqual(session.put.call_count, 2)
        self.assertTrue(session.mutated)
        self.assertEqual(session.original[host.SETTINGS[1]], "")

    def test_ambiguous_first_setting_failure_still_requires_restore(self):
        session = host.TalkBackSession(Mock())
        session.command = Mock(return_value=host.SHORT_COMPONENT)
        session.observed_identity = Mock(return_value=IDENTITY)
        session.settings = Mock(return_value=dict.fromkeys(host.SETTINGS))
        session.state = Mock(return_value=EMPTY)
        session.put = Mock(side_effect=host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT"))
        with self.assertRaises(host.AccessibilityError):
            session.setup()
        self.assertTrue(session.mutated)
        self.assertIsNotNone(session.original)

    def test_unexpected_service_refused_before_any_setting_change(self):
        session = host.TalkBackSession(Mock())
        session.command = Mock(return_value="other/.Service")
        session.put = Mock()
        with self.assertRaises(host.AccessibilityError):
            session.setup()
        session.put.assert_not_called()
        self.assertFalse(session.mutated)

    def test_wait_is_bounded_and_cannot_convert_malformed_evidence_to_readiness(self):
        clock = Mock(side_effect=[0, 0, 21])
        session = host.TalkBackSession(Mock(), clock=clock, sleep=Mock())
        session.state = Mock(return_value=EMPTY)
        with self.assertRaisesRegex(host.AccessibilityError, "A11Y_SERVICE_WAIT_TIMEOUT"):
            session.wait_state(BOUND)
        session.state.side_effect = host.AccessibilityError("A11Y_CURRENT_USER_DENIED")
        session.clock = Mock(return_value=0)
        with self.assertRaisesRegex(host.AccessibilityError, "A11Y_CURRENT_USER_DENIED"):
            session.wait_state(BOUND)

    def test_restore_exact_original_values_and_observed_binding(self):
        session = host.TalkBackSession(Mock())
        session.original = dict(zip(host.SETTINGS, (None, "", "0")))
        session.original_state, session.mutated = EMPTY, True
        session.command, session.put, session.wait_state = Mock(), Mock(), Mock()
        session.settings = Mock(return_value=session.original)
        session.state = Mock(return_value=EMPTY)
        session.restore()
        self.assertTrue(session.restored)
        self.assertEqual([call.args for call in session.put.call_args_list], list(session.original.items()))
        session.command.assert_called_once_with("shell", "am", "force-stop", "--user", "0", host.PACKAGE)
        session.wait_state.assert_called_once_with(EMPTY, phase="restore_original_service")

    def test_restore_mismatch_or_ownership_loss_never_passes(self):
        for fail in ("values", "ownership"):
            session = host.TalkBackSession(Mock())
            session.original, session.original_state, session.mutated = dict.fromkeys(host.SETTINGS), EMPTY, True
            session.command, session.put, session.wait_state = Mock(), Mock(), Mock()
            session.settings = Mock(return_value=dict.fromkeys(host.SETTINGS, ""))
            session.state = Mock(return_value=EMPTY)
            if fail == "ownership":
                session.command.side_effect = host.AccessibilityError("EMULATOR_TRANSPORT_CHANGED")
            with self.assertRaises(host.AccessibilityError):
                session.restore()
            self.assertFalse(session.restored)
            if fail == "ownership":
                session.put.assert_not_called()

    def test_scenario_finally_restores_after_native_failure(self):
        emulator, session = Mock(), Mock()
        session.original, session.original_state, session.restored = dict.fromkeys(host.SETTINGS), EMPTY, True
        session.method.side_effect = host.AccessibilityError("A11Y_NATIVE_SCENARIO_FAILED")
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session), self.assertRaises(host.AccessibilityError):
            host.run_scenarios(emulator, [], [], evidence)
        session.restore.assert_called_once()
        self.assertTrue(evidence["secure_settings_restored"])
        self.assertEqual(len(evidence["scenarios"]), 1)

    def test_first_mutation_failure_reaches_real_finally_restore(self):
        session = host.TalkBackSession(Mock())
        session.install = Mock()
        session.command = Mock(return_value=host.SHORT_COMPONENT)
        session.observed_identity = Mock(return_value=IDENTITY)
        session.settings = Mock(return_value=dict.fromkeys(host.SETTINGS))
        session.state = Mock(return_value=EMPTY)
        session.put = Mock(side_effect=host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT"))
        session.restore = Mock()
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session), self.assertRaises(host.AccessibilityError):
            host.run_scenarios(Mock(), [], [], evidence)
        session.restore.assert_called_once()
        self.assertTrue(session.mutated)
        self.assertEqual(evidence["scenario_failure_code"], "EMULATOR_COMMAND_TIMEOUT")
        self.assertFalse(evidence["secure_settings_restored"])

    def test_scenario_restore_failure_cannot_be_masked_by_native_pass(self):
        session = Mock()
        session.original, session.original_state, session.restored = {}, EMPTY, False
        session.restore.side_effect = host.AccessibilityError("A11Y_RESTORE_MISMATCH")
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session), patch("builtins.print"), self.assertRaises(host.AccessibilityError):
            host.run_scenarios(Mock(), [], [], evidence)
        self.assertFalse(evidence["secure_settings_restored"])

    def test_native_failure_never_reads_success_marker_and_still_observes_post_binding(self):
        session = host.TalkBackSession(Mock())
        session.require_bound = Mock(return_value={"exact_component_bound": True})
        session.require_absent = Mock()
        session.command = Mock(side_effect=["", "", "User \"synthetic\" (id=0, flags=0) (current): deviceLocked=0\n", native().replace("OK (1 test)", "FAILURES!!!")])
        outcome = {}
        with self.assertRaisesRegex(host.AccessibilityError, "A11Y_NATIVE_SCENARIO_FAILED"):
            session.method(METHOD, IDENTITY, outcome)
        self.assertEqual(session.require_bound.call_count, 2)
        self.assertFalse(outcome["passed"])
        self.assertEqual(session.command.call_count, 4)

    def test_successful_native_needs_post_binding_and_valid_scenario(self):
        session = host.TalkBackSession(Mock())
        session.require_bound = Mock(return_value={"exact_component_bound": True})
        session.require_absent = Mock()
        session.command = Mock(side_effect=["", "", "User \"synthetic\" (id=0, flags=0) (current): deviceLocked=0\n", native(), json.dumps(scenario())])
        outcome = {}
        session.method(METHOD, IDENTITY, outcome)
        self.assertTrue(outcome["passed"])
        self.assertEqual(session.command.call_args.args[4:6], ("-c", "2049"))

    def test_post_binding_loss_defeats_native_success_before_marker_read(self):
        session = host.TalkBackSession(Mock())
        session.require_bound = Mock(side_effect=[{}, host.AccessibilityError("A11Y_SERVICE_NOT_BOUND")])
        session.require_absent = Mock()
        session.command = Mock(side_effect=["", "", "User \"synthetic\" (id=0, flags=0) (current): deviceLocked=0\n", native()])
        outcome = {}
        with self.assertRaisesRegex(host.AccessibilityError, "A11Y_SERVICE_NOT_BOUND"):
            session.method(METHOD, IDENTITY, outcome)
        self.assertFalse(outcome["passed"])
        self.assertTrue(outcome["native"]["passed"])
        self.assertEqual(session.command.call_count, 4)

    def test_stale_evidence_is_never_deleted_to_make_test_pass(self):
        session = host.TalkBackSession(Mock())
        session.command = Mock(return_value="present")
        with self.assertRaisesRegex(host.AccessibilityError, "A11Y_EVIDENCE_PREEXISTING"):
            session.require_absent(f"m2-accessibility-{METHOD}.json")
        self.assertEqual(session.command.call_count, 1)
        self.assertNotIn("rm ", session.command.call_args.kwargs["stdin"].decode())

    def test_low_disk_fails_before_android_tools_or_runtime(self):
        with patch.object(host.os, "name", "nt"), patch.object(host.shutil, "disk_usage", return_value=SimpleNamespace(free=1024)), \
                patch.object(host.base, "AndroidTools") as tools, patch.object(host, "RunLease") as lease:
            with self.assertRaisesRegex(host.AccessibilityError, "A11Y_DISK_SPACE_REQUIRED"):
                host.execute(None, None, None, None)
            tools.assert_not_called()
            lease.assert_not_called()

    def test_lease_checks_held_file_inode_directory_pid_and_token(self):
        lease = object.__new__(host.RunLease)
        lease.pid = host.os.getpid()
        lease.token = b"a" * 48
        lease.file = io.BytesIO(lease.token)
        lease.identity = SimpleNamespace(st_dev=1, st_ino=2)
        lease.directory = SimpleNamespace(st_dev=1, st_ino=3)
        lease.path, lease.run = Mock(), Mock()
        lease.path.stat.return_value = SimpleNamespace(st_dev=1, st_ino=2, st_size=48)
        lease.run.stat.return_value = SimpleNamespace(st_dev=1, st_ino=3)
        with patch.object(host.base, "checked_path"):
            lease.assert_owned()
            lease.path.stat.return_value.st_ino = 4
            with self.assertRaisesRegex(host.AccessibilityError, "A11Y_RUN_OWNERSHIP_LOST"):
                lease.assert_owned()
            lease.path.stat.return_value.st_ino = 2
            lease.file = io.BytesIO(b"b" * 48)
            with self.assertRaisesRegex(host.AccessibilityError, "A11Y_RUN_OWNERSHIP_LOST"):
                lease.assert_owned()


class DiagnosticTests(unittest.TestCase):
    def timed_session(self):
        return host.TalkBackSession(Mock(), clock=Mock(side_effect=[0, 0, 21]), sleep=Mock())

    def test_timeout_keeps_last_valid_state_and_existing_clock_sleep_budget(self):
        session = self.timed_session()
        session.state = Mock(return_value=EMPTY)
        with self.assertRaisesRegex(host.AccessibilityError, "A11Y_SERVICE_WAIT_TIMEOUT"):
            session.wait_state(BOUND)
        evidence = host.diagnostic_snapshot(session)
        wait = evidence["waits"]["setup_service_readiness"]
        self.assertEqual(wait, {"budget_seconds": 20, "attempts": 2, "outcome": "timeout",
                                "last_observation": {"kind": "parsed_state", "state": EMPTY},
                                "previous_observation": None})
        self.assertEqual(session.clock.call_count, 3)
        self.assertEqual(session.state.call_count, 2)
        session.sleep.assert_called_once_with(0.25)
        session.emulator.command.assert_not_called()

    def test_each_original_retryable_error_retained_without_changing_retry(self):
        expected = {"A11Y_SERVICE_NOT_STABLE", "A11Y_ACTIVITY_SERVICE_INVALID", "A11Y_BINDER_MISSING",
                    "A11Y_BINDING_NOT_RECEIVED", "A11Y_SYSTEM_CLIENT_MISSING", "A11Y_ACTIVITY_PROCESS_INVALID"}
        self.assertEqual(host.RETRYABLE_STATE_ERRORS, expected)
        for code in expected:
            with self.subTest(code=code):
                session = self.timed_session()
                session.state = Mock(side_effect=host.AccessibilityError(code))
                with self.assertRaisesRegex(host.AccessibilityError, "A11Y_SERVICE_WAIT_TIMEOUT"):
                    session.wait_state(BOUND)
                wait = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]
                self.assertEqual(wait["outcome"], "timeout")
                self.assertEqual(wait["last_observation"], {"kind": "retryable_error", "code": code})
                self.assertEqual(session.state.call_count, 2)
                session.sleep.assert_called_once_with(0.25)

    def test_success_replaces_old_retryable_error_with_final_parsed_state(self):
        session = host.TalkBackSession(Mock(), clock=Mock(side_effect=[0, 0]), sleep=Mock())
        session.state = Mock(side_effect=[host.AccessibilityError("A11Y_BINDER_MISSING"), BOUND])
        session.wait_state(BOUND)
        evidence = host.diagnostic_snapshot(session)
        wait = evidence["waits"]["setup_service_readiness"]
        self.assertEqual(wait["outcome"], "target_reached")
        self.assertEqual(wait["last_observation"], {"kind": "parsed_state", "state": BOUND})
        self.assertIsNone(wait["previous_observation"])
        self.assertNotIn("A11Y_BINDER_MISSING", json.dumps(evidence))

    def test_nonretryable_errors_exit_immediately_and_foreign_tokens_are_not_exported(self):
        class PRIVATE_CLASS(Exception):
            pass
        for error, expected in ((host.AccessibilityError("A11Y_CURRENT_USER_DENIED"), "A11Y_CURRENT_USER_DENIED"),
                                (host.AccessibilityError("A11Y_PRIVATE_CANARY"), "A11Y_DIAGNOSTIC_OTHER"),
                                (PRIVATE_CLASS("PRIVATE_MESSAGE"), "A11Y_DIAGNOSTIC_OTHER")):
            with self.subTest(kind=expected):
                session = host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())
                session.state = Mock(side_effect=error)
                with self.assertRaises(type(error)) as caught:
                    session.wait_state(BOUND)
                self.assertIs(caught.exception, error)
                evidence = host.diagnostic_snapshot(session)
                self.assertEqual(evidence["waits"]["setup_service_readiness"]["last_observation"],
                                 {"kind": "fatal_error", "code": expected})
                self.assertNotIn("PRIVATE", json.dumps(evidence))
                session.sleep.assert_not_called()
                session.state.assert_called_once()

    def test_at_most_two_waits_are_retained_and_snapshot_is_detached(self):
        session = host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())
        session.state = Mock(return_value=EMPTY)
        for _ in range(5):
            for phase in host.WAIT_PHASES:
                session.wait_state(EMPTY, phase=phase)
        snapshot = host.diagnostic_snapshot(session)
        self.assertEqual(set(snapshot["waits"]), host.WAIT_PHASES)
        self.assertEqual(len(snapshot["waits"]), 2)
        session.wait_observations["setup_service_readiness"]["outcome"] = "waiting"
        self.assertEqual(snapshot["waits"]["setup_service_readiness"]["outcome"], "target_reached")
        self.assertLessEqual(len(json.dumps(snapshot).encode()), 4096)

    def test_setup_failure_retains_validated_identity_before_real_restoration(self):
        session = host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())
        session.install = Mock()
        session.command = Mock(return_value=host.SHORT_COMPONENT)
        session.observed_identity = Mock(return_value=IDENTITY)
        original = dict(zip(host.SETTINGS, (None, "0", "0")))
        session.settings = Mock(return_value=original)
        session.put = Mock(side_effect=[None, host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT"), None, None, None])
        session.state = Mock(return_value=EMPTY)
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session):
            with self.assertRaisesRegex(host.AccessibilityError, "EMULATOR_COMMAND_TIMEOUT"):
                host.run_scenarios(Mock(), [], [], evidence)
        self.assertEqual(evidence["scenario_failure_stage"], "enable_accessibility")
        self.assertTrue(evidence["secure_settings_restored"])
        self.assertEqual(evidence["service_diagnostics"]["installed_identity"], IDENTITY)
        self.assertEqual(evidence["service_diagnostics"]["stage"], "restored")
        self.assertEqual(evidence["service_diagnostics"]["waits"]["restore_original_service"]["outcome"], "target_reached")
        self.assertEqual([call.args for call in session.put.call_args_list],
                         [(host.SETTINGS[0], host.COMPONENT), (host.SETTINGS[1], "1"), *original.items()])

    def test_setup_wait_and_restore_wait_keep_separate_final_observations(self):
        session = host.TalkBackSession(Mock(), clock=Mock(side_effect=[0, 21, 22]), sleep=Mock())
        session.install = Mock()
        session.command = Mock(return_value=host.SHORT_COMPONENT)
        session.observed_identity = Mock(return_value=IDENTITY)
        original = dict(zip(host.SETTINGS, (None, "0", "0")))
        session.settings = Mock(return_value=original)
        session.put = Mock()
        session.state = Mock(return_value=EMPTY)
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session):
            with self.assertRaisesRegex(host.AccessibilityError, "A11Y_SERVICE_WAIT_TIMEOUT"):
                host.run_scenarios(Mock(), [], [], evidence)
        self.assertEqual(evidence["scenario_failure_stage"], "setup_service_readiness")
        waits = evidence["service_diagnostics"]["waits"]
        self.assertEqual(waits["setup_service_readiness"]["outcome"], "timeout")
        self.assertEqual(waits["restore_original_service"]["outcome"], "target_reached")
        self.assertEqual(evidence["scenarios"], [])
        self.assertTrue(evidence["secure_settings_restored"])

    def test_identity_failure_does_not_invent_validated_identity(self):
        session = host.TalkBackSession(Mock())
        session.install = Mock()
        session.command = Mock(return_value=host.SHORT_COMPONENT)
        session.observed_identity = Mock(side_effect=host.AccessibilityError("A11Y_VERSION_INVALID"))
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session):
            with self.assertRaisesRegex(host.AccessibilityError, "A11Y_VERSION_INVALID"):
                host.run_scenarios(Mock(), [], [], evidence)
        self.assertEqual(evidence["scenario_failure_stage"], "installed_identity")
        self.assertIsNone(evidence["service_diagnostics"]["installed_identity"])
        self.assertTrue(evidence["secure_settings_restored"])

    def test_restoration_failure_does_not_erase_setup_body_stage(self):
        session = host.TalkBackSession(Mock())
        session.install = Mock()
        session.command = Mock(return_value=host.SHORT_COMPONENT)
        session.observed_identity = Mock(return_value=IDENTITY)
        session.settings = Mock(return_value=dict(zip(host.SETTINGS, (None, "0", "0"))))
        session.state = Mock(return_value=EMPTY)
        session.put = Mock(side_effect=host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT"))
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session):
            with self.assertRaisesRegex(host.AccessibilityError, "EMULATOR_COMMAND_TIMEOUT"):
                host.run_scenarios(Mock(), [], [], evidence)
        self.assertEqual(evidence["scenario_failure_stage"], "enable_service")
        self.assertEqual(evidence["restoration_failure_stage"], "restore_service_setting")
        self.assertFalse(evidence["secure_settings_restored"])

    def test_diagnostic_formatting_failure_cannot_skip_actual_restoration(self):
        session = host.TalkBackSession(Mock())
        session.install = Mock(side_effect=host.AccessibilityError("A11Y_INSTALL_FAILED"))
        original_restore = session.restore
        session.restore = Mock(side_effect=original_restore)
        evidence = {"scenarios": []}
        with patch.object(host, "TalkBackSession", return_value=session), patch.object(host.json, "dumps", side_effect=ValueError("PRIVATE_CANARY")):
            with self.assertRaisesRegex(host.AccessibilityError, "A11Y_INSTALL_FAILED"):
                host.run_scenarios(Mock(), [], [], evidence)
        session.restore.assert_called_once()
        self.assertTrue(evidence["secure_settings_restored"])
        self.assertEqual(evidence["service_diagnostics"], {"schema": 2, "code": "A11Y_DIAGNOSTICS_UNAVAILABLE"})
        self.assertNotIn("PRIVATE", str(evidence))

    def test_diagnostic_overflow_and_invalid_shape_use_fixed_markers(self):
        session = host.TalkBackSession(Mock())
        with patch.object(host.json, "dumps", return_value="x" * 4097):
            self.assertEqual(host.diagnostic_snapshot(session), {"schema": 2, "code": "A11Y_DIAGNOSTICS_BOUND"})
        for identity in ({**IDENTITY, "raw": "PRIVATE_CANARY"}, {**IDENTITY, "android_api": True}):
            session.installed_identity = identity
            self.assertEqual(host.diagnostic_snapshot(session), {"schema": 2, "code": "A11Y_DIAGNOSTICS_UNAVAILABLE"})
        session.installed_identity = None
        session.wait_observations["private_stage"] = "PRIVATE_CANARY"
        self.assertNotIn("PRIVATE", json.dumps(host.diagnostic_snapshot(session)))


class TimeoutContextTests(unittest.TestCase):
    guard = call("shell", "am", "get-current-user", timeout=5, maximum=64)
    accessibility = call("shell", "dumpsys", "accessibility", timeout=5)
    binding = call("shell", "dumpsys", "activity", "services", host.COMPONENT, timeout=5, maximum=131072)

    def session(self):
        return host.TalkBackSession(Mock(), clock=Mock(return_value=0), sleep=Mock())

    def test_exact_failing_boundary_keeps_one_previous_state_and_same_exception(self):
        empty = dump_state(enabled=False, bound=False, touch=False)
        for index, label in enumerate(("current_user_guard", "accessibility_dump", "current_user_guard", "talkback_binding_dump")):
            with self.subTest(boundary=index):
                session = self.session()
                error = host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT")
                session.emulator.command.side_effect = ["0", empty, *["0", dump_state(), "0"][:index], error]
                with self.assertRaises(host.AccessibilityError) as caught:
                    session.wait_state(BOUND)
                self.assertIs(caught.exception, error)
                self.assertEqual(session.emulator.command.call_args_list,
                                 [self.guard, self.accessibility, *[self.guard, self.accessibility, self.guard, self.binding][:index + 1]])
                session.sleep.assert_called_once_with(0.25)
                self.assertEqual(session.clock.call_count, 2)
                snapshot = host.diagnostic_snapshot(session)
                self.assertEqual(snapshot["schema"], 2)
                wait = snapshot["waits"]["setup_service_readiness"]
                self.assertEqual((wait["attempts"], wait["budget_seconds"], wait["outcome"]), (2, 20, "fatal_error"))
                self.assertEqual(wait["last_observation"]["guarded_operation"], label)
                self.assertEqual(wait["last_observation"]["code"], "EMULATOR_COMMAND_TIMEOUT")
                self.assertEqual(wait["previous_observation"]["state"], EMPTY)
                session.wait_observations["setup_service_readiness"]["previous_observation"]["state"]["bound_count"] = 1
                session.wait_observations["setup_service_readiness"]["previous_observation"]["bound_structure"]["event_fields"] = 2
                self.assertEqual(wait["previous_observation"]["state"], EMPTY)
                self.assertEqual(wait["previous_observation"]["bound_structure"]["event_fields"], 0)

    def test_timeout_keeps_latest_retryable_error_instead_of_earlier_state(self):
        session = self.session()
        error = host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT")
        session.emulator.command.side_effect = ["0", dump_state(enabled=False, bound=False, touch=False),
            "0", dump_state(binding="{" + host.SHORT_COMPONENT + "}"), "0", error]
        with self.assertRaises(host.AccessibilityError) as caught:
            session.wait_state(BOUND)
        self.assertIs(caught.exception, error)
        wait = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]
        self.assertEqual(wait["previous_observation"], {"kind": "retryable_error", "code": "A11Y_SERVICE_NOT_STABLE"})
        self.assertEqual(wait["last_observation"]["guarded_operation"], "accessibility_dump")
        self.assertEqual(session.sleep.call_args_list, [call(0.25), call(0.25)])
        self.assertEqual(session.emulator.command.call_count, 6)

    def test_first_failure_has_no_previous_and_current_user_denial_skips_dump(self):
        for reply in (host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT"), "10"):
            with self.subTest(timeout=isinstance(reply, Exception)):
                session = self.session()
                session.emulator.command.side_effect = [reply]
                with self.assertRaises(host.AccessibilityError) as caught:
                    session.wait_state(BOUND)
                if isinstance(reply, Exception):
                    self.assertIs(caught.exception, reply)
                wait = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]
                self.assertIsNone(wait["previous_observation"])
                self.assertEqual(wait["last_observation"]["guarded_operation"], "current_user_guard")
                self.assertEqual(session.emulator.command.call_args_list, [self.guard])
                session.sleep.assert_not_called()

    def test_identity_precheck_failure_labels_guarded_call_without_claiming_payload_ran(self):
        emulator = object.__new__(host.base.OwnedEmulator)
        error = host.AccessibilityError("EMULATOR_TRANSPORT_CHANGED")
        emulator.identity = Mock(side_effect=[None, error])
        emulator.tools = SimpleNamespace(adb="synthetic-adb")
        emulator.target = {"transport": "1"}
        session = host.TalkBackSession(emulator, clock=Mock(return_value=0), sleep=Mock())
        with patch.object(host.base, "run_bounded", return_value="0") as payload:
            with self.assertRaises(host.AccessibilityError) as caught:
                session.wait_state(BOUND)
        self.assertIs(caught.exception, error)
        payload.assert_called_once_with(["synthetic-adb", "-t", "1", "shell", "am", "get-current-user"],
                                        stdin=None, timeout=5, maximum=64)
        self.assertEqual(emulator.identity.call_count, 2)
        observation = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]["last_observation"]
        self.assertEqual(observation["guarded_operation"], "accessibility_dump")

    def test_parser_failure_does_not_inherit_a_previous_attempt_or_command_label(self):
        for first in (dump_state(binding="{" + host.SHORT_COMPONENT + "}"),
                      host.AccessibilityError("A11Y_SERVICE_NOT_STABLE")):
            with self.subTest(command_failed=isinstance(first, Exception)):
                session = self.session()
                session.failed_guarded_operation = "talkback_binding_dump"
                session.emulator.command.side_effect = ["0", first, "0", "invalid"]
                with self.assertRaisesRegex(host.AccessibilityError, "A11Y_USER_STATE_INVALID"):
                    session.wait_state(BOUND)
                wait = host.diagnostic_snapshot(session)["waits"]["setup_service_readiness"]
                self.assertEqual(wait["last_observation"], {"kind": "fatal_error", "code": "A11Y_USER_STATE_INVALID"})
                self.assertEqual(wait["previous_observation"]["code"], "A11Y_SERVICE_NOT_STABLE")
                self.assertEqual(session.emulator.command.call_count, 4)

    def test_later_success_for_same_phase_discards_fatal_context_and_history(self):
        session = self.session()
        session.emulator.command.side_effect = ["0", dump_state(enabled=False, bound=False, touch=False),
            "0", host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT"), "0", dump_state(), "0", dump_activity()]
        with self.assertRaises(host.AccessibilityError):
            session.wait_state(BOUND)
        failed = host.diagnostic_snapshot(session)
        session.wait_state(BOUND)
        successful = host.diagnostic_snapshot(session)
        wait = successful["waits"]["setup_service_readiness"]
        self.assertEqual(wait["outcome"], "target_reached")
        self.assertEqual(wait["attempts"], 1)
        self.assertIsNone(wait["previous_observation"])
        self.assertNotIn("guarded_operation", json.dumps(successful))
        self.assertNotIn("EMULATOR_COMMAND_TIMEOUT", json.dumps(successful))
        self.assertEqual(failed["waits"]["setup_service_readiness"]["outcome"], "fatal_error")
        self.assertEqual(session.emulator.command.call_args_list,
                         [self.guard, self.accessibility, self.guard, self.accessibility,
                          self.guard, self.accessibility, self.guard, self.binding])

    def test_only_exact_authored_argument_tuples_get_specific_labels(self):
        cases = ((('shell', 'am', 'get-current-user'), "current_user_guard"),
                 (('shell', 'dumpsys', 'accessibility'), "accessibility_dump"),
                 (('shell', 'dumpsys', 'activity', 'services', host.COMPONENT), "talkback_binding_dump"),
                 (('shell', 'dumpsys', 'activity', 'services', host.SHORT_COMPONENT), "other"),
                 (('shell', 'dumpsys', 'accessibility', 'PRIVATE_CANARY'), "other"),
                 (('PRIVATE_CANARY',), "other"))
        self.assertEqual(host.GUARDED_OPERATIONS, {"current_user_guard", "accessibility_dump", "talkback_binding_dump", "other"})
        for parts, expected in cases:
            with self.subTest(label=expected):
                session = self.session()
                error = ValueError("PRIVATE_CANARY")
                session.emulator.command.side_effect = ["0", error]
                session.state = lambda: session.command(*parts)
                with self.assertRaises(ValueError) as caught:
                    session.wait_state(BOUND)
                self.assertIs(caught.exception, error)
                snapshot = host.diagnostic_snapshot(session)
                last = snapshot["waits"]["setup_service_readiness"]["last_observation"]
                self.assertEqual(last, {"kind": "fatal_error", "code": "A11Y_DIAGNOSTIC_OTHER", "guarded_operation": expected})
                self.assertNotIn("PRIVATE", json.dumps(snapshot))

    def test_actual_restore_success_or_failure_cannot_overwrite_setup_context(self):
        for fail_restore in (False, True):
            with self.subTest(fail_restore=fail_restore):
                session = self.session()
                error = host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT")
                restore_error = host.AccessibilityError("EMULATOR_TRANSPORT_CHANGED")
                session.install = Mock()
                session.original = dict(zip(host.SETTINGS, (None, "0", "0")))
                session.original_state = dict(EMPTY)
                session.mutated = True
                session.setup = lambda: session.wait_state(BOUND)
                session.settings = Mock(return_value=dict(session.original))
                session.put = Mock()
                empty = dump_state(enabled=False, bound=False, touch=False)
                # setup state, setup timeout, restore force-stop, restore state, final state
                session.emulator.command.side_effect = ["0", empty, "0", error, "0", "", "0",
                    restore_error if fail_restore else empty, "0", empty]
                evidence = {"scenarios": []}
                with patch.object(host, "TalkBackSession", return_value=session):
                    with self.assertRaises(host.AccessibilityError) as caught:
                        host.run_scenarios(Mock(), [], [], evidence)
                self.assertIs(caught.exception, restore_error if fail_restore else error)
                waits = evidence["service_diagnostics"]["waits"]
                self.assertEqual(waits["setup_service_readiness"]["last_observation"],
                    {"kind": "fatal_error", "code": "EMULATOR_COMMAND_TIMEOUT", "guarded_operation": "accessibility_dump"})
                self.assertEqual(waits["setup_service_readiness"]["previous_observation"]["state"], EMPTY)
                self.assertIsNone(waits["restore_original_service"]["previous_observation"])
                self.assertEqual(evidence["secure_settings_restored"], not fail_restore)
                self.assertEqual(evidence["scenarios"], [])

    def test_invalid_context_is_rejected_with_fixed_marker(self):
        valid_last = {"kind": "fatal_error", "code": "EMULATOR_COMMAND_TIMEOUT", "guarded_operation": "accessibility_dump"}
        valid_previous = {"kind": "parsed_state", "state": dict(EMPTY)}
        base_wait = {"budget_seconds": 20, "attempts": 2, "outcome": "fatal_error",
                     "last_observation": valid_last, "previous_observation": valid_previous}
        malformed = [
            {"last_observation": {**valid_last, "guarded_operation": label}}
            for label in ("PRIVATE_CANARY", "ACCESSIBILITY_DUMP", True, None, [], {"raw": "PRIVATE_CANARY"})
        ] + [
            {"last_observation": {**valid_last, "code": "PRIVATE_CANARY"}},
            {"last_observation": {**valid_last, "raw": "PRIVATE_CANARY"}},
            {"previous_observation": {**valid_previous, "raw": "PRIVATE_CANARY"}},
            {"previous_observation": {**valid_previous, "state": {**EMPTY, "bound_count": True}}},
            {"previous_observation": {**valid_previous, "state": {**EMPTY, "enabled_component": "PRIVATE_CANARY"}}},
            {"previous_observation": {**valid_previous, "guarded_operation": "other"}},
            {"previous_observation": {**valid_previous, "bound_structure": {"schema": 1}}},
            {"previous_observation": {"kind": "retryable_error", "code": "EMULATOR_COMMAND_TIMEOUT"}},
            {"previous_observation": valid_last}, {"previous_observation": [valid_previous]},
            {"previous_observation": {**valid_previous, "previous_observation": valid_previous}},
            {"attempts": 1}, {"attempts": True}, {"outcome": "target_reached"},
            {"last_observation": None}, {"extra": "PRIVATE_CANARY"},
        ]
        for change in malformed:
            with self.subTest(fields=tuple(change)):
                session = self.session()
                session.wait_observations["setup_service_readiness"] = {**base_wait, **change}
                self.assertEqual(host.diagnostic_snapshot(session), {"schema": 2, "code": "A11Y_DIAGNOSTICS_UNAVAILABLE"})

    def test_malformed_previous_cannot_replace_original_exception_or_escape_sanitization(self):
        session = self.session()
        error = host.AccessibilityError("EMULATOR_COMMAND_TIMEOUT")
        def state():
            if session.wait_observations["setup_service_readiness"]["attempts"] == 1:
                return {**EMPTY, "raw": "PRIVATE_CANARY"}
            raise error
        session.state = state
        with self.assertRaises(host.AccessibilityError) as caught:
            session.wait_state(BOUND)
        self.assertIs(caught.exception, error)
        self.assertEqual(host.diagnostic_snapshot(session), {"schema": 2, "code": "A11Y_DIAGNOSTICS_UNAVAILABLE"})
        self.assertNotIn("PRIVATE", str(session.wait_observations))


class OuterCleanupTests(unittest.TestCase):
    def test_restore_failure_still_exits_owned_emulator_and_retains_failed_result(self):
        self.exercise_cleanup("restore")

    def test_inherited_preserve_hook_import_failure_is_fixed_failed_cleanup(self):
        self.exercise_cleanup("import")

    def exercise_cleanup(self, failure):
        emulator = MagicMock()
        emulator.evidence = {}
        emulator.__enter__.return_value = emulator
        parent, run, result = MagicMock(), MagicMock(), MagicMock()
        result.relative_to.return_value = "owned/result.json"
        stream = MagicMock()
        result.open.return_value.__enter__.return_value = stream
        lease_context = MagicMock()
        lease_context.__enter__.return_value = Mock(spec=["assert_owned"])
        def scenarios(_emulator, _artifacts, _hashes, evidence):
            evidence["secure_settings_restored"] = failure != "restore"
            if failure == "restore":
                raise host.AccessibilityError("A11Y_RESTORE_MISMATCH")
        original_exit = host.base.OwnedEmulator.__exit__
        def stop(*_args):
            if failure == "restore":
                emulator.evidence.update(owned_emulator_stopped=True, owned_emulator_ports_closed=True)
                return False
            # Exercise the real unchanged base except branch, including import failure.
            emulator.owner = Mock()
            emulator.owner.close.side_effect = OSError("PRIVATE_CANARY")
            import builtins
            actual_import = builtins.__import__
            def guarded_import(name, *args, **kwargs):
                if name == "tests.browser_runner":
                    raise ImportError("PRIVATE_CANARY")
                return actual_import(name, *args, **kwargs)
            with patch("builtins.__import__", side_effect=guarded_import):
                original_exit(emulator)
        emulator.__exit__.side_effect = stop
        with patch.object(host.os, "name", "nt"), patch.object(host.shutil, "disk_usage", return_value=SimpleNamespace(free=20 * 1024**3)), \
                patch.object(host.base, "AndroidTools"), patch.object(host.base, "verify_artifacts", return_value=(("app", "test"), {})), \
                patch.object(host.base, "checked_path", side_effect=[parent, run, result]), \
                patch.object(host.base, "digest", return_value="hash"), patch.object(host, "RunLease", return_value=lease_context), \
                patch.object(host.base, "OwnedEmulator", return_value=emulator), patch.object(host, "run_scenarios", side_effect=scenarios), \
                patch.object(host.base.integration, "MobileHarness") as database, patch("builtins.print"):
            with self.assertRaises((host.AccessibilityError, ImportError)):
                host.execute("app", "hash", "test", "hash")
            database.assert_not_called()
        emulator.__exit__.assert_called_once()
        captured = json.loads("".join(call.args[0] for call in stream.write.call_args_list))
        self.assertFalse(captured["ok"])
        self.assertFalse(captured["database_started"])
        self.assertNotIn("PRIVATE_CANARY", str(captured))
        if failure == "import":
            self.assertEqual(captured["code"], "A11Y_RUN_FAILED")
            self.assertEqual(captured["cleanup_failure_code"], "A11Y_OWNED_CLEANUP_UNCERTAIN")
            self.assertFalse(captured["emulator"]["owned_emulator_stopped"])
            self.assertFalse(captured["emulator"]["owned_emulator_ports_closed"])
        else:
            self.assertEqual(captured["code"], "A11Y_RESTORE_MISMATCH")
            self.assertFalse(captured["secure_settings_restored"])


if __name__ == "__main__":
    unittest.main()

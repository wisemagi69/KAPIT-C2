"""Pure denial/coherence tests; no device, server, build or database access."""
from contextlib import ExitStack
import io
import json
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import MagicMock, patch

from infra import mobile_network_diagnostic as host

RUN = "a" * 32
PRIVATE = "PRIVATE_CANARY_TOKEN_CONTENT"


def owner_mock():
    return MagicMock(spec=["assert_owned"])


def row(seq, route="CHALLENGE", status=200):
    return {"seq": seq, "route": route, "stage": "RESPONSE_BODY", "terminal": "END", "io": "NONE", "errno": "NONE", "status": status}


def record(success=True):
    value = {"schema": 1, "run": RUN, "completed": True, "enrollment_succeeded": success,
             "failure_kind": "NONE" if success else "NETWORK", "failed_at": "NONE" if success else "AUTHENTICATE",
             "policies": {key: True for key in host.POLICIES}, "overflow": False,
             "teardown": {key: True for key in host.TEARDOWN}, "requests": [row(1), row(2, "TOKEN")]}
    if not success:
        value["requests"] = [{**row(1), "stage": "CONNECT", "terminal": "FAIL", "io": "CONNECT", "errno": "ECONNREFUSED", "status": 0}]
    return value


def native(passed=True):
    result = ""
    for code in (1, 0 if passed else -2):
        for key, value in (("class", host.TEST_CLASS), ("test", host.METHOD), ("current", "1"), ("numtests", "1")):
            result += f"INSTRUMENTATION_STATUS: {key}={value}\n"
        if code == -2:
            result += "INSTRUMENTATION_STATUS: stack=java.lang.AssertionError: ENROLLMENT_TRANSPORT_DIAGNOSTIC_FAILED\n"
        result += f"INSTRUMENTATION_STATUS_CODE: {code}\n"
    return result + ("OK (1 test)\n" if passed else "FAILURES!!!\n") + "INSTRUMENTATION_CODE: -1\n"


def parse(value):
    return host.validate_record(host.parse_record(json.dumps(value), RUN))


class RecordTests(unittest.TestCase):
    def denied(self, value):
        with self.assertRaises(host.Error):
            parse(value)

    def test_all_complete_routes_have_real_success_prerequisites(self):
        for sequence in host.ROUTES:
            with self.subTest(sequence=sequence):
                value = record()
                value["requests"] = [row(index, route, 409 if route == "TOKEN" and index < len(sequence) else 200)
                                     for index, route in enumerate(sequence, 1)]
                self.assertEqual(parse(value), value)

    def test_network_connect_refusal_is_failed_diagnostic_record(self):
        value = parse(record(False))
        self.assertEqual(value["failure_kind"], "NETWORK")
        self.assertEqual(value["requests"][0]["errno"], "ECONNREFUSED")

    def test_http200_decode_and_store_failure_are_allowed(self):
        for kind in ("INVALID_RESPONSE", "STORE"):
            value = record()
            value.update(enrollment_succeeded=False, failure_kind=kind, failed_at="AUTHENTICATE")
            self.assertEqual(parse(value)["failure_kind"], kind)

    def test_outer_budget_is_distinct_from_timeout(self):
        value = record(False)
        value["failure_kind"] = "OUTER_BUDGET"
        value["requests"][0].update(terminal="NONE", io="NONE", errno="NONE")
        self.assertEqual(parse(value)["failure_kind"], "OUTER_BUDGET")
        value["failure_kind"] = "TIMEOUT"
        self.assertEqual(parse(value)["failure_kind"], "TIMEOUT")

    def test_cancellation_can_retain_io_observed_before_call_failed(self):
        for kind in ("OUTER_BUDGET", "CANCELLED"):
            value = record(False)
            value["failure_kind"] = kind
            value["requests"][0]["terminal"] = "NONE"
            result = parse(value)
            self.assertEqual(result["requests"][0]["io"], "CONNECT")
            self.assertEqual(result["requests"][0]["errno"], "ECONNREFUSED")

    def test_precheck_storage_and_cancellation_are_not_transport_failures(self):
        for kind in ("STORE", "CANCELLED"):
            value = record(False)
            value.update(failure_kind=kind, failed_at="PRECHECK", requests=[])
            self.assertEqual(parse(value)["failed_at"], "PRECHECK")
        value = record(False)
        value.update(failure_kind="NETWORK", failed_at="PRECHECK", requests=[])
        self.denied(value)

    def test_failed_policy_query_defaults_are_unverified_precheck(self):
        value = record(False)
        value.update(failure_kind="OTHER", failed_at="PRECHECK", requests=[])
        value["policies"] = {key: False for key in host.POLICIES}
        self.assertEqual(parse(value)["failure_kind"], "OTHER")
        for kind in ("STORE", "CANCELLED"):
            value["failure_kind"] = kind
            self.denied(value)

    def test_terminal_end_without_http_response_is_impossible(self):
        value = record(False)
        value["requests"][0].update(terminal="END", io="NONE", errno="NONE", stage="CONNECT", status=0)
        self.denied(value)

    def test_zero_request_auth_failure_and_policy_precheck(self):
        value = record(False)
        value["requests"] = []
        self.assertEqual(parse(value)["requests"], [])
        value.update(failed_at="PRECHECK", failure_kind="UNAVAILABLE")
        value["policies"]["internet_permission"] = False
        self.assertFalse(parse(value)["policies"]["internet_permission"])

    def test_later_teardown_does_not_erase_original_failure(self):
        value = record(False)
        value["teardown"]["runtime_closed"] = False
        self.assertEqual(parse(value)["failure_kind"], "NETWORK")
        value = record()
        value.update(failure_kind="OTHER", failed_at="TEARDOWN")
        value["teardown"]["runtime_closed"] = False
        self.assertTrue(parse(value)["enrollment_succeeded"])

    def test_bound_ascii_truncated_and_stale_run(self):
        for raw in ("", " " * 2049, "\u00e9", json.dumps(record())[:-1], json.dumps(record()).replace(RUN, "b" * 32)):
            with self.subTest(raw_length=len(raw)), self.assertRaises(host.Error):
                host.parse_record(raw, RUN)

    def test_duplicate_keys_are_rejected_at_every_depth(self):
        for raw in (json.dumps(record()).replace('"schema": 1', '"schema": 1, "schema": 1'),
                    json.dumps(record()).replace('"seq": 1', '"seq": 1, "seq": 1'),
                    json.dumps(record()).replace('"client_closed": true', '"client_closed": true, "client_closed": true')):
            with self.assertRaises(host.Error):
                host.parse_record(raw, RUN)

    def test_unknown_keys_and_private_enum_canaries_rejected(self):
        for path in (("private",), ("requests", 0, "private"), ("policies", "private"), ("teardown", "private"),
                     ("failure_kind",), ("failed_at",), ("requests", 0, "route"), ("requests", 0, "stage"),
                     ("requests", 0, "io"), ("requests", 0, "errno"), ("requests", 0, "terminal")):
            value = record()
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = PRIVATE
            with self.subTest(path=path):
                self.denied(value)

    def test_integer_boolean_confusion(self):
        for path in (("schema",), ("requests", 0, "seq"), ("requests", 0, "status")):
            value = record()
            target = value
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = True
            self.denied(value)
        for key in ("completed", "enrollment_succeeded", "overflow"):
            value = record()
            value[key] = 1
            self.denied(value)
        for key in ("policies", "teardown"):
            value = record()
            value[key][next(iter(value[key]))] = 1
            self.denied(value)

    def test_count_sequence_route_and_status_bounds(self):
        for change in (lambda v: v["requests"].append(row(3, "TOKEN")),
                       lambda v: v["requests"].extend([row(3)] * 4),
                       lambda v: v["requests"][0].update(seq=0),
                       lambda v: v["requests"][0].update(route="TOKEN"),
                       lambda v: v["requests"][0].update(status=99),
                       lambda v: v["requests"][0].update(status=600)):
            value = record()
            change(value)
            self.denied(value)

    def test_overflow_and_other_route_are_finite_but_never_accepted(self):
        for change in (lambda v: v.update(overflow=True), lambda v: v["requests"][0].update(route="OTHER")):
            value = record(False)
            change(value)
            self.assertEqual(host.parse_record(json.dumps(value), RUN), value)
            self.denied(value)

    def test_impossible_progress_and_io_combinations(self):
        for changes in ({"terminal": "FAIL", "io": "NONE"}, {"terminal": "END", "io": "CONNECT"},
                        {"terminal": "NONE", "io": "CONNECT"}, {"errno": "EPERM", "io": "NONE"},
                        {"stage": "CONNECT", "status": 200}, {"stage": "RESPONSE_BODY", "status": 0}):
            value = record(False)
            value["requests"][0].update(changes)
            self.denied(value)

    def test_all_nonfinal_rows_require_actual_success_even_failed_chain(self):
        for route, status in ((["CHALLENGE", "TOKEN"], 401), (["CHALLENGE", "TOKEN"], 0),
                              (["CHALLENGE", "TOKEN", "CHALLENGE"], 200)):
            value = record(False)
            value["requests"] = [row(index, name) for index, name in enumerate(route, 1)]
            value["requests"][-2]["status"] = status
            self.denied(value)
        value = record(False)
        value["requests"].append(row(2, "TOKEN"))
        self.denied(value)

    def test_completion_failure_stage_and_success_contradictions(self):
        changes = ({"completed": False}, {"enrollment_succeeded": False}, {"failure_kind": "NETWORK"},
                   {"failure_kind": "NETWORK", "failed_at": "VALIDATION"},
                   {"failure_kind": "OTHER", "failed_at": "PRECHECK"},
                   {"failure_kind": "OTHER", "failed_at": "TEARDOWN"})
        for change in changes:
            value = record()
            value.update(change)
            self.denied(value)
        value = record(False)
        value.update(failed_at="VALIDATION", failure_kind="OTHER")
        self.denied(value)

    def test_policy_denial_cannot_coexist_with_requests_or_success(self):
        for success in (True, False):
            value = record(success)
            value["policies"]["cleartext_loopback"] = False
            self.denied(value)


class NativeTests(unittest.TestCase):
    def test_exact_single_pass_and_failure(self):
        for passed in (True, False):
            value = host.native_result(native(passed))
            self.assertEqual(value["passed"], passed)
            self.assertEqual(value["method_completed_count"], 1)
            host.validate_native_record(value, parse(record(passed)))

    def test_wrong_class_method_counts_duplicates_and_missing_completion(self):
        raw = native()
        for changed in (raw.replace(host.TEST_CLASS, host.base.TEST_CLASS), raw.replace(host.METHOD, "enrollAndQueue"),
                        raw.replace("numtests=1", "numtests=2"), raw.replace("current=1", "current=2"),
                        raw.replace("class=" + host.TEST_CLASS, "class=" + host.TEST_CLASS + "\nINSTRUMENTATION_STATUS: class=" + host.TEST_CLASS, 1),
                        raw.replace("INSTRUMENTATION_CODE: -1", ""), raw + "INSTRUMENTATION_CODE: -1\n",
                        raw + "INSTRUMENTATION_STATUS: test=" + host.METHOD + "\n"):
            with self.subTest(length=len(changed)):
                result = host.native_result(changed)
                self.assertFalse(result["passed"])
                self.assertEqual(result["method_completed_count"], 0)

    def test_error_or_marker_cannot_enable_passing_status(self):
        for error in ("FAILURES", "INSTRUMENTATION_FAILED", "shortMsg=" + PRIVATE,
                      "java.lang.AssertionError: " + PRIVATE, "ENROLLMENT_TRANSPORT_DIAGNOSTIC_FAILED"):
            value = host.native_result(native() + error + "\n")
            self.assertFalse(value["passed"])
            self.assertNotIn(PRIVATE, json.dumps(value))

    def test_failed_method_never_promoted_by_success_metadata(self):
        with self.assertRaises(host.Error):
            host.validate_native_record(host.native_result(native(False)), record())
        with self.assertRaises(host.Error):
            host.validate_native_record(host.native_result(native()), record(False))

    def test_failed_record_requires_fixed_failure_marker(self):
        result = host.native_result(native(False).replace("ENROLLMENT_TRANSPORT_DIAGNOSTIC_FAILED", PRIVATE))
        with self.assertRaises(host.Error):
            host.validate_native_record(result, record(False))
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_terminal_order_and_marker_trailing_content_cannot_validate(self):
        raw = native().replace("INSTRUMENTATION_CODE: -1\n", "")
        result = host.native_result("INSTRUMENTATION_CODE: -1\n" + raw)
        self.assertEqual(result["outcome"], "incomplete")
        raw = native(False).replace("ENROLLMENT_TRANSPORT_DIAGNOSTIC_FAILED", "ENROLLMENT_TRANSPORT_DIAGNOSTIC_FAILED " + PRIVATE)
        result = host.native_result(raw)
        with self.assertRaises(host.Error):
            host.validate_native_record(result, record(False))
        self.assertNotIn(PRIVATE, json.dumps(result))

    def test_passing_status_with_failed_record_cannot_validate(self):
        result = host.native_result(native(False).replace("INSTRUMENTATION_STATUS_CODE: -2", "INSTRUMENTATION_STATUS_CODE: 0"))
        with self.assertRaises(host.Error):
            host.validate_native_record(result, record(False))

    def test_partial_native_tail_never_credits_completion(self):
        for raw in (native().rstrip("\n"), native() + "INSTRUMENTATION_STATUS: clas",
                    native() + "INSTRUMENTATION_STATUS: clas\n", native() + "INSTRUMENTATION_STATUS_CODE: "):
            result = host.native_result(raw)
            self.assertFalse(result["passed"])
            self.assertEqual(result["method_completed_count"], 0)


class CommandTests(unittest.TestCase):
    def emulator(self):
        emulator = object.__new__(host.NetworkEmulator)
        emulator.command = MagicMock()
        return emulator

    def test_only_exact_instrumentation_with_validated_nonce(self):
        emulator = self.emulator()
        emulator.command.return_value = native()
        self.assertTrue(emulator.invoke(RUN)["passed"])
        emulator.command.assert_called_once_with("shell", "am", "instrument", "-w", "-r", "-e", "class",
            host.TEST_CLASS + "#" + host.METHOD, "-e", "ownedEmulator", "true", "-e", "diagnosticRun", RUN,
            host.base.TEST_PACKAGE + "/" + host.base.RUNNER, timeout=180)
        emulator.command.reset_mock()
        for invalid in (";" + RUN, RUN + "\n", PRIVATE, None):
            with self.assertRaises(host.Error):
                emulator.invoke(invalid)
        emulator.command.assert_not_called()

    def test_fixed_stdin_marker_guards_and_2049_bound(self):
        emulator = self.emulator()
        emulator.command.return_value = "absent"
        emulator.marker_absent()
        args, kwargs = emulator.command.call_args
        self.assertEqual(args, ("shell", "run-as", host.base.PACKAGE, "--user", "0", "sh"))
        for suffix in ("", ".new", ".bak"):
            self.assertIn(f"test ! -e {host.MARKER}{suffix}\n", kwargs["stdin"].decode())
            self.assertIn(f"test ! -L {host.MARKER}{suffix}\n", kwargs["stdin"].decode())
        emulator.read_record()
        args, kwargs = emulator.command.call_args
        self.assertEqual(kwargs["timeout"], 5)
        self.assertEqual(kwargs["maximum"], 2049)
        self.assertIn(f"head -c 2049 {host.MARKER}\n", kwargs["stdin"].decode())
        self.assertNotIn("-c", args)

    def test_health_checks_exact_reverse_and_http_without_retaining_bodies(self):
        emulator, owner, evidence = self.emulator(), owner_mock(), {}
        emulator.command.return_value = "(reverse) tcp:18082 tcp:18082\n"
        with patch.object(host.base.integration, "Client") as client:
            client.return_value.request.side_effect = [(200, {"mode": "normal", "private": PRIVATE}), (401, {"private": PRIVATE})]
            host.observe_health(emulator, owner, evidence)
            self.assertEqual(client.return_value.request.call_args_list[0].args, (host.base.integration.STATE_PATH,))
            self.assertEqual(client.return_value.request.call_args_list[1].args, ("/api/v1/mobile/me/",))
        emulator.command.assert_called_once_with("reverse", "--list", timeout=5, maximum=4096)
        self.assertEqual(evidence, {"held_api_and_listener_owned": True, "reverse_count": 1, "reverse_exact": True,
                                   "state_status": 200, "normal_mode": True, "me_status": 401, "complete": True})
        self.assertNotIn(PRIVATE, json.dumps(evidence))

    def test_lost_ownership_prevents_device_and_http(self):
        emulator, owner = self.emulator(), owner_mock()
        owner.assert_owned.side_effect = RuntimeError(PRIVATE)
        with patch.object(host.base.integration, "Client") as client, self.assertRaises(RuntimeError):
            host.observe_health(emulator, owner, {})
        emulator.command.assert_not_called()
        client.assert_not_called()

    def test_reverse_mismatch_never_repaired_and_no_http(self):
        emulator = self.emulator()
        for raw in ("\n", "(reverse) tcp:18082 tcp:18083\n", "(reverse) tcp:18082 tcp:18082\n(reverse) tcp:1234 tcp:1234\n"):
            emulator.command.reset_mock()
            emulator.command.return_value = raw
            with patch.object(host.base.integration, "Client") as client, self.assertRaises(host.Error):
                host.observe_health(emulator, owner_mock(), {})
            self.assertEqual(emulator.command.call_count, 1)
            client.assert_not_called()

    def test_unready_http_remains_partial_observation(self):
        emulator = self.emulator()
        emulator.command.return_value = "(reverse) tcp:18082 tcp:18082\n"
        for responses in ([(503, {})], [(200, {"mode": "offline"})], [(200, {"mode": "normal"}), (200, {})]):
            evidence = {}
            with patch.object(host.base.integration, "Client") as client, self.assertRaises(host.Error):
                client.return_value.request.side_effect = responses
                host.observe_health(emulator, owner_mock(), evidence)
            self.assertNotIn("complete", evidence)


class FlowTests(unittest.TestCase):
    def setup_flow(self, passed):
        emulator = MagicMock()
        emulator.invoke.return_value = host.native_result(native(passed))
        emulator.read_record.return_value = json.dumps(record(passed))
        return emulator, owner_mock(), {}

    @staticmethod
    def health(emulator, owner, evidence):
        evidence["complete"] = True

    def run_flow(self, passed):
        emulator, owner, evidence = self.setup_flow(passed)
        with patch.object(host, "observe_health", side_effect=self.health), patch.object(host, "observe_counts",
                side_effect=[host.expected_counts(False), host.expected_counts(passed)]):
            if passed:
                host.run_diagnostic(emulator, owner, RUN, evidence)
            else:
                with self.assertRaises(host.Error):
                    host.run_diagnostic(emulator, owner, RUN, evidence)
        emulator.invoke.assert_called_once_with(RUN)
        emulator.read_record.assert_called_once_with()
        return evidence

    def test_single_real_native_pass_requires_independent_effects(self):
        evidence = self.run_flow(True)
        self.assertTrue(evidence["enrollment_accepted"])
        self.assertTrue(evidence["diagnostic_collected"])

    def test_useful_failed_native_record_is_not_enrollment_pass(self):
        evidence = self.run_flow(False)
        self.assertTrue(evidence["diagnostic_collected"])
        self.assertFalse(evidence["enrollment_accepted"])
        self.assertEqual(evidence["native"]["outcome"], "failed")

    def test_native_failure_survives_metadata_health_and_count_failures(self):
        emulator, owner, evidence = self.setup_flow(False)
        emulator.read_record.side_effect = RuntimeError(PRIVATE)
        with patch.object(host, "observe_health", side_effect=[None, RuntimeError(PRIVATE)]), patch.object(host, "observe_counts",
                side_effect=[host.expected_counts(False), RuntimeError(PRIVATE)]), self.assertRaises(host.Error):
            host.run_diagnostic(emulator, owner, RUN, evidence)
        self.assertEqual(evidence["native"]["outcome"], "failed")
        for key in ("record_failure", "after_health_failure", "after_counts_failure"):
            self.assertIn(key, evidence)
        self.assertNotIn(PRIVATE, json.dumps(evidence))
        emulator.invoke.assert_called_once()

    def test_native_timeout_still_attempts_final_evidence_without_retry(self):
        emulator, owner, evidence = self.setup_flow(False)
        emulator.invoke.side_effect = TimeoutError(PRIVATE)
        with patch.object(host, "observe_health", side_effect=self.health), patch.object(host, "observe_counts",
                side_effect=[host.expected_counts(False), host.expected_counts(False)]), self.assertRaises(host.Error):
            host.run_diagnostic(emulator, owner, RUN, evidence)
        self.assertEqual(evidence["native_invocation_failure"]["exception_class"], "TimeoutError")
        self.assertIn("record", evidence)
        self.assertIn("record_validation_failure", evidence)
        self.assertNotIn(PRIVATE, json.dumps(evidence))
        emulator.invoke.assert_called_once()

    def test_unrecognized_metadata_canary_never_enters_evidence(self):
        emulator, owner, evidence = self.setup_flow(False)
        emulator.read_record.return_value = json.dumps({**record(False), "private": PRIVATE})
        with patch.object(host, "observe_health", side_effect=self.health), patch.object(host, "observe_counts",
                side_effect=[host.expected_counts(False), host.expected_counts(False)]), self.assertRaises(host.Error):
            host.run_diagnostic(emulator, owner, RUN, evidence)
        self.assertNotIn("record", evidence)
        self.assertEqual(evidence["record_failure"]["code"], "NETWORK_RECORD_FIELDS")
        self.assertEqual(evidence["native"]["outcome"], "failed")
        self.assertNotIn(PRIVATE, json.dumps(evidence))

    def test_before_failure_or_existing_effects_prevent_native(self):
        for existing in (False, True):
            emulator, owner, evidence = self.setup_flow(True)
            with patch.object(host, "observe_health", side_effect=None if existing else RuntimeError(PRIVATE)), patch.object(host, "observe_counts",
                    return_value=host.expected_counts(True)), self.assertRaises((RuntimeError, host.Error)):
                host.run_diagnostic(emulator, owner, RUN, evidence)
            emulator.invoke.assert_not_called()

    def test_failed_post_health_and_wrong_server_effects_prevent_pass(self):
        for counts in (host.expected_counts(False), {**host.expected_counts(True), "reports": 1}):
            emulator, owner, evidence = self.setup_flow(True)
            with patch.object(host, "observe_health", side_effect=self.health), patch.object(host, "observe_counts",
                    side_effect=[host.expected_counts(False), counts]), self.assertRaises(host.Error):
                host.run_diagnostic(emulator, owner, RUN, evidence)
            self.assertFalse(evidence["enrollment_accepted"])
            self.assertTrue(evidence["native"]["passed"])

    def test_lost_owner_after_native_prevents_all_further_observations(self):
        emulator, owner, evidence = self.setup_flow(False)
        owner.assert_owned.side_effect = RuntimeError(PRIVATE)
        with patch.object(host, "observe_health", side_effect=self.health) as health, patch.object(host, "observe_counts",
                return_value=host.expected_counts(False)) as counts, self.assertRaises(host.Error):
            host.run_diagnostic(emulator, owner, RUN, evidence)
        emulator.read_record.assert_not_called()
        self.assertEqual(health.call_count, 1)
        self.assertEqual(counts.call_count, 1)


class SourceAndOwnershipTests(unittest.TestCase):
    def test_fixed_error_codes_only_and_no_private_or_unknown_text(self):
        self.assertEqual(host.failure(host.Error("NETWORK_RECORD_OWNER"), "record")["code"], "NETWORK_RECORD_OWNER")
        for error in (host.Error(PRIVATE), host.Error("NETWORK_" + PRIVATE),
                      host.Error("NETWORK_RECORD_OWNER " + PRIVATE), RuntimeError("NETWORK_RECORD_OWNER"),
                      host.Error("NETWORK_RECORD_OWNER", PRIVATE)):
            evidence = host.failure(error, "record")
            self.assertNotIn("code", evidence)
            self.assertNotIn(PRIVATE, json.dumps(evidence))

    def test_runlease_specialization_preserves_inherited_guards(self):
        self.assertIs(host.RunOwnership.__enter__, host.RunLease.__enter__)
        self.assertIs(host.RunOwnership.assert_owned, host.RunLease.assert_owned)
        self.assertIs(host.RunOwnership.__exit__, host.RunLease.__exit__)
        with patch.object(host.base, "checked_path", side_effect=lambda path: path):
            lease = host.RunOwnership(host.ROOT / ".cache/m1-runtime/mobile-network" / ("a" * 24))
            self.assertIsNone(lease.file)
            for path in (host.ROOT / ".cache/m1-runtime/mobile-accessibility" / ("a" * 24),
                         host.ROOT / ".cache/m1-runtime/mobile-network" / "not-a-run"):
                with self.assertRaises(host.Error):
                    host.RunOwnership(path)

    def test_composite_ownership_checks_lease_before_harness(self):
        lease, harness = owner_mock(), owner_mock()
        lease.assert_owned.side_effect = RuntimeError(PRIVATE)
        with self.assertRaises(RuntimeError):
            host.CombinedOwnership(lease, harness).assert_owned()
        harness.assert_owned.assert_not_called()

    def test_changed_or_unfrozen_sources_fail_before_tools(self):
        with patch.object(host, "FROZEN", {"known": None}), patch.object(host.base, "digest") as digest:
            with self.assertRaises(host.Error):
                host.verify_sources()
        with patch.object(host, "verify_sources", side_effect=host.Error("NETWORK_SOURCE_CHANGED")), patch.object(host.base, "AndroidTools") as tools, patch.object(host.base, "observed_harness") as harness:
            with self.assertRaises(host.Error):
                host.execute("app", "a" * 64, "test", "b" * 64)
            tools.assert_not_called()
            harness.assert_not_called()
            digest.assert_not_called()
        with patch.object(host, "FROZEN", {"known": "a" * 64}), patch.object(host.base, "digest", return_value="b" * 64):
            with self.assertRaises(host.Error):
                host.verify_sources()

    def test_disk_gate_precedes_android_or_harness(self):
        with patch.object(host, "verify_sources", return_value={}), patch.object(host.shutil, "disk_usage", return_value=SimpleNamespace(free=12 * 1024**3 - 1)), patch.object(host.base, "AndroidTools") as tools, patch.object(host.base, "observed_harness") as harness:
            with self.assertRaises(host.Error):
                host.execute("app", "a" * 64, "test", "b" * 64)
        tools.assert_not_called()
        harness.assert_not_called()

    def test_source_unchanged_is_false_when_missing_or_changed(self):
        with patch.object(host.base, "digest", side_effect=OSError(PRIVATE)):
            self.assertFalse(host.unchanged({"known": "a" * 64}))
        with patch.object(host.base, "digest", return_value="b" * 64):
            self.assertFalse(host.unchanged({"known": "a" * 64}))

    def test_postflight_requires_every_cleanup_and_input_identity(self):
        for missing in (None, "database_cleanup_passed", "owned_emulator_stopped", "owned_emulator_ports_closed"):
            evidence = {"ok": True, "database_cleanup_passed": True,
                        "emulator": {"owned_emulator_stopped": True, "owned_emulator_ports_closed": True}}
            if missing == "database_cleanup_passed":
                evidence[missing] = False
            elif missing:
                evidence["emulator"][missing] = False
            with patch.object(host, "unchanged", return_value=True), patch.object(host.base, "digest", return_value="a" * 64):
                host.final_guards(evidence, {}, {}, ("app", "test"), ("a" * 64, "a" * 64))
            self.assertEqual(evidence["ok"], missing is None)
        for values in ((False, True), (True, False)):
            evidence = {"ok": True, "database_cleanup_passed": True,
                        "emulator": {"owned_emulator_stopped": True, "owned_emulator_ports_closed": True}}
            with patch.object(host, "unchanged", side_effect=values), patch.object(host.base, "digest", return_value="a" * 64):
                host.final_guards(evidence, {}, {}, ("app", "test"), ("a" * 64, "a" * 64))
            self.assertFalse(evidence["ok"])
        evidence["ok"] = True
        with patch.object(host, "unchanged", return_value=True), patch.object(host.base, "digest", side_effect=["a" * 64, "b" * 64]):
            host.final_guards(evidence, {}, {}, ("app", "test"), ("a" * 64, "a" * 64))
        self.assertFalse(evidence["artifacts_unchanged"])
        self.assertFalse(evidence["ok"])


class LifecycleTests(unittest.TestCase):
    def execute_mocked(self, body_failure=False, emulator_failure=False, database_failure=False, boot_failure=False):
        """Exercise actual execute + inherited observed_harness with no real side effects."""
        events, captured = [], {}
        parent, run, result = MagicMock(), MagicMock(), MagicMock()
        run.name = "a" * 24
        run.__truediv__.return_value = result
        result.relative_to.return_value = ".cache/m1-runtime/mobile-network/fake/result.json"
        stream = MagicMock()
        result.open.return_value.__enter__.return_value = stream
        stream.write.side_effect = lambda raw: captured.update(json.loads(raw))
        lease = owner_mock()
        lease_context = MagicMock()
        lease_context.__enter__.return_value = lease
        harness = MagicMock(spec=["__enter__", "__exit__", "assert_owned"])
        harness.__enter__.return_value = harness
        emulator = MagicMock()
        emulator.evidence = {}

        def enter_emulator():
            events.append("emulator_enter")
            if boot_failure:
                raise RuntimeError(PRIVATE)
            return emulator

        def close_emulator(*args):
            events.append("emulator_close")
            emulator.evidence.update(owned_emulator_stopped=not emulator_failure, owned_emulator_ports_closed=not emulator_failure)
            if emulator_failure:
                raise RuntimeError(PRIVATE)
            return False

        def close_harness(*args):
            events.append("harness_close")
            if database_failure:
                raise RuntimeError(PRIVATE)
            return False

        def body(emulator, owner, nonce, evidence):
            events.append("native")
            evidence["native"] = host.native_result(native(not body_failure))
            if body_failure:
                raise host.Error("NETWORK_ENROLLMENT_NOT_ACCEPTED")

        emulator.__enter__.side_effect = enter_emulator
        emulator.__exit__.side_effect = close_emulator
        harness.__exit__.side_effect = close_harness
        with ExitStack() as stack:
            for target, name, value in ((host, "verify_sources", {}), (host.shutil, "disk_usage", SimpleNamespace(free=20 * 1024**3)),
                                        (host.base, "digest", "a" * 64), (host.base, "AndroidTools", MagicMock()),
                                        (host.base, "verify_artifacts", (("app", "test"), {})),
                                        (host, "RunOwnership", lease_context), (host.base.integration, "MobileHarness", harness),
                                        (host, "NetworkEmulator", emulator)):
                stack.enter_context(patch.object(target, name, return_value=value))
            stack.enter_context(patch.object(host.base, "checked_path", side_effect=[parent, run, result]))
            stack.enter_context(patch.object(host, "run_diagnostic", side_effect=body))
            stack.enter_context(patch("sys.stdout", new=io.StringIO()))
            if any((body_failure, emulator_failure, database_failure, boot_failure)):
                with self.assertRaises((RuntimeError, host.Error)):
                    host.execute("app", "a" * 64, "test", "a" * 64)
            else:
                host.execute("app", "a" * 64, "test", "a" * 64)
        self.assertNotIn(PRIVATE, json.dumps(captured))
        return events, captured

    def test_emulator_closes_before_database_on_success(self):
        events, evidence = self.execute_mocked()
        self.assertEqual(events, ["emulator_enter", "native", "emulator_close", "harness_close"])
        self.assertTrue(evidence["ok"])
        self.assertTrue(evidence["cleanup_verified"])

    def test_native_failure_survives_both_cleanup_failures(self):
        events, evidence = self.execute_mocked(body_failure=True, emulator_failure=True, database_failure=True)
        self.assertEqual(events[-2:], ["emulator_close", "harness_close"])
        self.assertFalse(evidence["native"]["passed"])
        self.assertFalse(evidence["ok"])
        self.assertFalse(evidence["cleanup_verified"])
        self.assertIn("cleanup_failure", evidence)

    def test_boot_failure_cannot_claim_emulator_cleanup(self):
        events, evidence = self.execute_mocked(boot_failure=True)
        self.assertEqual(events, ["emulator_enter", "harness_close"])
        self.assertNotIn("native", evidence)
        self.assertTrue(evidence["database_cleanup_passed"])
        self.assertFalse(evidence["cleanup_verified"])


if __name__ == "__main__":
    unittest.main()

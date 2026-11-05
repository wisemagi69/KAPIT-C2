"""Guard behavior with fake command results; never claims real phone execution."""
import hashlib
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

from infra import mobile_device as device

TARGET = {"serial": "synthetic-usb", "state": "device", "transport": "7"}


class ParseTests(unittest.TestCase):
    def test_inventory_classifies_without_exposing_serials(self):
        parsed = device.parse_devices("List of devices attached\nsynthetic-usb device product:synthetic transport_id:7\n"
            "emulator-5568 device transport_id:8\n192.0.2.1:5555 device transport_id:9\n"
            "locked unauthorized transport_id:10\n")
        self.assertEqual(device.physical_candidates(parsed), [TARGET])

    def test_discovery_refuses_ambiguous_transport(self):
        for raw in ["bad", "List of devices attached\nphone device\n",
                    "List of devices attached\na device transport_id:1\nb device transport_id:1\n",
                    "List of devices attached\na device transport_id:1 transport_id:2\n"]:
            with self.assertRaises(device.DeviceError):
                device.parse_devices(raw)

    def test_reverse_map_parser_preserves_other_mappings_and_refuses_duplicates(self):
        self.assertEqual(device.parse_reverse("usb tcp:18082 tcp:18082\nusb tcp:9999 tcp:8888\n"),
                         {"tcp:18082": "tcp:18082", "tcp:9999": "tcp:8888"})
        for raw in ["usb tcp:1", "usb tcp:1 tcp:2\nusb tcp:1 tcp:3"]:
            with self.assertRaises(device.DeviceError):
                device.parse_reverse(raw)

    def test_reverse_empty_lf_crlf_and_blank_separators_are_empty_maps(self):
        for raw in ("", "\n", "\r\n", "\n\r\n", " \t\r\n\t\n"):
            with self.subTest(raw=repr(raw)):
                self.assertEqual(device.parse_reverse(raw), {})

    def test_reverse_terminal_blank_and_separated_mapping_rows_preserve_all_entries(self):
        for ending in ("\n", "\r\n"):
            raw = ending + "usb tcp:18082 tcp:18082" + ending * 2 + " \t" + ending
            raw += "usb tcp:9999 tcp:8888" + ending * 2
            with self.subTest(ending=repr(ending)):
                self.assertEqual(device.parse_reverse(raw),
                                 {"tcp:18082": "tcp:18082", "tcp:9999": "tcp:8888"})

    def test_reverse_blanks_do_not_hide_bad_rows_or_duplicate_mappings(self):
        for raw in ("\nusb\n\n", "\r\nusb tcp:1\r\n\r\n", "\nusb tcp:1 tcp:2 extra\n\n",
                    "\nusb tcp:1 tcp:2\n\nusb tcp:1 tcp:2\n\n",
                    "\r\nusb tcp:1 tcp:2\r\n \t\r\nusb tcp:1 tcp:3\r\n\r\n"):
            with self.subTest(raw=repr(raw)), self.assertRaisesRegex(device.DeviceError, "DEVICE_REVERSE_UNCERTAIN"):
                device.parse_reverse(raw)

    def test_environment_does_not_inherit_target_server_or_java_injection(self):
        with patch.dict(device.os.environ, {"ADB_SERVER_SOCKET": "remote", "ANDROID_SERIAL": "other",
                "JAVA_TOOL_OPTIONS": "-javaagent:bad", "PATH": "retained"}, clear=True):
            self.assertEqual(device.safe_environment(), {"PATH": "retained"})


class SessionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.apk = Path(self.temp.name) / "fixture.apk"
        self.apk.write_bytes(b"synthetic apk bytes")
        self.digest = hashlib.sha256(self.apk.read_bytes()).hexdigest()
        self.tools, self.harness = Mock(), Mock()
        self.harness.assert_owned = Mock()
        self.tools.discover.return_value = [TARGET.copy()]
        self.tools.verify_apk.return_value = (self.apk, {"apk_sha256": self.digest})
        self.installed, self.mapping = False, None
        self.tools.command.side_effect = self.command

    def command(self, target, *parts, **kwargs):
        if parts == ("get-devpath",): return "usb:synthetic"
        if parts == ("shell", "getprop", "ro.kernel.qemu"): return "0"
        if parts == ("shell", "getprop", "ro.build.version.sdk"): return "35"
        if parts == ("shell", "am", "get-current-user"): return "0"
        if parts == ("shell", "pm", "list", "users"): return "Users:\n UserInfo{0:Owner:c13} running\n"
        if parts[:4] == ("shell", "pm", "list", "packages"):
            return "package:" + device.PACKAGE if self.installed else ""
        if parts == ("reverse", "--list"):
            return "usb tcp:18082 " + self.mapping + "\n\n" if self.mapping else "\n"
        if parts[:1] == ("install",):
            self.installed = True
            return "Success\n"
        if parts == ("reverse", "--no-rebind", device.ENDPOINT, device.ENDPOINT):
            self.mapping = device.ENDPOINT
            return ""
        if parts == ("reverse", "--remove", device.ENDPOINT):
            self.mapping = None
            return ""
        self.fail("Unexpected test command")

    def session(self):
        return device.PhysicalSession(self.tools, self.harness, self.apk, self.digest)

    def mutations(self):
        return [call.args[1:] for call in self.tools.command.call_args_list
                if call.args[1] == "install" or (call.args[1] == "reverse" and call.args[2] != "--list")]

    def test_new_fixture_install_and_only_owned_reverse_removed(self):
        with self.session() as session:
            self.assertTrue(session.evidence["installed_new_isolated_package"])
            self.assertFalse(session.evidence["mobile_workflow_verified"])
            self.assertEqual(self.mapping, device.ENDPOINT)
        self.assertTrue(self.installed)
        self.assertIsNone(self.mapping)
        self.assertEqual(self.mutations(), [("install", "--user", "0", str(self.apk)),
            ("reverse", "--no-rebind", device.ENDPOINT, device.ENDPOINT),
            ("reverse", "--remove", device.ENDPOINT)])

    def test_existing_package_refused_without_any_mutation(self):
        self.installed = True
        with self.assertRaisesRegex(device.DeviceError, "DEVICE_PACKAGE_PREEXISTING"):
            self.session().__enter__()
        self.assertEqual(self.mutations(), [])

    def test_existing_reverse_refused_before_install(self):
        for mapping in (device.ENDPOINT, "tcp:7777"):
            self.mapping = mapping
            with self.subTest(mapping=mapping), self.assertRaisesRegex(device.DeviceError, "DEVICE_REVERSE_PREEXISTING"):
                self.session().__enter__()
        self.assertEqual(self.mutations(), [])

    def test_blank_separators_preserve_unrelated_map_through_owned_cleanup(self):
        original = self.command
        def with_unrelated(target, *parts, **kwargs):
            result = original(target, *parts, **kwargs)
            return result + "\nusb tcp:9999 tcp:8888\n\n" if parts == ("reverse", "--list") else result
        self.tools.command.side_effect = with_unrelated
        with self.session():
            self.assertEqual(self.mapping, device.ENDPOINT)
        self.assertIsNone(self.mapping)
        self.assertEqual(device.parse_reverse(with_unrelated(TARGET, "reverse", "--list")), {"tcp:9999": "tcp:8888"})
        self.assertEqual(self.mutations(), [("install", "--user", "0", str(self.apk)),
            ("reverse", "--no-rebind", device.ENDPOINT, device.ENDPOINT),
            ("reverse", "--remove", device.ENDPOINT)])

    def test_blank_separated_bad_or_duplicate_rows_refuse_before_mutation(self):
        original = self.command
        for raw in ("\nusb tcp:1\n\n", "usb tcp:1 tcp:2\n\nusb tcp:1 tcp:3\n\n"):
            self.tools.command.side_effect = lambda target, *parts, **kwargs: (
                raw if parts == ("reverse", "--list") else original(target, *parts, **kwargs))
            with self.assertRaisesRegex(device.DeviceError, "DEVICE_REVERSE_UNCERTAIN"):
                self.session().__enter__()
        self.assertEqual(self.mutations(), [])

    def test_no_phone_or_multiple_phones_refused_without_mutation(self):
        for targets in [[], [TARGET, {**TARGET, "transport": "8"}]]:
            self.tools.discover.return_value = targets
            with self.assertRaisesRegex(device.DeviceError, "DEVICE_PHYSICAL_TARGET_UNAVAILABLE"):
                self.session().__enter__()
        self.assertEqual(self.mutations(), [])

    def test_emulator_cannot_be_adopted(self):
        self.tools.discover.return_value = [{**TARGET, "serial": "emulator-5568"}]
        with self.assertRaisesRegex(device.DeviceError, "DEVICE_PHYSICAL_TARGET_UNAVAILABLE"):
            self.session().__enter__()
        self.assertEqual(self.mutations(), [])

    def test_transport_reconnection_preserves_tunnel_and_package(self):
        session = self.session().__enter__()
        self.tools.discover.return_value = [{**TARGET, "transport": "8"}]
        with self.assertRaisesRegex(device.DeviceError, "DEVICE_CONNECTION_CHANGED"):
            session.__exit__(None, None, None)
        self.assertEqual(self.mapping, device.ENDPOINT)
        self.assertTrue(self.installed)
        self.assertNotIn(("reverse", "--remove", device.ENDPOINT), self.mutations())

    def test_replaced_reverse_is_not_removed(self):
        session = self.session().__enter__()
        self.mapping = "tcp:9999"
        with self.assertRaisesRegex(device.DeviceError, "DEVICE_CLEANUP_UNCERTAIN_RETAINED"):
            session.__exit__(None, None, None)
        self.assertEqual(self.mapping, "tcp:9999")
        self.assertNotIn(("reverse", "--remove", device.ENDPOINT), self.mutations())

    def test_harness_lost_denies_all_device_mutation(self):
        self.harness.assert_owned.side_effect = RuntimeError("safe ownership error")
        with self.assertRaises(RuntimeError):
            self.session().__enter__()
        self.assertEqual(self.mutations(), [])

    def test_changed_apk_retains_installed_package_and_does_not_forward(self):
        original = self.command
        def alter(target, *parts, **kwargs):
            result = original(target, *parts, **kwargs)
            if parts[:1] == ("install",): self.apk.write_bytes(b"changed")
            return result
        self.tools.command.side_effect = alter
        with self.assertRaisesRegex(device.DeviceError, "DEVICE_APK_CHANGED"):
            self.session().__enter__()
        self.assertTrue(self.installed)
        self.assertIsNone(self.mapping)

    def test_failed_signature_verification_cannot_install(self):
        self.tools.verify_apk.side_effect = device.DeviceError("DEVICE_APK_SIGNATURE_DENIED")
        with self.assertRaises(device.DeviceError):
            self.session().__enter__()
        self.assertEqual(self.mutations(), [])

    def test_multiple_users_refused_before_install(self):
        original = self.command
        self.tools.command.side_effect = lambda target, *parts, **kwargs: (
            "Users:\n UserInfo{0:Owner:c13}\n UserInfo{10:Work:30}\n"
            if parts == ("shell", "pm", "list", "users") else original(target, *parts, **kwargs))
        with self.assertRaisesRegex(device.DeviceError, "DEVICE_MULTIPLE_USERS_UNSUPPORTED"):
            self.session().__enter__()
        self.assertEqual(self.mutations(), [])


class ApkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.apk = self.root / "android/fixture.apk"
        self.apk.parent.mkdir()
        self.apk.write_bytes(b"synthetic fixture")
        for path in ["sdk/platform-tools/adb.exe", "sdk/build-tools/36.1.0/aapt2.exe",
                     "sdk/build-tools/36.1.0/lib/apksigner.jar", "java/bin/java.exe"]:
            file = self.root / path
            file.parent.mkdir(parents=True, exist_ok=True)
            file.touch()
        self.tools = device.AndroidTools(self.root / "sdk", self.root / "java")
        self.hash = hashlib.sha256(self.apk.read_bytes()).hexdigest()
        self.badging = "package: name='org.kapit.c2.mobile.spike' versionCode='1'\ntargetSdkVersion:'36'\napplication-debuggable\n"
        self.signed = "Verified using v2 scheme (APK Signature Scheme v2): true\nSigner #1 certificate SHA-256 digest: " + "a" * 64 + "\n"
        self.root_patch = patch.object(device, "ROOT", self.root)
        self.root_patch.start()
        self.addCleanup(self.root_patch.stop)

    def test_exact_isolated_identity_hash_target_and_signature(self):
        self.tools.run = Mock(side_effect=[self.badging, self.signed])
        path, evidence = self.tools.verify_apk(self.apk, self.hash)
        self.assertEqual(path, self.apk)
        self.assertEqual(evidence["package"], device.PACKAGE)
        self.assertEqual(evidence["apk_sha256"], self.hash)

    def test_demo_release_wrong_target_and_invalid_signature_denied(self):
        for badging, signed in [(self.badging.replace(".spike", ".demo"), self.signed),
                               (self.badging.replace("application-debuggable", ""), self.signed),
                               (self.badging.replace("'36'", "'34'"), self.signed),
                               (self.badging, self.signed.replace("true", "false"))]:
            self.tools.run = Mock(side_effect=[badging, signed])
            with self.assertRaises(device.DeviceError):
                self.tools.verify_apk(self.apk, self.hash)

    def test_wrong_hash_and_external_path_denied_before_tools(self):
        self.tools.run = Mock()
        for path, digest in [(self.apk, "0" * 64), (self.root / "other.apk", self.hash)]:
            with self.assertRaises(device.DeviceError):
                self.tools.verify_apk(path, digest)
        self.tools.run.assert_not_called()


if __name__ == "__main__":
    unittest.main()

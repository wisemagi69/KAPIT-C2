"""Bounded physical USB attachment for the separately owned M2 test runtime.

Inventory is read-only. Installation is available only through an in-process
MobileHarness owner. The isolated spike package is retained, never reset or
automatically removed; a later run refuses that pre-existing package.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[1]
PACKAGE = "org.kapit.c2.mobile.spike"
ENDPOINT = "tcp:18082"


class DeviceError(RuntimeError):
    """Only fixed error codes leave this boundary."""


def require(value, code):
    if not value:
        raise DeviceError(code)


def parse_devices(raw):
    lines = raw.splitlines()
    require(lines and lines[0].strip() == "List of devices attached", "DEVICE_DISCOVERY_INVALID")
    devices = []
    for line in lines[1:]:
        if not line.strip():
            continue
        fields = line.split()
        require(len(fields) >= 2, "DEVICE_DISCOVERY_INVALID")
        attributes = {}
        for field in fields[2:]:
            if ":" in field:
                name, value = field.split(":", 1)
                require(name not in attributes, "DEVICE_DISCOVERY_INVALID")
                attributes[name] = value
        transport = attributes.get("transport_id", "")
        require(transport.isascii() and transport.isdecimal() and int(transport) > 0,
                "DEVICE_DISCOVERY_INVALID")
        devices.append({"serial": fields[0], "state": fields[1], "transport": transport})
    require(len({item["transport"] for item in devices}) == len(devices), "DEVICE_DISCOVERY_INVALID")
    return devices


def physical_candidates(devices):
    # A physical USB identity is additionally checked with get-devpath and the
    # device's emulator property before any package or tunnel mutation.
    return [item for item in devices if item["state"] == "device"
            and not item["serial"].startswith("emulator-") and ":" not in item["serial"]
            and not item["serial"].endswith("._adb-tls-connect._tcp")]


def parse_reverse(raw):
    mappings = {}
    for line in raw.splitlines():
        parts = line.split()
        if not parts:
            continue
        require(len(parts) == 3, "DEVICE_REVERSE_UNCERTAIN")
        _, remote, local = parts
        require(remote not in mappings, "DEVICE_REVERSE_UNCERTAIN")
        mappings[remote] = local
    return mappings


def safe_environment():
    # Preserve tool locations, but remove ADB server/target overrides and JVM
    # injection. No system-wide environment or shared ADB server is changed.
    env = dict(os.environ)
    for name in list(env):
        if name.upper().startswith("ADB_") or name.upper() in {
                "ANDROID_SERIAL", "ANDROID_ADB_SERVER_PORT", "JAVA_TOOL_OPTIONS",
                "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH"}:
            env.pop(name)
    return env


class AndroidTools:
    def __init__(self, sdk=None, java=None):
        self.sdk = Path(sdk or os.environ.get("KAPIT_ANDROID_SDK",
                        str(Path(os.environ.get("LOCALAPPDATA", "")) / "Android/Sdk"))).resolve()
        self.java = Path(java or os.environ.get("KAPIT_JAVA_HOME",
                         r"C:\Program Files\Android\Android Studio\jbr")).resolve()
        self.adb = self.sdk / "platform-tools/adb.exe"
        require(self.adb.is_file(), "DEVICE_ADB_UNAVAILABLE")

    def run(self, command, timeout=15):
        try:
            result = subprocess.run([str(part) for part in command], cwd=ROOT,
                env=safe_environment(), capture_output=True, text=True, timeout=timeout,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        except (OSError, subprocess.TimeoutExpired, UnicodeError):
            raise DeviceError("DEVICE_COMMAND_UNAVAILABLE") from None
        require(result.returncode == 0 and len(result.stdout) <= 262144 and len(result.stderr) <= 16384,
                "DEVICE_COMMAND_FAILED")
        return result.stdout

    def discover(self):
        return parse_devices(self.run([self.adb, "devices", "-l"]))

    def command(self, target, *parts, timeout=15):
        # Transport IDs pin this specific connection. A reconnection must be a
        # new explicit session; do not fall back to a serial or any device.
        require(target in self.discover(), "DEVICE_CONNECTION_CHANGED")
        return self.run([self.adb, "-t", target["transport"], *parts], timeout)

    def verify_apk(self, path, expected):
        path = Path(path).resolve()
        require(path.is_relative_to((ROOT / "android").resolve()) and path.is_file()
                and path.suffix == ".apk", "DEVICE_APK_PATH_DENIED")
        require(isinstance(expected, str) and re.fullmatch(r"[0-9a-f]{64}", expected), "DEVICE_APK_HASH_INVALID")
        require(hashlib.sha256(path.read_bytes()).hexdigest() == expected, "DEVICE_APK_HASH_MISMATCH")
        build = self.sdk / "build-tools/36.1.0"
        aapt = build / "aapt2.exe"
        signer = build / "lib/apksigner.jar"
        java = self.java / "bin/java.exe"
        require(aapt.is_file() and signer.is_file() and java.is_file(), "DEVICE_APK_TOOLS_UNAVAILABLE")
        badging = self.run([aapt, "dump", "badging", path])
        package = re.findall(r"^package: name='([^']+)'", badging, flags=re.MULTILINE)
        require(package == [PACKAGE] and "application-debuggable" in badging.splitlines(),
                "DEVICE_APK_IDENTITY_DENIED")
        require("targetSdkVersion:'36'" in badging.splitlines(), "DEVICE_APK_TARGET_DENIED")
        signed = self.run([java, "-jar", signer, "verify", "--verbose", "--print-certs", path], timeout=30)
        require("Verified using v2 scheme (APK Signature Scheme v2): true" in signed.splitlines(),
                "DEVICE_APK_SIGNATURE_DENIED")
        certificates = re.findall(r"^Signer #1 certificate SHA-256 digest: ([0-9a-f]{64})$", signed, re.MULTILINE)
        require(len(certificates) == 1 and hashlib.sha256(path.read_bytes()).hexdigest() == expected,
                "DEVICE_APK_CHANGED")
        return path, {"package": PACKAGE, "apk_sha256": expected, "certificate_sha256": certificates[0]}


class PhysicalSession:
    """Only the held harness may install/connect a new isolated fixture app."""
    def __init__(self, tools, harness, apk, expected):
        self.tools, self.harness = tools, harness
        self.apk, self.expected = apk, expected
        self.target = None
        self.tunnel_owned = False
        self.evidence = {}

    def assert_owned(self):
        self.harness.assert_owned()
        require(self.target in self.tools.discover(), "DEVICE_CONNECTION_CHANGED")

    def command(self, *parts, timeout=15):
        self.assert_owned()
        return self.tools.command(self.target, *parts, timeout=timeout)

    def __enter__(self):
        self.harness.assert_owned()
        candidates = physical_candidates(self.tools.discover())
        require(len(candidates) == 1, "DEVICE_PHYSICAL_TARGET_UNAVAILABLE")
        self.target = candidates[0]
        require(self.command("get-devpath").strip().startswith("usb:"), "DEVICE_USB_REQUIRED")
        require(self.command("shell", "getprop", "ro.kernel.qemu").strip() in {"", "0"}, "DEVICE_EMULATOR_DENIED")
        api = self.command("shell", "getprop", "ro.build.version.sdk").strip()
        require(api.isascii() and api.isdecimal() and 35 <= int(api) <= 100, "DEVICE_API_UNSUPPORTED")
        require(self.command("shell", "am", "get-current-user").strip() == "0", "DEVICE_USER_UNSUPPORTED")
        users = self.command("shell", "pm", "list", "users")
        require(re.findall(r"UserInfo\{(\d+):", users) == ["0"], "DEVICE_MULTIPLE_USERS_UNSUPPORTED")
        # Include known uninstalled packages: residual prior data must not be
        # accidentally adopted. A matching prefix is also refused conservatively.
        require(not self.command("shell", "pm", "list", "packages", "-u", PACKAGE).strip(),
                "DEVICE_PACKAGE_PREEXISTING")
        require(ENDPOINT not in parse_reverse(self.command("reverse", "--list")), "DEVICE_REVERSE_PREEXISTING")
        apk, proof = self.tools.verify_apk(self.apk, self.expected)
        # No -r, -d, -g, uninstall, clear or credential/settings commands.
        require("Success" in self.command("install", "--user", "0", str(apk), timeout=120).splitlines(),
                "DEVICE_INSTALL_FAILED_RETAINED")
        installed = self.command("shell", "pm", "list", "packages", "--user", "0", PACKAGE).splitlines()
        require(installed == ["package:" + PACKAGE], "DEVICE_INSTALL_UNCERTAIN_RETAINED")
        require(hashlib.sha256(apk.read_bytes()).hexdigest() == self.expected, "DEVICE_APK_CHANGED")
        try:
            # --no-rebind provides the atomic pre-existing mapping refusal.
            self.command("reverse", "--no-rebind", ENDPOINT, ENDPOINT)
            self.tunnel_owned = True
            require(parse_reverse(self.command("reverse", "--list")).get(ENDPOINT) == ENDPOINT,
                    "DEVICE_REVERSE_UNCERTAIN")
        except BaseException:
            self.__exit__(*sys.exc_info())
            raise
        self.evidence = {"physical_phone": True, "observed_api": int(api), **proof,
            "installed_new_isolated_package": True, "package_retained_on_exit": True,
            "loopback_usb_reverse": True, "mobile_workflow_verified": False}
        return self

    def __exit__(self, *args):
        if self.tunnel_owned:
            # Uncertain connection/mapping ownership leaves it untouched. Never
            # remove-all, reconnect to another transport, or uninstall a package.
            self.assert_owned()
            require(parse_reverse(self.command("reverse", "--list")).get(ENDPOINT) == ENDPOINT,
                    "DEVICE_CLEANUP_UNCERTAIN_RETAINED")
            self.command("reverse", "--remove", ENDPOINT)
            self.tunnel_owned = False
            require(ENDPOINT not in parse_reverse(self.command("reverse", "--list")),
                    "DEVICE_CLEANUP_UNCERTAIN_RETAINED")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("mode", choices=("inventory", "build"), default="inventory", nargs="?")
    args = parser.parse_args()
    try:
        if args.mode == "build":
            # This command still requires the orchestrator's serialized heavy
            # slot. It uses the existing strict wrapper and local tool paths.
            result = subprocess.run([sys.executable, str(ROOT / "android/tools/build.py"),
                ":app:assembleSpikeDebug", "--dependency-verification=strict"], cwd=ROOT,
                env=safe_environment(), check=False)
            require(result.returncode == 0, "DEVICE_BUILD_FAILED")
            apk = ROOT / "android/app/build/outputs/apk/spike/debug/app-spike-debug.apk"
            digest = hashlib.sha256(apk.read_bytes()).hexdigest()
            _, proof = AndroidTools().verify_apk(apk, digest)
            print(json.dumps({"built": True, **proof}))
        else:
            devices = AndroidTools().discover()
            print(json.dumps({"physical_candidates": len(physical_candidates(devices)),
                              "unavailable_targets": sum(item["state"] != "device" for item in devices),
                              "emulators": sum(item["serial"].startswith("emulator-") for item in devices),
                              "mutations": False}))
        return 0
    except Exception as error:
        print(json.dumps({"ok": False, "code": str(error) if isinstance(error, DeviceError) else "DEVICE_HELPER_FAILED"}))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

"""Owned headless emulator acceptance. Never addresses a connected physical phone."""
from pathlib import Path
import argparse
import json
import os
import secrets
import socket
import subprocess
import time
from owned_process import OwnedProcessTree

ROOT = Path(__file__).resolve().parents[1]
PORT = 5568
SERIAL = f"emulator-{PORT}"
PACKAGE = "org.kapit.c2.mobile.spike"


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", default=str(Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk"))
    args = parser.parse_args()
    sdk = Path(args.sdk).resolve()
    image = sdk / "system-images" / "android-36" / "google_apis" / "x86_64"
    if not (image / "system.img").is_file():
        raise SystemExit("Existing API36 Google APIs x86_64 image required")
    app = ROOT / "app/build/outputs/apk/spike/debug/app-spike-debug.apk"
    tests = ROOT / "app/build/outputs/apk/androidTest/spike/debug/app-spike-debug-androidTest.apk"
    if not app.is_file() or not tests.is_file():
        raise SystemExit("Build both isolated spike APKs before running the emulator")
    for port in (PORT, PORT + 1):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    token = secrets.token_hex(6)
    name = f"KapitSpike_{token}"
    avdhome = ROOT / ".tooling" / "avd"
    avdhome.mkdir(parents=True, exist_ok=True)
    avd = avdhome / f"{name}.avd"
    avd.mkdir(exist_ok=False)
    (avdhome / f"{name}.ini").write_text(f"avd.ini.encoding=UTF-8\npath={avd}\ntarget=android-36\n", encoding="utf-8")
    (avd / "config.ini").write_text("\n".join([
        f"AvdId={name}", f"avd.ini.displayname={name}", "avd.ini.encoding=UTF-8",
        f"image.sysdir.1={image}", "abi.type=x86_64", "hw.cpu.arch=x86_64",
        "hw.cpu.ncore=2", "hw.ramSize=2048", "hw.lcd.width=720", "hw.lcd.height=1280",
        "hw.lcd.density=320", "hw.keyboard=yes", "hw.gpu.enabled=yes", "hw.gpu.mode=swiftshader_indirect",
        "disk.dataPartition.size=2147483648", "fastboot.forceColdBoot=yes", "showDeviceFrame=no",
        "tag.id=google_apis", "tag.display=Google APIs", "PlayStore.enabled=false", "target=android-36", "",
    ]), encoding="utf-8")
    env = os.environ.copy()
    env["ANDROID_AVD_HOME"] = str(avdhome)
    env["ANDROID_USER_HOME"] = str(ROOT / ".android-user-home")
    env.pop("ANDROID_SDK_HOME", None)
    log = ROOT / ".tooling" / "emulator-spike.log"
    evidence = {"environment": "owned_headless_emulator", "api": 36, "abi": "x86_64", "physical_phone": False, "gates": []}
    adb = sdk / "platform-tools" / "adb.exe"

    def command(*parts, timeout=60):
        if child.poll() is not None:
            raise RuntimeError("Owned emulator process is no longer running")
        # Bind mutations to the AVD started by this held process, never a phone or another AVD.
        if parts and (parts[0] == "install" or parts[:2] in (("shell", "am"), ("shell", "input"),
                ("shell", "locksettings"), ("shell", "settings"), ("emu", "kill"))):
            identity = subprocess.run([str(adb), "-s", SERIAL, "emu", "avd", "name"],
                capture_output=True, text=True, timeout=10)
            lines = identity.stdout.splitlines()
            if identity.returncode or not lines or lines[0].strip() != name:
                raise RuntimeError("Emulator ownership identity mismatch; no device mutation performed")
        result = subprocess.run([str(adb), "-s", SERIAL, *parts], capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("Owned emulator command failed; no device or credential output copied")
        return result.stdout

    owner = OwnedProcessTree()
    flags = subprocess.CREATE_NO_WINDOW | 0x4  # CREATE_SUSPENDED: attach tree ownership first.
    with log.open("w", encoding="utf-8") as stream:
        child = subprocess.Popen([str(sdk / "emulator" / "emulator.exe"), "-avd", name, "-port", str(PORT),
            "-no-window", "-no-audio", "-no-boot-anim", "-no-snapshot", "-gpu", "swiftshader_indirect",
            "-no-metrics"], env=env, stdout=stream, stderr=subprocess.STDOUT, creationflags=flags)
        try:
            owner.attach_and_resume(child)
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise RuntimeError("Owned emulator exited before boot; inspect local emulator-spike.log")
                try:
                    if command("shell", "getprop", "sys.boot_completed", timeout=10).strip() == "1":
                        break
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                time.sleep(2)
            else:
                raise RuntimeError("Owned emulator boot timed out")
            if command("shell", "getprop", "ro.kernel.qemu").strip() != "1":
                raise RuntimeError("Target is not the owned emulator")
            observed_api = command("shell", "getprop", "ro.build.version.sdk").strip()
            observed_abi = command("shell", "getprop", "ro.product.cpu.abi").strip()
            if observed_api != "36" or observed_abi != "x86_64":
                raise RuntimeError("Owned emulator API/ABI does not match the selected compatibility fixture")
            evidence["observed_api"] = int(observed_api)
            evidence["observed_abi"] = observed_abi
            evidence["observed_android_release"] = command("shell", "getprop", "ro.build.version.release").strip()
            evidence["observed_page_size"] = int(command("shell", "getconf", "PAGESIZE").strip())
            evidence["gates"].append({"gate": "owned_api36_boot", "passed": True})
            print("Owned API36 emulator ready; installing isolated spike APKs", flush=True)
            if command("shell", "pm", "list", "packages", "--user", "0", PACKAGE).strip():
                raise RuntimeError("Existing spike installation refused; no package overwritten")
            for apk in (app, tests):
                if "Success" not in command("install", str(apk), timeout=90):
                    raise RuntimeError("Isolated spike APK installation failed")
            evidence["gates"].append({"gate": "isolated_spike_install", "passed": True})
            output = command("shell", "am", "instrument", "-w", "-e", "class",
                "org.kapit.c2.mobile.StorageCompatibilityTest",
                f"{PACKAGE}.test/androidx.test.runner.AndroidJUnitRunner", timeout=180)
            # Only synthetic instrumentation output; never copy logcat or emulator account/device details.
            (ROOT / ".tooling" / "storage-instrumentation.txt").write_text(output, encoding="utf-8")
            passed = "OK (10 tests)" in output and "FAILURES" not in output and "INSTRUMENTATION_FAILED" not in output
            evidence["gates"].append({"gate": "storage_instrumentation_10", "passed": passed})
            print(f"Storage instrumentation passed={passed}", flush=True)
            if not passed:
                raise RuntimeError("Storage instrumentation failed; inspect local sanitized test output")
            pin = str(secrets.randbelow(900000) + 100000)
            command("shell", "settings", "put", "system", "screen_off_timeout", "180000")
            command("shell", "locksettings", "set-pin", pin)

            def unlock():
                command("shell", "input", "keyevent", "KEYCODE_SLEEP")
                time.sleep(1)
                command("shell", "input", "keyevent", "KEYCODE_WAKEUP")
                time.sleep(1)
                command("shell", "input", "swipe", "360", "1100", "360", "300", "250")
                time.sleep(1)
                command("shell", "input", "text", pin)
                command("shell", "input", "keyevent", "KEYCODE_ENTER")
                time.sleep(2)

            def credential_phase(phase):
                result = command("shell", "am", "instrument", "-w", "-e", "class",
                    "org.kapit.c2.mobile.CredentialKeyCompatibilityTest", "-e", "ownedEmulator", "true",
                    "-e", "phase", phase, f"{PACKAGE}.test/androidx.test.runner.AndroidJUnitRunner", timeout=90)
                (ROOT / ".tooling" / f"credential-{phase}.txt").write_text(result, encoding="utf-8")
                ok = "OK (1 test)" in result and "FAILURES" not in result and "INSTRUMENTATION_FAILED" not in result
                evidence["gates"].append({"gate": f"credential_bound_{phase}", "passed": ok})
                print(f"Credential-bound {phase} passed={ok}", flush=True)
                if not ok:
                    raise RuntimeError(f"Credential-bound {phase} failed; encrypted fixture remains for diagnosis")

            unlock()
            credential_phase("provision")
            command("shell", "input", "keyevent", "KEYCODE_SLEEP")
            time.sleep(2)
            credential_phase("locked")
            unlock()
            credential_phase("unlocked")
            print("Testing actual 60-second credential expiry while emulator remains unlocked", flush=True)
            for step in range(13):
                time.sleep(5)
                if step % 3 == 2:
                    print(f"Credential expiry observation: {(step + 1) * 5}s", flush=True)
            credential_phase("expired")
            unlock()
            credential_phase("reauthenticated")
            command("shell", "locksettings", "clear", "--old", pin)
            pin = None
            credential_phase("invalidated")
        finally:
            # Stop only this held process/tunnel. Do not issue adb kill-server or touch any phone.
            try:
                if child.poll() is None:
                    command("emu", "kill", timeout=15)
                    child.wait(timeout=20)
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            finally:
                owner.close()  # Kills only descendants of the originally suspended child.
                child.wait(timeout=20)
            evidence["owned_emulator_stopped"] = child.poll() is not None
            deadline = time.monotonic() + 10
            closed = False
            while time.monotonic() < deadline:
                closed = True
                for port in (PORT, PORT + 1):
                    with socket.socket() as probe:
                        probe.settimeout(0.5)
                        if probe.connect_ex(("127.0.0.1", port)) == 0:
                            closed = False
                if closed:
                    break
                time.sleep(0.2)
            evidence["owned_emulator_ports_closed"] = closed
            (ROOT / ".tooling" / "emulator-spike-results.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            if not closed:
                raise RuntimeError("Owned emulator ports did not close; no unrelated process will be terminated")


if __name__ == "__main__":
    main()

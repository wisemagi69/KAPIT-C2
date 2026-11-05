"""Actual storage/runtime/keyboard tests on a fresh owned API36 AVD; never selects a phone."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import time
from owned_process import OwnedProcessTree

ROOT = Path(__file__).resolve().parents[1]
PORT = 5568
SERIAL = f"emulator-{PORT}"
READINESS_PROBE = "org.kapit.c2.mobile.security.DeviceReadinessProbe#appSeesEligibleUnlockedDevice"
PACKAGE = "org.kapit.c2.mobile.spike"
METHODS = [
    "submitFreezesExactlyOneOperationAcrossTwentyCommandReplays",
    "failedSubmitRollsBackSnapshotOutboxAndCommandTogether",
    "failedDenialCleanupCannotCloseReplacementAccount",
    "freshWalReaderUsesHandleOwnedKeyAndCloseErasesIt",
    "saveRevisionAndCommandReplayPreventLostUpdates",
    "accountAndEnrollmentIsolationPreserveOriginalQueue",
    "sameBootRestartRestoresButLogoutRemainsDeniedAcrossClose",
    "leaseExpiryAndBootDiscontinuityNeverUseWallClock",
    "contextReassignmentPausesFrozenBytesAndExplicitlyCreatesNewDraft",
    "staleClaimCannotAcknowledgeAndReopenRecoversSameFrozenOperation",
    "persistedClaimTimeoutFencesLateReceiptWithoutChangingBytes",
    "manualRetryCannotBypassPersistedRetryAfter",
    "backgroundInvalidationRollsBackMutationPausedBeforeCommit",
    "changedDeviceEligibilityBeforeCommitRollsBackWithoutWaitingForBroadcast",
    "missingWrappingKeyRetainsCiphertextAndNeverRegenerates",
    "lateFenceCleanupCannotCloseNewAccountAndDetachedCredentialsAreCleared",
    "renewalPreservesGenerationButFencesOldTokensAnchorsAndMonitor",
    "renewalCannotAdoptChangedFamilyOrAuthority",
    "unsupportedTemplateFencesPreviousAuthorityAndPreservesQueue",
    "cacheBoundsAndScopeDenialClearCacheWithoutDeletingQueue",
    "liveDatabaseWalAndMetadataContainNoSourceOrTokenCanary",
    "immutableTriggersAndForwardMigrationPreservePendingBytes",
]
EXTRA_METHODS = {
    "org.kapit.c2.mobile.data.WorkerStoreTest": [
        "workerNeverPublishesReadyAndCloseErasesItsActualHandleAndSecrets",
        "foregroundTakeoverRetiresWorkerWithoutLosingImmutableQueue",
        "exactWorkerDeadlineRollsBackCommitAndErasesCapability",
        "workerBootDiscontinuityClosesHandleAndForbidsFreshAcquisition",
        "workerDeviceChangeAtCommitRollsBackAndClosesHandle",
        "periodicMonitorClosesLeakedWorkerAtDeadlineWithoutCapabilityCall",
        "workerRefreshRotatesPrivatelyAndRenewalDoesNotExtendCapabilityDeadline",
        "workerScopeDenialClearsActualCacheAndRetainsQueueBeforeReauthentication",
        "markerIsCommittedBeforeDispatchAndRestartCannotReuseOldRefresh",
        "exactRefreshRotationCommitsOnceWithoutChangingPublicGeneration",
        "ordinaryRenewalCannotClearCommittedRefreshUncertainty",
        "failedRotationTransactionRetainsMarkerAndOriginalCredentialsAtomically",
        "mismatchedRefreshCapabilityCannotClearMarker",
        "persistedAttemptAndDelayAndConservativeTokenClockSurviveReopen",
        "versionTwoMigrationAddsEmptyMarkerWithoutChangingPendingBytes",
        "schedulingCheckDuringAnotherSessionsLiveRefreshDoesNotDenyAccount",
        "orphanedRefreshMarkerStillRequiresRecoveryOnSchedulingCheck",
        "undispatchedRefreshAbandonKeepsOriginalCredentialsAndLaterUnlock",
        "anotherSessionCannotAbandonRefreshMarker",
    ],
    "org.kapit.c2.mobile.security.EnrollmentJournalTest": [
        "lostIssuanceReusesOwnedKeyAfterRepositoryRestartAndBindsOnlyExactEnrollment",
        "wrongOwnerInstallationKeyAndBoundEnrollmentNeverSign",
        "staleGenerationRevisionAndForeignIssuerCannotMutateJournal",
        "crashAfterDiscoveryReservationFailsClosedWithoutGeneratingRepeatedAliases",
        "interruptedCandidatePersistenceRetainsOneKeyAndRefusesAliasGrowth",
        "interruptedBindingRetainsOwnerAndSameKeyForExplicitRecovery",
        "missingOrCorruptJournalPreservesKeysAndCannotInitializeReplacement",
        "concurrentProofPreparationBindingAndPublicReadCompleteWithoutLockInversion",
    ],
    "org.kapit.c2.mobile.sync.AndroidSchedulingIntegrationTest": [
        "oldChainCancellationCannotCancelReplacementChain",
        "cancelledParentCannotResurrectThroughContinuation",
        "earlierOwnedWakeupReplacesDelayedKeepRequest",
        "coalescedRerunPreservesRunningParentAndUpdatesBlockedSuccessor",
        "continuationReceivesOnlyOpaqueInputAfterParentCompletion",
    ],
    "org.kapit.c2.mobile.ui.MobileKeyboardTest": [
        "signInTabReverseTabAndEnterReachOneAction",
        "imeNextAndDoneFocusErrorsThenClearSubmittedCredentials",
        "offlineAndBusySignInRemainDisabledAndGenerationClearsInput",
        "invalidEditorSubmissionFocusesVisibleFieldAndSupportsReverseTab",
        "keyboardConfirmationRequiresExplicitCommitAndPreventsDuplicateQueue",
        "offlineOutboxKeepsDistinctStatesAndKeyboardSyncHonorsBusyGate",
        "lockAndNewGenerationDiscardRememberedEditorInput",
    ],
}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--sdk", default=str(Path(os.environ["LOCALAPPDATA"]) / "Android" / "Sdk"))
    parser.add_argument("--apk-dir", type=Path, help="Retained baseline directory containing the two isolated APKs")
    subset = parser.add_mutually_exclusive_group()
    subset.add_argument("--production-test", action="append", choices=METHODS, help="Bounded diagnostic subset; never a complete-suite pass")
    subset.add_argument("--screen-lock-only", action="store_true", help="Actual screen-lock gate only; never a complete-suite pass")
    subset.add_argument("--keyboard-only", action="store_true", help="Seven keyboard methods plus actual screen-lock gate; never a complete-suite pass")
    args = parser.parse_args()
    sdk = Path(args.sdk).resolve()
    image = sdk / "system-images/android-36/google_apis/x86_64"
    if not (image / "system.img").is_file():
        raise SystemExit("Existing API36 system image required")
    apks = ([args.apk_dir.resolve() / "app-spike-debug.apk", args.apk_dir.resolve() / "app-spike-debug-androidTest.apk"]
            if args.apk_dir else [ROOT / "app/build/outputs/apk/spike/debug/app-spike-debug.apk",
            ROOT / "app/build/outputs/apk/androidTest/spike/debug/app-spike-debug-androidTest.apk"])
    if not all(path.is_file() for path in apks):
        raise SystemExit("Build isolated spike application and instrumentation APKs first")
    for port in (PORT, PORT + 1):
        with socket.socket() as probe:
            probe.bind(("127.0.0.1", port))
    run = secrets.token_hex(6)
    name = f"KapitStorage_{run}"
    avdhome = ROOT / ".tooling/avd"
    avdhome.mkdir(parents=True, exist_ok=True)
    avd = avdhome / f"{name}.avd"
    avd.mkdir(exist_ok=False)
    (avdhome / f"{name}.ini").write_text(f"avd.ini.encoding=UTF-8\npath={avd}\ntarget=android-36\n", encoding="utf-8")
    (avd / "config.ini").write_text("\n".join([
        f"AvdId={name}", f"avd.ini.displayname={name}", "avd.ini.encoding=UTF-8", f"image.sysdir.1={image}",
        "abi.type=x86_64", "hw.cpu.arch=x86_64", "hw.cpu.ncore=2", "hw.ramSize=2048", "hw.lcd.width=720",
        "hw.lcd.height=1280", "hw.lcd.density=320", "hw.keyboard=yes", "hw.gpu.enabled=yes",
        "hw.gpu.mode=swiftshader_indirect", "disk.dataPartition.size=2147483648", "fastboot.forceColdBoot=yes",
        "showDeviceFrame=no", "tag.id=google_apis", "tag.display=Google APIs", "PlayStore.enabled=false", "target=android-36", "",
    ]), encoding="utf-8")
    output_dir = ROOT / ".tooling" / f"storage-evidence-{run}"
    output_dir.mkdir(exist_ok=False)
    evidence = {"run": run, "environment": "fresh_owned_headless_emulator", "physical_phone": False,
                "synthetic_authenticated_contexts": True, "actual_server_authentication": False, "gates": [],
                "complete_suite_requested": not args.production_test and not args.screen_lock_only and not args.keyboard_only,
                "production_subset": args.production_test, "screen_lock_only": args.screen_lock_only, "keyboard_only": args.keyboard_only,
                "apks": [{"name": p.name, "sha256": hashlib.sha256(p.read_bytes()).hexdigest()} for p in apks]}
    env = os.environ.copy()
    env["ANDROID_AVD_HOME"] = str(avdhome)
    env["ANDROID_USER_HOME"] = str(ROOT / ".android-user-home")
    env.pop("ANDROID_SDK_HOME", None)
    adb = sdk / "platform-tools/adb.exe"
    owner = OwnedProcessTree()

    def command(*parts, timeout=60):
        if child.poll() is not None:
            raise RuntimeError("Owned emulator process exited")
        # All calls are bound to this held child and its exact newly generated AVD name.
        identity = subprocess.run([str(adb), "-s", SERIAL, "emu", "avd", "name"], capture_output=True, text=True, timeout=10)
        lines = identity.stdout.splitlines()
        if identity.returncode or not lines or lines[0].strip() != name:
            raise RuntimeError("Owned AVD identity mismatch; no target operation performed")
        result = subprocess.run([str(adb), "-s", SERIAL, *parts], capture_output=True, text=True, timeout=timeout)
        if result.returncode:
            raise RuntimeError("Owned emulator command failed; credential/device output omitted")
        return result.stdout

    with (output_dir / "emulator.log").open("w", encoding="utf-8") as log:
        child = subprocess.Popen([str(sdk / "emulator/emulator.exe"), "-avd", name, "-port", str(PORT), "-no-window",
            "-no-audio", "-no-boot-anim", "-no-snapshot", "-gpu", "swiftshader_indirect", "-no-metrics"],
            env=env, stdout=log, stderr=subprocess.STDOUT, creationflags=subprocess.CREATE_NO_WINDOW | 0x4)
        try:
            owner.attach_and_resume(child)
            deadline = time.monotonic() + 240
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise RuntimeError("Owned emulator exited before boot")
                try:
                    if command("shell", "getprop", "sys.boot_completed", timeout=10).strip() == "1":
                        break
                except (RuntimeError, subprocess.TimeoutExpired):
                    pass
                time.sleep(2)
            else:
                raise RuntimeError("Owned emulator boot timed out")
            if command("shell", "getprop", "ro.kernel.qemu").strip() != "1":
                raise RuntimeError("Target is not an emulator")
            api = command("shell", "getprop", "ro.build.version.sdk").strip()
            abi = command("shell", "getprop", "ro.product.cpu.abi").strip()
            if api != "36" or abi != "x86_64":
                raise RuntimeError("Unexpected owned emulator API/ABI")
            evidence.update(observed_api=int(api), observed_abi=abi,
                observed_android_release=command("shell", "getprop", "ro.build.version.release").strip(),
                observed_page_size=int(command("shell", "getconf", "PAGESIZE").strip()))
            try:
                packages = command("shell", "pm", "list", "packages", "--show-versioncode", "com.google.android.marvin.talkback").splitlines()
                versions = [match.group(1) for line in packages if (match := re.fullmatch(
                    r"package:com\.google\.android\.marvin\.talkback versionCode:(\d{1,20})", line.strip()))]
                evidence["talkback_inventory"] = {"observed": not packages or len(versions) == 1,
                    "present": True if len(versions) == 1 else (False if not packages else None),
                    "version_code": int(versions[0]) if len(versions) == 1 else None}
            except (RuntimeError, subprocess.TimeoutExpired):
                evidence["talkback_inventory"] = {"observed": False, "present": None, "version_code": None}
            if command("shell", "pm", "list", "packages", "--user", "0", PACKAGE).strip():
                raise RuntimeError("Pre-existing fixture package refused")
            for apk in apks:
                if "Success" not in command("install", str(apk), timeout=90):
                    raise RuntimeError("Isolated APK installation failed")
            command("shell", "settings", "put", "system", "screen_off_timeout", "180000")
            pin = str(secrets.randbelow(900000) + 100000)
            command("shell", "locksettings", "set-pin", pin)

            def device_unlocked():
                # AOSP TrustManagerService dumpUser emits this for the current user;
                # use it only as host readiness, never instead of app eligibility checks.
                state = command("shell", "dumpsys", "trust")
                current = [line for line in state.splitlines() if "(id=0," in line and "(current)" in line]
                return len(current) == 1 and re.search(r"\bdeviceLocked=0(?:,|$)", current[0]) is not None

            def app_sees_unlocked():
                # The same check the protected store makes; host trust state alone has raced it.
                result = command("shell", "am", "instrument", "-w", "-e", "class", READINESS_PROBE, "-e", "ownedEmulator", "true",
                    f"{PACKAGE}.test/androidx.test.runner.AndroidJUnitRunner", timeout=60)
                return "OK (1 test)" in result and "FAILURES" not in result and "INSTRUMENTATION_FAILED" not in result

            def unlock():
                for attempt in range(3):
                    command("shell", "input", "keyevent", "KEYCODE_SLEEP"); time.sleep(2)
                    command("shell", "input", "keyevent", "KEYCODE_WAKEUP"); time.sleep(3)
                    command("shell", "input", "swipe", "360", "1100", "360", "300", "400"); time.sleep(3)
                    command("shell", "input", "keyevent", *("KEYCODE_DEL" for _ in range(6)))
                    command("shell", "input", "text", pin)
                    command("shell", "input", "keyevent", "KEYCODE_ENTER")
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if device_unlocked():
                            break
                        time.sleep(1)
                    else:
                        print(f"Owned credential unlock readiness attempt {attempt + 1} did not confirm unlocked state", flush=True)
                        continue
                    app_deadline = time.monotonic() + 20
                    while time.monotonic() < app_deadline:
                        if app_sees_unlocked():
                            # Observed 31 Oct: locked while awake about a second after a confirmed unlock,
                            # first after a fresh PIN. Readiness needs the unlock to hold, not just to happen.
                            time.sleep(5)
                            if device_unlocked() and app_sees_unlocked():
                                return
                            evidence["unstable_unlock"] = evidence.get("unstable_unlock", 0) + 1
                            print(f"Owned credential unlock readiness attempt {attempt + 1}: unlock did not hold", flush=True)
                            break
                        time.sleep(2)
                    else:
                        print(f"Owned credential unlock readiness attempt {attempt + 1}: app did not see an eligible unlocked device", flush=True)
                    continue
                raise RuntimeError("Owned emulator credential unlock readiness failed; no protected test started")

            tests = [] if args.screen_lock_only or args.keyboard_only else [("org.kapit.c2.mobile.data.ProductionStoreTest#" + method, 1) for method in (args.production_test or METHODS)]
            if args.keyboard_only:
                tests = [(f"org.kapit.c2.mobile.ui.MobileKeyboardTest#{method}", 1)
                         for method in EXTRA_METHODS["org.kapit.c2.mobile.ui.MobileKeyboardTest"]]
            if not args.production_test and not args.screen_lock_only and not args.keyboard_only:
                tests += [("org.kapit.c2.mobile.security.EnrollmentProofKeysTest", 1), ("org.kapit.c2.mobile.ui.MobileActivityTest", 2)]
                tests += [("org.kapit.c2.mobile.ui.MobileStoreIntegrationTest#" + method, 1) for method in [
                "composeEditsSavesQueuesAndShowsReceiptWithoutPublicationClaim",
                "backgroundClearsComposeAndFreshUnlockReopensRetainedQueue",
                "controllerRestartRestoresLockedSelectionAndLogoutRemainsDenied",
                "backgroundBeforeCommitRollsBackQueueAndPreventsLateUiSuccess",
                ]]
                tests += [(f"{class_name}#{method}", 1) for class_name, methods in EXTRA_METHODS.items() for method in methods]
            # Acceptance compares completed gates with this expected count; all-passed alone can be a truncated run.
            # Every mode except a bounded production subset ends with the actual screen-lock gate.
            evidence["expected_gate_count"] = len(tests) + (0 if args.production_test else 1)
            def device_state():
                # Bounded diagnostics only: lock flag and power wakefulness, never credential or screen content.
                try:
                    wake = re.search(r"mWakefulness=(\w+)", command("shell", "dumpsys", "power"))
                    return {"device_locked": not device_unlocked(), "wakefulness": wake.group(1) if wake else None}
                except (RuntimeError, subprocess.TimeoutExpired):
                    return {"device_locked": None, "wakefulness": None}

            for index, (test, count) in enumerate(tests):
                unlock()
                # The emulator has re-locked within seconds of a confirmed unlock (31 Oct runs). Re-check just
                # before launch and repeat the full unlock and app probe; a test that then fails still fails.
                if not device_unlocked():
                    evidence["relocked_before_test"] = evidence.get("relocked_before_test", 0) + 1
                    print("Owned emulator re-locked after readiness; repeating unlock before the test", flush=True)
                    unlock()
                print(f"Production-store acceptance {index + 1}/{len(tests)}: {test.rsplit('.', 1)[-1]}", flush=True)
                result = command("shell", "am", "instrument", "-w", "-e", "class", test, "-e", "ownedEmulator", "true",
                    f"{PACKAGE}.test/androidx.test.runner.AndroidJUnitRunner", timeout=120)
                file = output_dir / f"instrumentation-{index + 1:02}.txt"
                file.write_text(result, encoding="utf-8")
                passed = f"OK ({count} test{'s' if count != 1 else ''})" in result and "FAILURES" not in result and "INSTRUMENTATION_FAILED" not in result
                gate = {"test": test, "count": count, "passed": passed, "output": file.name,
                    "sha256": hashlib.sha256(file.read_bytes()).hexdigest()}
                if not passed:
                    # Separates an emulator re-lock or sleep from an application failure in the record.
                    gate["device_after_failure"] = device_state()
                    # Keyguard's own log names why it showed (for example doKeyguard reasons); bounded, no PIN involved.
                    try:
                        keyguard = command("shell", "logcat", "-d", "-t", "400", "-s", "KeyguardViewMediator:*", "LockSettingsService:*")
                        log_file = output_dir / f"keyguard-after-failure-{index + 1:02}.txt"
                        log_file.write_bytes(keyguard.encode("utf-8")[:65536])
                        gate["keyguard_log"] = {"output": log_file.name, "sha256": hashlib.sha256(log_file.read_bytes()).hexdigest()}
                    except (RuntimeError, subprocess.TimeoutExpired):
                        gate["keyguard_log"] = None
                evidence["gates"].append(gate)
                print(f"Actual instrumentation passed={passed}", flush=True)
                if not passed:
                    print(f"Device after failure: {gate['device_after_failure']}", flush=True)
                    raise RuntimeError("Production-store instrumentation failed; inspect local synthetic evidence")
            if args.production_test:
                return  # finally still stops the exact owned emulator and records this subset.
            unlock()
            print("Actual production screen-lock fence: waiting for the protected fixture", flush=True)
            # Identity check immediately precedes this owned asynchronous instrumentation command.
            command("shell", "getprop", "ro.kernel.qemu")
            test = "org.kapit.c2.mobile.data.ProductionStoreTest#actualScreenOffClosesProductionHandleAndClearsCredentials"
            instrument = subprocess.Popen([str(adb), "-s", SERIAL, "shell", "am", "instrument", "-w", "-e", "class", test,
                "-e", "ownedEmulator", "true", f"{PACKAGE}.test/androidx.test.runner.AndroidJUnitRunner"],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, creationflags=subprocess.CREATE_NO_WINDOW)

            def retain_readiness_failure(code):
                # Preserve bounded evidence before the existing fail-closed cleanup.
                # A failed readiness gate does not establish a screen-lock outcome.
                if instrument.poll() is None:
                    instrument.terminate()
                drain_complete = True
                try:
                    stdout, stderr = instrument.communicate(timeout=10)
                except subprocess.TimeoutExpired as failure:
                    stdout, stderr = failure.output, failure.stderr
                    drain_complete = False
                artifacts = {}
                for stream, content in (("stdout", stdout), ("stderr", stderr)):
                    raw = content if isinstance(content, bytes) else (content or "").encode("utf-8")
                    file = output_dir / f"instrumentation-screen-lock-{stream}.txt"
                    file.write_bytes(raw[:65536])
                    artifacts[stream] = {"output": file.name, "sha256": hashlib.sha256(file.read_bytes()).hexdigest(),
                        "truncated": len(raw) > 65536}
                evidence["gates"].append({"test": test, "count": 1, "passed": False,
                    "stage": "screen_lock_readiness", "code": code, "screen_lock_observed": False,
                    "drain_complete": drain_complete, "artifacts": artifacts})

            try:
                deadline = time.monotonic() + 35
                while time.monotonic() < deadline:
                    if instrument.poll() is not None:
                        retain_readiness_failure("FIXTURE_EXITED_BEFORE_READINESS")
                        raise RuntimeError("Screen-lock fixture exited before its readiness marker")
                    try:
                        if command("shell", "run-as", PACKAGE, "cat", "no_backup/task060-screen-ready").strip() == "READY":
                            break
                    except RuntimeError:
                        pass
                    time.sleep(0.5)
                else:
                    retain_readiness_failure("FIXTURE_READINESS_TIMEOUT")
                    raise RuntimeError("Screen-lock fixture readiness timed out")
                command("shell", "input", "keyevent", "KEYCODE_SLEEP")
                result, _ = instrument.communicate(timeout=45)
                file = output_dir / "instrumentation-screen-lock.txt"
                file.write_text(result, encoding="utf-8")
                passed = instrument.returncode == 0 and "OK (1 test)" in result and "FAILURES" not in result and "INSTRUMENTATION_FAILED" not in result
                evidence["gates"].append({"test": test, "count": 1, "passed": passed, "output": file.name, "sha256": hashlib.sha256(file.read_bytes()).hexdigest()})
                print(f"Actual screen-lock production handle fence passed={passed}", flush=True)
                if not passed:
                    raise RuntimeError("Actual screen-lock production-store gate failed")
            finally:
                if instrument.poll() is None:
                    instrument.terminate(); instrument.wait(timeout=10)
        finally:
            try:
                if child.poll() is None:
                    command("emu", "kill", timeout=15); child.wait(timeout=20)
            except (RuntimeError, subprocess.TimeoutExpired):
                pass
            finally:
                owner.close(); child.wait(timeout=20)
            evidence["owned_emulator_stopped"] = child.poll() is not None
            evidence["all_expected_gates_passed"] = (evidence.get("expected_gate_count") == len(evidence["gates"])
                                                     and all(gate["passed"] for gate in evidence["gates"]))
            deadline = time.monotonic() + 10
            ports_closed = False
            while time.monotonic() < deadline:
                ports_closed = True
                for port in (PORT, PORT + 1):
                    with socket.socket() as probe:
                        probe.settimeout(0.5)
                        if probe.connect_ex(("127.0.0.1", port)) == 0:
                            ports_closed = False
                if ports_closed:
                    break
                time.sleep(0.2)
            evidence["owned_emulator_ports_closed"] = ports_closed
            # Each run's fresh AVD is a ~3.6 GB disposable disk; 17 left behind filled the disk on 31 Oct.
            # Remove only this run's exact AVD, and only once its emulator has stopped. Evidence stays in output_dir.
            avd_removed = False
            if evidence["owned_emulator_stopped"] and ports_closed:
                try:
                    shutil.rmtree(avd)
                    (avdhome / f"{name}.ini").unlink()
                    avd_removed = True
                except OSError:
                    pass
            evidence["owned_avd_removed"] = avd_removed
            (output_dir / "results.json").write_text(json.dumps(evidence, indent=2) + "\n", encoding="utf-8")
            print(f"Evidence: {output_dir.relative_to(ROOT)}; owned emulator stopped={evidence['owned_emulator_stopped']}, ports closed={ports_closed}", flush=True)
            if not ports_closed:
                raise RuntimeError("Owned emulator ports did not close; unrelated processes untouched")


if __name__ == "__main__":
    main()

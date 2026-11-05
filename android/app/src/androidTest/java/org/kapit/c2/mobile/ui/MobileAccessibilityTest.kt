package org.kapit.c2.mobile.ui

import android.accessibilityservice.AccessibilityServiceInfo
import android.app.UiAutomation
import android.content.ComponentName
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import android.util.AtomicFile
import android.view.InputDevice
import android.view.KeyEvent
import android.view.View
import android.view.WindowManager
import android.view.accessibility.AccessibilityEvent
import android.view.accessibility.AccessibilityManager
import android.view.accessibility.AccessibilityNodeInfo
import android.view.accessibility.AccessibilityWindowInfo
import androidx.activity.compose.setContent
import androidx.compose.runtime.mutableStateOf
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TestName
import org.junit.runner.RunWith
import org.kapit.c2.mobile.MainActivity

/**
 * Actual platform tree and installed TalkBack keyboard interaction, with synthetic presentation only.
 * No Compose test rule, direct accessibility focus/click action, fake auth, receipt or unlock callback.
 * Host separately proves bound-service state and restores its owned disposable emulator settings.
 * Default/Alt keymap is an explicit prerequisite; touch gestures and human listening are not tested.
 */
@RunWith(AndroidJUnit4::class)
class MobileAccessibilityTest {
    @get:Rule val testName = TestName()
    private val instrumentation = InstrumentationRegistry.getInstrumentation()
    private val context = instrumentation.targetContext
    private val presentation = mutableStateOf(MobileUiState())
    private val commands = mutableListOf<MobileAction>()
    private var scenario: ActivityScenario<MainActivity>? = null
    private lateinit var automation: UiAutomation
    private var previousAutomationFlags: Int? = null
    private var deadline = 0L
    private var versionCode = 0L
    private var versionName = ""
    private val focusEvents = AtomicInteger()
    private val anyFocusEvents = AtomicInteger() // Diagnostic count only, any package.
    private var nextMoves = 0
    private var previousMoves = 0
    private var activations = 0

    @Before fun requireOwnedTalkBackEnvironment() {
        val args = InstrumentationRegistry.getArguments()
        check(context.packageName.endsWith(".spike") && Build.VERSION.SDK_INT >= 35) { "A11Y_PACKAGE_API" }
        check(Build.HARDWARE in setOf("ranchu", "goldfish") && args.getString("ownedEmulator") == "true") { "A11Y_OWNERSHIP" }
        check(testName.methodName in METHODS && args.getString("class") == "${javaClass.name}#${testName.methodName}") { "A11Y_ISOLATED_METHOD" }
        check(args.getString("talkbackKeymap") == "default-alt") { "A11Y_KEYMAP_PREREQUISITE" }
        check(!evidenceFile.exists() && !File(context.noBackupFilesDir, "m2-live-phase").exists()) { "A11Y_FRESH_FIXTURE_REQUIRED" }
        val installed = context.packageManager.getPackageInfo(TALKBACK_PACKAGE, PackageManager.PackageInfoFlags.of(0))
        versionCode = installed.longVersionCode
        versionName = installed.versionName ?: ""
        check(versionCode > 0 && args.getString("talkbackVersionCode")?.toLongOrNull() == versionCode) { "A11Y_VERSION_MISMATCH" }
        check(versionName.length in 1..80 && versionName.all { it.code in 32..126 }) { "A11Y_VERSION_METADATA" }
        check(Build.FINGERPRINT.length in 1..256 && Build.FINGERPRINT.all { it.code in 32..126 }) { "A11Y_BUILD_METADATA" }
        // This must be the first UiAutomation acquisition in this isolated instrumentation process.
        automation = instrumentation.getUiAutomation(UiAutomation.FLAG_DONT_SUPPRESS_ACCESSIBILITY_SERVICES)
        previousAutomationFlags = automation.serviceInfo.flags
        automation.serviceInfo = automation.serviceInfo.apply {
            flags = flags or AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS
        }
        deadline = SystemClock.elapsedRealtime() + 150_000
        await("A11Y_SERVICE_UNAVAILABLE", 15_000) { serviceReady() }
        automation.setOnAccessibilityEventListener { event ->
            if (event.eventType == AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED) anyFocusEvents.incrementAndGet()
            if (event.eventType == AccessibilityEvent.TYPE_VIEW_ACCESSIBILITY_FOCUSED && event.packageName?.toString() == context.packageName) {
                focusEvents.incrementAndGet() // No event/source/text retained or logged.
            }
        }
    }

    @After fun closeFixtureAndRestoreAutomationFlags() {
        try { scenario?.close() }
        finally {
            closeHidKeyboard()
            scenario = null
            instrumentation.runOnMainSync { commands.clear(); presentation.value = MobileUiState() }
            if (::automation.isInitialized) {
                automation.setOnAccessibilityEventListener(null)
                previousAutomationFlags?.let { original ->
                    automation.serviceInfo = automation.serviceInfo.apply { flags = original }
                }
            }
        }
    }

    @Test fun talkBackSignInPasswordErrorsAndActivation() {
        show(MobileUiState(accountGeneration = 7, access = MobileAccess.SIGNED_OUT,
            capabilities = MobileCapabilities(authenticate = true), connection = ConnectionUi.NOT_CHECKED))
        navigateTo { edit(it, "Username") && it.isEnabled }
        roundTripFocus()
        navigateTo { edit(it, "Password") && it.isEnabled }
        check(focused { it.isPassword }) { "A11Y_PASSWORD_ROLE" }
        navigateTo { button(it, "Continue securely") }
        activate { tree { edit(it, "Username") && it.isContentInvalid && !it.error.isNullOrBlank() } }
        check(tree { hasLabel(it, "Check the marked sign-in fields.") && it.liveRegion == View.ACCESSIBILITY_LIVE_REGION_ASSERTIVE }) { "A11Y_SIGNIN_LIVE_ERROR" }
        assertActions { it.isEmpty() }
        // Platform text setup is separate from the TalkBack navigation/activation being measured.
        setSyntheticText("Username", "synthetic.accessibility")
        setSyntheticText("Password", "Synthetic-fixture-only")
        check(tree { edit(it, "Password") && it.isPassword && it.text?.contains("Synthetic-fixture-only") != true }) { "A11Y_PASSWORD_MASKING" }
        navigateTo { button(it, "Continue securely") }
        activate { actionCount() == 1 }
        assertActions { actions -> actions.singleOrNull().let { it is MobileAction.SignIn && it.generation == 7L &&
            it.username == "synthetic.accessibility" && it.password == "Synthetic-fixture-only" } }
        check(tree { button(it, "Signing in…") && !it.isEnabled }) { "A11Y_SIGNIN_DISABLED" }
        finishScenario()
    }

    @Test fun talkBackEditorValidationAndFieldNavigation() {
        show(editor(validForm().copy(siteLabel = "")))
        navigateTo { button(it, "Review & queue submission") }
        activate { tree { edit(it, "Site label") && it.isContentInvalid && !it.error.isNullOrBlank() } }
        check(tree { hasLabel(it, "1 field needs attention. Review the marked fields.") && it.liveRegion == View.ACCESSIBILITY_LIVE_REGION_ASSERTIVE }) { "A11Y_EDITOR_LIVE_ERROR" }
        navigateTo { edit(it, "Site label") }
        check(focused { it.isEnabled && it.isContentInvalid && !it.error.isNullOrBlank() }) { "A11Y_EDITOR_FIELD_ERROR" }
        roundTripFocus()
        assertActions { it.isEmpty() }
        finishScenario()
    }

    @Test fun talkBackConfirmationRequiresExplicitQueueAndKeepsLockAvailable() {
        show(editor(validForm()))
        navigateTo { button(it, "Review & queue submission") }
        activate { tree { hasLabel(it, "Queue this fixed submission?") } }
        assertActions { it.isEmpty() }
        navigateTo { button(it, "Keep editing") }
        activate { !tree { hasLabel(it, "Queue this fixed submission?") } }
        assertActions { it.isEmpty() }
        navigateTo { button(it, "Review & queue submission") }
        activate { tree { hasLabel(it, "Queue this fixed submission?") } }
        navigateTo { button(it, "Confirm & queue") }
        activate { actionCount() == 1 }
        assertActions { actions -> actions.singleOrNull().let { it is MobileAction.QueueSubmission && it.generation == 7L &&
            it.expectedDraftRevision == 3L && it.form == validForm() && it.commandId.isNotEmpty() } }
        check(!tree { hasLabel(it, "Queue this fixed submission?") }) { "A11Y_CONFIRMATION_DISMISSED" }
        check(tree { button(it, "Review & queue submission") && !it.isEnabled }) { "A11Y_DUPLICATE_QUEUE_DISABLED" }
        navigateTo { button(it, "Lock") && it.isEnabled }
        activate { actionCount() == 2 }
        assertActions { it.size == 2 && it[0] is MobileAction.QueueSubmission && it[1] == MobileAction.Lock(7) }
        finishScenario()
    }

    @Test fun talkBackOfflineOutboxDistinguishesReceiptAndDisabledRetry() {
        val offline = workspace().copy(screen = MobileScreen.OUTBOX, connection = ConnectionUi.OFFLINE,
            outbox = listOf(OutboxItemUi("queued-accessibility-fixture", "Synthetic queued item", "fixture time", DeliveryUi.QUEUED, canRetry = true),
                OutboxItemUi("received-accessibility-fixture", "Synthetic received item", "fixture time", DeliveryUi.RECEIVED)))
        show(offline)
        navigateTo { hasLabel(it, "Queued on this phone") }
        navigateTo { hasLabel(it, "Received by server") }
        check(tree { button(it, "Sync now") && !it.isEnabled } && tree { button(it, "Retry same submission") && !it.isEnabled }) { "A11Y_OFFLINE_ACTIONS_DISABLED" }
        navigateTo { button(it, "Retry same submission") && !it.isEnabled }
        combo(KeyEvent.KEYCODE_ENTER)
        SystemClock.sleep(300)
        assertActions { it.isEmpty() }
        update(offline.copy(connection = ConnectionUi.NOT_CHECKED, capabilities = offline.capabilities.copy(synchronize = true)))
        navigateTo { button(it, "Sync now") && it.isEnabled }
        activate { actionCount() == 1 }
        assertActions { it == listOf(MobileAction.SyncNow(7)) }
        finishScenario()
    }

    @Test fun talkBackLockedAndExpiredAccessExposeRecoveryActionsOnly() {
        show(MobileUiState(accountGeneration = 7, access = MobileAccess.LOCKED,
            capabilities = MobileCapabilities(unlock = true, authenticate = true)))
        navigateTo { hasLabel(it, "Workspace locked") }
        check(!tree { edit(it, "Site label") || hasLabel(it, "Synthetic accessibility site") }) { "A11Y_LOCKED_CONTENT_HIDDEN" }
        navigateTo { button(it, "Unlock workspace") && it.isEnabled }
        activate { actionCount() == 1 }
        assertActions { it == listOf(MobileAction.Unlock(7)) }
        // Presentation transition only; no fake credential return or successful unlock is injected.
        update(MobileUiState(accountGeneration = 8, access = MobileAccess.LEASE_EXPIRED,
            capabilities = MobileCapabilities(authenticate = true)))
        navigateTo { hasLabel(it, "Connect to renew access") }
        check(!tree { button(it, "Unlock workspace") || edit(it, "Site label") }) { "A11Y_EXPIRED_CONTENT_HIDDEN" }
        navigateTo { button(it, "Sign in online to this account") && it.isEnabled }
        activate { actionCount() == 2 }
        assertActions { it == listOf(MobileAction.Unlock(7), MobileAction.BeginSignIn(8, true)) }
        finishScenario()
    }

    private fun show(state: MobileUiState) {
        presentation.value = state
        scenario = ActivityScenario.launch(MainActivity::class.java).also { host ->
            host.onActivity { activity ->
                check(activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0) { "A11Y_SECURE_WINDOW" }
                activity.setContent { KapitMobileApp(presentation.value, MobileActions { commands += it }) }
            }
        }
        await("A11Y_APP_WINDOW_UNAVAILABLE") { tree { it.packageName?.toString() == context.packageName } }
    }

    private fun update(state: MobileUiState) {
        instrumentation.runOnMainSync { presentation.value = state }
        instrumentation.waitForIdleSync()
        SystemClock.sleep(150)
    }

    private fun serviceReady(): Boolean {
        val manager = context.getSystemService(AccessibilityManager::class.java)
        if (!manager.isEnabled || !manager.isTouchExplorationEnabled) return false
        val found = manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_SPOKEN).singleOrNull {
            ComponentName.unflattenFromString(it.id) == ComponentName(TALKBACK_PACKAGE, TALKBACK_CLASS)
        } ?: return false
        return found.resolveInfo.serviceInfo.packageName == TALKBACK_PACKAGE && found.resolveInfo.serviceInfo.name == TALKBACK_CLASS &&
            found.flags and AccessibilityServiceInfo.FLAG_REQUEST_FILTER_KEY_EVENTS != 0
    }

    private fun navigateTo(target: (AccessibilityNodeInfo) -> Boolean) {
        check(serviceReady()) { "A11Y_SERVICE_LOST" }
        combo(KeyEvent.KEYCODE_DPAD_LEFT, control = true) // TalkBack key + Ctrl + Left: first item.
        try { await("A11Y_FIRST_FOCUS_UNAVAILABLE") { focusIdentity() != null } }
        catch (failure: IllegalStateException) {
            if (failure.message != "A11Y_FIRST_FOCUS_UNAVAILABLE") throw failure
            // TASK-093 location diagnostic: where focus is after "first item", then after one "next item".
            val codes = focusLocation("FIRST")
            combo(KeyEvent.KEYCODE_DPAD_RIGHT)
            SystemClock.sleep(1_500)
            error("A11Y_FIRST_FOCUS_UNAVAILABLE " + (codes + focusLocation("NEXT") + activeOwner()).joinToString(" "))
        }
        val navigationDeadline = minOf(deadline, SystemClock.elapsedRealtime() + 35_000)
        repeat(96) {
            if (focused(target)) return
            check(SystemClock.elapsedRealtime() < navigationDeadline) { "A11Y_NAVIGATION_BUDGET" }
            move(KeyEvent.KEYCODE_DPAD_RIGHT)
        }
        error("A11Y_TARGET_NOT_REACHED")
    }

    private fun roundTripFocus() {
        val original = checkNotNull(focusIdentity()) { "A11Y_ROUNDTRIP_START" }
        move(KeyEvent.KEYCODE_DPAD_RIGHT)
        move(KeyEvent.KEYCODE_DPAD_LEFT)
        await("A11Y_REVERSE_FOCUS_MISMATCH") { focusIdentity() == original }
    }

    private fun move(key: Int) {
        val before = focusIdentity()
        val eventsBefore = focusEvents.get()
        combo(key)
        try {
            await("A11Y_SERVICE_FOCUS_DID_NOT_MOVE", 2_500) {
                focusEvents.get() > eventsBefore && focusIdentity()?.let { it != before } == true
            }
        } catch (failure: IllegalStateException) {
            if (failure.message != "A11Y_SERVICE_FOCUS_DID_NOT_MOVE") throw failure
            // TASK-093 diagnostic: fixed codes only; the scenario still fails with the original code.
            error("A11Y_SERVICE_FOCUS_DID_NOT_MOVE " + focusDiagnostics(key, before).joinToString(" "))
        }
        if (key == KeyEvent.KEYCODE_DPAD_RIGHT) nextMoves++ else previousMoves++
    }

    private fun activate(completed: () -> Boolean) {
        check(focused { it.isEnabled && it.isClickable }) { "A11Y_ACTIVATION_TARGET" }
        combo(KeyEvent.KEYCODE_ENTER) // TalkBack Default: activate accessibility-focused item.
        await("A11Y_ACTIVATION_NO_EFFECT", completed = completed)
        activations++
    }

    // TASK-093: a virtual USB HID keyboard created through the platform `hid` shell command (the input path the
    // API36 UiAutomation Javadoc recommends). Its keys traverse the full input pipeline, including the
    // accessibility input filter TalkBack listens on, exactly as a physical keyboard's do.
    private var hidOutput: ParcelFileDescriptor? = null
    private var hidInput: java.io.OutputStream? = null

    private fun hidWrite(json: String) {
        val input = checkNotNull(hidInput) { "A11Y_HID_UNAVAILABLE" }
        check(runCatching { input.write((json + "\n").toByteArray(Charsets.US_ASCII)); input.flush() }.isSuccess) { "A11Y_HID_WRITE_FAILED" }
    }

    private fun hidPresent() = InputDevice.getDeviceIds().any { id ->
        InputDevice.getDevice(id)?.let { it.name == HID_NAME && it.supportsSource(InputDevice.SOURCE_KEYBOARD) &&
            it.keyboardType == InputDevice.KEYBOARD_TYPE_ALPHABETIC && !it.isVirtual } == true
    }

    private fun hidKeyboard() {
        if (hidInput != null) return
        val (output, input) = automation.executeShellCommandRw("hid -").let { it[0] to it[1] }
        hidOutput = output
        hidInput = ParcelFileDescriptor.AutoCloseOutputStream(input)
        val descriptor = HID_BOOT_KEYBOARD.joinToString(",") { "\"0x%02x\"".format(it) }
        hidWrite("""{"id":"1","command":"register","name":"$HID_NAME","vid":"0x18d1","pid":"0x7a11","bus":"usb","descriptor":[$descriptor]}""")
        await("A11Y_HID_KEYBOARD_UNAVAILABLE", 10_000) { hidPresent() }
        SystemClock.sleep(500)
    }

    private fun hidReport(modifiers: Int, usage: Int) {
        hidWrite("""{"id":"1","command":"report","report":["0x%02x","0x00","0x%02x","0x00","0x00","0x00","0x00","0x00"]}""".format(modifiers, usage))
        SystemClock.sleep(40)
    }

    private fun closeHidKeyboard() {
        try { hidInput?.close() } catch (_: Exception) {} finally { hidInput = null }
        try { hidOutput?.close() } catch (_: Exception) {} finally { hidOutput = null }
    }

    private fun ownerCategory(owner: String?) = when (owner) {
        null -> "NONE"
        context.packageName -> "APP"
        TALKBACK_PACKAGE -> "TALKBACK"
        "com.android.systemui" -> "SYSTEMUI"
        else -> "OTHER"
    }

    @Suppress("DEPRECATION")
    private fun activeOwner(prefix: String = "ACTIVE"): String = "A11Y_DIAG_${prefix}_" + ownerCategory(runCatching {
        automation.rootInActiveWindow?.let { root -> try { root.packageName?.toString() } finally { root.recycle() } } }.getOrNull())

    /** Fixed codes only: owner category and window type of the accessibility-focused node, anywhere. */
    @Suppress("DEPRECATION")
    private fun focusLocation(prefix: String): List<String> {
        val node = runCatching { automation.findFocus(AccessibilityNodeInfo.FOCUS_ACCESSIBILITY) }.getOrNull()
            ?: return listOf("A11Y_DIAG_${prefix}_OWNER_NONE")
        return try {
            val window = runCatching { node.window?.let { w -> try { w.type } finally { w.recycle() } } }.getOrNull()
            val type = when (window) {
                AccessibilityWindowInfo.TYPE_APPLICATION -> "APPLICATION"
                AccessibilityWindowInfo.TYPE_SYSTEM -> "SYSTEM"
                AccessibilityWindowInfo.TYPE_INPUT_METHOD -> "INPUT_METHOD"
                AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY -> "OVERLAY"
                null -> "UNKNOWN"
                else -> "OTHER"
            }
            listOf("A11Y_DIAG_${prefix}_OWNER_" + ownerCategory(node.packageName?.toString()), "A11Y_DIAG_${prefix}_WIN_$type")
        } finally { node.recycle() }
    }

    @Suppress("DEPRECATION")
    private fun focusDiagnostics(key: Int, before: Pair<Int, Int>?): List<String> {
        val codes = mutableListOf<String>()
        codes += activeOwner()
        codes += focusLocation("NEXT")
        codes += if (anyFocusEvents.get() > 0) "A11Y_DIAG_ANY_FOCUS_SEEN" else "A11Y_DIAG_NO_FOCUS_EVENTS"
        codes += when (context.resources.configuration.hardKeyboardHidden) {
            android.content.res.Configuration.HARDKEYBOARDHIDDEN_NO -> "A11Y_DIAG_HARDKB_PRESENT"
            android.content.res.Configuration.HARDKEYBOARDHIDDEN_YES -> "A11Y_DIAG_HARDKB_HIDDEN"
            else -> "A11Y_DIAG_HARDKB_UNDEFINED"
        }
        // One probe with Action/Meta. Attempt 9: Android treats it as a system shortcut (launcher), not TalkBack.
        val anyBefore = anyFocusEvents.get()
        val moved = runCatching {
            combo(key, metaProbe = true)
            await("A11Y_DIAG_PROBE", 2_500) { anyFocusEvents.get() > anyBefore || focusIdentity()?.let { it != before } == true }
        }.isSuccess
        codes += if (moved) "A11Y_DIAG_META_MOVED" else "A11Y_DIAG_META_NOT_MOVED"
        // Where the probe left focus, and which app is now active (attempt 10 left this ambiguous).
        codes += focusLocation("PROBE")
        codes += activeOwner("PROBE_ACTIVE")
        return codes
    }

    private fun combo(key: Int, control: Boolean = false, metaProbe: Boolean = false) {
        check(serviceReady() && SystemClock.elapsedRealtime() < deadline) { "A11Y_INPUT_PREREQUISITE" }
        hidKeyboard()
        val usage = when (key) {
            KeyEvent.KEYCODE_DPAD_RIGHT -> 0x4F
            KeyEvent.KEYCODE_DPAD_LEFT -> 0x50
            KeyEvent.KEYCODE_ENTER -> 0x28
            else -> error("A11Y_KEY_UNMAPPED")
        }
        val modifier = if (metaProbe) HID_LEFT_GUI else HID_LEFT_ALT
        val combined = if (control) modifier or HID_LEFT_CTRL else modifier
        try {
            hidReport(modifier, 0)
            if (control) hidReport(combined, 0)
            hidReport(combined, usage)
            hidReport(combined, 0)
        } finally {
            try { if (control) hidReport(modifier, 0) }
            finally { hidReport(0, 0) }
        }
        instrumentation.waitForIdleSync()
        SystemClock.sleep(100)
    }


    @Suppress("DEPRECATION")
    private fun focused(predicate: (AccessibilityNodeInfo) -> Boolean): Boolean {
        val node = automation.findFocus(AccessibilityNodeInfo.FOCUS_ACCESSIBILITY) ?: return false
        return try { node.packageName?.toString() == context.packageName && node.isVisibleToUser && node.isAccessibilityFocused && predicate(node) }
        finally { node.recycle() }
    }

    private fun focusIdentity(): Pair<Int, Int>? {
        var identity: Pair<Int, Int>? = null
        focused { identity = it.windowId to it.hashCode(); true }
        return identity
    }

    /** Inspect only the application's platform tree, bounded in memory; never serialize nodes. */
    @Suppress("DEPRECATION")
    private fun tree(predicate: (AccessibilityNodeInfo) -> Boolean): Boolean {
        var remaining = 512
        fun visit(node: AccessibilityNodeInfo, depth: Int): Boolean {
            check(--remaining >= 0 && depth <= 32 && node.childCount <= 128) { "A11Y_TREE_BOUND" }
            if (node.isVisibleToUser && predicate(node)) return true
            for (index in 0 until node.childCount) {
                val child = node.getChild(index) ?: continue
                try { if (visit(child, depth + 1)) return true } finally { child.recycle() }
            }
            return false
        }
        val windows = automation.windows
        try {
            for (window in windows) {
                if (window.type != AccessibilityWindowInfo.TYPE_APPLICATION) continue
                val root = window.root ?: continue
                try { if (root.packageName?.toString() == context.packageName && visit(root, 0)) return true }
                finally { root.recycle() }
            }
            return false
        } finally { windows.forEach { it.recycle() } }
    }

    private fun hasLabel(node: AccessibilityNodeInfo, label: String): Boolean =
        listOf(node.text, node.contentDescription, node.hintText).any { value ->
            value?.toString()?.split('\n')?.any { it == label } == true
        }
    private fun button(node: AccessibilityNodeInfo, label: String) = node.className?.toString() == "android.widget.Button" && hasLabel(node, label)
    private fun edit(node: AccessibilityNodeInfo, label: String) = node.className?.toString() == "android.widget.EditText" && node.isEditable && hasLabel(node, label)

    private fun setSyntheticText(label: String, value: String) {
        val args = Bundle().apply { putCharSequence(AccessibilityNodeInfo.ACTION_ARGUMENT_SET_TEXT_CHARSEQUENCE, value) }
        check(tree { node -> edit(node, label) && node.isEnabled && node.performAction(AccessibilityNodeInfo.ACTION_SET_TEXT, args) }) { "A11Y_TEXT_FIXTURE_SETUP" }
        instrumentation.waitForIdleSync()
    }

    private fun actionCount(): Int { var count = 0; instrumentation.runOnMainSync { count = commands.size }; return count }
    private fun assertActions(predicate: (List<MobileAction>) -> Boolean) {
        var matched = false
        instrumentation.runOnMainSync { matched = predicate(commands.toList()) }
        check(matched) { "A11Y_COMMAND_SEQUENCE" }
    }
    private fun await(code: String, timeout: Long = 5_000, completed: () -> Boolean) {
        val end = minOf(deadline, SystemClock.elapsedRealtime() + timeout)
        do { if (completed()) return; SystemClock.sleep(50) } while (SystemClock.elapsedRealtime() < end)
        error(code)
    }

    private val evidenceFile get() = File(context.noBackupFilesDir, "m2-accessibility-${testName.methodName}.json")
    private fun finishScenario() {
        check(serviceReady() && nextMoves > 0 && activations > 0 && focusEvents.get() > 0) { "A11Y_SERVICE_EVIDENCE_INCOMPLETE" }
        val evidence = JSONObject().put("schema", 1).put("method", testName.methodName)
            .put("talkback_component", "$TALKBACK_PACKAGE/$TALKBACK_CLASS").put("talkback_version_code", versionCode)
            .put("talkback_version_name", versionName).put("android_api", Build.VERSION.SDK_INT).put("android_build", Build.FINGERPRINT)
            .put("native_enabled_spoken_service", true).put("native_touch_exploration", true)
            .put("keymap_prerequisite", "default-alt").put("next_focus_moves", nextMoves).put("previous_focus_moves", previousMoves)
            .put("observed_app_accessibility_focus_events", focusEvents.get()).put("verified_activations", activations)
            .put("platform_assertions_passed", true).put("scenario_passed", true)
            .put("synthetic_presentation", true).put("actual_authentication", false).put("touch_gestures", false).put("human_listening", false)
        val bytes = evidence.toString().toByteArray(Charsets.UTF_8)
        check(bytes.size <= 2048 && !evidenceFile.exists()) { "A11Y_EVIDENCE_BOUND" }
        val file = AtomicFile(evidenceFile); val stream = file.startWrite()
        try { stream.write(bytes); file.finishWrite(stream) }
        catch (failure: Exception) { file.failWrite(stream); throw failure }
    }

    private fun workspace() = MobileUiState(accountGeneration = 7, access = MobileAccess.READY, localDataLoaded = true,
        context = AccountContextUi("Synthetic author", "Synthetic organization", "Synthetic unit", "Synthetic channel", "DEMO-REDUCED", "Synthetic fixture lease", true),
        capabilities = MobileCapabilities(unlock = true, saveDraft = true, queueSubmission = true))
    private fun editor(form: MaintenanceForm) = workspace().copy(screen = MobileScreen.EDITOR,
        editor = EditorUi("synthetic-accessibility-draft", 3, form, estimatedServerTimeMillis = 1792195200000L))
    private fun validForm() = MaintenanceForm("2026-10-17T00:00:00Z", MaintenanceCategory.WATER_SUPPLY, MaintenanceUrgency.ROUTINE,
        MaintenanceArea.A, "Synthetic accessibility site", "Synthetic author", "Synthetic maintenance fixture", MaintenanceAssistance.INSPECTION)

    companion object {
        private const val TALKBACK_PACKAGE = "com.google.android.marvin.talkback"
        private const val TALKBACK_CLASS = "com.google.android.marvin.talkback.TalkBackService"
        private const val HID_NAME = "KAPIT synthetic test keyboard"
        private const val HID_LEFT_CTRL = 0x01
        private const val HID_LEFT_ALT = 0x04
        private const val HID_LEFT_GUI = 0x08
        // Standard USB HID boot keyboard report descriptor (8-byte input report, no report ID).
        private val HID_BOOT_KEYBOARD = intArrayOf(
            0x05, 0x01, 0x09, 0x06, 0xA1, 0x01, 0x05, 0x07, 0x19, 0xE0, 0x29, 0xE7, 0x15, 0x00, 0x25, 0x01,
            0x75, 0x01, 0x95, 0x08, 0x81, 0x02, 0x95, 0x01, 0x75, 0x08, 0x81, 0x01, 0x95, 0x05, 0x75, 0x01,
            0x05, 0x08, 0x19, 0x01, 0x29, 0x05, 0x91, 0x02, 0x95, 0x01, 0x75, 0x03, 0x91, 0x01, 0x95, 0x06,
            0x75, 0x08, 0x15, 0x00, 0x25, 0x65, 0x05, 0x07, 0x19, 0x00, 0x29, 0x65, 0x81, 0x00, 0xC0)
        private val METHODS = setOf("talkBackSignInPasswordErrorsAndActivation", "talkBackEditorValidationAndFieldNavigation",
            "talkBackConfirmationRequiresExplicitQueueAndKeepsLockAvailable", "talkBackOfflineOutboxDistinguishesReceiptAndDisabledRetry",
            "talkBackLockedAndExpiredAccessExposeRecoveryActionsOnly")
    }
}

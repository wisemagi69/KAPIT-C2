package org.kapit.c2.mobile.sync

import android.content.Context
import android.app.KeyguardManager
import android.accessibilityservice.AccessibilityServiceInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.SystemClock
import android.util.AtomicFile
import android.view.accessibility.AccessibilityWindowInfo
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.kapit.c2.mobile.MainActivity
import org.kapit.c2.mobile.ui.*

/** Host enters/cancels the real system credential UI. No PIN, fake callback or private screenshot. */
@RunWith(AndroidJUnit4::class)
class SystemCredentialIntegrationTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private lateinit var controller: MobileController
    private val automation get() = InstrumentationRegistry.getInstrumentation().uiAutomation
    private val credentialPackage: String by lazy {
        @Suppress("DEPRECATION")
        val intent = context.getSystemService(KeyguardManager::class.java).createConfirmDeviceCredentialIntent("KAPIT test", "Device credential")
            ?: error("Credential intent unavailable")
        @Suppress("DEPRECATION")
        val resolved = context.packageManager.resolveActivity(intent, PackageManager.MATCH_DEFAULT_ONLY)?.activityInfo?.packageName
        check(resolved in setOf("com.android.settings", "com.android.systemui"))
        resolved!!
    }

    @Test fun actualCredentialCancelSuccessAndRecreation() {
        check(Build.VERSION.SDK_INT >= 35 && context.packageName.endsWith(".spike"))
        check(InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        check(File(context.noBackupFilesDir, "m2-live-phase").isFile)
        val originalFlags = automation.serviceInfo.flags
        automation.serviceInfo = automation.serviceInfo.apply { flags = flags or AccessibilityServiceInfo.FLAG_RETRIEVE_INTERACTIVE_WINDOWS }
        try {
        phase("starting")
        stage("launch")
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            stage("controller")
            scenario.onActivity { controller = ViewModelProvider(it)[MobileControllerModel::class.java].controller }
            waitLocked("lock_wait_1")
            stage("click_unlock_1")
            compose.onNodeWithText("Unlock workspace").performClick()
            waitCredentialWindow("window_wait_1")
            phase("cancel_ready")
            stage("cancel_wait")
            compose.waitUntil(60_000) { (!credentialWindowPresent() && scenario.state == Lifecycle.State.RESUMED && controller.unlockRequest.value == null && !controller.state.value.busy).also { observe() } }
            check(!controller.state.value.showsProtectedContent)
            waitLocked("lock_wait_2")

            stage("click_unlock_2")
            compose.onNodeWithText("Unlock workspace").performClick()
            waitCredentialWindow("window_wait_2")
            phase("unlock_ready")
            stage("unlock_wait")
            compose.waitUntil(60_000) { (controller.state.value.showsProtectedContent && controller.state.value.localDataLoaded).also { observe() } }
            check(controller.state.value.outbox.size == 1 && controller.state.value.outbox.single().delivery == DeliveryUi.RECEIVED)

            stage("click_lock")
            compose.onNodeWithText("Lock").performClick()
            waitLocked("lock_wait_3")
            stage("click_unlock_3")
            compose.onNodeWithText("Unlock workspace").performClick()
            waitCredentialWindow("window_wait_3")
            stage("created_wait")
            // TASK-118: an opaque credential activity stops MainActivity (CREATED); the API36 SystemUI
            // overlay prompt only covers it (STARTED). Either way the old prompt is still open here.
            compose.waitUntil(30_000) { coveredByPrompt(scenario).also { observe() } }
            phase("recreate_ready")
            stage("recreate")
            scenario.recreate()
            stage("controller_2")
            scenario.onActivity { controller = ViewModelProvider(it)[MobileControllerModel::class.java].controller }
            check(controller.unlockRequest.value == null && !controller.state.value.showsProtectedContent)
            waitCredentialWindow("window_wait_4")
            check(coveredByPrompt(scenario))
            phase("stale_ready")
            stage("stale_wait")
            // Host completes the OLD real system prompt. The recreated Activity has no old ticket.
            compose.waitUntil(60_000) { (phaseValue() == "stale_returned").also { observe() } }
            stage("resumed_wait")
            compose.waitUntil(30_000) { (scenario.state == Lifecycle.State.RESUMED).also { observe() } }
            stage("idle_wait")
            compose.waitForIdle()
            check(!controller.state.value.showsProtectedContent && controller.unlockRequest.value == null)
            waitLocked("lock_wait_4")
            phase("completed")
            stage("done")
        }
        } finally { automation.serviceInfo = automation.serviceInfo.apply { flags = originalFlags } }
    }

    private fun coveredByPrompt(scenario: ActivityScenario<MainActivity>): Boolean = when (scenario.state) {
        Lifecycle.State.CREATED -> true
        Lifecycle.State.STARTED -> credentialWindowPresent()
        else -> false
    }

    private fun waitCredentialWindow(name: String) {
        stage(name)
        compose.waitUntil(30_000) { credentialWindowPresent().also { observe(window = it); census() } }
    }
    @Suppress("DEPRECATION")
    private fun credentialWindowPresent(): Boolean {
        // TASK-115: on API36 the confirm-credential UI is a SystemUI system window (attempt13 census).
        // Accept it only when active AND focused and the keyguard is not locked, so the lock screen
        // (also a SystemUI system window) never counts. The original application-window rule is unchanged.
        val keyguardLocked = context.getSystemService(KeyguardManager::class.java).isKeyguardLocked
        return automation.windows.any { window ->
            try {
                val application = window.type == AccessibilityWindowInfo.TYPE_APPLICATION && (window.isActive || window.isFocused)
                val systemPrompt = window.type == AccessibilityWindowInfo.TYPE_SYSTEM && window.isActive && window.isFocused && !keyguardLocked
                if (!application && !systemPrompt) false
                else window.root?.let { node ->
                    try {
                        val owner = node.packageName?.toString()
                        if (application) owner == credentialPackage else owner == "com.android.systemui"
                    } finally { node.recycle() }
                } ?: false
            } finally { window.recycle() }
        }
    }

    private fun waitLocked(name: String) {
        stage(name)
        compose.waitUntil(30_000) {
            val state = controller.state.value
            (!state.busy && !state.showsProtectedContent && state.access in setOf(MobileAccess.LOCKED, MobileAccess.UNLOCK_REQUIRED)).also { observe() }
        }
    }
    private val marker get() = AtomicFile(File(context.noBackupFilesDir, "m2-credential-phase"))
    private fun phase(value: String) {
        check(value in setOf("starting", "cancel_ready", "unlock_ready", "recreate_ready", "stale_ready", "completed"))
        val stream = marker.startWrite()
        try { stream.write(value.toByteArray(Charsets.US_ASCII)); marker.finishWrite(stream) }
        catch (failure: Exception) { marker.failWrite(stream); throw failure }
    }
    private fun phaseValue(): String {
        val bytes = marker.readFully()
        check(bytes.size <= 32)
        return bytes.toString(Charsets.US_ASCII)
    }

    // TASK-109 diagnostic stage checkpoint: a separate app-private file holding one line of
    // fixed enums/booleans, so a host-side timeout still shows the last step reached. Best
    // effort only: it never throws and never changes an action, predicate, deadline or marker.
    // Lifecycle is deliberately not read here: ActivityScenario.state waits for main-thread idle,
    // which would block the checkpoint in exactly the stall it diagnoses (l= stays "u").
    private var stageName = "init"
    private var stageSequence = 0
    private var lastStageWrite = 0L
    private fun stage(name: String) {
        if (name in STAGES) stageName = name
        observe(force = true)
    }
    private fun observe(window: Boolean? = null, force: Boolean = false) {
        try {
            val now = SystemClock.elapsedRealtime()
            if (!force && now - lastStageWrite < 500) return
            lastStageWrite = now
            stageSequence = minOf(stageSequence + 1, 99_999)
            val state = if (::controller.isInitialized) controller.state.value else null
            val pending = if (::controller.isInitialized) controller.unlockRequest.value != null else null
            val record = "v1 n=$stageSequence st=$stageName b=${flag(state?.busy)} p=${flag(state?.showsProtectedContent)}" +
                " a=${state?.access?.name ?: "u"} w=${flag(window)} l=u r=${flag(pending)}"
            if (record.length > 160 || record.any { it.code !in 32..126 }) return
            val file = AtomicFile(File(context.noBackupFilesDir, "m2-credential-stage"))
            val stream = file.startWrite()
            try { stream.write(record.toByteArray(Charsets.US_ASCII)); file.finishWrite(stream) }
            catch (failure: Exception) { file.failWrite(stream) }
        } catch (_: Exception) {
        }
    }
    private fun flag(value: Boolean?) = when (value) { true -> "1"; false -> "0"; null -> "u" }

    // TASK-113 window census, written only inside credential-window waits to a separate file.
    // Per window: type code, active, focused and package class; never text, labels or raw names.
    private var censusSequence = 0
    private var lastCensusWrite = 0L
    @Suppress("DEPRECATION")
    private fun census() {
        try {
            val now = SystemClock.elapsedRealtime()
            if (now - lastCensusWrite < 500) return
            lastCensusWrite = now
            censusSequence = minOf(censusSequence + 1, 99_999)
            val windows = automation.windows
            val items = ArrayList<String>(8)
            try {
                for (window in windows.take(8)) {
                    val type = when (window.type) {
                        AccessibilityWindowInfo.TYPE_APPLICATION -> "A"
                        AccessibilityWindowInfo.TYPE_SYSTEM -> "S"
                        AccessibilityWindowInfo.TYPE_INPUT_METHOD -> "I"
                        AccessibilityWindowInfo.TYPE_ACCESSIBILITY_OVERLAY -> "O"
                        AccessibilityWindowInfo.TYPE_SPLIT_SCREEN_DIVIDER -> "D"
                        AccessibilityWindowInfo.TYPE_MAGNIFICATION_OVERLAY -> "M"
                        else -> "X"
                    }
                    val owner = window.root?.let { node ->
                        try {
                            // TASK-116: fixed owner classes only; the package name itself is never written.
                            val name = node.packageName?.toString()
                            when {
                                name == null -> "n"
                                name == context.packageName -> "a"
                                name == "com.android.settings" -> "s"
                                name == "com.android.systemui" -> "u"
                                name == "android" -> "y"
                                name == "com.android.permissioncontroller" || name == "com.google.android.permissioncontroller" -> "p"
                                name == "com.google.android.gms" -> "g"
                                name == "com.android.launcher3" || name == "com.google.android.apps.nexuslauncher" -> "l"
                                name.startsWith("com.google.android.") -> "q"
                                name.startsWith("com.android.") -> "r"
                                else -> "o"
                            }
                        } finally { node.recycle() }
                    } ?: "n"
                    items.add(type + (if (window.isActive) "1" else "0") + (if (window.isFocused) "1" else "0") + owner)
                }
            } finally { windows.forEach { it.recycle() } }
            val record = "v1 n=$censusSequence st=$stageName k=${minOf(windows.size, 99)} w=" +
                (if (items.isEmpty()) "-" else items.joinToString(","))
            if (record.length > 160 || record.any { it.code !in 32..126 }) return
            val file = AtomicFile(File(context.noBackupFilesDir, "m2-credential-windows"))
            val stream = file.startWrite()
            try { stream.write(record.toByteArray(Charsets.US_ASCII)); file.finishWrite(stream) }
            catch (failure: Exception) { file.failWrite(stream) }
        } catch (_: Exception) {
        }
    }

    private companion object {
        val STAGES = setOf("launch", "controller", "lock_wait_1", "click_unlock_1", "window_wait_1", "cancel_wait",
            "lock_wait_2", "click_unlock_2", "window_wait_2", "unlock_wait", "click_lock", "lock_wait_3",
            "click_unlock_3", "window_wait_3", "created_wait", "recreate", "controller_2", "window_wait_4",
            "stale_wait", "resumed_wait", "idle_wait", "lock_wait_4", "done")
    }
}

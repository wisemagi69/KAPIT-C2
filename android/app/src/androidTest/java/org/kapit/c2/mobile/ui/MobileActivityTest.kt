package org.kapit.c2.mobile.ui

import android.os.Build
import android.view.WindowManager
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onAllNodesWithText
import androidx.lifecycle.Lifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.kapit.c2.mobile.MainActivity

/** Real installed Activity smoke gates; run only on the orchestrator-owned synthetic emulator. */
@RunWith(AndroidJUnit4::class)
class MobileActivityTest {
    // Reads the Activity's own Compose semantics, so a lock-screen, keyboard or system window that briefly holds
    // focus cannot hide the gate the way the previous rootInActiveWindow lookup could.
    @get:Rule val compose = createEmptyComposeRule()

    @Test fun launchesComposeGateWithSecureWindowAndNoFabricatedWorkspace() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            scenario.onActivity { activity ->
                assertTrue(activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
            }
            awaitGate()
            assertFalse(hasText("Android compatibility build. Account sign-in and reporting are being integrated."))
            assertFalse(hasText("Keep maintenance moving."))
            if (Build.VERSION.SDK_INT < 35) {
                assertTrue(hasText("Android 15 or later required"))
                assertFalse(hasText("Username"))
            }
        }
    }

    @Test fun backgroundAndRecreationRemainBehindAccessGate() {
        ActivityScenario.launch(MainActivity::class.java).use { scenario ->
            awaitGate()
            scenario.moveToState(Lifecycle.State.CREATED)
            scenario.moveToState(Lifecycle.State.RESUMED)
            awaitGate()
            scenario.recreate()
            awaitGate()
            assertFalse(hasText("Keep maintenance moving."))
            scenario.onActivity { activity ->
                assertTrue(activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
            }
        }
    }

    private fun awaitGate() {
        try {
            compose.waitUntil(10_000) { hasText("Training and evaluation") || hasText("Protected workspace") }
        } catch (_: Throwable) {
            assertTrue("Expected the real Compose access gate", false)
        }
    }

    // No Compose hierarchy yet (Activity still starting) counts as "not shown", never as a pass.
    private fun hasText(expected: String): Boolean =
        runCatching { compose.onAllNodesWithText(expected).fetchSemanticsNodes().isNotEmpty() }.getOrDefault(false)
}

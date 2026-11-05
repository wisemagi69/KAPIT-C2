package org.kapit.c2.mobile.ui

import android.os.Build
import android.view.WindowManager
import androidx.activity.compose.setContent
import androidx.compose.runtime.mutableStateOf
import androidx.compose.ui.input.key.Key
import androidx.compose.ui.semantics.LiveRegionMode
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.ExperimentalTestApi
import androidx.compose.ui.test.SemanticsMatcher
import androidx.compose.ui.test.SemanticsNodeInteraction
import androidx.compose.ui.test.assert
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsEnabled
import androidx.compose.ui.test.assertIsFocused
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performImeAction
import androidx.compose.ui.test.performKeyInput
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.test.performTextInput
import androidx.compose.ui.test.pressKey
import androidx.compose.ui.test.withKeyDown
import androidx.test.core.app.ActivityScenario
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import org.kapit.c2.mobile.MainActivity

/**
 * Production Compose screens with synthetic presentation state and recorded commands only.
 * No fake runtime, authentication result, receipt acceptance or unlock callback is installed.
 * Keyboard/semantics assertions are not TalkBack or real system credential Activity evidence.
 */
@OptIn(ExperimentalTestApi::class)
@RunWith(AndroidJUnit4::class)
class MobileKeyboardTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val presentation = mutableStateOf(MobileUiState())
    private val commands = mutableListOf<MobileAction>()
    private var scenario: ActivityScenario<MainActivity>? = null

    @Before fun requireOwnedSyntheticEmulator() {
        val instrumentation = InstrumentationRegistry.getInstrumentation()
        check(instrumentation.targetContext.packageName.endsWith(".spike"))
        check(InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        check(Build.HARDWARE in setOf("ranchu", "goldfish") && Build.VERSION.SDK_INT >= 35)
    }

    @After fun closeHostAndDropFixtureReferences() {
        scenario?.close()
        scenario = null
        commands.clear()
        presentation.value = MobileUiState()
    }

    @Test fun signInTabReverseTabAndEnterReachOneAction() {
        show(signIn())
        val username = compose.onNodeWithText("Username")
        val password = compose.onNodeWithText("Password")
        username.performScrollTo().performClick().performTextInput("synthetic-keyboard-user")
        username.performKeyInput { pressKey(Key.Tab) }
        password.assertIsFocused().assertIsDisplayed()
        password.performKeyInput { withKeyDown(Key.ShiftLeft) { pressKey(Key.Tab) } }
        username.assertIsFocused().assertIsDisplayed()
        username.performKeyInput { pressKey(Key.Tab) }
        password.assertIsFocused().performTextInput("synthetic-keyboard-password")
        password.performKeyInput { pressKey(Key.Tab) }
        val submit = compose.onNodeWithText("Continue securely")
        submit.assertIsFocused().assertIsDisplayed().performKeyInput { pressKey(Key.Enter) }
        compose.runOnIdle {
            assertEquals(1, commands.size)
            val command = commands.single() as MobileAction.SignIn
            assertEquals(7L, command.generation)
            assertTrue("Keyboard dispatch preserves the fixture fields", command.username == "synthetic-keyboard-user" && command.password == "synthetic-keyboard-password")
        }
        username.assertIsNotEnabled()
        password.assertIsNotEnabled()
        assertEmptyEditable(username)
        assertEmptyEditable(password)
        compose.onRoot().performKeyInput { pressKey(Key.Enter) }
        assertCommandCount(1)
    }

    @Test fun imeNextAndDoneFocusErrorsThenClearSubmittedCredentials() {
        show(signIn())
        val username = compose.onNodeWithText("Username")
        val password = compose.onNodeWithText("Password")
        password.performScrollTo().performClick().performImeAction()
        username.assertIsFocused().assertIsDisplayed()
        compose.onNodeWithText("Check the marked sign-in fields.")
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Assertive))
        assertCommandCount(0)
        username.performTextInput("synthetic-ime-user")
        username.performImeAction()
        password.assertIsFocused().assertIsDisplayed().performImeAction()
        password.assertIsFocused().assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Error))
        assertCommandCount(0)
        password.performTextInput("synthetic-ime-password")
        password.performImeAction()
        compose.runOnIdle {
            assertEquals(1, commands.size)
            assertTrue(commands.single() is MobileAction.SignIn)
        }
        assertEmptyEditable(username)
        assertEmptyEditable(password)
        username.assertIsNotEnabled()
        password.assertIsNotEnabled()
    }

    @Test fun offlineAndBusySignInRemainDisabledAndGenerationClearsInput() {
        show(signIn())
        val username = compose.onNodeWithText("Username")
        val password = compose.onNodeWithText("Password")
        username.performScrollTo().performClick().performTextInput("synthetic-unsubmitted-user")
        password.performScrollTo().performClick().performTextInput("synthetic-unsubmitted-password")
        update(signIn().copy(busy = true))
        username.assertIsNotEnabled()
        password.assertIsNotEnabled()
        compose.onRoot().performKeyInput { pressKey(Key.Enter) }
        assertCommandCount(0)
        update(signIn().copy(accountGeneration = 8, connection = ConnectionUi.OFFLINE,
            capabilities = MobileCapabilities(unlock = true)))
        username.assertIsNotEnabled()
        password.assertIsNotEnabled()
        assertEmptyEditable(username)
        assertEmptyEditable(password)
        compose.onNodeWithText("Continue securely").assertIsNotEnabled()
        compose.onNodeWithText("Cannot reach the local service").assertExists()
        enter("Verify device unlock")
        compose.runOnIdle {
            assertEquals(1, commands.size)
            assertEquals(MobileAction.Unlock(8), commands.single())
        }
    }

    @Test fun invalidEditorSubmissionFocusesVisibleFieldAndSupportsReverseTab() {
        show(editor(validForm().copy(siteLabel = "")))
        enter("Review & queue submission")
        val site = compose.onNodeWithText("Site label")
        site.assertIsFocused().assertIsDisplayed()
            .assert(SemanticsMatcher.keyIsDefined(SemanticsProperties.Error))
        compose.onNodeWithText("1 field needs attention. Review the marked fields.")
            .assert(SemanticsMatcher.expectValue(SemanticsProperties.LiveRegion, LiveRegionMode.Assertive))
        compose.onNodeWithText("Queue this fixed submission?").assertDoesNotExist()
        assertCommandCount(0)
        site.performTextInput("Synthetic keyboard site")
        site.performKeyInput { pressKey(Key.Tab) }
        val reporter = compose.onNodeWithText("Reporter label")
        reporter.assertIsFocused().assertIsDisplayed()
        reporter.performKeyInput { withKeyDown(Key.ShiftLeft) { pressKey(Key.Tab) } }
        site.assertIsFocused().assertIsDisplayed().performImeAction()
        reporter.assertIsFocused().assertIsDisplayed()
        assertCommandCount(0)
    }

    @Test fun keyboardConfirmationRequiresExplicitCommitAndPreventsDuplicateQueue() {
        val initial = editor(validForm())
        show(initial)
        enter("Review & queue submission")
        compose.onNodeWithText("Queue this fixed submission?").assertExists()
        assertCommandCount(0)
        enter("Keep editing", scroll = false)
        compose.onNodeWithText("Queue this fixed submission?").assertDoesNotExist()
        assertCommandCount(0)
        enter("Review & queue submission")
        enter("Confirm & queue", scroll = false)
        val queuedCommand = compose.runOnIdle {
            assertEquals(1, commands.size)
            val command = commands.single() as MobileAction.QueueSubmission
            assertEquals(7L, command.generation)
            assertEquals(3L, command.expectedDraftRevision)
            assertTrue("Confirmed fixture snapshot is preserved", command.form == validForm())
            assertTrue(command.commandId.isNotEmpty())
            command
        }
        compose.onNodeWithText("Queue this fixed submission?").assertDoesNotExist()
        compose.onNodeWithText("Review & queue submission").assertIsNotEnabled()
        update(initial.copy(busy = true))
        compose.onNodeWithText("Site label").assertIsNotEnabled()
        // Lock intentionally remains available while submission is pending; target it explicitly.
        val lock = compose.onNodeWithText("Lock").assertIsEnabled()
        lock.performSemanticsAction(SemanticsActions.RequestFocus) { assertTrue(it()) }
        lock.assertIsFocused().assertIsDisplayed().performKeyInput { pressKey(Key.Enter); pressKey(Key.Enter) }
        compose.runOnIdle {
            assertEquals(listOf(queuedCommand, MobileAction.Lock(7), MobileAction.Lock(7)), commands)
        }
    }

    @Test fun offlineOutboxKeepsDistinctStatesAndKeyboardSyncHonorsBusyGate() {
        val initial = workspace().copy(screen = MobileScreen.OUTBOX, connection = ConnectionUi.OFFLINE,
            notice = MobileNotice.CONNECTION_UNAVAILABLE, outbox = listOf(
                OutboxItemUi("queued-fixture", "Synthetic queued fixture", "fixture time", DeliveryUi.QUEUED, canRetry = true),
                OutboxItemUi("received-fixture", "Synthetic received fixture", "fixture time", DeliveryUi.RECEIVED)))
        show(initial)
        compose.onNodeWithText("Queued on this phone").assertExists()
        compose.onNodeWithText("Received by server").assertExists()
        compose.onNodeWithText("Sync now").assertIsNotEnabled()
        compose.onNodeWithText("Retry same submission").assertIsNotEnabled()
        assertCommandCount(0)
        val available = initial.copy(connection = ConnectionUi.NOT_CHECKED,
            capabilities = initial.capabilities.copy(synchronize = true))
        update(available.copy(busy = true))
        compose.onNodeWithText("Sync now").assertIsNotEnabled()
        compose.onNodeWithText("Retry same submission").assertIsNotEnabled()
        update(available)
        enter("Sync now")
        compose.runOnIdle {
            assertEquals(1, commands.size)
            assertEquals(MobileAction.SyncNow(7), commands.single())
        }
        compose.onNodeWithText("Queued on this phone").assertExists()
        compose.onNodeWithText("Received by server").assertExists()
    }

    @Test fun lockAndNewGenerationDiscardRememberedEditorInput() {
        show(editor(validForm().copy(siteLabel = "")))
        compose.onNodeWithText("Site label").performScrollTo().performClick().performTextInput("SYNTHETIC_KEYBOARD_UNSAVED")
        update(MobileUiState(accountGeneration = 8, access = MobileAccess.LOCKED,
            capabilities = MobileCapabilities(unlock = true)))
        compose.onNodeWithText("SYNTHETIC_KEYBOARD_UNSAVED").assertDoesNotExist()
        compose.onNodeWithText("Site label").assertDoesNotExist()
        enter("Unlock workspace")
        compose.runOnIdle { assertEquals(MobileAction.Unlock(8), commands.single()) }
        update(editor(validForm().copy(siteLabel = "")).copy(accountGeneration = 9))
        assertEmptyEditable(compose.onNodeWithText("Site label"))
        compose.onNodeWithText("SYNTHETIC_KEYBOARD_UNSAVED").assertDoesNotExist()
    }

    private fun show(state: MobileUiState) {
        presentation.value = state
        scenario = ActivityScenario.launch(MainActivity::class.java).also { host ->
            host.onActivity { activity ->
                assertTrue(activity.window.attributes.flags and WindowManager.LayoutParams.FLAG_SECURE != 0)
                activity.setContent {
                    KapitMobileApp(presentation.value, MobileActions { commands += it })
                }
            }
        }
        compose.waitForIdle()
    }

    private fun update(state: MobileUiState) {
        compose.runOnIdle { presentation.value = state }
        compose.waitForIdle()
    }

    /** Focus setup is explicit; activation always uses a real key event, never performClick. */
    private fun enter(label: String, scroll: Boolean = true) {
        val node = compose.onNodeWithText(label)
        if (scroll) node.performScrollTo()
        // Switch the target window (including a dialog) into keyboard mode before focus setup.
        node.performKeyInput { pressKey(Key.Tab) }
        node.performSemanticsAction(SemanticsActions.RequestFocus) { assertTrue(it()) }
        node.assertIsFocused().assertIsDisplayed().performKeyInput { pressKey(Key.Enter) }
    }

    private fun assertEmptyEditable(node: SemanticsNodeInteraction) {
        assertTrue("Fixture input must be cleared", node.fetchSemanticsNode().config[SemanticsProperties.EditableText].text.isEmpty())
    }

    private fun assertCommandCount(expected: Int) = compose.runOnIdle { assertEquals(expected, commands.size) }
    private fun signIn() = MobileUiState(accountGeneration = 7, access = MobileAccess.SIGNED_OUT,
        capabilities = MobileCapabilities(authenticate = true), connection = ConnectionUi.NOT_CHECKED)
    private fun workspace() = MobileUiState(accountGeneration = 7, access = MobileAccess.READY, localDataLoaded = true,
        context = AccountContextUi("Synthetic author", "Synthetic organization", "Synthetic unit", "Synthetic channel", "DEMO-REDUCED", "Synthetic lease fixture", true),
        capabilities = MobileCapabilities(unlock = true, saveDraft = true, queueSubmission = true))
    private fun editor(form: MaintenanceForm) = workspace().copy(screen = MobileScreen.EDITOR,
        editor = EditorUi("synthetic-keyboard-draft", 3, form, estimatedServerTimeMillis = 1792195200000L))
    private fun validForm() = MaintenanceForm("2026-10-17T00:00:00Z", MaintenanceCategory.WATER_SUPPLY,
        MaintenanceUrgency.ROUTINE, MaintenanceArea.A, "Synthetic keyboard site", "Synthetic author",
        "Synthetic maintenance fixture", MaintenanceAssistance.INSPECTION)
}

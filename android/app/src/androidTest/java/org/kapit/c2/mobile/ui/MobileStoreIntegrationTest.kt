package org.kapit.c2.mobile.ui

import android.content.Context
import android.os.Build
import androidx.activity.compose.setContent
import androidx.compose.runtime.getValue
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.junit4.createEmptyComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onAllNodesWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performTextInput
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.test.core.app.ActivityScenario
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.asCoroutineDispatcher
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.put
import org.junit.After
import org.junit.Before
import org.junit.Rule
import org.junit.Test
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.kapit.c2.mobile.MainActivity
import org.kapit.c2.mobile.data.local.AndroidProtectedRepository
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.security.AndroidAccessEnvironment

/**
 * Real Compose/controller/Room/SQLCipher/Keystore integration, only in the owned spike emulator.
 * Synthetic authenticated context and receipt fixtures do NOT prove server authentication/delivery.
 * The test mounts production Compose with its isolated real controller and forwards host lifecycle;
 * it does not install an alternate runtime factory or authentication bypass in the application.
 */
@RunWith(AndroidJUnit4::class)
class MobileStoreIntegrationTest {
    @get:Rule val compose = createEmptyComposeRule()
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val fixtureRoot = File(context.noBackupFilesDir, "ui-store-test-${UUID.randomUUID()}")
    private val environment = AndroidAccessEnvironment(context)
    private val executor = Executors.newSingleThreadExecutor()
    private val dispatcher = executor.asCoroutineDispatcher()
    private val repositories = mutableListOf<AndroidProtectedRepository>()
    private var scenario: ActivityScenario<MainActivity>? = null
    private lateinit var repository: AndroidProtectedRepository
    private lateinit var controller: MobileController
    private val server = 1792195200000L
    private val site = "Synthetic UI fixture site"
    private val narrative = "SYNTHETIC_UI_PROTECTED_CANARY"
    private val authority = AuthorizedContext(
        CaptureContext(AccountIdentity(uuid(), uuid(), uuid()), uuid(), uuid(), "private", MAINTENANCE_TEMPLATE),
        uuid(), 0, "Synthetic UI author", "Synthetic organization", "Synthetic unit", "Synthetic channel")
    private fun content() = MaintenanceContent("2026-10-17T00:00:00Z", "WATER_SUPPLY", "ROUTINE", "Area A", site, "Synthetic UI author", narrative, "Inspection")

    @Before fun prepareOwnedFixture() {
        check(context.packageName.endsWith(".spike"))
        check(InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        check(Build.HARDWARE in setOf("ranchu", "goldfish"))
        check(!fixtureRoot.exists())
        environment.requireEligibleUnlockedDevice()
        repository = newRepository()
    }

    @After fun closeOwnedFixture() {
        closeHost()
        repositories.forEach { try { it.close() } catch (_: Exception) {} }
        dispatcher.close()
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        keys.deleteEntry("kapit.wrap.v1.${authority.capture.account.storeRef}")
        check(fixtureRoot.parentFile.canonicalFile == context.noBackupFilesDir.canonicalFile && fixtureRoot.name.startsWith("ui-store-test-"))
        fixtureRoot.deleteRecursively()
    }

    @Test fun composeEditsSavesQueuesAndShowsReceiptWithoutPublicationClaim() {
        activate()
        mount()
        awaitReady()
        compose.onNodeWithText("Create maintenance report").performScrollTo().performClick()
        awaitState { it.editor != null && !it.busy }
        compose.onNodeWithText("Water supply").performScrollTo().performClick()
        compose.onNodeWithText("Routine").performScrollTo().performClick()
        compose.onNodeWithText("Area A").performScrollTo().performClick()
        compose.onNodeWithText("Site label").performScrollTo().performTextInput(site)
        compose.onNodeWithText("Reporter label").performScrollTo().performTextInput("Synthetic UI author")
        compose.onNodeWithText("Maintenance details").performScrollTo().performTextInput(narrative)
        compose.onNodeWithText("Inspection").performScrollTo().performClick()
        compose.onNodeWithText("Save editable draft").performScrollTo().performClick()
        awaitState { it.notice == MobileNotice.DRAFT_SAVED && !it.busy }
        val saved = repository.snapshot(repository.access.value.generation).drafts.single()
        assertTrue("The UI edit must reach the actual encrypted store", saved.content.narrative == narrative)
        compose.onNodeWithText("Review & queue submission").performScrollTo().performClick()
        compose.onNodeWithText("Queue this fixed submission?").assertIsDisplayed()
        compose.onNodeWithText("Confirm & queue").performClick()
        awaitState { it.screen == MobileScreen.OUTBOX && it.outbox.singleOrNull()?.delivery == DeliveryUi.QUEUED && !it.busy }
        compose.onAllNodesWithText("Queued on this phone")[0].performScrollTo().assertIsDisplayed()
        assertTrue(repository.snapshot(repository.access.value.generation).drafts.isEmpty())
        assertEquals(1, repository.snapshot(repository.access.value.generation).outbox.size)

        // A strict, synthetic receipt tests local receipt/UI separation, not a network round trip.
        repository.claimNext(repository.access.value.generation)!!.use { claim ->
            repository.commitReceipt(claim, AcceptedReceipt.parse(CanonicalJson.bytes(buildJsonObject {
                put("operation_id", claim.operationId); put("report_id", claim.reportId); put("revision_id", uuid())
                put("revision_no", claim.expectedRevision + 1); put("delivery_status", "RECEIVED")
                put("processing_status", "PENDING"); put("shared", false)
            }), claim))
        }
        onMain { controller.onForeground() }
        awaitState { it.outbox.singleOrNull()?.delivery == DeliveryUi.RECEIVED }
        compose.onNodeWithText("Received by server").performScrollTo().assertIsDisplayed()
        compose.onNodeWithText("Approved projection shared").assertDoesNotExist()
        assertFalse(controller.state.value.reports.loaded)
    }

    @Test fun backgroundClearsComposeAndFreshUnlockReopensRetainedQueue() {
        activate()
        val queued = queueFixture()
        mount(); awaitReady()
        onMain { controller.dispatch(MobileAction.Navigate(controller.state.value.accountGeneration, MobileScreen.OUTBOX)) }
        awaitState { it.screen == MobileScreen.OUTBOX && !it.busy }
        compose.onNodeWithText(site).performScrollTo().assertIsDisplayed()
        scenario!!.moveToState(Lifecycle.State.CREATED)
        awaitState { !it.showsProtectedContent && !it.busy }
        assertNull(controller.state.value.context)
        assertTrue(controller.state.value.outbox.isEmpty())
        scenario!!.moveToState(Lifecycle.State.RESUMED)
        compose.onNodeWithText("Workspace locked").assertIsDisplayed()
        compose.onNodeWithText(site).assertDoesNotExist()
        val beforePrompt = controller.state.value.accountGeneration
        onMain { controller.dispatch(MobileAction.Unlock(beforePrompt)) }
        awaitState { controller.unlockRequest.value != null }
        val ticket = controller.unlockRequest.value!!.id
        scenario!!.moveToState(Lifecycle.State.CREATED)
        onMain { controller.completeDeviceUnlock(ticket, true) }
        assertFalse(controller.state.value.showsProtectedContent)
        scenario!!.moveToState(Lifecycle.State.RESUMED)
        awaitReady()
        assertTrue(controller.state.value.accountGeneration > beforePrompt)
        assertTrue(controller.state.value.outbox.single().id == queued.operationId)
        // This supplies a controlled callback; actual system credential Activity routing is separate.
    }

    @Test fun controllerRestartRestoresLockedSelectionAndLogoutRemainsDenied() {
        activate(); val queued = queueFixture()
        mount(); awaitReady(); closeHost()
        repository = newRepository()
        mount()
        awaitState { it.access == MobileAccess.LOCKED && !it.busy }
        assertNull(controller.state.value.context)
        assertTrue(controller.state.value.outbox.isEmpty())
        compose.onNodeWithText(site).assertDoesNotExist()
        confirmFixtureUnlock()
        awaitReady()
        assertTrue(controller.state.value.outbox.single().id == queued.operationId)
        onMain { controller.dispatch(MobileAction.SignOut(controller.state.value.accountGeneration)) }
        awaitState { it.access == MobileAccess.SIGNED_OUT && !it.busy }
        assertEquals(MobileNotice.SIGNED_OUT_LOCAL, controller.state.value.notice)
        closeHost()
        repository = newRepository()
        mount()
        awaitState { it.access == MobileAccess.SIGNED_OUT && !it.busy }
        assertFalse(repository.access.value.ready)
        assertTrue(controller.state.value.outbox.isEmpty())
        assertTrue(File(fixtureRoot, "${authority.capture.account.storeRef}/protected.db").length() > 0)
    }

    @Test fun backgroundBeforeCommitRollsBackQueueAndPreventsLateUiSuccess() {
        activate(); mount(); awaitReady()
        onMain { controller.dispatch(MobileAction.NewDraft(controller.state.value.accountGeneration)) }
        awaitState { it.editor != null && !it.busy }
        val editor = controller.state.value.editor!!
        val reached = CountDownLatch(1)
        val release = CountDownLatch(1)
        repository.beforeCommit = { reached.countDown(); check(release.await(15, TimeUnit.SECONDS)) }
        try {
            onMain { controller.dispatch(MobileAction.QueueSubmission(controller.state.value.accountGeneration, uuid(), editor.draftId, editor.draftRevision, 0, content().toForm())) }
            assertTrue("Queue transaction must reach the controlled pre-commit gate", reached.await(10, TimeUnit.SECONDS))
            scenario!!.moveToState(Lifecycle.State.CREATED)
            assertFalse(controller.state.value.showsProtectedContent)
            assertFalse(repository.access.value.ready)
            release.countDown()
            awaitState { !it.busy }
            repository.beforeCommit = null
            scenario!!.moveToState(Lifecycle.State.RESUMED)
            compose.onNodeWithText(narrative).assertDoesNotExist()
            confirmFixtureUnlock(); awaitReady()
            val snapshot = repository.snapshot(repository.access.value.generation)
            assertTrue(snapshot.outbox.isEmpty())
            assertTrue(snapshot.drafts.single().id == editor.draftId)
            assertNotEquals(MobileNotice.SUBMISSION_QUEUED, controller.state.value.notice)
        } finally { release.countDown(); repository.beforeCommit = null }
    }

    private fun newRepository() = AndroidProtectedRepository(context, fixtureRoot, environment, false).also(repositories::add)
    private fun activate() {
        val anchor = repository.beginOnlineRequest(repository.access.value.generation)
        SessionSecrets("synthetic-ui-access".toByteArray(), "synthetic-ui-refresh".toByteArray(), server + 3_600_000, server + 86_400_000).use {
            repository.activateOnline(anchor, authority, LeaseOffer(server, server + 86_400_000, server + 172_800_000, 86_400), it)
        }
    }
    private fun queueFixture(): OutboxRecord {
        val generation = repository.access.value.generation
        val draft = repository.createDraft(generation, uuid(), content())
        return repository.queueDraft(generation, uuid(), draft.id, draft.revision, 0, draft.content)
    }
    private fun mount() {
        check(scenario == null)
        scenario = ActivityScenario.launch(MainActivity::class.java)
        scenario!!.onActivity { activity ->
            controller = MobileController(true, MobileRuntime(repository), ioDispatcher = dispatcher)
            activity.lifecycle.addObserver(LifecycleEventObserver { _, event ->
                when (event) {
                    Lifecycle.Event.ON_START -> controller.onForeground()
                    Lifecycle.Event.ON_STOP -> controller.onBackground()
                    Lifecycle.Event.ON_DESTROY -> controller.onActivityDestroyed()
                    else -> Unit
                }
            })
            activity.setContent {
                val state by controller.state.collectAsStateWithLifecycle()
                KapitMobileApp(state, controller)
            }
        }
    }
    private fun closeHost() {
        scenario?.close()
        scenario = null
        if (::controller.isInitialized) onMain { controller.close() }
        if (!executor.isShutdown) executor.submit {}.get(15, TimeUnit.SECONDS)
    }
    private fun confirmFixtureUnlock() {
        onMain { controller.dispatch(MobileAction.Unlock(controller.state.value.accountGeneration)) }
        awaitState { controller.unlockRequest.value != null }
        val ticket = controller.unlockRequest.value!!.id
        onMain { controller.completeDeviceUnlock(ticket, true) }
    }
    private fun awaitReady() = awaitState { it.showsProtectedContent && it.localDataLoaded && !it.busy }
    private fun awaitState(predicate: (MobileUiState) -> Boolean) = compose.waitUntil(timeoutMillis = 15_000) { predicate(controller.state.value) }
    private fun onMain(block: () -> Unit) = InstrumentationRegistry.getInstrumentation().runOnMainSync(block)
    private fun uuid() = UUID.randomUUID().toString()
}

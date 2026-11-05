package org.kapit.c2.mobile.ui

import java.util.ArrayDeque
import java.util.UUID
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.NonCancellable
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.withContext
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.domain.*

/** Controller contract tests use an explicit fake port; they make no encryption/server/device claim. */
class MobileControllerTest {
    @Test fun staleOrLockedCameraCommandCannotRetainOrCommitDetachedBytes() {
        val repo = Repository()
        controller(repo, Live()).use { controller ->
            val generation = controller.state.value.accountGeneration
            controller.onBackground()
            val action = MobileAction.QueuePhoto(generation, uuid(50), uuid(51), 1, uuid(52),
                PhotoPolicy.capture(now, 1000, null), byteArrayOf(-1, -40, -1, -39))
            controller.dispatch(action)
            assertFalse(controller.state.value.showsProtectedContent)
            try { action.bytes(); fail("Rejected private buffer must close") }
            catch (failure: StoreFailure) { assertEquals(StoreCode.STALE_GENERATION, failure.code) }
        }
    }
    @Test fun unsupportedTemplateClearsPrivateUiAndCannotBeDowngradedByUnlockOrBackground() {
        val repo = Repository()
        controller(repo, Live()).use { controller ->
            controller.dispatch(MobileAction.NewDraft(controller.state.value.accountGeneration))
            assertNotNull(controller.state.value.editor)
            repo.invalidate(StoreCode.TEMPLATE_UNSUPPORTED)
            assertEquals(MobileAccess.TEMPLATE_UNSUPPORTED, controller.state.value.access)
            assertNull(controller.state.value.editor)
            assertNull(controller.state.value.context)
            assertTrue(controller.state.value.drafts.isEmpty())
            assertEquals(MobileCapabilities(), controller.state.value.capabilities)
            val calls = repo.calls
            controller.dispatch(MobileAction.Unlock(controller.state.value.accountGeneration))
            controller.dispatch(MobileAction.BeginSignIn(controller.state.value.accountGeneration, true))
            assertEquals(calls, repo.calls)
            controller.onBackground()
            controller.onForeground()
            assertEquals(StoreCode.TEMPLATE_UNSUPPORTED, repo.access.value.reason)
            assertEquals(MobileAccess.TEMPLATE_UNSUPPORTED, controller.state.value.access)
        }
    }

    @Test fun unsupportedApiNeverTouchesRepositoryOrAllowsEnrollment() {
        val repo = Repository()
        val live = Live()
        val controller = controller(repo, live, supported = false)
        controller.dispatch(MobileAction.SignIn(0, SignInPurpose.ENROLL_OR_RECOVER, "synthetic", "synthetic"))
        controller.dispatch(MobileAction.NewDraft(0))
        assertEquals(MobileAccess.UNSUPPORTED_DEVICE, controller.state.value.access)
        assertEquals(MobileCapabilities(), controller.state.value.capabilities)
        assertEquals(0, repo.calls)
        assertEquals(0, live.authCalls)
        controller.close()
    }

    @Test fun defaultLivePortDoesNotPretendAuthenticationOrDeliveryExists() {
        val repo = Repository(ready = false)
        controller(repo, UnavailableMobileLivePort).use { controller ->
            assertFalse(controller.state.value.capabilities.authenticate)
            assertFalse(controller.state.value.capabilities.synchronize)
            controller.dispatch(MobileAction.SignIn(1, SignInPurpose.ENROLL_OR_RECOVER, "synthetic", "synthetic"))
            assertFalse(controller.state.value.showsProtectedContent)
            assertEquals(0, repo.activations)
        }
    }

    @Test fun startupRestoresOnlyOpaqueSelectionBeforeEnablingAnyActions() {
        val repo = Repository(ready = false).apply { restoreReason = StoreCode.LOCKED }
        val io = ManualDispatcher()
        val controller = MobileController(true, MobileRuntime(repo, Live()), Dispatchers.Unconfined, io)
        assertEquals(MobileAccess.STARTING, controller.state.value.access)
        assertFalse(controller.state.value.capabilities.authenticate)
        controller.dispatch(MobileAction.NewDraft(1))
        controller.dispatch(MobileAction.BeginSignIn(1, false))
        assertEquals(0, repo.draftCreates)
        io.runAll()
        assertEquals(MobileAccess.LOCKED, controller.state.value.access)
        assertTrue(controller.state.value.capabilities.unlock)
        assertEquals(0, repo.snapshots)
        assertTrue(repo.unlockGenerations.isEmpty())
        controller.close(); io.runAll()
    }

    @Test fun persistedDenialRestoresWithoutOpeningSourceOrDowngradingIt() {
        val repo = Repository(ready = false).apply { restoreReason = StoreCode.REVOKED }
        controller(repo, Live()).use { controller ->
            assertEquals(MobileAccess.ENROLLMENT_SUSPENDED, controller.state.value.access)
            assertNull(controller.state.value.context)
            assertEquals(0, repo.snapshots)
            controller.onBackground()
            controller.onForeground()
            assertEquals(StoreCode.REVOKED, repo.access.value.reason)
            assertFalse(controller.state.value.capabilities.unlock)
        }
    }

    @Test fun backgroundDuringStartupInvalidatesOldRestoreAndRetriesWithFreshGeneration() {
        val repo = Repository(ready = false).apply { restoreReason = StoreCode.LEASE_EXPIRED }
        val io = ManualDispatcher()
        val controller = MobileController(true, MobileRuntime(repo, Live()), Dispatchers.Unconfined, io)
        controller.onBackground()
        val fencedGeneration = repo.access.value.generation
        controller.onForeground()
        io.runAll()
        assertEquals(listOf(fencedGeneration), repo.restoreGenerations)
        assertEquals(MobileAccess.LEASE_EXPIRED, controller.state.value.access)
        assertTrue(controller.state.value.accountGeneration > fencedGeneration)
        assertEquals(0, repo.snapshots)
        controller.close(); io.runAll()
    }

    @Test fun staleActionsCannotReadNavigateOrMutateAfterLock() {
        val repo = Repository()
        controller(repo).use { controller ->
            val generation = controller.state.value.accountGeneration
            controller.dispatch(MobileAction.NewDraft(generation))
            assertNotNull(controller.state.value.editor)
            controller.dispatch(MobileAction.Lock(generation))
            val calls = repo.calls
            controller.dispatch(MobileAction.Navigate(generation, MobileScreen.OUTBOX))
            controller.dispatch(MobileAction.NewDraft(generation))
            assertEquals(calls, repo.calls)
            assertFalse(controller.state.value.showsProtectedContent)
            assertNull(controller.state.value.editor)
            assertTrue(controller.state.value.drafts.isEmpty())
        }
    }

    @Test fun credentialActivityBackgroundFencesAndReturnUsesFreshGeneration() {
        val repo = Repository()
        controller(repo).use { controller ->
            controller.dispatch(MobileAction.Lock(controller.state.value.accountGeneration))
            val beforePrompt = controller.state.value.accountGeneration
            controller.dispatch(MobileAction.Unlock(beforePrompt))
            val ticket = controller.unlockRequest.value!!.id
            controller.onBackground()
            val returnGeneration = repo.access.value.generation
            assertTrue(returnGeneration > beforePrompt)
            controller.completeDeviceUnlock(ticket, true)
            assertTrue(repo.unlockGenerations.isEmpty())
            assertFalse(controller.state.value.showsProtectedContent)
            controller.onForeground()
            assertEquals(listOf(returnGeneration), repo.unlockGenerations)
            assertTrue(controller.state.value.showsProtectedContent)
            controller.completeDeviceUnlock(ticket, true)
            assertEquals(1, repo.unlockGenerations.size)
        }
    }

    @Test fun canceledOrReplacedCredentialPromptCannotUnlockAnotherSelection() {
        val repo = Repository()
        controller(repo, Live()).use { controller ->
            controller.dispatch(MobileAction.Lock(controller.state.value.accountGeneration))
            controller.dispatch(MobileAction.Unlock(controller.state.value.accountGeneration))
            val canceled = controller.unlockRequest.value!!.id
            controller.completeDeviceUnlock(canceled, false)
            assertTrue(repo.unlockGenerations.isEmpty())
            controller.dispatch(MobileAction.Unlock(controller.state.value.accountGeneration))
            val replaced = controller.unlockRequest.value!!.id
            controller.dispatch(MobileAction.BeginSignIn(controller.state.value.accountGeneration, false))
            controller.completeDeviceUnlock(replaced, true)
            assertTrue(repo.unlockGenerations.isEmpty())
            assertFalse(controller.state.value.showsProtectedContent)
            assertNull(controller.unlockRequest.value)
        }
    }

    @Test fun destroyedActivityConsumesPromptWithoutUnlockingRetainedController() {
        val repo = Repository()
        controller(repo).use { controller ->
            controller.dispatch(MobileAction.Lock(controller.state.value.accountGeneration))
            controller.dispatch(MobileAction.Unlock(controller.state.value.accountGeneration))
            val oldTicket = controller.unlockRequest.value!!.id
            controller.onBackground()
            controller.onActivityDestroyed()
            controller.onForeground()
            controller.completeDeviceUnlock(oldTicket, true)
            assertTrue(repo.unlockGenerations.isEmpty())
            assertFalse(controller.state.value.showsProtectedContent)
            assertNull(controller.unlockRequest.value)
        }
    }

    @Test fun authorityExpiryClearsAllProtectedSurfacesImmediately() {
        val repo = Repository()
        controller(repo).use { controller ->
            controller.dispatch(MobileAction.NewDraft(controller.state.value.accountGeneration))
            repo.invalidate(StoreCode.LEASE_EXPIRED)
            val state = controller.state.value
            assertEquals(MobileAccess.LEASE_EXPIRED, state.access)
            assertNull(state.context)
            assertNull(state.editor)
            assertNull(state.reportDetail)
            assertTrue(state.drafts.isEmpty())
            assertTrue(state.outbox.isEmpty())
            assertEquals(ReportPageUi(), state.reports)
            controller.onBackground()
            assertEquals(StoreCode.LEASE_EXPIRED, repo.access.value.reason)
        }
    }

    @Test fun repositoryRejectionNeverProducesQueueSuccessAndRetryUsesSameCommand() {
        val repo = Repository()
        controller(repo).use { controller ->
            controller.dispatch(MobileAction.NewDraft(controller.state.value.accountGeneration))
            val editor = controller.state.value.editor!!
            val command = MobileAction.QueueSubmission(controller.state.value.accountGeneration, uuid(20), editor.draftId, editor.draftRevision, 0, content.toForm())
            repo.queueFailure = StoreCode.STALE_DRAFT
            controller.dispatch(command)
            assertEquals(MobileNotice.CONFLICT, controller.state.value.notice)
            assertTrue(controller.state.value.outbox.isEmpty())
            repo.queueFailure = null
            controller.dispatch(command)
            assertEquals(MobileNotice.SUBMISSION_QUEUED, controller.state.value.notice)
            assertEquals(DeliveryUi.QUEUED, controller.state.value.outbox.single().delivery)
            assertEquals(MobileScreen.OUTBOX, controller.state.value.screen)
            assertEquals(listOf(uuid(20), uuid(20)), repo.queueCommands)
            assertFalse(controller.state.value.capabilities.synchronize)
        }
    }

    @Test fun duplicateBusyActionCannotReleaseLatchOrStartAnotherMutation() {
        val repo = Repository()
        val live = Live().apply { reportWait = CompletableDeferred() }
        controller(repo, live).use { controller ->
            val generation = controller.state.value.accountGeneration
            controller.dispatch(MobileAction.LoadReports(generation, ReportFilterUi.ALL, 1))
            assertTrue(controller.state.value.busy)
            controller.dispatch(MobileAction.NewDraft(generation))
            assertTrue(controller.state.value.busy)
            controller.dispatch(MobileAction.NewDraft(generation))
            assertEquals(0, repo.draftCreates)
            live.reportWait!!.complete(ReportPageUi(loaded = true))
            assertFalse(controller.state.value.busy)
            assertEquals(1, live.reportCalls)
        }
    }

    @Test fun lateNonCooperativeNetworkResponseCannotRepopulateAfterBackground() {
        val repo = Repository()
        val live = Live().apply { reportWait = CompletableDeferred(); nonCancellable = true }
        controller(repo, live).use { controller ->
            controller.dispatch(MobileAction.LoadReports(controller.state.value.accountGeneration, ReportFilterUi.ALL, 1))
            controller.onBackground()
            live.reportWait!!.complete(ReportPageUi(loaded = true, totalCount = 999))
            controller.onForeground()
            assertFalse(controller.state.value.showsProtectedContent)
            assertEquals(0, controller.state.value.reports.totalCount)
            assertNull(controller.state.value.context)
        }
    }

    @Test fun authenticationSuccessCannotBypassFailedLocalKeyActivationAndSecretsClose() {
        val repo = Repository(ready = false).apply { activationFailure = StoreCode.UNLOCK_REQUIRED }
        val live = Live()
        controller(repo, live).use { controller ->
            authorizeCredentialEntry(controller)
            controller.dispatch(MobileAction.SignIn(controller.state.value.accountGeneration, SignInPurpose.ENROLL_OR_RECOVER, "synthetic", "synthetic"))
            assertEquals(1, live.authCalls)
            assertFalse(controller.state.value.showsProtectedContent)
            assertEquals(MobileAccess.UNLOCK_REQUIRED, controller.state.value.access)
            assertSecretsClosed(live.lastSession!!.secrets)
        }
    }

    @Test fun successfulLocalActivationAdvancesGenerationAndClosesDetachedSecrets() {
        val repo = Repository(ready = false)
        val live = Live()
        controller(repo, live).use { controller ->
            authorizeCredentialEntry(controller)
            val requestGeneration = controller.state.value.accountGeneration
            controller.dispatch(MobileAction.SignIn(requestGeneration, SignInPurpose.ENROLL_OR_RECOVER, "synthetic", "synthetic"))
            assertEquals(1, repo.activations)
            assertTrue(controller.state.value.accountGeneration > requestGeneration)
            assertTrue(controller.state.value.showsProtectedContent)
            assertFalse(controller.state.value.busy)
            assertSecretsClosed(live.lastSession!!.secrets)
        }
    }

    @Test fun noOpSyncDoesNotClaimServiceConnectivityOrReceipt() {
        val repo = Repository()
        controller(repo, Live()).use { controller ->
            controller.dispatch(MobileAction.SyncNow(controller.state.value.accountGeneration))
            assertEquals(ConnectionUi.NOT_CHECKED, controller.state.value.connection)
            assertNull(controller.state.value.notice)
        }
    }

    @Test fun authenticationResponseAfterAccountSwitchCannotActivateOldAnchor() {
        val repo = Repository(ready = false)
        val live = Live().apply { authWait = CompletableDeferred(); nonCancellable = true }
        controller(repo, live).use { controller ->
            authorizeCredentialEntry(controller)
            controller.dispatch(MobileAction.SignIn(controller.state.value.accountGeneration, SignInPurpose.ENROLL_OR_RECOVER, "synthetic", "synthetic"))
            controller.dispatch(MobileAction.BeginSignIn(controller.state.value.accountGeneration, false))
            val session = session()
            live.authWait!!.complete(session)
            assertEquals(0, repo.activations)
            assertFalse(controller.state.value.showsProtectedContent)
            assertSecretsClosed(session.secrets)
        }
    }

    @Test fun correctionRequiresFreshReturnedAuthorityAndNeverTrustsOldUiDetail() {
        val repo = Repository()
        val live = Live().apply { detail = detail(ReviewUi.APPROVED, true) }
        controller(repo, live).use { controller ->
            val generation = controller.state.value.accountGeneration
            controller.dispatch(MobileAction.CorrectReport(generation, uuid(50), 1))
            assertEquals(0, repo.correctionCreates)
            assertEquals(MobileNotice.CONFLICT, controller.state.value.notice)
            live.detail = detail(ReviewUi.RETURNED, true)
            controller.dispatch(MobileAction.CorrectReport(generation, uuid(50), 1))
            assertEquals(1, repo.correctionCreates)
            assertEquals(2, live.correctionCalls)
            assertEquals(1, controller.state.value.editor!!.expectedReportRevision)
        }
    }

    @Test fun logoutInvalidatesBeforeIoAndDoesNotClaimServerRevocation() {
        val repo = Repository()
        val io = ManualDispatcher()
        val controller = MobileController(true, MobileRuntime(repo, Live()), Dispatchers.Unconfined, io)
        io.runAll()
        val oldGeneration = repo.access.value.generation
        controller.dispatch(MobileAction.SignOut(oldGeneration))
        assertFalse(repo.access.value.ready)
        assertTrue(repo.access.value.generation > oldGeneration)
        assertFalse(controller.state.value.showsProtectedContent)
        assertThrowsStore(StoreCode.STALE_GENERATION) { repo.createDraft(oldGeneration, uuid(60)) }
        io.runAll()
        assertEquals(MobileNotice.SIGNED_OUT_LOCAL, controller.state.value.notice)
        controller.close()
        io.runAll()
    }

    @Test fun confirmedRemoteLogoutUsesOnlyDetachedTokenAndAlwaysClosesIt() {
        val authorization = LogoutAuthorization(byteArrayOf(7))
        val repo = Repository().apply { logoutToken = authorization }
        val live = Live().apply { logoutResult = LogoutConfirmation.CONFIRMED }
        controller(repo, live).use { controller ->
            controller.dispatch(MobileAction.SignOut(controller.state.value.accountGeneration))
            assertFalse(repo.access.value.ready)
            assertEquals(1, live.logoutCalls)
            assertEquals(MobileNotice.SIGNED_OUT_CONFIRMED, controller.state.value.notice)
            assertThrowsStore(StoreCode.AUTH_REQUIRED) { authorization.copyAccessToken() }
        }
    }

    @Test fun oldReloadCannotOverwriteLaterSaveInSameAccountGeneration() {
        val repo = Repository()
        val main = ManualDispatcher()
        val io = ManualDispatcher()
        val controller = MobileController(true, MobileRuntime(repo), main, io)
        repeat(3) { main.runAll(); io.runAll() }
        main.runAll()
        controller.onForeground()
        main.runAll()
        io.runAll() // old snapshot completion is queued on main; a newer command is submitted first.
        controller.dispatch(MobileAction.NewDraft(controller.state.value.accountGeneration))
        repeat(3) { main.runAll(); io.runAll() }
        main.runAll()
        assertEquals(1, controller.state.value.drafts.size)
        assertEquals(MobileScreen.EDITOR, controller.state.value.screen)
        assertNotNull(controller.state.value.editor)
        controller.close()
        repeat(2) { main.runAll(); io.runAll() }
    }

    @Test fun oldNonCooperativeReloadFailureCannotFenceNewerSameGenerationResult() {
        val repo = Repository()
        controller(repo).use { controller ->
            val generation = controller.state.value.accountGeneration
            repo.snapshotHook = {
                repo.snapshotHook = null
                controller.onForeground() // A newer refresh completes before the old call fails.
                throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
            }
            controller.onForeground()
            assertTrue(controller.state.value.showsProtectedContent)
            assertEquals(generation, controller.state.value.accountGeneration)
            assertNull(controller.state.value.notice)
        }
    }

    private fun controller(repo: Repository, live: MobileLivePort = UnavailableMobileLivePort, supported: Boolean = true) =
        MobileController(supported, MobileRuntime(repo, live), Dispatchers.Unconfined, Dispatchers.Unconfined)

    private fun authorizeCredentialEntry(controller: MobileController) {
        controller.dispatch(MobileAction.Unlock(controller.state.value.accountGeneration))
        val ticket = controller.unlockRequest.value!!.id
        controller.onBackground()
        controller.completeDeviceUnlock(ticket, true)
        controller.onForeground()
        assertTrue(controller.state.value.capabilities.authenticate)
    }

    private fun assertSecretsClosed(secrets: SessionSecrets) = assertThrowsStore(StoreCode.AUTH_REQUIRED) { secrets.copyAccessToken() }
    private fun assertThrowsStore(code: StoreCode, action: () -> Unit) {
        try { action(); fail("Expected fixed store denial") } catch (failure: StoreFailure) { assertEquals(code, failure.code) }
    }

    private class ManualDispatcher : CoroutineDispatcher() {
        private val work = ArrayDeque<Runnable>()
        override fun dispatch(context: CoroutineContext, block: Runnable) { work.addLast(block) }
        fun runAll() {
            var count = 0
            while (work.isNotEmpty()) { check(count++ < 1000); work.removeFirst().run() }
        }
    }

    private class Live : MobileLivePort {
        override val available = true
        var authCalls = 0
        var reportCalls = 0
        var correctionCalls = 0
        var logoutCalls = 0
        var logoutResult = LogoutConfirmation.UNCONFIRMED
        var authWait: CompletableDeferred<MobileSession>? = null
        var reportWait: CompletableDeferred<ReportPageUi>? = null
        var nonCancellable = false
        var lastSession: MobileSession? = null
        var detail = detail(ReviewUi.RETURNED, true)
        override suspend fun authenticate(anchor: OnlineRequestAnchor, purpose: SignInPurpose, username: String, password: String): MobileSession {
            authCalls++
            val response = authWait?.let { if (nonCancellable) withContext(NonCancellable) { it.await() } else it.await() } ?: session()
            lastSession = response
            return response
        }
        override suspend fun synchronize(generation: Long) = MobileSyncOutcome(serviceReached = false)
        override suspend fun reports(generation: Long, filter: ReportFilterUi, page: Int): ReportPageUi {
            reportCalls++
            return reportWait?.let { if (nonCancellable) withContext(NonCancellable) { it.await() } else it.await() } ?: ReportPageUi(loaded = true)
        }
        override suspend fun report(generation: Long, reportId: String, revision: Int) = detail
        override suspend fun correction(generation: Long, reportId: String, revision: Int): ReportDetailUi { correctionCalls++; return detail }
        override suspend fun logout(authorization: LogoutAuthorization): LogoutConfirmation { logoutCalls++; return logoutResult }
        override fun cancelForFence(previousGeneration: Long, reason: StoreCode) = Unit
        override fun close() = Unit
    }

    private class Repository(ready: Boolean = true) : ProtectedRepository {
        override val access = MutableStateFlow(StoreAccess(1, ready, if (ready) StoreCode.READY else StoreCode.SIGNED_OUT, if (ready) "synthetic-store" else null))
        var calls = 0
        var snapshots = 0
        var draftCreates = 0
        var activations = 0
        var correctionCreates = 0
        var queueFailure: StoreCode? = null
        var activationFailure: StoreCode? = null
        var logoutToken: LogoutAuthorization? = null
        var restoreReason: StoreCode? = null
        var snapshotHook: (() -> Unit)? = null
        val restoreGenerations = mutableListOf<Long>()
        val queueCommands = mutableListOf<String>()
        val unlockGenerations = mutableListOf<Long>()
        private val drafts = linkedMapOf<String, DraftRecord>()
        private val outbox = linkedMapOf<String, OutboxRecord>()
        private fun checkGeneration(expected: Long, ready: Boolean = true) {
            calls++
            if (expected != access.value.generation) throw StoreFailure(StoreCode.STALE_GENERATION)
            if (ready && !access.value.ready) throw StoreFailure(access.value.reason)
        }
        override fun restoreSelection(expectedGeneration: Long): StoreAccess {
            checkGeneration(expectedGeneration, false)
            restoreGenerations += expectedGeneration
            restoreReason?.let { access.value = StoreAccess(expectedGeneration + 1, false, it, "synthetic-store") }
            return access.value
        }
        override fun beginOnlineRequest(expectedGeneration: Long): OnlineRequestAnchor {
            checkGeneration(expectedGeneration, false); return OnlineRequestAnchor(expectedGeneration, ClockStamp(10, "test-boot"))
        }
        override fun activateOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets): StoreAccess {
            checkGeneration(anchor.generation, false)
            activationFailure?.let { invalidate(it); throw StoreFailure(it) }
            activations++
            access.value = StoreAccess(access.value.generation + 1, true, StoreCode.READY, "synthetic-store")
            return access.value
        }
        override fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets): StoreAccess {
            checkGeneration(anchor.generation)
            return access.value
        }
        override fun unlock(expectedGeneration: Long): StoreAccess {
            checkGeneration(expectedGeneration, false)
            unlockGenerations += expectedGeneration
            access.value = access.value.copy(generation = expectedGeneration + 1, ready = true, reason = StoreCode.READY)
            return access.value
        }
        override fun invalidate(reason: StoreCode): StoreAccess {
            calls++
            access.value = access.value.copy(generation = access.value.generation + 1, ready = false, reason = reason)
            return access.value
        }
        override fun logoutAndInvalidate(expectedGeneration: Long): LogoutFence {
            checkGeneration(expectedGeneration, false)
            return LogoutFence(invalidate(StoreCode.SIGNED_OUT), logoutToken)
        }
        override fun fence(reason: StoreCode, invalidatedGeneration: Long?): StoreAccess {
            calls++
            return if (invalidatedGeneration == null) invalidate(reason) else access.value
        }
        override fun snapshot(expectedGeneration: Long): LocalSnapshot {
            checkGeneration(expectedGeneration)
            snapshots++
            snapshotHook?.invoke()
            return LocalSnapshot(context, 3_600_000, now, drafts.values.toList(), outbox.values.toList())
        }
        override fun createDraft(expectedGeneration: Long, commandId: String, content: MaintenanceContent): DraftRecord {
            checkGeneration(expectedGeneration)
            val draft = DraftRecord(uuid(100 + draftCreates++), 1, if (content.observedAt.isEmpty()) content.copy(observedAt = "2026-10-17T09:30:00Z") else content, null, 0, null, context.capture, now)
            drafts[draft.id] = draft
            return draft
        }
        override fun openDraft(expectedGeneration: Long, draftId: String): DraftRecord { checkGeneration(expectedGeneration); return drafts[draftId] ?: throw StoreFailure(StoreCode.NOT_FOUND) }
        override fun saveDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedRevision: Long, content: MaintenanceContent): DraftRecord {
            val draft = openDraft(expectedGeneration, draftId)
            if (draft.revision != expectedRevision) throw StoreFailure(StoreCode.STALE_DRAFT)
            return draft.copy(revision = draft.revision + 1, content = content).also { drafts[draftId] = it }
        }
        override fun queueDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedDraftRevision: Long, expectedReportRevision: Int, content: MaintenanceContent): OutboxRecord {
            checkGeneration(expectedGeneration)
            queueCommands += commandId
            queueFailure?.let { throw StoreFailure(it) }
            val result = OutboxRecord(uuid(200), uuid(201), expectedReportRevision, content, context.capture, "0".repeat(64), DeliveryState.QUEUED, null, 0, null, now, null)
            drafts.remove(draftId)
            outbox[result.operationId] = result
            return result
        }
        override fun createCorrectionDraft(expectedGeneration: Long, commandId: String, reportId: String, expectedReportRevision: Int, content: MaintenanceContent, predecessorOperationId: String?): DraftRecord {
            correctionCreates++
            return createDraft(expectedGeneration, commandId, content).copy(reportId = reportId, expectedReportRevision = expectedReportRevision).also { drafts[it.id] = it }
        }
        override fun reconcileOperation(expectedGeneration: Long, commandId: String, operationId: String): DraftRecord = throw StoreFailure(StoreCode.NOT_FOUND)
        override fun claimNext(expectedGeneration: Long): DeliveryClaim? = null
        override fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt) = Unit
        override fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long?) = Unit
        override fun retryOperation(expectedGeneration: Long, operationId: String) { checkGeneration(expectedGeneration) }
        override fun credentials(expectedGeneration: Long): SessionSecrets { checkGeneration(expectedGeneration); return session().secrets }
        override fun cacheReports(expectedGeneration: Long, reports: List<CachedReport>) = Unit
        override fun cachedReports(expectedGeneration: Long): List<CachedReport> = emptyList()
        override fun cacheOpenedRevision(expectedGeneration: Long, report: CachedReport) = Unit
        override fun cachedOpenedRevision(expectedGeneration: Long, reportId: String, revision: Int): CachedReport? = null
        override fun close() = Unit
    }

    companion object {
        private const val now = 1792229400000L
        private fun uuid(value: Int) = "00000000-0000-4000-8000-${value.toString().padStart(12, '0')}"
        private val context = AuthorizedContext(CaptureContext(AccountIdentity(uuid(1), uuid(2), uuid(3)), uuid(4), uuid(5), "DEMO-REDUCED", MAINTENANCE_TEMPLATE), uuid(6), 0, "Synthetic reporter", "Synthetic organization", "Synthetic unit", "Synthetic channel")
        private val content = MaintenanceContent("2026-10-17T09:30:00Z", "WATER_SUPPLY", "ROUTINE", "Area A", "Fictional pump", "Synthetic reporter", "Synthetic inspection request", "Inspection")
        private fun session() = MobileSession(context, LeaseOffer(now, now + 86_400_000, now + 604_800_000, 86_400), SessionSecrets(byteArrayOf(1), byteArrayOf(2), now + 600_000, now + 604_800_000))
        private fun detail(review: ReviewUi, canCorrect: Boolean) = ReportDetailUi(uuid(50), "Synthetic reference", 1, content.toForm(), DeliveryUi.RECEIVED, ProcessingUi.PREPARED, review, canCorrect = canCorrect)
    }
}

package org.kapit.c2.mobile.ui

import java.io.Closeable
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import org.kapit.c2.mobile.domain.*

/** An opaque, memory-only system prompt ticket. No account labels, credentials or source fields. */
data class DeviceUnlockRequest(val id: Long)

/**
 * Activity invokes actions/lifecycle/prompt callbacks on its main dispatcher. Storage and transport
 * run on IO. A separate epoch rejects even non-cooperative late responses after every local fence;
 * repository generation and its own transaction checks remain the authority for durable writes.
 * No controller, UI model or prompt ticket is saved in an Android state bundle.
 */
class MobileController(
    private val supportedDevice: Boolean,
    private val runtime: MobileRuntime?,
    mainDispatcher: CoroutineDispatcher = Dispatchers.Main.immediate,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
) : MobileActions, Closeable {
    private val scope = CoroutineScope(SupervisorJob() + mainDispatcher)
    private val repository get() = checkNotNull(runtime).repository
    private val live get() = checkNotNull(runtime).live
    private val mutableState = MutableStateFlow(MobileUiState())
    val state: StateFlow<MobileUiState> = mutableState.asStateFlow()
    private val mutableUnlockRequest = MutableStateFlow<DeviceUnlockRequest?>(null)
    val unlockRequest: StateFlow<DeviceUnlockRequest?> = mutableUnlockRequest.asStateFlow()
    private var foreground = true
    private var closed = false
    private var epoch = 0L
    private var activeJob: Job? = null
    private var commandRunning = false
    private var refreshJob: Job? = null
    private var presentationVersion = 0L
    private var bootstrapJob: Job? = null
    private var bootstrapping = false
    private var needsSelectionRestore = false
    private var cleanupJob: Job? = null
    private var closingStore = false
    private var credentialConfirmed = false
    private var nextPromptId = 0L
    private var promptGeneration: Long? = null
    private var promptStoreRef: String? = null
    private var promptResult: Boolean? = null
    private var signInPurpose = SignInPurpose.ENROLL_OR_RECOVER

    init {
        if (!supportedDevice || runtime == null) {
            mutableState.value = MobileUiState(access = if (!supportedDevice) MobileAccess.UNSUPPORTED_DEVICE else MobileAccess.STORAGE_UNAVAILABLE)
        } else {
            needsSelectionRestore = !repository.access.value.ready && repository.access.value.storeRef == null
            bootstrapping = needsSelectionRestore
            scope.launch { repository.access.collect { observeAccess(it) } }
            if (needsSelectionRestore) restoreSelection() else observeAccess(repository.access.value)
        }
    }

    override fun dispatch(action: MobileAction) {
        if (action is MobileAction.QueuePhoto && (closed || !supportedDevice || !foreground || runtime == null || state.value.busy || closingStore ||
                !repository.access.value.ready ||
                bootstrapping || needsSelectionRestore || !state.value.showsProtectedContent ||
                action.generation != state.value.accountGeneration || action.generation != repository.access.value.generation)) {
            action.close(); return
        }
        if (closed || !supportedDevice || runtime == null || !foreground || bootstrapping || needsSelectionRestore) return
        if (action.generation != state.value.accountGeneration || action.generation != repository.access.value.generation) return
        if (state.value.access == MobileAccess.TEMPLATE_UNSUPPORTED && action !is MobileAction.SignOut && action !is MobileAction.DismissNotice) return
        when (action) {
            is MobileAction.Lock -> fence(StoreCode.LOCKED)
            is MobileAction.SignOut -> signOut(action.generation)
            is MobileAction.BeginSignIn -> {
                signInPurpose = if (action.recoverEnrollment) SignInPurpose.RECOVER_ENROLLMENT else SignInPurpose.ENROLL_OR_RECOVER
                fence(if (action.recoverEnrollment) StoreCode.AUTH_REQUIRED else StoreCode.SIGNED_OUT)
            }
            is MobileAction.Unlock -> requestDeviceUnlock()
            is MobileAction.DismissNotice -> mutableState.value = state.value.copy(notice = null)
            is MobileAction.SignIn -> signIn(action)
            else -> protectedCommand(action)
        }
    }

    /** System credential Activity may stop this Activity. It never preserves an open store. */
    fun onBackground() {
        foreground = false
        if (closed || !supportedDevice || runtime == null) return
        val reason = backgroundReason(repository.access.value)
        fence(reason, preservePrompt = mutableUnlockRequest.value != null)
    }

    fun onForeground() {
        if (closed) return
        foreground = true
        if (needsSelectionRestore) { restoreSelection(); return }
        finishDeviceUnlockIfReady()
        if (supportedDevice && runtime != null && repository.access.value.ready) reload()
    }

    /** Cancellation, stale callbacks and a prompt from a destroyed/replaced Activity cannot unlock. */
    fun completeDeviceUnlock(requestId: Long, successful: Boolean) {
        if (closed || mutableUnlockRequest.value?.id != requestId) return
        promptResult = successful
        finishDeviceUnlockIfReady()
    }

    /** The platform callback belongs to one Activity instance and cannot survive its destruction. */
    fun onActivityDestroyed() {
        clearPrompt()
        credentialConfirmed = false
        if (!closed) completed()
    }

    private fun restoreSelection() {
        if (closed || !foreground || closingStore || !needsSelectionRestore) return
        bootstrapJob?.cancel()
        bootstrapping = true
        val restoreEpoch = epoch
        val expected = repository.access.value.generation
        mutableState.value = MobileUiState(accountGeneration = expected, access = MobileAccess.STARTING, busy = true)
        bootstrapJob = scope.launch {
            try {
                val restored = withContext(ioDispatcher) { repository.restoreSelection(expected) }
                if (!closed && foreground && restoreEpoch == epoch && restored == repository.access.value) {
                    needsSelectionRestore = false
                    bootstrapping = false
                    observeAccess(restored)
                    completed()
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) {
                if (!closed && restoreEpoch == epoch) {
                    needsSelectionRestore = false
                    bootstrapping = false
                    if (failure is StoreFailure && failure.code == StoreCode.STALE_GENERATION) observeAccess(repository.access.value)
                    else showFailure(failure)
                    completed()
                }
            }
        }
    }

    private fun requestDeviceUnlock() {
        if (state.value.busy || closingStore || !state.value.capabilities.unlock) return
        // Start with a fresh closed generation even when the prompt is requested from sign-in.
        fence(backgroundReason(repository.access.value))
        val ticket = DeviceUnlockRequest(++nextPromptId)
        promptGeneration = repository.access.value.generation
        promptStoreRef = repository.access.value.storeRef
        promptResult = null
        mutableUnlockRequest.value = ticket
        mutableState.value = state.value.copy(busy = true)
    }

    private fun finishDeviceUnlockIfReady() {
        if (!foreground || closingStore || closed) return
        mutableUnlockRequest.value ?: return
        val result = promptResult ?: return
        val expected = promptGeneration
        val expectedStore = promptStoreRef
        mutableUnlockRequest.value = null
        promptGeneration = null
        promptStoreRef = null
        promptResult = null
        if (!result || expected == null || expected != repository.access.value.generation || expectedStore != repository.access.value.storeRef) {
            credentialConfirmed = false
            observeAccess(repository.access.value)
            completed()
            return
        }
        credentialConfirmed = true
        if (repository.access.value.storeRef == null || repository.access.value.reason in setOf(StoreCode.SIGNED_OUT, StoreCode.AUTH_REQUIRED, StoreCode.LEASE_EXPIRED, StoreCode.CLOCK_UNTRUSTED)) {
            // This only enables credential entry. It never invents a lease or opens an old account.
            mutableState.value = blank(repository.access.value, MobileAccess.SIGNED_OUT).copy(busy = false)
            completed()
            return
        }
        val commandEpoch = epoch
        commandRunning = true
        activeJob = scope.launch {
            try {
                withContext(ioDispatcher) { repository.unlock(expected) }
                if (current(commandEpoch, repository.access.value.generation)) reload()
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) { if (commandEpoch == epoch && !closed) showFailure(failure) }
            finally { if (commandEpoch == epoch && !closed) { commandRunning = false; completed(); reload() } }
        }
    }

    private fun signIn(action: MobileAction.SignIn) {
        if (state.value.busy || closingStore) { completed(); return }
        if (state.value.access != MobileAccess.SIGNED_OUT || !state.value.capabilities.authenticate || action.purpose != signInPurpose || !credentialConfirmed) {
            notice(MobileNotice.AUTH_REQUIRED); return
        }
        if (!validCredentialText(action.username, 150) || !validCredentialText(action.password, 128)) {
            notice(MobileNotice.CREDENTIALS_REJECTED); return
        }
        val commandEpoch = epoch
        commandRunning = true
        mutableState.value = state.value.copy(busy = true, connection = ConnectionUi.CONNECTING, notice = null)
        activeJob = scope.launch {
            try {
                withContext(ioDispatcher) {
                    val anchor = repository.beginOnlineRequest(action.generation)
                    live.authenticate(anchor, action.purpose, action.username, action.password).use { session ->
                        // A non-cooperative transport returning after cancellation cannot activate an old anchor.
                        repository.activateOnline(anchor, session.context, session.lease, session.secrets)
                    }
                }
                if (commandEpoch == epoch && foreground && !closed) {
                    mutableState.value = state.value.copy(connection = ConnectionUi.CONNECTED)
                    reload()
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) { if (commandEpoch == epoch && !closed) showFailure(failure) }
            finally { if (commandEpoch == epoch && !closed) { commandRunning = false; completed(); reload() } }
        }
    }

    private data class CommandResult(
        val snapshot: LocalSnapshot,
        val screen: MobileScreen? = null,
        val editor: EditorUi? = null,
        val reports: ReportPageUi? = null,
        val detail: ReportDetailUi? = null,
        val notice: MobileNotice? = null,
        val connected: Boolean = false,
    )

    private fun protectedCommand(action: MobileAction) {
        if (state.value.busy || closingStore) { (action as? MobileAction.QueuePhoto)?.close(); completed(); return }
        if (!state.value.showsProtectedContent || !repository.access.value.ready) { (action as? MobileAction.QueuePhoto)?.close(); notice(MobileNotice.AUTH_REQUIRED); return }
        val commandEpoch = epoch
        val generation = action.generation
        refreshJob?.cancel()
        val viewVersion = ++presentationVersion
        commandRunning = true
        mutableState.value = state.value.copy(busy = true, notice = null)
        activeJob = scope.launch {
            try {
                val result = withContext(ioDispatcher) { executeProtected(action) }
                if (current(commandEpoch, generation) && viewVersion == presentationVersion) apply(result)
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) { if (current(commandEpoch, generation)) showFailure(failure) }
            finally {
                if (action is MobileAction.QueuePhoto) action.close()
                if (current(commandEpoch, generation)) { commandRunning = false; completed() }
            }
        }
        if (action is MobileAction.QueuePhoto) activeJob?.invokeOnCompletion { action.close() }
    }

    private suspend fun executeProtected(action: MobileAction): CommandResult {
        val generation = action.generation
        val before = repository.snapshot(generation)
        fun editing(draft: DraftRecord): CommandResult {
            val snapshot = repository.snapshot(generation)
            return CommandResult(snapshot, MobileScreen.EDITOR, editor = draft.toEditor(snapshot.serverNowMillis))
        }
        return when (action) {
            is MobileAction.QueuePhoto -> {
                val detail = state.value.reportDetail ?: throw StoreFailure(StoreCode.NOT_FOUND)
                requireStore(detail.reportId == action.reportId && detail.revisionId == action.revisionId && detail.revision == action.revision &&
                    detail.history.firstOrNull()?.revision == action.revision, StoreCode.STALE_GENERATION)
                val bytes = action.bytes()
                try { repository.queuePhoto(generation, action.operationId, action.reportId, action.revisionId, action.revision, action.capture, bytes) }
                finally { bytes.fill(0); action.close() }
                CommandResult(repository.snapshot(generation), detail = detail.copy(photos = repository.photos(generation, detail.reportId, action.revisionId),
                    photoStatus = "Saved in the encrypted private queue. Upload is not yet confirmed."))
            }
            is MobileAction.UploadPhoto -> {
                requireLive()
                val detail = state.value.reportDetail ?: throw StoreFailure(StoreCode.NOT_FOUND)
                val revision = detail.revisionId ?: throw StoreFailure(StoreCode.NOT_FOUND)
                requireStore(repository.photos(generation, detail.reportId, revision).any { it.operationId == action.operationId && it.evidenceId == null }, StoreCode.NOT_FOUND)
                live.uploadPhoto(generation, action.operationId)
                CommandResult(repository.snapshot(generation), detail = detail.copy(photos = repository.photos(generation, detail.reportId, revision),
                    photoStatus = "Private upload received in quarantine. This is not image validation."), connected = true)
            }
            is MobileAction.PhotoStatus -> {
                requireLive()
                val detail = state.value.reportDetail ?: throw StoreFailure(StoreCode.NOT_FOUND)
                val revision = detail.revisionId ?: throw StoreFailure(StoreCode.NOT_FOUND)
                requireStore(repository.photos(generation, detail.reportId, revision).any { it.evidenceId == action.evidenceId }, StoreCode.NOT_FOUND)
                val status = live.photoStatus(generation, action.evidenceId)
                CommandResult(repository.snapshot(generation), detail = detail.copy(photoStatus =
                    if (status.state == "VALIDATED_PRIVATE") "Server reports private validation. No mobile download is enabled."
                    else "Quarantined or not validated. No image download is enabled."), connected = true)
            }
            is MobileAction.Navigate -> {
                if (action.screen in setOf(MobileScreen.EDITOR, MobileScreen.REPORT_DETAIL)) throw StoreFailure(StoreCode.NOT_FOUND)
                CommandResult(before, action.screen)
            }
            is MobileAction.NewDraft -> editing(repository.createDraft(generation, UUID.randomUUID().toString()))
            is MobileAction.OpenDraft -> editing(repository.openDraft(generation, action.draftId))
            is MobileAction.SaveDraft -> {
                val saved = repository.saveDraft(generation, action.commandId, action.draftId, action.expectedDraftRevision, action.form.toContent())
                editing(saved).copy(notice = MobileNotice.DRAFT_SAVED)
            }
            is MobileAction.QueueSubmission -> {
                val errors = validateMaintenanceForm(action.form, before.serverNowMillis)
                if (errors.isNotEmpty()) throw StoreFailure(StoreCode.VALIDATION_ERROR)
                // Repository must validate both expected revisions, frozen scope and canonical bytes atomically.
                repository.queueDraft(generation, action.commandId, action.draftId, action.expectedDraftRevision, action.expectedReportRevision, action.form.toContent())
                CommandResult(repository.snapshot(generation), MobileScreen.OUTBOX, notice = MobileNotice.SUBMISSION_QUEUED)
            }
            is MobileAction.SyncNow -> {
                requireLive()
                val sync = live.synchronize(generation)
                val after = repository.snapshot(generation)
                val oldReceipts = before.outbox.filter { it.delivery == DeliveryState.RECEIVED }.map { it.operationId }.toSet()
                val received = after.outbox.any { it.delivery == DeliveryState.RECEIVED && it.operationId !in oldReceipts }
                CommandResult(after, notice = if (received) MobileNotice.RECEIPT_SAVED else null, connected = sync.serviceReached)
            }
            is MobileAction.RetryOperation -> {
                requireLive()
                repository.retryOperation(generation, action.localOperationId)
                val sync = live.synchronize(generation)
                CommandResult(repository.snapshot(generation), connected = sync.serviceReached)
            }
            is MobileAction.ReconcileOperation -> editing(repository.reconcileOperation(generation, UUID.randomUUID().toString(), action.localOperationId))
            is MobileAction.LoadReports -> {
                requireLive()
                if (action.page !in 1..1_000_000) throw StoreFailure(StoreCode.VALIDATION_ERROR)
                val page = live.reports(generation, action.filter, action.page)
                CommandResult(repository.snapshot(generation), MobileScreen.REPORTS, reports = page.copy(items = page.items.toList()), connected = true)
            }
            is MobileAction.OpenReport -> {
                requireLive()
                val detail = live.report(generation, action.reportId, action.revision)
                if (detail.reportId != action.reportId || detail.revision != action.revision) throw MobileLiveFailure(LiveFailureCode.INVALID_RESPONSE)
                CommandResult(repository.snapshot(generation), MobileScreen.REPORT_DETAIL, detail = detail.copy(history = detail.history.toList()), connected = true)
            }
            is MobileAction.CorrectReport -> {
                requireLive()
                val returned = live.correction(generation, action.reportId, action.expectedRevision)
                if (returned.reportId != action.reportId || returned.revision != action.expectedRevision || !returned.canCorrect || returned.review != ReviewUi.RETURNED)
                    throw StoreFailure(StoreCode.STALE_DRAFT)
                // A fresh typed transport result, never a cached UI detail, supplies the source.
                editing(repository.createCorrectionDraft(generation, UUID.randomUUID().toString(), action.reportId, action.expectedRevision, returned.form.toContent()))
            }
            else -> throw StoreFailure(StoreCode.VALIDATION_ERROR)
        }
    }

    private fun requireLive() { if (!live.available) throw MobileLiveFailure(LiveFailureCode.UNAVAILABLE) }

    /** Immediate generation revoke precedes any potentially blocking durable close. */
    private fun fence(reason: StoreCode, preservePrompt: Boolean = false) {
        epoch++
        bootstrapJob?.cancel()
        bootstrapping = false
        activeJob?.cancel()
        activeJob = null
        commandRunning = false
        refreshJob?.cancel()
        presentationVersion++
        credentialConfirmed = false
        if (!preservePrompt) clearPrompt()
        // StateFlow collectors may resume synchronously from invalidate on an immediate dispatcher.
        closingStore = true
        val previous = repository.access.value.generation
        val access = repository.invalidate(reason)
        live.cancelForFence(previous, reason)
        if (preservePrompt) {
            if (promptStoreRef == access.storeRef) promptGeneration = access.generation else clearPrompt()
        }
        mutableState.value = blank(access).copy(busy = true)
        val fenceEpoch = epoch
        val previousCleanup = cleanupJob
        cleanupJob = scope.launch {
            try {
                previousCleanup?.join()
                withContext(ioDispatcher) { repository.fence(reason, access.generation) }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) {
                if (fenceEpoch == epoch && !closed) mutableState.value = blank(repository.access.value).copy(notice = MobileNotice.STORAGE_UNAVAILABLE)
            } finally {
                if (fenceEpoch == epoch && !closed) {
                    closingStore = false
                    if (mutableUnlockRequest.value != null) {
                        if (promptStoreRef == repository.access.value.storeRef) promptGeneration = repository.access.value.generation else clearPrompt()
                    }
                    observeAccess(repository.access.value)
                    completed()
                    finishDeviceUnlockIfReady()
                    if (foreground && needsSelectionRestore) restoreSelection()
                }
            }
        }
    }

    private fun signOut(generation: Long) {
        if (closingStore) return
        epoch++
        activeJob?.cancel()
        activeJob = null
        commandRunning = false
        refreshJob?.cancel()
        presentationVersion++
        credentialConfirmed = false
        clearPrompt()
        signInPurpose = SignInPurpose.RECOVER_ENROLLMENT
        val commandEpoch = epoch
        closingStore = true
        val logout = try { repository.logoutAndInvalidate(generation) }
        catch (_: StoreFailure) { closingStore = false; observeAccess(repository.access.value); return }
        val invalidated = logout.access
        // Closing generation is synchronous. A remote logout cannot reopen this account for tokens.
        mutableState.value = blank(invalidated, MobileAccess.SIGNED_OUT).copy(busy = true)
        live.cancelForFence(generation, StoreCode.SIGNED_OUT)
        cleanupJob = scope.launch {
            var localCompleted = false
            var remote = LogoutConfirmation.UNCONFIRMED
            try {
                withContext(ioDispatcher) {
                    repository.fence(StoreCode.SIGNED_OUT, invalidated.generation)
                    localCompleted = true
                    logout.authorization?.let { if (live.available) remote = live.logout(it) }
                }
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (_: Exception) { /* Never turn a missing response into confirmed server revocation. */ }
            finally {
                logout.authorization?.close()
                if (commandEpoch == epoch && !closed) {
                    closingStore = false
                    mutableState.value = blank(repository.access.value, MobileAccess.SIGNED_OUT).copy(
                        notice = when {
                            !localCompleted -> MobileNotice.STORAGE_UNAVAILABLE
                            remote == LogoutConfirmation.CONFIRMED -> MobileNotice.SIGNED_OUT_CONFIRMED
                            else -> MobileNotice.SIGNED_OUT_LOCAL
                        })
                    completed()
                }
            }
        }
    }

    private fun observeAccess(access: StoreAccess) {
        if (closed || runtime == null || bootstrapping || access != repository.access.value) return
        if (!access.ready) {
            if (access.generation != state.value.accountGeneration && !closingStore) {
                epoch++
                activeJob?.cancel()
                commandRunning = false
                refreshJob?.cancel()
                presentationVersion++
                clearPrompt()
                credentialConfirmed = false
                live.cancelForFence(state.value.accountGeneration, access.reason)
            }
            mutableState.value = blank(access).copy(busy = closingStore || mutableUnlockRequest.value != null)
        } else if (!foreground) {
            fence(StoreCode.LOCKED, preservePrompt = mutableUnlockRequest.value != null)
        } else if (!closingStore && (access.generation != state.value.accountGeneration || !state.value.showsProtectedContent)) {
            mutableState.value = blank(access, MobileAccess.STARTING)
            reload()
        }
    }

    private fun reload() {
        if (closed || closingStore || commandRunning || !foreground || !repository.access.value.ready) return
        val commandEpoch = epoch
        val generation = repository.access.value.generation
        refreshJob?.cancel()
        val viewVersion = ++presentationVersion
        refreshJob = scope.launch {
            try {
                val snapshot = withContext(ioDispatcher) { repository.snapshot(generation) }
                if (current(commandEpoch, generation) && viewVersion == presentationVersion) apply(CommandResult(snapshot))
            } catch (cancelled: CancellationException) { throw cancelled }
            catch (failure: Exception) { if (current(commandEpoch, generation) && viewVersion == presentationVersion) showFailure(failure) }
        }
    }

    private fun apply(result: CommandResult) {
        val previous = state.value
        val snapshot = result.snapshot
        val context = snapshot.context
        val supportedTemplate = context.capture.templateVersion == MAINTENANCE_TEMPLATE
        val screen = result.screen ?: previous.screen
        mutableState.value = previous.copy(
            accountGeneration = repository.access.value.generation, access = MobileAccess.READY,
            context = AccountContextUi(context.displayName, context.organizationLabel, context.unitLabel, context.channelLabel, context.capture.profile,
                "Offline access is bounded by the verified lease and device unlock.", supportedTemplate),
            capabilities = MobileCapabilities(authenticate = live.available && credentialConfirmed, unlock = true,
                saveDraft = supportedTemplate, queueSubmission = supportedTemplate, synchronize = live.available, readReports = live.available),
            screen = screen, localDataLoaded = true,
            drafts = snapshot.drafts.map { DraftUi(it.id, it.content.siteLabel.ifEmpty { "Untitled maintenance draft" },
                MaintenanceCategory.entries.firstOrNull { category -> category.wireValue == it.content.category }?.label ?: "Category not chosen", dateLabel(it.savedAtServerMillis)) },
            outbox = snapshot.outbox.map { item -> OutboxItemUi(item.operationId, item.content.siteLabel.ifEmpty { "Maintenance submission" }, dateLabel(item.queuedAtServerMillis),
                DeliveryUi.valueOf(item.delivery.name), item.pause?.let { PauseUi.valueOf(it.name) },
                retryAtLabel = item.nextAttemptElapsed?.let { "Waiting for retry eligibility" },
                canRetry = item.delivery == DeliveryState.QUEUED && item.pause == null && live.available,
                canCreateCorrection = item.delivery in setOf(DeliveryState.NEEDS_CORRECTION, DeliveryState.CONFLICT) || item.pause == PauseReason.CONTEXT_CHANGED) },
            editor = if (screen == MobileScreen.EDITOR) result.editor ?: previous.editor else null,
            reports = result.reports ?: previous.reports,
            reportDetail = if (screen == MobileScreen.REPORT_DETAIL) result.detail ?: previous.reportDetail else null,
            notice = result.notice ?: previous.notice,
            connection = if (result.connected) ConnectionUi.CONNECTED else previous.connection,
        )
    }

    private fun blank(access: StoreAccess, override: MobileAccess? = null): MobileUiState {
        val mobileAccess = override ?: access.reason.toMobileAccess()
        val canPrompt = access.reason !in setOf(StoreCode.UNSUPPORTED_DEVICE, StoreCode.KEY_UNAVAILABLE, StoreCode.REVOKED, StoreCode.SCOPE_DENIED, StoreCode.STORAGE_UNAVAILABLE, StoreCode.TEMPLATE_UNSUPPORTED)
        return MobileUiState(accountGeneration = access.generation, access = mobileAccess,
            capabilities = MobileCapabilities(authenticate = live.available && mobileAccess != MobileAccess.TEMPLATE_UNSUPPORTED && (mobileAccess != MobileAccess.SIGNED_OUT || credentialConfirmed),
                unlock = canPrompt && (access.storeRef != null || live.available)),
            connection = if (live.available) ConnectionUi.NOT_CHECKED else ConnectionUi.UNAVAILABLE,
            interactionRevision = state.value.interactionRevision, signInPurpose = signInPurpose)
    }

    private fun showFailure(failure: Exception) {
        when (failure) {
            is StoreFailure -> when (failure.code) {
                StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED, StoreCode.LEASE_EXPIRED, StoreCode.CLOCK_UNTRUSTED,
                StoreCode.KEY_UNAVAILABLE, StoreCode.REVOKED, StoreCode.SCOPE_DENIED, StoreCode.AUTH_REQUIRED,
                StoreCode.UNSUPPORTED_DEVICE, StoreCode.STORAGE_UNAVAILABLE, StoreCode.TEMPLATE_UNSUPPORTED -> fence(failure.code)
                StoreCode.STALE_DRAFT, StoreCode.COMMAND_CONFLICT, StoreCode.CONTEXT_CHANGED -> notice(MobileNotice.CONFLICT)
                StoreCode.VALIDATION_ERROR -> notice(MobileNotice.VALIDATION_REQUIRED)
                StoreCode.STALE_GENERATION -> observeAccess(repository.access.value)
                else -> notice(MobileNotice.TEMPORARY_FAILURE)
            }
            is MobileLiveFailure -> when (failure.code) {
                LiveFailureCode.AUTH_REQUIRED -> fence(StoreCode.AUTH_REQUIRED)
                LiveFailureCode.REVOKED -> fence(StoreCode.REVOKED)
                LiveFailureCode.SCOPE_DENIED -> fence(StoreCode.SCOPE_DENIED)
                LiveFailureCode.CONTEXT_CHANGED -> fence(StoreCode.CONTEXT_CHANGED)
                LiveFailureCode.CREDENTIALS_REJECTED -> notice(MobileNotice.CREDENTIALS_REJECTED)
                LiveFailureCode.CONFLICT -> notice(MobileNotice.CONFLICT)
                else -> {
                    mutableState.value = state.value.copy(connection = if (failure.code == LiveFailureCode.OFFLINE) ConnectionUi.OFFLINE else ConnectionUi.UNAVAILABLE)
                    notice(MobileNotice.CONNECTION_UNAVAILABLE)
                }
            }
            else -> notice(MobileNotice.TEMPORARY_FAILURE)
        }
    }

    private fun current(commandEpoch: Long, generation: Long): Boolean = !closed && foreground && epoch == commandEpoch && repository.access.value.generation == generation && repository.access.value.ready
    private fun notice(notice: MobileNotice) { mutableState.value = state.value.copy(notice = notice); completed() }
    private fun completed() { mutableState.value = state.value.copy(busy = bootstrapping || closingStore || commandRunning || mutableUnlockRequest.value != null, interactionRevision = state.value.interactionRevision + 1) }
    private fun clearPrompt() { mutableUnlockRequest.value = null; promptGeneration = null; promptStoreRef = null; promptResult = null }

    override fun close() {
        if (closed) return
        closed = true
        epoch++
        activeJob?.cancel()
        bootstrapJob?.cancel()
        refreshJob?.cancel()
        clearPrompt()
        mutableState.value = MobileUiState(access = MobileAccess.LOCKED)
        if (runtime != null && supportedDevice) {
            val previous = repository.access.value.generation
            val reason = backgroundReason(repository.access.value)
            repository.invalidate(reason)
            live.cancelForFence(previous, reason)
            scope.launch { try { withContext(ioDispatcher) { runtime.close() } } finally { scope.cancel() } }
        } else scope.cancel()
    }
}

private fun backgroundReason(access: StoreAccess): StoreCode = when (access.reason) {
    StoreCode.READY, StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED -> if (access.storeRef == null) StoreCode.SIGNED_OUT else StoreCode.LOCKED
    else -> access.reason // Never downgrade signed-out, expired, lost-key or known-revoked state.
}

private fun StoreCode.toMobileAccess(): MobileAccess = when (this) {
    StoreCode.READY -> MobileAccess.STARTING
    StoreCode.SIGNED_OUT, StoreCode.AUTH_REQUIRED -> MobileAccess.SIGNED_OUT
    StoreCode.LOCKED -> MobileAccess.LOCKED
    StoreCode.UNLOCK_REQUIRED -> MobileAccess.UNLOCK_REQUIRED
    StoreCode.LEASE_EXPIRED, StoreCode.CLOCK_UNTRUSTED -> MobileAccess.LEASE_EXPIRED
    StoreCode.KEY_UNAVAILABLE -> MobileAccess.KEY_UNAVAILABLE
    StoreCode.UNSUPPORTED_DEVICE -> MobileAccess.UNSUPPORTED_DEVICE
    StoreCode.REVOKED, StoreCode.SCOPE_DENIED -> MobileAccess.ENROLLMENT_SUSPENDED
    StoreCode.CONTEXT_CHANGED -> MobileAccess.CONTEXT_CHANGED
    StoreCode.TEMPLATE_UNSUPPORTED -> MobileAccess.TEMPLATE_UNSUPPORTED
    else -> MobileAccess.STORAGE_UNAVAILABLE
}

internal fun MaintenanceForm.toContent() = MaintenanceContent(observedAt, category?.wireValue ?: "", urgency?.wireValue ?: "", area?.wireValue ?: "", siteLabel, reporterLabel, narrative, assistance?.wireValue ?: "")
internal fun MaintenanceContent.toForm() = MaintenanceForm(observedAt, MaintenanceCategory.entries.firstOrNull { it.wireValue == category },
    MaintenanceUrgency.entries.firstOrNull { it.wireValue == urgency }, MaintenanceArea.entries.firstOrNull { it.wireValue == areaLabel }, siteLabel, reporterLabel, narrative,
    MaintenanceAssistance.entries.firstOrNull { it.wireValue == assistanceRequested })
private fun DraftRecord.toEditor(serverNowMillis: Long) = EditorUi(id, revision, content.toForm(), expectedReportRevision,
    correctionReference = reportId?.let { "Returned report correction" }, estimatedServerTimeMillis = serverNowMillis)
private fun dateLabel(millis: Long): String = SimpleDateFormat("dd MMM yyyy, HH:mm 'UTC'", Locale.ROOT).apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(millis))

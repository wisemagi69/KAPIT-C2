package org.kapit.c2.mobile.sync

import java.io.Closeable
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.*
import org.kapit.c2.mobile.domain.*

/** Creates the real owner on IO; constructing a foreground lease never opens disk or keys. */
internal class RuntimeRepositoryOwner(
    private val scope: CoroutineScope,
    private val factory: () -> RuntimeStorage,
    private val io: CoroutineDispatcher = Dispatchers.IO,
    private val requireIo: () -> Unit = {},
    private val onReleased: (StoreAccess) -> Unit = {},
) : Closeable {
    private val monitor = Any()
    private val ready = CompletableDeferred<RuntimeStorage>()
    private var actual: RuntimeStorage? = null
    private var current: RuntimeRepository? = null
    private var state = StoreAccess(1)
    private val beforeInitialization = mutableListOf<OwnedFence>()
    private var closed = false

    init {
        scope.launch(io) {
            try {
                val created = factory()
                synchronized(monitor) {
                    if (closed) { created.repository.close(); throw StoreFailure(StoreCode.STALE_GENERATION) }
                    requireStore(created.repository.access.value.generation == 1L, StoreCode.STORAGE_UNAVAILABLE)
                    beforeInitialization.forEach { pending ->
                        val fenced = created.repository.invalidate(pending.reason)
                        requireStore(fenced.generation == pending.generation, StoreCode.STORAGE_UNAVAILABLE)
                    }
                    beforeInitialization.clear()
                    actual = created
                    publishLocked(created.repository.access.value)
                    ready.complete(created)
                }
                created.repository.access.collect { publish(it) }
            } catch (_: CancellationException) { ready.completeExceptionally(StoreFailure(StoreCode.STORAGE_UNAVAILABLE)) }
            catch (_: Exception) {
                synchronized(monitor) {
                    publishLocked(StoreAccess(state.generation + 1, reason = StoreCode.STORAGE_UNAVAILABLE, storeRef = state.storeRef))
                    ready.completeExceptionally(StoreFailure(StoreCode.STORAGE_UNAVAILABLE))
                }
            }
        }
    }

    fun acquire(onSchedule: (StoreAccess) -> Unit): RuntimeRepository {
        var old: RuntimeRepository? = null
        val lease = synchronized(monitor) {
            requireStore(!closed, StoreCode.STORAGE_UNAVAILABLE)
            current?.let {
                invalidateLocked(it, closeReason(state))
                it.retired = true
                it.mutableAccess.value = it.mutableAccess.value.copy(ready = false, reason = StoreCode.STALE_GENERATION)
                old = it
            }
            RuntimeRepository(this, state, onSchedule).also { current = it }
        }
        // Durable cleanup belongs to the old lease and never targets a replacement generation.
        old?.let { prior -> scope.launch(io) { try { prior.close() } catch (_: Exception) { /* Safe state is already fenced. */ } } }
        return lease
    }

    fun isCurrent(lease: RuntimeRepository): Boolean = synchronized(monitor) { !closed && !lease.retired && current === lease }
    fun isUnowned(access: StoreAccess): Boolean = synchronized(monitor) {
        !closed && current == null && state == access && !state.ready && state.reason == StoreCode.LOCKED && state.storeRef != null
    }
    suspend fun storage(): RuntimeStorage = ready.await()

    fun invalidate(lease: RuntimeRepository, reason: StoreCode): StoreAccess = synchronized(monitor) {
        if (!isCurrent(lease)) return@synchronized lease.mutableAccess.value.copy(ready = false, reason = StoreCode.STALE_GENERATION)
        invalidateLocked(lease, reason)
    }

    private fun invalidateLocked(lease: RuntimeRepository, reason: StoreCode): StoreAccess {
        val result = actual?.repository?.invalidate(reason)
            ?: StoreAccess(state.generation + 1, false, reason, state.storeRef).also { beforeInitialization += OwnedFence(it.generation, reason) }
        lease.pending[result.generation] = OwnedFence(result.generation, reason)
        publishLocked(result)
        return result
    }

    fun logout(lease: RuntimeRepository, expectedGeneration: Long): LogoutFence = synchronized(monitor) {
        requireStore(isCurrent(lease) && state.generation == expectedGeneration, StoreCode.STALE_GENERATION)
        val result = actual?.repository?.logoutAndInvalidate(expectedGeneration)
            ?: LogoutFence(invalidateLocked(lease, StoreCode.SIGNED_OUT), null)
        lease.pending[result.access.generation] = OwnedFence(result.access.generation, StoreCode.SIGNED_OUT)
        publishLocked(result.access)
        result
    }

    fun fence(lease: RuntimeRepository, reason: StoreCode, generation: Long?): StoreAccess {
        requireIo()
        val captured = generation ?: invalidate(lease, reason).generation
        val owned = synchronized(monitor) {
            if (lease.completed[captured] == reason) return state
            lease.pending[captured]
        }
        requireStore(owned != null && owned.reason == reason, StoreCode.STALE_GENERATION)
        val store = runBlocking { ready.await() }
        val result = store.repository.fence(reason, captured)
        synchronized(monitor) { lease.pending.remove(captured); lease.completed[captured] = reason; publishLocked(store.repository.access.value) }
        return result
    }

    fun <T> call(lease: RuntimeRepository, action: (RuntimeStorage) -> T): T {
        requireIo()
        requireStore(isCurrent(lease), StoreCode.STALE_GENERATION)
        val store = runBlocking { ready.await() }
        requireStore(isCurrent(lease), StoreCode.STALE_GENERATION)
        val result = action(store)
        publish(store.repository.access.value)
        if (!isCurrent(lease)) {
            (result as? Closeable)?.close()
            throw StoreFailure(StoreCode.STALE_GENERATION)
        }
        return result
    }

    fun release(lease: RuntimeRepository) {
        requireIo()
        val fences = synchronized(monitor) {
            if (lease.released && lease.pending.isEmpty()) return
            if (current === lease && !closed) {
                if (state.ready || lease.pending.isEmpty()) invalidateLocked(lease, closeReason(state))
                current = null
            }
            lease.retired = true
            lease.released = true
            lease.mutableAccess.value = lease.mutableAccess.value.copy(ready = false)
            lease.pending.values.toList()
        }
        var failed = false
        fences.forEach { pending ->
            try { fence(lease, pending.reason, pending.generation) } catch (_: Exception) { failed = true }
        }
        if (failed) throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
        val handoff = synchronized(monitor) {
            state.takeIf { !lease.handedOff && current == null && !closed && it.reason == StoreCode.LOCKED &&
                !it.ready && it.storeRef != null && fences.any { captured -> captured.generation == it.generation } }
                ?.also { lease.handedOff = true }
        }
        handoff?.let(onReleased)
    }

    private fun publish(access: StoreAccess) = synchronized(monitor) { publishLocked(access) }
    private fun publishLocked(access: StoreAccess) {
        if (access.generation < state.generation) return
        state = access
        current?.takeUnless { it.retired }?.mutableAccess?.value = access
    }

    /** Final process-owner teardown only; foreground MobileRuntime.close never invokes this. */
    override fun close() {
        requireIo()
        val store = synchronized(monitor) {
            closed = true
            current?.let { it.retired = true; it.mutableAccess.value = it.mutableAccess.value.copy(ready = false, reason = StoreCode.LOCKED) }
            current = null
            actual
        }
        store?.repository?.close()
    }

    internal data class OwnedFence(val generation: Long, val reason: StoreCode)
    private fun closeReason(value: StoreAccess) = when (value.reason) {
        StoreCode.READY, StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED -> if (value.storeRef == null) StoreCode.SIGNED_OUT else StoreCode.LOCKED
        else -> value.reason
    }
}

/** Public storage operations are delegated only while this exact foreground lease owns access. */
internal class RuntimeRepository(
    private val owner: RuntimeRepositoryOwner,
    initial: StoreAccess,
    private val onSchedule: (StoreAccess) -> Unit,
) : ProtectedRepository {
    internal val mutableAccess = MutableStateFlow(initial)
    override val access: StateFlow<StoreAccess> = mutableAccess.asStateFlow()
    internal var retired = false
    internal var released = false
    internal var handedOff = false
    internal val pending = linkedMapOf<Long, RuntimeRepositoryOwner.OwnedFence>()
    internal val completed = mutableMapOf<Long, StoreCode>()
    fun isCurrent() = owner.isCurrent(this)
    private fun <T> call(body: (ProtectedRepository) -> T) = owner.call(this) { body(it.repository) }
    private fun scheduled(access: StoreAccess): StoreAccess { if (access.ready) onSchedule(access); return access }
    override fun restoreSelection(expectedGeneration: Long) = call { it.restoreSelection(expectedGeneration) }
    override fun beginOnlineRequest(expectedGeneration: Long) = call { it.beginOnlineRequest(expectedGeneration) }
    override fun activateOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets) =
        scheduled(call { it.activateOnline(anchor, context, offer, secrets) })
    override fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets) =
        call { it.renewOnline(anchor, context, offer, secrets) }
    override fun unlock(expectedGeneration: Long) = scheduled(call { it.unlock(expectedGeneration) })
    override fun invalidate(reason: StoreCode) = owner.invalidate(this, reason)
    override fun logoutAndInvalidate(expectedGeneration: Long) = owner.logout(this, expectedGeneration)
    override fun fence(reason: StoreCode, invalidatedGeneration: Long?): StoreAccess {
        val captured = invalidatedGeneration ?: invalidate(reason).generation
        return owner.fence(this, reason, captured).also {
            if (it.generation == captured && isCurrent() && access.value == it && it.reason == StoreCode.LOCKED && !it.ready) onSchedule(it)
        }
    }
    override fun snapshot(expectedGeneration: Long) = call { it.snapshot(expectedGeneration) }
    override fun createDraft(expectedGeneration: Long, commandId: String, content: MaintenanceContent) = call { it.createDraft(expectedGeneration, commandId, content) }
    override fun openDraft(expectedGeneration: Long, draftId: String) = call { it.openDraft(expectedGeneration, draftId) }
    override fun saveDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedRevision: Long, content: MaintenanceContent) =
        call { it.saveDraft(expectedGeneration, commandId, draftId, expectedRevision, content) }
    override fun queueDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedDraftRevision: Long, expectedReportRevision: Int, content: MaintenanceContent): OutboxRecord =
        call { it.queueDraft(expectedGeneration, commandId, draftId, expectedDraftRevision, expectedReportRevision, content) }.also { onSchedule(access.value) }
    override fun createCorrectionDraft(expectedGeneration: Long, commandId: String, reportId: String, expectedReportRevision: Int, content: MaintenanceContent, predecessorOperationId: String?) =
        call { it.createCorrectionDraft(expectedGeneration, commandId, reportId, expectedReportRevision, content, predecessorOperationId) }
    override fun reconcileOperation(expectedGeneration: Long, commandId: String, operationId: String) = call { it.reconcileOperation(expectedGeneration, commandId, operationId) }
    override fun claimNext(expectedGeneration: Long) = call { it.claimNext(expectedGeneration) }
    override fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt) = call { it.commitReceipt(claim, receipt) }
    override fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long?) = call { it.recordFailure(claim, delivery, pause, retryAfterMillis) }
    override fun retryOperation(expectedGeneration: Long, operationId: String) = call { it.retryOperation(expectedGeneration, operationId) }
    override fun credentials(expectedGeneration: Long) = call { it.credentials(expectedGeneration) }
    override fun cacheReports(expectedGeneration: Long, reports: List<CachedReport>) = call { it.cacheReports(expectedGeneration, reports) }
    override fun cachedReports(expectedGeneration: Long) = call { it.cachedReports(expectedGeneration) }
    override fun cacheOpenedRevision(expectedGeneration: Long, report: CachedReport) = call { it.cacheOpenedRevision(expectedGeneration, report) }
    override fun cachedOpenedRevision(expectedGeneration: Long, reportId: String, revision: Int) = call { it.cachedOpenedRevision(expectedGeneration, reportId, revision) }
    override fun close() = owner.release(this)
}

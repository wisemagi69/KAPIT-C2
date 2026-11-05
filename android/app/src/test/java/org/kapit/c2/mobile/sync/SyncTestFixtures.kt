package org.kapit.c2.mobile.sync

import kotlinx.coroutines.flow.MutableStateFlow
import org.kapit.c2.mobile.data.remote.*
import org.kapit.c2.mobile.domain.*

internal fun id(n: Int) = "00000000-0000-4000-8000-${n.toString().padStart(12, '0')}"
internal val testContext = AuthorizedContext(CaptureContext(AccountIdentity(id(1), id(2), id(3)), id(4), id(5),
    "DEMO-REDUCED", MAINTENANCE_TEMPLATE), id(6), 1, "Synthetic reporter", "Synthetic organization", "Synthetic unit", "Synthetic channel")
internal const val testNow = 1_792_224_000_000L
internal val testOffer = LeaseOffer(testNow, testNow + 86_400_000, testNow + 604_800_000, 86_400)
internal fun secrets() = SessionSecrets(byteArrayOf(1, 2), byteArrayOf(3, 4), testNow + 600_000, testNow + 604_800_000)
internal fun remoteSession() = RemoteSession(RemoteContext(testContext, testOffer), secrets())
internal fun claim(generation: Long = 1) = DeliveryClaim(generation, testContext.capture.account.storeRef, id(10), id(11), 0,
    "a".repeat(64), id(12), id(13), "boot", 121_000, "immutable synthetic operation".toByteArray())
internal fun acceptedReceipt(claim: DeliveryClaim) = AcceptedReceipt.parse(("{\"operation_id\":\"${claim.operationId}\",\"report_id\":\"${claim.reportId}\",\"revision_id\":\"${id(14)}\"," +
    "\"revision_no\":1,\"delivery_status\":\"RECEIVED\",\"processing_status\":\"PENDING\",\"shared\":false}").toByteArray(), claim)

/** Model fixtures test orchestration only; they make no storage durability/encryption claim. */
internal open class ProtocolFixture : RemoteProtocol {
    override suspend fun challenge(request: ChallengeRequest, start: ClockStamp): ValidatedChallenge = error("unexpected challenge")
    override suspend fun token(challenge: ValidatedChallenge, signature: ByteArray, start: ClockStamp): RemoteSession = error("unexpected token")
    override suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteSession = error("unexpected refresh")
    override suspend fun me(access: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteContext = error("unexpected me")
    override suspend fun logout(access: ByteArray) = error("unexpected logout")
    override suspend fun receipt(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt = error("unexpected receipt")
    override suspend fun send(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt = error("unexpected send")
    override suspend fun reports(access: ByteArray, query: ReportQuery): RemoteReportPage = error("unexpected reports")
    override suspend fun revision(access: ByteArray, reportId: String, revision: Int): RemoteRevision = error("unexpected revision")
    override fun close() = Unit
}

internal class DurableRefreshModel { var marker: RefreshAttempt? = null; var revision = 0L; var replacements = 0 }
internal class SessionFixture(val durable: DurableRefreshModel = DurableRefreshModel()) : SyncSession {
    override val generation = 1L
    override val storeRef = testContext.capture.account.storeRef
    override val context = testContext
    var elapsed = 1_000L
    var usable = true
    var stale = false
    var denied: StoreCode? = null
    var pending = true
    var attempts = 1
    var committed = 0
    var delay: Long? = null
    var delivery: DeliveryState? = null
    var failCommit = false
    var closed = false
    val credentialsDetached = mutableListOf<SessionSecrets>()
    override fun beginOnlineRequest(): OnlineRequestAnchor {
        if (stale) throw StoreFailure(StoreCode.STALE_GENERATION)
        denied?.let { throw StoreFailure(it) }
        return OnlineRequestAnchor(generation, clock(), durable.revision)
    }
    override fun clock() = ClockStamp(elapsed, "boot")
    override fun serverTimeLowerMillis() = testNow
    override fun accessTokenUsable(): Boolean { beginOnlineRequest(); return usable && durable.marker == null }
    override fun credentials(): SessionSecrets {
        beginOnlineRequest()
        if (durable.marker != null) throw StoreFailure(StoreCode.AUTH_REQUIRED)
        return secrets().also { credentialsDetached += it }
    }
    override fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets) {
        check(durable.marker == null); durable.revision++
    }
    override fun beginRefresh(anchor: OnlineRequestAnchor): RefreshAttempt {
        check(anchor.authorityRevision == durable.revision && durable.marker == null)
        return object : RefreshAttempt {}.also { durable.marker = it }
    }
    override fun completeRefresh(attempt: RefreshAttempt, anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets) {
        beginOnlineRequest()
        check(durable.marker === attempt && anchor.authorityRevision == durable.revision)
        if (failCommit) throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
        durable.replacements++; durable.revision++; durable.marker = null; usable = true
    }
    var failAbandon = false
    var abandons = 0
    override fun abandonRefresh(attempt: RefreshAttempt) {
        beginOnlineRequest()
        check(durable.marker === attempt)
        if (failAbandon) throw StoreFailure(StoreCode.AUTH_REQUIRED)
        abandons++; durable.marker = null
    }
    override fun claimNext(): ClaimedOperation? {
        beginOnlineRequest()
        return if (pending) { pending = false; ClaimedOperation(claim(), attempts) } else null
    }
    override fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt) { beginOnlineRequest(); committed++ }
    override fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long?) {
        beginOnlineRequest(); this.delivery = delivery; delay = retryAfterMillis
    }
    override fun deny(reason: StoreCode) { if (stale) throw StoreFailure(StoreCode.STALE_GENERATION); denied = reason }
    override fun nextDeliveryDelayMillis() = delay
    override fun close() { closed = true }
}

internal open class RepositoryFixture : ProtectedRepository {
    override val access = MutableStateFlow(StoreAccess(1))
    var revision = 0L
    var closed = false
    var fenceFailure = false
    val durableFences = mutableListOf<Pair<Long, StoreCode>>()
    val pendingFences = mutableMapOf<Long, StoreCode>()
    fun selectReady() { access.value = StoreAccess(access.value.generation, true, StoreCode.READY, testContext.capture.account.storeRef) }
    fun checkGeneration(generation: Long) { if (generation != access.value.generation) throw StoreFailure(StoreCode.STALE_GENERATION) }
    override fun restoreSelection(expectedGeneration: Long): StoreAccess { checkGeneration(expectedGeneration); return access.value }
    override fun beginOnlineRequest(expectedGeneration: Long): OnlineRequestAnchor { checkGeneration(expectedGeneration); return OnlineRequestAnchor(expectedGeneration, ClockStamp(1_000, "boot"), revision) }
    override fun activateOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets): StoreAccess {
        checkGeneration(anchor.generation); access.value = StoreAccess(anchor.generation + 1, true, StoreCode.READY, context.capture.account.storeRef); return access.value
    }
    override fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets): StoreAccess { revision++; return access.value }
    override fun unlock(expectedGeneration: Long): StoreAccess { checkGeneration(expectedGeneration); selectReady(); return access.value }
    override fun invalidate(reason: StoreCode): StoreAccess {
        access.value = access.value.copy(generation = access.value.generation + 1, ready = false, reason = reason)
        pendingFences[access.value.generation] = reason
        return access.value
    }
    override fun logoutAndInvalidate(expectedGeneration: Long): LogoutFence { checkGeneration(expectedGeneration); return LogoutFence(invalidate(StoreCode.SIGNED_OUT), null) }
    override fun fence(reason: StoreCode, invalidatedGeneration: Long?): StoreAccess {
        val generation = invalidatedGeneration ?: invalidate(reason).generation
        check(pendingFences[generation] == reason || durableFences.contains(generation to reason))
        if (fenceFailure) throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
        pendingFences.remove(generation); durableFences += generation to reason
        return access.value
    }
    override fun snapshot(expectedGeneration: Long): LocalSnapshot = unsupported()
    override fun createDraft(expectedGeneration: Long, commandId: String, content: MaintenanceContent): DraftRecord = unsupported()
    override fun openDraft(expectedGeneration: Long, draftId: String): DraftRecord = unsupported()
    override fun saveDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedRevision: Long, content: MaintenanceContent): DraftRecord = unsupported()
    override fun queueDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedDraftRevision: Long, expectedReportRevision: Int, content: MaintenanceContent): OutboxRecord = unsupported()
    override fun createCorrectionDraft(expectedGeneration: Long, commandId: String, reportId: String, expectedReportRevision: Int, content: MaintenanceContent, predecessorOperationId: String?): DraftRecord = unsupported()
    override fun reconcileOperation(expectedGeneration: Long, commandId: String, operationId: String): DraftRecord = unsupported()
    override fun claimNext(expectedGeneration: Long): DeliveryClaim? = unsupported()
    override fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt): Unit = unsupported()
    override fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long?): Unit = unsupported()
    override fun retryOperation(expectedGeneration: Long, operationId: String): Unit = unsupported()
    override fun credentials(expectedGeneration: Long): SessionSecrets = unsupported()
    override fun cacheReports(expectedGeneration: Long, reports: List<CachedReport>): Unit = unsupported()
    override fun cachedReports(expectedGeneration: Long): List<CachedReport> = unsupported()
    override fun cacheOpenedRevision(expectedGeneration: Long, report: CachedReport): Unit = unsupported()
    override fun cachedOpenedRevision(expectedGeneration: Long, reportId: String, revision: Int): CachedReport? = unsupported()
    override fun close() { closed = true }
    private fun unsupported(): Nothing = error("unexpected repository operation")
}

internal fun storageFixture(repository: ProtectedRepository) = object : RuntimeStorage {
    override val repository = repository
    override val journal: EnrollmentJournal get() = error("unexpected journal")
    override fun foreground(generation: Long): SyncSession = error("unexpected foreground")
    override fun worker(storeRef: String): SyncSession = error("unexpected worker")
}

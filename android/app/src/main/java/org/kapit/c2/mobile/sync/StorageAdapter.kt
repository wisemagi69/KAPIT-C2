package org.kapit.c2.mobile.sync

import org.kapit.c2.mobile.data.local.AndroidProtectedRepository
import org.kapit.c2.mobile.domain.*

/** Adapts real086 capabilities; does not implement a second journal/store or grant authority. */
@androidx.annotation.RequiresApi(35)
internal class StorageAdapter(override val repository: AndroidProtectedRepository) : RuntimeStorage {
    override val journal: EnrollmentJournal = JournalAdapter(repository.enrollmentJournal)
    override fun foreground(generation: Long): SyncSession = SessionAdapter(repository.foregroundSync(generation))
    override fun worker(storeRef: String): SyncSession = SessionAdapter(repository.openWorker(repository.access.value.generation, storeRef))
}

private class SessionAdapter(private val actual: StoreSyncSession) : SyncSession {
    override val generation get() = actual.generation
    override val storeRef get() = actual.storeRef
    override val context get() = actual.context
    override fun beginOnlineRequest() = actual.beginOnlineRequest()
    override fun clock() = actual.clock()
    override fun serverTimeLowerMillis() = actual.serverTimeLowerMillis()
    override fun accessTokenUsable() = actual.accessTokenUsable()
    override fun credentials() = actual.credentials()
    override fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets) = actual.renewOnline(anchor, context, offer, secrets)
    override fun beginRefresh(anchor: OnlineRequestAnchor): RefreshAttempt = Refresh(actual.beginRefresh(anchor))
    override fun completeRefresh(attempt: RefreshAttempt, anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets) =
        actual.completeRefresh((attempt as? Refresh ?: throw StoreFailure(StoreCode.STALE_GENERATION)).actual, anchor, context, offer, secrets)
    override fun abandonRefresh(attempt: RefreshAttempt) =
        actual.abandonRefresh((attempt as? Refresh ?: throw StoreFailure(StoreCode.STALE_GENERATION)).actual)
    override fun claimNext(): ClaimedOperation? = actual.claimNext()?.let { ClaimedOperation(it.claim, it.attempt) }
    override fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt) = actual.commitReceipt(claim, receipt)
    override fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long?) = actual.recordFailure(claim, delivery, pause, retryAfterMillis)
    override fun deny(reason: StoreCode) = actual.deny(reason)
    override fun nextDeliveryDelayMillis() = actual.nextDeliveryDelayMillis()
    override fun close() = actual.close()
    private class Refresh(val actual: StoreRefreshAttempt) : RefreshAttempt
}

private class JournalAdapter(private val actual: ProtectedEnrollmentJournal) : EnrollmentJournal {
    override fun discovery(generation: Long): DiscoveryHandle = Discovery(actual.discovery(generation))
    override fun publicSpki(discovery: DiscoveryHandle) = actual.publicSpki(discovery.actual())
    override fun reserveOwner(discovery: DiscoveryHandle, organizationId: String, userId: String): EnrollmentReservation =
        actual.reserveOwner(discovery.actual(), EnrollmentOwner(organizationId, userId)).let { EnrollmentReservation(Attempt(it.attempt), it.requiresFreshChallenge) }
    override fun publicSpki(attempt: EnrollmentAttempt) = actual.publicSpki(attempt.actual())
    override fun sign(attempt: EnrollmentAttempt, validatedProof: ByteArray) = actual.sign(attempt.actual(), validatedProof)
    override fun bindEnrollment(attempt: EnrollmentAttempt, account: AccountIdentity): EnrollmentBinding = Binding(actual.bindEnrollment(attempt.actual(), account))
    override fun bindingForStore(generation: Long, storeRef: String): EnrollmentBinding? = actual.bindingForStore(generation, storeRef)?.let(::Binding)
    override fun matchesOwner(binding: EnrollmentBinding, organizationId: String, userId: String) =
        actual.matchesOwner((binding as? Binding ?: throw StoreFailure(StoreCode.STALE_GENERATION)).actual, EnrollmentOwner(organizationId, userId))
    private fun DiscoveryHandle.actual() = (this as? Discovery ?: throw StoreFailure(StoreCode.STALE_GENERATION)).actual
    private fun EnrollmentAttempt.actual() = (this as? Attempt ?: throw StoreFailure(StoreCode.STALE_GENERATION)).actual
    private class Discovery(val actual: DiscoveryTicket) : DiscoveryHandle {
        override val generation get() = actual.generation
        override val installationId get() = actual.installationId
    }
    private class Attempt(val actual: OwnedEnrollmentAttempt) : EnrollmentAttempt {
        override val generation get() = actual.generation
        override val installationId get() = actual.installationId
    }
    private class Binding(val actual: EnrollmentStoreBinding) : EnrollmentBinding(actual.ownerIndex, actual.storeRef, actual.installationId)
}

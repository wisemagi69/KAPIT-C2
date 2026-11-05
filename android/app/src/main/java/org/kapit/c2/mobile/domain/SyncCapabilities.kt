package org.kapit.c2.mobile.domain

import java.io.Closeable

/** Restricted network capability: no drafts, snapshots, caches or DAO access. All calls are IO-only. */
interface StoreSyncSession : Closeable {
    val generation: Long
    val storeRef: String
    val context: AuthorizedContext
    fun beginOnlineRequest(): OnlineRequestAnchor
    fun clock(): ClockStamp
    fun serverTimeLowerMillis(): Long
    fun serverTimeUpperMillis(): Long
    fun accessTokenUsable(marginMillis: Long = 30_000): Boolean
    fun credentials(): SessionSecrets
    fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets)
    fun beginRefresh(anchor: OnlineRequestAnchor): StoreRefreshAttempt
    fun completeRefresh(attempt: StoreRefreshAttempt, anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets)
    fun abandonRefresh(attempt: StoreRefreshAttempt)
    fun claimNext(): ClaimedDelivery?
    fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt)
    fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long? = null)
    fun deny(reason: StoreCode)
    fun nextDeliveryDelayMillis(): Long?
}

/** Fresh private handle; closing it never closes a newer foreground/worker authority. */
interface WorkerStoreCapability : StoreSyncSession

/** Opaque identity checked against the durable marker; possession alone grants no authority. */
class StoreRefreshAttempt internal constructor(internal val id: String, internal val capability: String,
    internal val generation: Long, internal val revision: Long, internal val familyId: String) {
    override fun toString() = "StoreRefreshAttempt(redacted)"
}

class ClaimedDelivery(val claim: DeliveryClaim, val attempt: Int) : Closeable {
    init { requireStore(attempt >= 1, StoreCode.STORAGE_UNAVAILABLE) }
    override fun close() = claim.close()
    override fun toString() = "ClaimedDelivery(redacted)"
}

class EnrollmentOwner(val organizationId: String, val userId: String) {
    init { canonicalUuid(organizationId); canonicalUuid(userId) }
    override fun toString() = "EnrollmentOwner(redacted)"
}

class DiscoveryTicket internal constructor(val generation: Long, val installationId: String,
    internal val journalRevision: Long, internal val proofRef: String, internal val issuer: String) {
    override fun toString() = "DiscoveryTicket(redacted)"
}

class OwnedEnrollmentAttempt internal constructor(val generation: Long, val installationId: String,
    internal val journalRevision: Long, internal val ownerIndex: String, internal val proofRef: String,
    internal val issuer: String) {
    override fun toString() = "OwnedEnrollmentAttempt(redacted)"
}

class OwnerReservation(val attempt: OwnedEnrollmentAttempt, val requiresFreshChallenge: Boolean)

/** Opaque metadata only: an exact account/enrollment must come from a validated online response. */
class EnrollmentStoreBinding internal constructor(val generation: Long, val ownerIndex: String,
    val storeRef: String, val installationId: String, internal val journalRevision: Long,
    internal val issuer: String) {
    override fun toString() = "EnrollmentStoreBinding(redacted)"
}

interface ProtectedEnrollmentJournal {
    fun discovery(expectedGeneration: Long): DiscoveryTicket
    fun publicSpki(discovery: DiscoveryTicket): ByteArray
    fun reserveOwner(discovery: DiscoveryTicket, owner: EnrollmentOwner): OwnerReservation
    fun publicSpki(attempt: OwnedEnrollmentAttempt): ByteArray
    fun sign(attempt: OwnedEnrollmentAttempt, validatedProof: ByteArray): ByteArray
    fun bindEnrollment(attempt: OwnedEnrollmentAttempt, account: AccountIdentity): EnrollmentStoreBinding
    fun bindingForStore(expectedGeneration: Long, storeRef: String): EnrollmentStoreBinding?
    fun matchesOwner(binding: EnrollmentStoreBinding, owner: EnrollmentOwner): Boolean
}

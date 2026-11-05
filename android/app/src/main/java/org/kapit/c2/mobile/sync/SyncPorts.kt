package org.kapit.c2.mobile.sync

import java.io.Closeable
import org.kapit.c2.mobile.data.remote.*
import org.kapit.c2.mobile.domain.*

/** Runtime-owned bridge to the reviewed086 storage capabilities. All methods are IO-only. */
internal interface SyncSession : Closeable {
    val generation: Long
    val storeRef: String
    val context: AuthorizedContext
    fun beginOnlineRequest(): OnlineRequestAnchor
    fun clock(): ClockStamp
    fun serverTimeLowerMillis(): Long
    fun accessTokenUsable(): Boolean
    fun credentials(): SessionSecrets
    fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets)
    /** Persist uncertainty before dispatch; a process restart must never retry the marked token. */
    fun beginRefresh(anchor: OnlineRequestAnchor): RefreshAttempt
    fun completeRefresh(attempt: RefreshAttempt, anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets)
    /** Release this exact marker only when the refresh request provably never left the device. */
    fun abandonRefresh(attempt: RefreshAttempt)
    fun claimNext(): ClaimedOperation?
    fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt)
    fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long? = null)
    fun deny(reason: StoreCode)
    fun nextDeliveryDelayMillis(): Long?
}

internal interface RefreshAttempt

internal class ClaimedOperation(val claim: DeliveryClaim, val attempt: Int) : Closeable {
    init { require(attempt >= 1) }
    override fun close() = claim.close()
    override fun toString() = "ClaimedOperation(redacted)"
}

/** Test doubles implement this boundary only in test sources; production always delegates080. */
internal interface RemoteProtocol : Closeable {
    suspend fun challenge(request: ChallengeRequest, start: ClockStamp): ValidatedChallenge
    suspend fun token(challenge: ValidatedChallenge, signature: ByteArray, start: ClockStamp): RemoteSession
    suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteSession
    suspend fun me(access: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteContext
    suspend fun logout(access: ByteArray)
    suspend fun receipt(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt
    suspend fun send(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt
    suspend fun reports(access: ByteArray, query: ReportQuery): RemoteReportPage
    suspend fun revision(access: ByteArray, reportId: String, revision: Int): RemoteRevision
    suspend fun uploadPhoto(access: ByteArray, value: PhotoUpload): PhotoReceipt = throw StoreFailure(StoreCode.NOT_FOUND)
    suspend fun photoStatus(access: ByteArray, evidenceId: String): PhotoStatus = throw StoreFailure(StoreCode.NOT_FOUND)
}

@androidx.annotation.RequiresApi(35)
internal class ProtocolAdapter(private val client: MobileProtocolClient) : RemoteProtocol {
    override suspend fun challenge(request: ChallengeRequest, start: ClockStamp) = client.challenge(request, start)
    override suspend fun token(challenge: ValidatedChallenge, signature: ByteArray, start: ClockStamp) = client.token(challenge, signature, start)
    override suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp) = client.refresh(refresh, expected, start)
    override suspend fun me(access: ByteArray, expected: AuthorizedContext, start: ClockStamp) = client.me(access, expected, start)
    override suspend fun logout(access: ByteArray) = client.logout(access)
    override suspend fun receipt(claim: DeliveryClaim, access: ByteArray) = client.receipt(claim, access)
    override suspend fun send(claim: DeliveryClaim, access: ByteArray) = client.send(claim, access)
    override suspend fun reports(access: ByteArray, query: ReportQuery) = client.reports(access, query)
    override suspend fun revision(access: ByteArray, reportId: String, revision: Int) = client.revision(access, reportId, revision)
    override suspend fun uploadPhoto(access: ByteArray, value: PhotoUpload) = client.uploadPhoto(access, value)
    override suspend fun photoStatus(access: ByteArray, evidenceId: String) = client.photoStatus(access, evidenceId)
    override fun close() = client.close()
}

internal data class SyncOutcome(val serviceReached: Boolean, val receiptsCommitted: Int, val nextDelayMillis: Long?)
internal data class DrainBudget(val maxOperations: Int = 20, val maxElapsedMillis: Long = 180_000) {
    init { require(maxOperations in 1..100 && maxElapsedMillis in 1..480_000) }
}

/** Opaque tickets are owned by086; no journal implementation or key alias lives in this bridge. */
internal interface DiscoveryHandle { val generation: Long; val installationId: String }
internal interface EnrollmentAttempt { val generation: Long; val installationId: String }
internal class EnrollmentReservation(val attempt: EnrollmentAttempt, val requiresFreshChallenge: Boolean)
internal open class EnrollmentBinding(val ownerIndex: String, val storeRef: String, val installationId: String) {
    override fun toString() = "EnrollmentBinding(redacted)"
}
internal interface EnrollmentJournal {
    fun discovery(generation: Long): DiscoveryHandle
    fun publicSpki(discovery: DiscoveryHandle): ByteArray
    fun reserveOwner(discovery: DiscoveryHandle, organizationId: String, userId: String): EnrollmentReservation
    fun publicSpki(attempt: EnrollmentAttempt): ByteArray
    fun sign(attempt: EnrollmentAttempt, validatedProof: ByteArray): ByteArray
    fun bindEnrollment(attempt: EnrollmentAttempt, account: AccountIdentity): EnrollmentBinding
    fun bindingForStore(generation: Long, storeRef: String): EnrollmentBinding?
    fun matchesOwner(binding: EnrollmentBinding, organizationId: String, userId: String): Boolean
}

internal interface RuntimeStorage {
    val repository: ProtectedRepository
    val journal: EnrollmentJournal
    fun foreground(generation: Long): SyncSession
    fun worker(storeRef: String): SyncSession
}

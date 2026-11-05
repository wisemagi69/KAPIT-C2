package org.kapit.c2.mobile.domain

import java.io.Closeable
import kotlinx.coroutines.flow.StateFlow

/**
 * Stable controller/worker boundary. Invoke storage methods on an IO dispatcher; never expose a DAO.
 * Every protected operation validates current generation, account, lease, boot and device state.
 * Controller observes access and immediately drops protected UI models whenever ready becomes false.
 * Inputs/results are private: no logs, saved-state bundles, notifications or WorkManager data.
 */
interface ProtectedRepository : Closeable {
    val access: StateFlow<StoreAccess>
    /** IO startup: restore opaque selection/denial only; never unwrap or open protected content. */
    fun restoreSelection(expectedGeneration: Long): StoreAccess
    fun beginOnlineRequest(expectedGeneration: Long): OnlineRequestAnchor
    fun activateOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets): StoreAccess
    /** Exact active authority only; atomically replace tokens/lease without changing UI generation. */
    fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets): StoreAccess
    fun unlock(expectedGeneration: Long): StoreAccess
    /** Immediate generation revocation/UI signal; follow with fence on IO for durable denial/closure. */
    fun invalidate(reason: StoreCode): StoreAccess
    /** Detach only a cached access token and revoke local authority atomically, with no disk/key IO. */
    fun logoutAndInvalidate(expectedGeneration: Long): LogoutFence
    /**
     * IO operation. Pass invalidate's returned generation to drain that exact captured fence;
     * delayed cleanup can never close/log out a newer selection. Null performs invalidate first.
     * Returning confirms durable denial metadata and closure for the captured fence.
     */
    fun fence(reason: StoreCode, invalidatedGeneration: Long? = null): StoreAccess
    fun snapshot(expectedGeneration: Long): LocalSnapshot
    fun createDraft(expectedGeneration: Long, commandId: String, content: MaintenanceContent = MaintenanceContent()): DraftRecord
    fun openDraft(expectedGeneration: Long, draftId: String): DraftRecord
    fun saveDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedRevision: Long, content: MaintenanceContent): DraftRecord
    fun queueDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedDraftRevision: Long, expectedReportRevision: Int, content: MaintenanceContent): OutboxRecord
    /** Controller supplies only a current, validated own-report RETURN response from live transport. */
    fun createCorrectionDraft(expectedGeneration: Long, commandId: String, reportId: String, expectedReportRevision: Int, content: MaintenanceContent, predecessorOperationId: String? = null): DraftRecord
    /** Explicit reconciliation makes a new editable draft; the old operation's bytes/ID remain frozen. */
    fun reconcileOperation(expectedGeneration: Long, commandId: String, operationId: String): DraftRecord
    fun claimNext(expectedGeneration: Long): DeliveryClaim?
    fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt)
    fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long? = null)
    fun retryOperation(expectedGeneration: Long, operationId: String)
    fun credentials(expectedGeneration: Long): SessionSecrets
    fun cacheReports(expectedGeneration: Long, reports: List<CachedReport>)
    fun cachedReports(expectedGeneration: Long): List<CachedReport>
    fun cacheOpenedRevision(expectedGeneration: Long, report: CachedReport)
    fun cachedOpenedRevision(expectedGeneration: Long, reportId: String, revision: Int): CachedReport?
    fun queuePhoto(generation: Long, operationId: String, reportId: String, revisionId: String, revision: Int, capture: String, bytes: ByteArray): Unit = throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
    fun photos(generation: Long, reportId: String, revisionId: String): List<PhotoPending> = emptyList()
    fun photoUpload(generation: Long, operationId: String): PhotoUpload = throw StoreFailure(StoreCode.NOT_FOUND)
    fun commitPhoto(generation: Long, operationId: String, receipt: PhotoReceipt): Unit = throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
}

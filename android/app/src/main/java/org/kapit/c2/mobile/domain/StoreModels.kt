package org.kapit.c2.mobile.domain

import java.io.Closeable
import java.security.MessageDigest
import java.util.UUID

const val MOBILE_PROTOCOL = "kapit-mobile-v1"
const val MAINTENANCE_TEMPLATE = "demo-maintenance-v1"

enum class StoreCode {
    READY, SIGNED_OUT, LOCKED, UNLOCK_REQUIRED, UNSUPPORTED_DEVICE, LEASE_EXPIRED, CLOCK_UNTRUSTED,
    KEY_UNAVAILABLE, STORAGE_UNAVAILABLE, AUTH_REQUIRED, REVOKED, SCOPE_DENIED, CONTEXT_CHANGED,
    STALE_GENERATION, STALE_DRAFT, COMMAND_CONFLICT, VALIDATION_ERROR, TEMPLATE_UNSUPPORTED,
    CLAIM_LOST, RECEIPT_INVALID, NOT_FOUND, ALREADY_RECEIVED,
}

class StoreFailure(val code: StoreCode) : RuntimeException(code.name)
internal fun requireStore(condition: Boolean, code: StoreCode) { if (!condition) throw StoreFailure(code) }
internal fun canonicalUuid(value: String): String {
    val parsed = try { UUID.fromString(value) } catch (_: IllegalArgumentException) { throw StoreFailure(StoreCode.VALIDATION_ERROR) }
    requireStore(parsed.toString() == value, StoreCode.VALIDATION_ERROR)
    return value
}

data class AccountIdentity(val organizationId: String, val userId: String, val enrollmentId: String) {
    init { listOf(organizationId, userId, enrollmentId).forEach(::canonicalUuid) }
    val storeRef: String get() = MessageDigest.getInstance("SHA-256")
        .digest("$MOBILE_PROTOCOL\n$organizationId\n$userId\n$enrollmentId\n".toByteArray(Charsets.UTF_8))
        .joinToString("") { "%02x".format(it) }
    override fun toString(): String = "AccountIdentity(redacted)"
}

data class CaptureContext(
    val account: AccountIdentity,
    val unitId: String,
    val channelId: String,
    val profile: String,
    val templateVersion: String,
) {
    init { canonicalUuid(unitId); canonicalUuid(channelId); requireStore(profile.isNotEmpty(), StoreCode.VALIDATION_ERROR) }
    override fun toString(): String = "CaptureContext(redacted)"
}

/** Constructed only by the authenticated transport adapter; never from an intent/UI role picker. */
data class AuthorizedContext(
    val capture: CaptureContext,
    val familyId: String,
    val permissionVersion: Long,
    val displayName: String,
    val organizationLabel: String,
    val unitLabel: String,
    val channelLabel: String,
    val role: String = "submitter",
) {
    init {
        canonicalUuid(familyId)
        requireStore(permissionVersion >= 0 && role == "submitter", StoreCode.SCOPE_DENIED)
    }
    override fun toString(): String = "AuthorizedContext(redacted)"
}

data class ClockStamp(val elapsedMillis: Long, val bootId: String?)
data class OnlineRequestAnchor(val generation: Long, val clock: ClockStamp, val authorityRevision: Long = 0)
data class LeaseOffer(val serverTimeMillis: Long, val leaseExpiresMillis: Long, val familyExpiresMillis: Long, val leaseSeconds: Long)
data class OfflineLease(
    val requestStartElapsed: Long, val responseElapsed: Long, val deadlineElapsed: Long,
    val bootId: String, val serverTimeMillis: Long, val familyExpiresServerMillis: Long,
)

data class StoreAccess(val generation: Long, val ready: Boolean = false, val reason: StoreCode = StoreCode.SIGNED_OUT, val storeRef: String? = null)

/** Fixed eight-field model. Drafts may be incomplete; submission performs authoritative validation. */
data class MaintenanceContent(
    val observedAt: String = "", val category: String = "", val urgency: String = "", val areaLabel: String = "",
    val siteLabel: String = "", val reporterLabel: String = "", val narrative: String = "", val assistanceRequested: String = "",
) { override fun toString(): String = "MaintenanceContent(redacted)" }

data class DraftRecord(
    val id: String, val revision: Long, val content: MaintenanceContent, val reportId: String?,
    val expectedReportRevision: Int, val predecessorOperationId: String?, val capture: CaptureContext,
    val savedAtServerMillis: Long,
) { override fun toString(): String = "DraftRecord(revision=$revision, content=redacted)" }

enum class DeliveryState { QUEUED, SENDING, RECEIVED, NEEDS_CORRECTION, CONFLICT }
enum class PauseReason { AUTH_REQUIRED, LOCKED, LEASE_EXPIRED, REVOKED, SCOPE_DENIED, CONTEXT_CHANGED }

data class OutboxRecord(
    val operationId: String, val reportId: String, val expectedRevision: Int, val content: MaintenanceContent,
    val capture: CaptureContext, val requestHash: String, val delivery: DeliveryState, val pause: PauseReason?,
    val attempts: Int, val nextAttemptElapsed: Long?, val queuedAtServerMillis: Long, val predecessorOperationId: String?,
) { override fun toString(): String = "OutboxRecord(delivery=$delivery, pause=$pause, content=redacted)" }

data class LocalSnapshot(val context: AuthorizedContext, val leaseDeadlineElapsed: Long, val serverNowMillis: Long, val drafts: List<DraftRecord>, val outbox: List<OutboxRecord>) {
    override fun toString(): String = "LocalSnapshot(redacted)"
}

/** A detached, bounded network claim. Call close after I/O; receipt commit rechecks every fence. */
class DeliveryClaim internal constructor(
    val generation: Long, val storeRef: String, val operationId: String, val reportId: String,
    val expectedRevision: Int, val requestHash: String, internal val claimToken: String,
    internal val claimSession: String, internal val claimBoot: String, internal val claimDeadline: Long,
    requestBytes: ByteArray,
) : Closeable {
    private val bytes = requestBytes.copyOf()
    private var closed = false
    @Synchronized fun copyRequestBytes(): ByteArray { requireStore(!closed, StoreCode.CLAIM_LOST); return bytes.copyOf() }
    @Synchronized override fun close() { bytes.fill(0); closed = true }
    override fun toString(): String = "DeliveryClaim(redacted)"
}

/** No data-class generated secret toString/copy. Callers must close all detached credentials. */
class SessionSecrets(accessToken: ByteArray, refreshToken: ByteArray, val accessExpiresServerMillis: Long, val refreshExpiresServerMillis: Long) : Closeable {
    private val access = accessToken.copyOf()
    private val refresh = refreshToken.copyOf()
    private var closed = false
    init { requireStore(access.size in 1..8192 && refresh.size in 1..512, StoreCode.VALIDATION_ERROR) }
    @Synchronized fun copyAccessToken(): ByteArray { requireStore(!closed, StoreCode.AUTH_REQUIRED); return access.copyOf() }
    @Synchronized fun copyRefreshToken(): ByteArray { requireStore(!closed, StoreCode.AUTH_REQUIRED); return refresh.copyOf() }
    @Synchronized override fun close() { access.fill(0); refresh.fill(0); closed = true }
    override fun toString(): String = "SessionSecrets(redacted)"
}

/** Sole purpose is one bounded remote logout attempt after local authority has already been revoked. */
class LogoutAuthorization internal constructor(accessToken: ByteArray) : Closeable {
    private val access = accessToken.copyOf()
    private var closed = false
    @Synchronized fun copyAccessToken(): ByteArray { requireStore(!closed, StoreCode.AUTH_REQUIRED); return access.copyOf() }
    @Synchronized override fun close() { access.fill(0); closed = true }
    override fun toString(): String = "LogoutAuthorization(redacted)"
}
data class LogoutFence(val access: StoreAccess, val authorization: LogoutAuthorization?)

class AcceptedReceipt private constructor(val operationId: String, val reportId: String, val revisionId: String, val revisionNo: Int) {
    companion object {
        /** Exact wire validation, including fields not needed by local receipt display. */
        fun parse(body: ByteArray, claim: DeliveryClaim): AcceptedReceipt {
            val value = ReceiptPolicy.validate(body, claim.operationId, claim.reportId, claim.expectedRevision)
            return AcceptedReceipt(value.operationId, value.reportId, value.revisionId, value.revisionNo)
        }
    }
    override fun toString(): String = "AcceptedReceipt(redacted)"
}

data class CachedReport(val reportId: String, val revision: Int, val validatedJson: String, val checkedAtServerMillis: Long) {
    override fun toString(): String = "CachedReport(redacted)"
}

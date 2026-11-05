package org.kapit.c2.mobile.ui

import java.io.Closeable
import org.kapit.c2.mobile.domain.AuthorizedContext
import org.kapit.c2.mobile.domain.LeaseOffer
import org.kapit.c2.mobile.domain.LogoutAuthorization
import org.kapit.c2.mobile.domain.OnlineRequestAnchor
import org.kapit.c2.mobile.domain.ProtectedRepository
import org.kapit.c2.mobile.domain.SessionSecrets
import org.kapit.c2.mobile.domain.StoreCode

/** Application-owned factory. Activity never accepts an endpoint, identity, or runtime from intents. */
interface MobileRuntimeOwner {
    fun createMobileRuntime(): MobileRuntime
}

class MobileRuntime(
    val repository: ProtectedRepository,
    val live: MobileLivePort = UnavailableMobileLivePort,
) : Closeable {
    override fun close() {
        try { live.close() } finally { repository.close() }
    }
}

/**
 * TASK-062 transport boundary. Implementations validate exact protocol, ownership, scope and bounded
 * server shapes before constructing these values. They must honour cancellation and the supplied
 * generation, never log inputs, and never publish UI state themselves. All suspend calls run on IO.
 * A successfully received auth response is not local access: controller must activate its anchor.
 * Credential rotation uses StoreSyncSession.beginRefresh/completeRefresh with the exact current
 * authority/anchor, a durable uncertainty marker, and unchanged generation. Context-only renewal
 * cannot rotate credentials or clear an unresolved marker. Full activateOnline belongs to
 * enrollment/explicit reauthentication; never advance
 * generation underneath an in-flight protected UI command merely to rotate its access credential.
 */
interface MobileLivePort : Closeable {
    suspend fun uploadPhoto(generation: Long, operationId: String): Unit = throw org.kapit.c2.mobile.domain.StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
    suspend fun photoStatus(generation: Long, evidenceId: String): org.kapit.c2.mobile.domain.PhotoStatus = throw org.kapit.c2.mobile.domain.StoreFailure(StoreCode.NOT_FOUND)
    val available: Boolean
    suspend fun authenticate(anchor: OnlineRequestAnchor, purpose: SignInPurpose, username: String, password: String): MobileSession
    suspend fun synchronize(generation: Long): MobileSyncOutcome
    /** Fresh online checks only. Offline cached status needs a separately labelled UI contract. */
    suspend fun reports(generation: Long, filter: ReportFilterUi, page: Int): ReportPageUi
    suspend fun report(generation: Long, reportId: String, revision: Int): ReportDetailUi
    /** Re-fetch current original-author RETURN authority; cached UI can never authorize a correction. */
    suspend fun correction(generation: Long, reportId: String, revision: Int): ReportDetailUi
    suspend fun logout(authorization: LogoutAuthorization): LogoutConfirmation
    /** Nonblocking: cancel this runtime's calls/work only. No DB/key/network I/O on the caller. */
    fun cancelForFence(previousGeneration: Long, reason: StoreCode)
}

class MobileSession(val context: AuthorizedContext, val lease: LeaseOffer, val secrets: SessionSecrets) : Closeable {
    override fun close() = secrets.close()
    override fun toString(): String = "MobileSession(redacted)"
}

enum class LogoutConfirmation { CONFIRMED, UNCONFIRMED }
/** A no-op drain/backoff is not evidence that the service was reached. */
data class MobileSyncOutcome(val serviceReached: Boolean)
enum class LiveFailureCode { UNAVAILABLE, OFFLINE, AUTH_REQUIRED, CREDENTIALS_REJECTED, REVOKED, SCOPE_DENIED, CONTEXT_CHANGED, CONFLICT, INVALID_RESPONSE, THROTTLED }
class MobileLiveFailure(val code: LiveFailureCode) : RuntimeException(code.name)

/** No fixture login or fabricated success is available through the installed Activity fallback. */
object UnavailableMobileLivePort : MobileLivePort {
    override val available = false
    private fun unavailable(): Nothing = throw MobileLiveFailure(LiveFailureCode.UNAVAILABLE)
    override suspend fun authenticate(anchor: OnlineRequestAnchor, purpose: SignInPurpose, username: String, password: String): MobileSession = unavailable()
    override suspend fun synchronize(generation: Long): MobileSyncOutcome = unavailable()
    override suspend fun reports(generation: Long, filter: ReportFilterUi, page: Int): ReportPageUi = unavailable()
    override suspend fun report(generation: Long, reportId: String, revision: Int): ReportDetailUi = unavailable()
    override suspend fun correction(generation: Long, reportId: String, revision: Int): ReportDetailUi = unavailable()
    override suspend fun logout(authorization: LogoutAuthorization) = LogoutConfirmation.UNCONFIRMED
    override fun cancelForFence(previousGeneration: Long, reason: StoreCode) = Unit
    override fun close() = Unit
}

package org.kapit.c2.mobile.data.remote

import androidx.annotation.RequiresApi
import java.io.Closeable
import java.time.Instant
import java.time.LocalDate
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.util.Base64
import kotlinx.serialization.json.*
import org.kapit.c2.mobile.domain.*

enum class RemoteFailureKind { INVALID_REQUEST, INVALID_RESPONSE, NETWORK, TIMEOUT, HTTP, CONTEXT_CHANGED, EXPIRED_RESPONSE, UNAVAILABLE }
enum class RemoteCode {
    INVALID_JSON, INVALID_IDEMPOTENCY_KEY, INVALID_FILTER, LOGIN_FAILED, AUTH_REQUIRED, REFRESH_REUSED,
    ACCESS_DENIED, NOT_FOUND, ENROLLMENT_EXISTS, ENROLLMENT_REVOKED, ENROLLMENT_LIMIT,
    IDEMPOTENCY_CONFLICT, REVISION_CONFLICT, CORRECTION_UNAVAILABLE, POLICY_UNAVAILABLE, SCOPE_UNAVAILABLE,
    REQUEST_TOO_LARGE, INVALID_REQUEST, VALIDATION_ERROR, TEMPLATE_UNSUPPORTED, THROTTLED, MOBILE_UNAVAILABLE, SERVER_ERROR,
}

/** No server message, URL, response body, credential or underlying exception is retained. */
class RemoteFailure(
    val kind: RemoteFailureKind,
    val status: Int? = null,
    val code: RemoteCode? = null,
    val retryAfterSeconds: Long? = null,
    val enrollmentId: String? = null,
    val mutationUncertain: Boolean = false,
    val retryAfterDate: ServerRetryDate? = null,
    /** No connection was ever established, so no request byte left the device (one-shot body, no transport retries). */
    val notDispatched: Boolean = false,
) : RuntimeException("MOBILE_${kind.name}") {
    internal fun uncertain() = if (notDispatched) this else RemoteFailure(kind, status, code, retryAfterSeconds, enrollmentId, true, retryAfterDate)
    val retryAfterServerMillis: Long? get() = retryAfterDate?.fixedMillis
    /** Supply the current trusted server-time estimate. Never substitute the phone wall clock. */
    @RequiresApi(35)
    fun retryDelaySeconds(serverNowMillis: Long): Long? = retryAfterSeconds ?: retryAfterDate?.delaySeconds(serverNowMillis)
    override fun toString() = "RemoteFailure(kind=$kind,status=$status,code=$code,mutationUncertain=$mutationUncertain)"
}

/** Parsed HTTP date only. RFC850's ambiguous century is resolved against the supplied server clock. */
class ServerRetryDate private constructor(internal val fixedMillis: Long?, private val reduced: Reduced?) {
    private class Reduced(val year: Int, val month: Int, val day: Int, val hour: Int, val minute: Int, val second: Int, val weekday: Int)
    companion object {
        internal fun fixed(millis: Long) = ServerRetryDate(millis, null)
        internal fun reduced(year: Int, month: Int, day: Int, hour: Int, minute: Int, second: Int, weekday: Int) =
            ServerRetryDate(null, Reduced(year, month, day, hour, minute, second, weekday))
    }
    @RequiresApi(35)
    fun delaySeconds(serverNowMillis: Long): Long? {
      return try {
        val deadline = fixedMillis ?: run {
            val parts = reduced!!
            val now = Instant.ofEpochMilli(serverNowMillis).atOffset(ZoneOffset.UTC).toLocalDateTime()
            val upper = now.plusYears(50)
            var year = Math.floorDiv(upper.year, 100) * 100 + parts.year
            // Choose the century before constructing the date: a rejected future century
            // may not have the leap day that is valid in the selected prior century.
            val candidateParts = listOf(year, parts.month, parts.day, parts.hour, parts.minute, parts.second)
            val upperParts = listOf(upper.year, upper.monthValue, upper.dayOfMonth, upper.hour, upper.minute, upper.second)
            val firstDifference = candidateParts.zip(upperParts).firstOrNull { it.first != it.second }
            if (firstDifference != null && firstDifference.first > firstDifference.second) year -= 100
            val candidate = LocalDateTime.of(year, parts.month, parts.day, parts.hour, parts.minute, minOf(parts.second, 59))
            if (candidate.dayOfWeek.value != parts.weekday) return null
            candidate.toInstant(ZoneOffset.UTC).plusSeconds(if (parts.second == 60) 1 else 0).toEpochMilli()
        }
        val difference = Math.subtractExact(deadline, serverNowMillis)
        if (difference <= 0) 0 else (difference / 1000 + if (difference % 1000 == 0L) 0 else 1).coerceAtMost(86400)
      } catch (_: Exception) { null }
    }
    override fun toString() = "ServerRetryDate(parsed)"
}

internal fun checkWire(value: Boolean) { if (!value) throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE) }
internal inline fun <T> wire(block: () -> T): T = try { block() }
catch (failure: RemoteFailure) { throw failure }
catch (_: Exception) { throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE) }
internal fun JsonObject.exact(vararg fields: String) = checkWire(keys == fields.toSet())
internal fun JsonObject.text(key: String, max: Int, nonempty: Boolean = true): String = requiredString(key).also {
    checkWire(StrictJson.validUnicode(it) && it.codePointCount(0, it.length) <= max && (!nonempty || it.isNotEmpty()))
}
internal fun JsonObject.obj(key: String) = this[key] as? JsonObject ?: throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE)
internal fun JsonObject.bool(key: String): Boolean {
    val value = this[key] as? JsonPrimitive
    checkWire(value != null && !value.isString && value.booleanOrNull != null)
    return value!!.boolean
}
internal fun JsonObject.uuid(key: String): String = canonicalUuid(text(key, 36))
internal fun JsonObject.nullableUuid(key: String): String? = if (this[key] == JsonNull) null else uuid(key)
@RequiresApi(35)
internal fun encode64(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
@RequiresApi(35)
internal fun decode64(value: String, maximum: Int): ByteArray {
    checkWire(value.length in 1..maximum && value.matches(Regex("[A-Za-z0-9_-]+")))
    return Base64.getUrlDecoder().decode(value).also { checkWire(encode64(it) == value) }
}

@RequiresApi(35)
internal fun authTime(value: String): Instant {
    checkWire(value.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\\.[0-9]{6}Z")))
    return Instant.parse(value)
}

/** Copy only transient input. Caller must close; JVM/HTTP String copies cannot be zeroized. */
class ChallengeRequest(
    val username: String,
    password: CharArray,
    val installationId: String,
    val enrollmentId: String?,
    publicKeySpki: ByteArray,
    val label: String,
    val expectedAccount: AccountIdentity? = null,
) : Closeable {
    private val password = password.copyOf()
    private val publicKey = publicKeySpki.copyOf()
    private var closed = false
    @Synchronized internal fun passwordCopy(): CharArray { check(!closed); return password.copyOf() }
    @Synchronized internal fun keyCopy(): ByteArray { check(!closed); return publicKey.copyOf() }
    @Synchronized override fun close() { password.fill('\u0000'); publicKey.fill(0); closed = true }
    override fun toString() = "ChallengeRequest(redacted)"
}

/** Created only after exact response/proof binding checks. Never serialize this to saved state. */
class ValidatedChallenge internal constructor(
    val challengeId: String, val nonce: String,
    val accountUserId: String, val organizationId: String, val enrollmentId: String?,
    internal val deadlineElapsed: Long, internal val arrivalElapsed: Long, internal val bootId: String,
    private val proof: ByteArray, internal val publicKey: ByteArray,
) {
    fun copyProofBytes(): ByteArray = proof.copyOf()
    internal fun requireCurrent(now: ClockStamp) {
        if (now.bootId != bootId || now.elapsedMillis < arrivalElapsed || now.elapsedMillis >= deadlineElapsed)
            throw RemoteFailure(RemoteFailureKind.EXPIRED_RESPONSE)
    }
    override fun toString() = "ValidatedChallenge(redacted)"
}

class RemoteContext internal constructor(val authority: AuthorizedContext, val lease: LeaseOffer) {
    override fun toString() = "RemoteContext(redacted)"
}
class RemoteSession internal constructor(val context: RemoteContext, val secrets: SessionSecrets) : Closeable {
    override fun close() = secrets.close()
    override fun toString() = "RemoteSession(redacted)"
}

enum class RemoteReportStatus { ALL, PENDING, PROCESSING, AWAITING_REVIEW, FAILED, APPROVED, RETURNED, REJECTED }
@RequiresApi(35)
data class ReportQuery(val status: RemoteReportStatus = RemoteReportStatus.ALL, val dateFrom: String? = null,
    val dateTo: String? = null, val page: Int = 1, val pageSize: Int = 10) {
    internal fun parameters(): List<Pair<String, String>> = try {
        require(page >= 1 && pageSize in 1..50)
        listOfNotNull(dateFrom, dateTo).forEach { require(it.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}"))); LocalDate.parse(it) }
        require(dateFrom == null || dateTo == null || dateFrom <= dateTo)
        buildList { add("status" to status.name); dateFrom?.let { add("date_from" to it) }; dateTo?.let { add("date_to" to it) }; add("page" to "$page"); add("page_size" to "$pageSize") }
    } catch (_: Exception) { throw RemoteFailure(RemoteFailureKind.INVALID_REQUEST) }
    override fun toString() = "ReportQuery(redacted)"
}

class RemoteReport internal constructor(val id: String, val revision: Int, val status: RemoteReportStatus,
    val reference: String, val category: String, val urgency: String, val areaLabel: String,
    val createdAt: String, val observedDate: String, val feedback: String?, val variantId: String?,
    internal val projection: JsonObject) {
    fun cached(checkedAtServerMillis: Long) = CachedReport(id, revision, CanonicalJson.bytes(projection).toString(Charsets.UTF_8), checkedAtServerMillis)
    override fun toString() = "RemoteReport(redacted)"
}
class RemoteReportPage internal constructor(val results: List<RemoteReport>, val count: Long, val page: Int, val pageSize: Int, val totalPages: Long) {
    override fun toString() = "RemoteReportPage(redacted)"
}
class RemoteRevisionHistory internal constructor(val revision: Int, val receivedAt: String, val status: RemoteReportStatus) {
    override fun toString() = "RemoteRevisionHistory(redacted)"
}
class RemoteReceipt internal constructor(val operationId: String, val reportId: String, val revisionId: String, val revision: Int) {
    override fun toString() = "RemoteReceipt(delivery=RECEIVED,processing=PENDING,shared=false,identity=redacted)"
}
class RemoteRevision internal constructor(val report: RemoteReport, val payload: MaintenanceContent,
    val receipt: RemoteReceipt, val canCorrect: Boolean, val history: List<RemoteRevisionHistory>, internal val projection: JsonObject) {
    /** Oversized valid online data remains usable; cache omission is not a fetch failure. */
    fun cacheOrNull(checkedAtServerMillis: Long): CachedReport? {
        val bytes = CanonicalJson.bytes(projection)
        return if (bytes.size <= 64 * 1024) CachedReport(report.id, report.revision, bytes.toString(Charsets.UTF_8), checkedAtServerMillis) else null
    }
    override fun toString() = "RemoteRevision(redacted)"
}

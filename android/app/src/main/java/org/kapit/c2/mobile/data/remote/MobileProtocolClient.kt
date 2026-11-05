package org.kapit.c2.mobile.data.remote

import androidx.annotation.RequiresApi
import java.io.Closeable
import java.time.LocalDateTime
import java.time.ZoneOffset
import java.time.format.DateTimeFormatter
import java.time.format.ResolverStyle
import java.util.Locale
import kotlinx.coroutines.CancellationException
import kotlinx.serialization.json.*
import org.kapit.c2.mobile.domain.*

/**
 * One HTTP attempt per operation. TASK-062 owns generations, serialized refresh, persistence,
 * cancellation on lock and recovery decisions. A received session is not an opened local store.
 * The caller's request-start anchor is never replaced with response-arrival time.
 */
@RequiresApi(35)
class MobileProtocolClient internal constructor(private val http: MobileHttpTransport, private val clock: () -> ClockStamp) : Closeable {
    companion object {
        /** Invoke on IO: default platform TLS initialization may perform blocking work. */
        fun configured(clock: () -> ClockStamp) = MobileProtocolClient(MobileHttpTransport(MobileEndpoint.configured()), clock)
    }

    suspend fun challenge(request: ChallengeRequest, requestStart: ClockStamp): ValidatedChallenge {
        val bytes = AuthCodec.challengeRequest(request)
        return post("auth/challenge/", bytes) { AuthCodec.challenge(it, request, requestStart, clock()) }
    }

    suspend fun token(challenge: ValidatedChallenge, signature: ByteArray, requestStart: ClockStamp): RemoteSession {
        val bytes = AuthCodec.tokenRequest(challenge, signature, clock())
        return post("auth/token/", bytes, allowEnrollment = true) { AuthCodec.session(it, requestStart, clock(), challenge = challenge) }
    }

    /** Never retry this credential after an uncertain response; reauthenticate the same enrollment. */
    suspend fun refresh(refreshToken: ByteArray, expected: AuthorizedContext, requestStart: ClockStamp): RemoteSession {
        val bytes = AuthCodec.refreshRequest(refreshToken)
        return post("auth/refresh/", bytes) { AuthCodec.session(it, requestStart, clock(), expected = expected) }
    }

    /** Context-only result: does not manufacture or replace access/refresh credentials. */
    suspend fun me(accessToken: ByteArray, expected: AuthorizedContext, requestStart: ClockStamp): RemoteContext =
        get("me/", accessToken) { AuthCodec.context(it, requestStart, clock(), expected) }

    /** Returns only after exact successful committed logout response; failures remain unconfirmed. */
    suspend fun logout(accessToken: ByteArray) {
        post("auth/logout/", "{}".toByteArray(), accessToken) {
            wire { val value = StrictJson.objectFrom(it); value.exact("logged_out"); checkWire(value.bool("logged_out")) }
        }
    }

    suspend fun send(claim: DeliveryClaim, accessToken: ByteArray): AcceptedReceipt {
        val bytes = claim.copyRequestBytes()
        try {
            wire {
                val request = StrictJson.objectFrom(bytes)
                request.exact("operation_id", "report_id", "expected_revision", "template_version", "payload")
                checkWire(request.uuid("operation_id") == claim.operationId && request.uuid("report_id") == claim.reportId)
                checkWire(request.requiredLong("expected_revision") == claim.expectedRevision.toLong() && claim.expectedRevision in 0..2147483646)
                checkWire(request.text("template_version", 64) == MAINTENANCE_TEMPLATE && RequestPolicy.requestHash(request) == claim.requestHash)
                RequestPolicy.validateSubmission(RequestPolicy.content(request.obj("payload")), Long.MAX_VALUE)
            }
        } catch (_: Exception) { bytes.fill(0); throw RemoteFailure(RemoteFailureKind.INVALID_REQUEST) }
        return post("sync/operations/", bytes, accessToken, operationId = claim.operationId, successes = setOf(200, 201)) {
            wire { AcceptedReceipt.parse(it, claim) }
        }
    }

    suspend fun receipt(claim: DeliveryClaim, accessToken: ByteArray): AcceptedReceipt =
        get("sync/receipts/${claim.operationId}/", accessToken) { wire { AcceptedReceipt.parse(it, claim) } }

    suspend fun reports(accessToken: ByteArray, query: ReportQuery): RemoteReportPage =
        get("reports/", accessToken, query.parameters(), ReportCodec.PAGE_LIMIT) { ReportCodec.page(it, query) }

    suspend fun revision(accessToken: ByteArray, reportId: String, revision: Int): RemoteRevision =
        get("reports/$reportId/revisions/$revision/", accessToken, responseLimit = ReportCodec.REVISION_LIMIT) { ReportCodec.revision(it, reportId, revision) }

    fun cancelAll() = http.cancelAll()
    suspend fun uploadPhoto(access: ByteArray, value: PhotoUpload): PhotoReceipt {
        val bytes = value.copyBytes()
        try { return http.evidence(value.pending.revisionId, access, bytes, value.pending.operationId, value.capture).use { reply ->
            if (reply.status !in setOf(200, 201)) throw error(reply, false)
            wire {
                val result = StrictJson.objectFrom(reply.bytes, 8192)
                result.exact("id", "operation_id", "state", "validation_code", "created_at")
                checkWire(result.uuid("operation_id") == value.pending.operationId && result.text("state", 32) == "QUARANTINED"
                    && result.text("validation_code", 64) == "DECODER_REQUIRED")
                java.time.Instant.parse(result.text("created_at", 50))
                PhotoReceipt(result.uuid("id"), value.pending.operationId)
            }
        } } catch (cancelled: CancellationException) { throw cancelled }
        catch (failure: RemoteFailure) { throw if (failure.kind !in setOf(RemoteFailureKind.INVALID_REQUEST, RemoteFailureKind.UNAVAILABLE)) failure.uncertain() else failure }
        finally { bytes.fill(0) }
    }

    suspend fun photoStatus(access: ByteArray, evidenceId: String): PhotoStatus = http.evidence(evidenceId, access).use { reply ->
        if (reply.status != 200) throw error(reply, false)
        wire {
            val result = StrictJson.objectFrom(reply.bytes, 8192)
            result.exact("evidence_id", "state", "validation_code", "can_download")
            checkWire(result.uuid("evidence_id") == evidenceId)
            val state = result.text("state", 32); val code = result.text("validation_code", 64)
            val unavailable = setOf("DECODER_REQUIRED", "DEPENDENCY_UNAVAILABLE", "PROVENANCE_UNAVAILABLE", "ISOLATION_UNAVAILABLE",
                "SCANNER_UNAVAILABLE", "SIGNATURES_STALE", "SCAN_NOT_CLEAN", "RESOURCE_LIMIT", "DECODE_UNAVAILABLE",
                "DERIVATIVE_LIMIT", "VALIDATION_STALE", "SCRATCH_CLEANUP_REQUIRED")
            val rejected = setOf("INVALID_IMAGE", "TYPE_MISMATCH", "PIXEL_LIMIT", "MULTIFRAME_UNSUPPORTED", "METADATA_INVALID")
            checkWire((state == "VALIDATED_PRIVATE" && code == "VALIDATION_COMPLETE") ||
                (state == "QUARANTINED" && code in unavailable) || (state == "REJECTED_PRIVATE" && code in rejected))
            checkWire(result.bool("can_download") == (state == "VALIDATED_PRIVATE"))
            PhotoStatus(evidenceId, state, code)
        }
    }
    override fun close() = http.close()

    private suspend fun <T> post(path: String, body: ByteArray, accessToken: ByteArray? = null,
        operationId: String? = null, allowEnrollment: Boolean = false, successes: Set<Int> = setOf(200), decode: (ByteArray) -> T): T {
        var attempted = false
        try {
            attempted = true
            return http.exchange(path, body, accessToken, operationId).use { reply ->
                if (reply.status !in successes) throw error(reply, allowEnrollment)
                decode(reply.bytes)
            }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (failure: RemoteFailure) { throw if (attempted && failure.kind != RemoteFailureKind.INVALID_REQUEST && failure.kind != RemoteFailureKind.UNAVAILABLE) failure.uncertain() else failure }
        catch (_: Exception) { throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE, mutationUncertain = attempted) }
        finally { body.fill(0) }
    }

    private suspend fun <T> get(path: String, accessToken: ByteArray, query: List<Pair<String, String>> = emptyList(),
        responseLimit: Int = 20 * 1024, decode: (ByteArray) -> T): T = http.exchange(path, accessToken = accessToken, query = query, responseLimit = responseLimit).use { reply ->
        if (reply.status != 200) throw error(reply, false)
        decode(reply.bytes)
    }

    private fun error(reply: HttpReply, allowEnrollment: Boolean): RemoteFailure {
        var code: RemoteCode? = null
        var enrollment: String? = null
        try {
            val value = StrictJson.objectFrom(reply.bytes)
            checkWire(value.keys.containsAll(setOf("code", "message")) && value.keys.all { it in setOf("code", "message", "errors", "enrollment_id") })
            value.text("message", 512, false) // Validate, then discard. Never display an untrusted server message.
            val parsed = RemoteCode.valueOf(value.text("code", 40))
            checkWire(validErrorStatus(parsed, reply.status))
            if ("errors" in value) validateErrors(value.getValue("errors"))
            if (parsed == RemoteCode.ENROLLMENT_EXISTS) {
                checkWire(allowEnrollment)
                enrollment = value.uuid("enrollment_id")
            } else checkWire("enrollment_id" !in value)
            code = parsed
        } catch (_: Exception) { enrollment = null }
        // Status survives malformed JSON/unknown code, so401/403 still fence authority in062.
        return RemoteFailure(RemoteFailureKind.HTTP, reply.status, code, retryAfter(reply.retryAfter, null), enrollment,
            retryAfterDate = parseRetryAfterDate(reply.retryAfter))
    }

    private fun validateErrors(value: JsonElement, depth: Int = 0) {
        checkWire(depth <= 3)
        when (value) {
            is JsonObject -> {
                checkWire(value.size <= 16 && value.keys.all { it in errorFields })
                value.values.forEach { validateErrors(it, depth + 1) }
            }
            is JsonArray -> { checkWire(value.size <= 8); value.forEach { validateErrors(it, depth + 1) } }
            is JsonPrimitive -> checkWire(value.isString && value.content.codePointCount(0, value.content.length) <= 256)
            else -> checkWire(false)
        }
    }
    private fun validErrorStatus(code: RemoteCode, status: Int): Boolean = status == when (code) {
        RemoteCode.INVALID_JSON, RemoteCode.INVALID_IDEMPOTENCY_KEY, RemoteCode.INVALID_FILTER -> 400
        RemoteCode.LOGIN_FAILED, RemoteCode.AUTH_REQUIRED, RemoteCode.REFRESH_REUSED -> 401
        RemoteCode.ACCESS_DENIED -> 403
        RemoteCode.NOT_FOUND -> 404
        RemoteCode.ENROLLMENT_EXISTS, RemoteCode.ENROLLMENT_REVOKED, RemoteCode.ENROLLMENT_LIMIT, RemoteCode.IDEMPOTENCY_CONFLICT,
        RemoteCode.REVISION_CONFLICT, RemoteCode.CORRECTION_UNAVAILABLE, RemoteCode.POLICY_UNAVAILABLE, RemoteCode.SCOPE_UNAVAILABLE -> 409
        RemoteCode.REQUEST_TOO_LARGE -> 413
        RemoteCode.INVALID_REQUEST -> 415
        RemoteCode.VALIDATION_ERROR, RemoteCode.TEMPLATE_UNSUPPORTED -> 422
        RemoteCode.THROTTLED -> 429
        RemoteCode.MOBILE_UNAVAILABLE -> 503
        RemoteCode.SERVER_ERROR -> if (status == 500) 500 else 503
    }
    private val errorFields = setOf("non_field_errors", "username", "password", "installation_id", "enrollment_id", "public_key_spki", "label", "challenge_id", "nonce", "signature", "refresh_token", "operation_id", "report_id", "expected_revision", "template_version", "payload", "observed_at", "category", "urgency", "area_label", "site_label", "reporter_label", "narrative", "assistance_requested")
}

/** HTTP-date needs a trusted server-time estimate supplied by062, never the phone wall clock. */
@RequiresApi(35)
fun retryAfter(value: String?, serverNowMillis: Long?): Long? {
    if (value == null || value.length > 128) return null
    if (value.matches(Regex("[0-9]+"))) return value.toLongOrNull()?.coerceAtMost(86400) ?: 86400
    if (serverNowMillis == null) return null
    return parseRetryAfterDate(value)?.delaySeconds(serverNowMillis)
}

@RequiresApi(35)
internal fun parseRetryAfterDate(value: String?): ServerRetryDate? = try {
    if (value == null || value.length > 128) null else {
        val shortDay = "Mon|Tue|Wed|Thu|Fri|Sat|Sun"
        val month = "Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec"
        val time = "[0-9]{2}:[0-9]{2}:[0-9]{2}"
        val imf = DateTimeFormatter.ofPattern("EEE, dd MMM uuuu HH:mm:ss 'GMT'", Locale.US).withResolverStyle(ResolverStyle.STRICT)
        when {
            value.matches(Regex("($shortDay), [0-9]{2} ($month) [0-9]{4} $time GMT")) ->
                fixedRetryDate(value, imf)
            value.matches(Regex("($shortDay) ($month) ( [1-9]|[0-9]{2}) $time [0-9]{4}")) -> {
                val parts = value.split(Regex(" +"))
                val normalized = "${parts[0]}, ${parts[2].padStart(2, '0')} ${parts[1]} ${parts[4]} ${parts[3]} GMT"
                fixedRetryDate(normalized, imf)
            }
            else -> {
                val days = listOf("Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday")
                val match = Regex("(${days.joinToString("|")}), ([0-9]{2})-($month)-([0-9]{2}) ($time) GMT").matchEntire(value)
                if (match == null) null else {
                    val (weekday, day, monthName, year, clock) = match.destructured
                    // A neutral leap-century validates calendar components without consulting a wall clock.
                    val parser = DateTimeFormatter.ofPattern("dd MMM uuuu HH:mm:ss", Locale.US).withResolverStyle(ResolverStyle.STRICT)
                    val leap = clock == "23:59:60"
                    val parsed = LocalDateTime.parse("$day $monthName ${2000 + year.toInt()} ${if (leap) "23:59:59" else clock}", parser)
                    ServerRetryDate.reduced(year.toInt(), parsed.monthValue, parsed.dayOfMonth, parsed.hour, parsed.minute,
                        if (leap) 60 else parsed.second, days.indexOf(weekday) + 1)
                }
            }
        }
    }
} catch (_: Exception) { null }

@RequiresApi(35)
private fun fixedRetryDate(value: String, formatter: DateTimeFormatter): ServerRetryDate {
    // Validate the original calendar day/weekday before conservatively mapping its leap second.
    // Only23:59:60 is normalized; an out-of-range second at any other time remains invalid.
    val leap = value.contains("23:59:60")
    val parsed = LocalDateTime.parse(if (leap) value.replace("23:59:60", "23:59:59") else value, formatter)
    return ServerRetryDate.fixed(parsed.toInstant(ZoneOffset.UTC).plusSeconds(if (leap) 1 else 0).toEpochMilli())
}

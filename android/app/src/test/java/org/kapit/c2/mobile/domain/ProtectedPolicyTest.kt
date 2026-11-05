package org.kapit.c2.mobile.domain

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test

class ProtectedPolicyTest {
    private val operation = "11111111-1111-4111-8111-111111111111"
    private val report = "22222222-2222-4222-8222-222222222222"
    private val revision = "33333333-3333-4333-8333-333333333333"
    private val content = MaintenanceContent("2026-10-17T00:00:00Z", "WATER_SUPPLY", "ROUTINE", "Area A", "Synthetic site", "Synthetic author", "Synthetic maintenance fixture", "Inspection")
    private val server = 1792195200000L
    private fun denied(code: StoreCode? = null, action: () -> Unit) {
        try { action(); fail("Expected safe denial") } catch (failure: StoreFailure) { if (code != null) assertEquals(code, failure.code) }
    }
    @Test fun sharedLeaseCasesMatchContract() {
        val fixture = javaClass.getResourceAsStream("/mobile-lease.json")!!.bufferedReader().use { Json.parseToJsonElement(it.readText()).jsonObject }
        for (item in fixture.getValue("cases").jsonArray) {
            val row = item.jsonObject
            fun long(key: String) = row.getValue(key).jsonPrimitive.long
            val start = ClockStamp(long("request_start_elapsed_ms"), "boot")
            val arrival = ClockStamp(long("response_elapsed_ms"), "boot")
            val offer = LeaseOffer(long("server_time_unix") * 1000, long("lease_expires_unix") * 1000, long("family_expires_unix") * 1000, long("lease_seconds"))
            if (row.getValue("expected_unlock").jsonPrimitive.boolean) assertEquals(long("expected_deadline_elapsed_ms"), LeasePolicy.accept(start, arrival, offer).deadlineElapsed)
            else denied { LeasePolicy.accept(start, arrival, offer) }
        }
    }
    @Test fun rebootRollbackMissingContinuityAndExactDeadlineDeny() {
        val lease = LeasePolicy.accept(ClockStamp(1000, "A"), ClockStamp(3000, "A"), LeaseOffer(server, server + 120000, server + 500000, 120))
        listOf(ClockStamp(4000, "B"), ClockStamp(4000, null), ClockStamp(2999, "A")).forEach { denied(StoreCode.CLOCK_UNTRUSTED) { LeasePolicy.requireValid(lease, it) } }
        LeasePolicy.requireValid(lease, ClockStamp(120999, "A"))
        denied(StoreCode.LEASE_EXPIRED) { LeasePolicy.requireValid(lease, ClockStamp(121000, "A")) }
    }
    @Test fun transitIsSubtractedAndNoWallClockCanExtendLease() {
        val lease = LeasePolicy.accept(ClockStamp(1000, "A"), ClockStamp(3000, "A"), LeaseOffer(server, server + 120000, server + 500000, 120))
        assertEquals(121000, lease.deadlineElapsed)
        assertEquals(server + 2000, LeasePolicy.estimatedServerTime(lease, ClockStamp(5000, "A")))
        assertEquals(server + 4000, LeasePolicy.expiryTimeUpperBound(lease, ClockStamp(5000, "A")))
    }
    @Test fun delayedResponseDoesNotFutureDateDraftWhileExpiryUsesConservativeTransit() {
        val lease = LeasePolicy.accept(ClockStamp(1000, "A"), ClockStamp(601000, "A"), LeaseOffer(server, server + 86400000, server + 172800000, 86400))
        assertEquals(server, LeasePolicy.estimatedServerTime(lease, ClockStamp(601000, "A")))
        assertEquals(server + 600000, LeasePolicy.expiryTimeUpperBound(lease, ClockStamp(601000, "A")))
        assertEquals(86401000, lease.deadlineElapsed)
    }
    @Test fun leaseOverflowAndInconsistentFamilyDeny() {
        denied { LeasePolicy.accept(ClockStamp(Long.MAX_VALUE - 1, "A"), ClockStamp(Long.MAX_VALUE - 1, "A"), LeaseOffer(server, server + 1000, server + 5000, 1)) }
        denied { LeasePolicy.accept(ClockStamp(1, "A"), ClockStamp(2, "A"), LeaseOffer(server, server + 1000, server + 999, 1)) }
    }
    @Test fun strictJsonRejectsDecodedDuplicatesFloatsAndInvalidUtf8() {
        listOf("{\"x\":1,\"\\u0078\":2}", "{\"x\":1.0}", "{\"x\":1e0}", "{\"x\":true,}", "{\"x\":\"\\ud800\"}", "{\"x\":9223372036854775808}", "{\"x\":01}").forEach {
            denied { StrictJson.objectFrom(it.toByteArray()) }
        }
        denied { StrictJson.objectFrom(byteArrayOf(123, 34, 120, 34, 58, 34, 0xc0.toByte(), 0xaf.toByte(), 34, 125)) }
        assertEquals(0, StrictJson.objectFrom("{\"x\":-0}".toByteArray()).requiredLong("x"))
    }
    @Test fun exactReceiptRejectsWrongIdentityTypeAndUnknownFields() {
        fun body(change: (MutableMap<String, JsonElement>) -> Unit = {}): ByteArray {
            val values = mutableMapOf<String, JsonElement>("operation_id" to JsonPrimitive(operation), "report_id" to JsonPrimitive(report), "revision_id" to JsonPrimitive(revision),
                "revision_no" to JsonPrimitive(1), "delivery_status" to JsonPrimitive("RECEIVED"), "processing_status" to JsonPrimitive("PENDING"), "shared" to JsonPrimitive(false))
            change(values); return CanonicalJson.bytes(JsonObject(values))
        }
        assertEquals(revision, ReceiptPolicy.validate(body(), operation, report, 0).revisionId)
        listOf<(MutableMap<String, JsonElement>) -> Unit>(
            { it["shared"] = JsonPrimitive("false") }, { it["revision_no"] = JsonPrimitive(true) }, { it["revision_no"] = JsonPrimitive(2) },
            { it["report_id"] = JsonPrimitive(operation) }, { it["extra"] = JsonNull }, { it.remove("processing_status") },
        ).forEach { change -> denied(StoreCode.RECEIPT_INVALID) { ReceiptPolicy.validate(body(change), operation, report, 0) } }
    }
    @Test fun timestampsAndUnicodeAreValidatedWithoutNormalization() {
        RequestPolicy.validateSubmission(content, server)
        RequestPolicy.validateSubmission(content.copy(observedAt = "2026-10-17T08:00:00+08:00"), server)
        denied { RequestPolicy.validateSubmission(content.copy(observedAt = "2026-02-30T00:00:00Z"), server) }
        denied { RequestPolicy.validateSubmission(content.copy(observedAt = "2026-10-17T00:05:01Z"), server) }
        denied { RequestPolicy.validateSubmission(content.copy(narrative = "\ud800"), server) }
        val decomposed = content.copy(siteLabel = "e\u0301")
        assertNotEquals(RequestPolicy.requestHash(RequestPolicy.request(operation, report, 0, decomposed, server)),
            RequestPolicy.requestHash(RequestPolicy.request(operation, report, 0, content.copy(siteLabel = "é"), server)))
    }
    @Test fun exactPayloadAndScalarLimitsRejectUnknownOrOversize() {
        denied { RequestPolicy.content(JsonObject(RequestPolicy.payload(content) + ("secret" to JsonPrimitive("synthetic")))) }
        val scalar = String(Character.toChars(0x1f6b0))
        RequestPolicy.validateDraft(content.copy(siteLabel = scalar.repeat(100)))
        denied { RequestPolicy.validateDraft(content.copy(siteLabel = scalar.repeat(101))) }
        denied { RequestPolicy.request("AAAAAAAA-1111-4111-8111-111111111111", report, 0, content, server) }
    }
    @Test fun accountEnrollmentIdentityAndPermissionZeroAreExplicit() {
        val account = AccountIdentity(operation, report, revision)
        assertNotEquals(account.storeRef, account.copy(enrollmentId = operation).storeRef)
        val context = AuthorizedContext(CaptureContext(account, operation, report, "private", MAINTENANCE_TEMPLATE), revision, 0, "Synthetic", "Org", "Unit", "Channel")
        assertEquals(0, context.permissionVersion)
        denied { account.copy(userId = "11111111-1111-4111-8111-11111111111") }
    }
    @Test fun detachedSecretsCloseAndNeverPrintToken() {
        val secret = SessionSecrets("synthetic-access".toByteArray(), "synthetic-refresh".toByteArray(), 1, 2)
        assertFalse(secret.toString().contains("synthetic")); secret.close()
        denied(StoreCode.AUTH_REQUIRED) { secret.copyAccessToken() }
        val logout = LogoutAuthorization("synthetic-access".toByteArray()); logout.close()
        denied(StoreCode.AUTH_REQUIRED) { logout.copyAccessToken() }
    }
}

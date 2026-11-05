package org.kapit.c2.mobile.data.remote

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.domain.*

class ReportCodecTest {
    @Test fun exactPageRetainsUnicodeFeedbackAndRejectsExtraSourceFieldsAndCountMismatch() {
        val feedback = "Synthetic e\u0301 \uD83D\uDE80 <script>display only</script>"
        val row = report(feedback = feedback)
        val page = ReportCodec.page(page(row), ReportQuery())
        assertEquals(feedback, page.results.single().feedback)
        assertEquals(1L, page.count)
        RemoteFixtures.reject { ReportCodec.page(page(JsonObject(row + ("raw_original" to JsonPrimitive("must fail")))), ReportQuery()) }
        val mismatch = StrictJson.objectFrom(page(row)).toMutableMap().apply { put("count", JsonPrimitive(2)) }
        RemoteFixtures.reject { ReportCodec.page(CanonicalJson.bytes(JsonObject(mismatch)), ReportQuery()) }
        val float = page(row).toString(Charsets.UTF_8).replace("\"count\":1", "\"count\":1.0")
        RemoteFixtures.reject { ReportCodec.page(float.toByteArray(), ReportQuery()) }
    }

    @Test fun filtersEnforceRealDatesRangeAndBoundedValuesBeforeAnyRequest() {
        listOf(ReportQuery(dateFrom = "2026-02-30"), ReportQuery(dateFrom = "2026-10-18", dateTo = "2026-10-17"),
            ReportQuery(dateFrom = "2026-1-1"), ReportQuery(page = 0), ReportQuery(pageSize = 51)).forEach { query ->
            assertEquals(RemoteFailureKind.INVALID_REQUEST, RemoteFixtures.reject { query.parameters() }.kind)
        }
        assertEquals("2147483647", ReportQuery(page = Int.MAX_VALUE).parameters().single { it.first == "page" }.second)
        RemoteFixtures.reject { ReportCodec.page(page(report()), ReportQuery(status = RemoteReportStatus.RETURNED)) }
    }

    @Test fun revisionBindsIdsReceiptRevisionAndCurrentCorrectionAuthority() {
        val body = revision(status = "RETURNED", correct = true)
        val result = ReportCodec.revision(body, RemoteFixtures.id(1), 1)
        assertTrue(result.canCorrect)
        assertEquals("Synthetic maintenance", result.payload.narrative)
        assertFalse(result.projection.containsKey("workflow"))
        assertNotNull(result.cacheOrNull(0))
        RemoteFixtures.reject { ReportCodec.revision(body, RemoteFixtures.id(2), 1) }
        RemoteFixtures.reject { ReportCodec.revision(body, RemoteFixtures.id(1), 2) }
        RemoteFixtures.reject { ReportCodec.revision(revision(status = "APPROVED", correct = true), RemoteFixtures.id(1), 1) }
        val invalidReceipt = StrictJson.objectFrom(body).toMutableMap().apply {
            put("receipt", JsonObject(getValue("receipt").jsonObject + ("shared" to JsonPrimitive(true))))
        }
        RemoteFixtures.reject { ReportCodec.revision(CanonicalJson.bytes(JsonObject(invalidReceipt)), RemoteFixtures.id(1), 1) }
        RemoteFixtures.reject { ReportCodec.revision(CanonicalJson.bytes(JsonObject(StrictJson.objectFrom(body) + ("receipt" to JsonNull))), RemoteFixtures.id(1), 1) }
    }

    @Test fun largeValidOnlineHistoryIsReturnedWithoutFalseCacheFailure() {
        val result = ReportCodec.revision(revision(number = 1000), RemoteFixtures.id(1), 1000)
        assertEquals(1000, result.history.size)
        assertNull(result.cacheOrNull(0))
        assertEquals(1000, result.report.revision)
    }

    @Test fun malformedHistoryAndWorkflowCannotEnterTheRetainedProjection() {
        val original = StrictJson.objectFrom(revision())
        val badHistory = JsonArray(listOf(buildJsonObject { put("revision_no", true); put("received_at", "yesterday"); put("status", "APPROVED") }))
        RemoteFixtures.reject { ReportCodec.revision(CanonicalJson.bytes(JsonObject(original + ("history" to badHistory))), RemoteFixtures.id(1), 1) }
        val unknownWorkflow = buildJsonObject { put("do_not_persist", "unvalidated private metadata") }
        val result = ReportCodec.revision(CanonicalJson.bytes(JsonObject(original + ("workflow" to unknownWorkflow))), RemoteFixtures.id(1), 1)
        assertFalse(result.cacheOrNull(0)!!.validatedJson.contains("do_not_persist"))
        RemoteFixtures.reject { ReportCodec.revision(CanonicalJson.bytes(JsonObject(original + ("workflow" to JsonPrimitive("invalid")))), RemoteFixtures.id(1), 1) }
    }

    @Test fun pageBoundedFeedbackUsesUnicodeScalarsAndDatesCannotBeInvented() {
        ReportCodec.page(page(report(feedback = "\uD83D\uDE80".repeat(4000))), ReportQuery())
        RemoteFixtures.reject { ReportCodec.page(page(report(feedback = "\uD83D\uDE80".repeat(4001))), ReportQuery()) }
        RemoteFixtures.reject { ReportCodec.page(page(JsonObject(report() + ("observed_date" to JsonPrimitive("2026-02-30")))), ReportQuery()) }
        RemoteFixtures.reject { ReportCodec.page(page(JsonObject(report() + ("revision_no" to JsonPrimitive("1")))), ReportQuery()) }
    }

    private fun report(number: Int = 1, status: String = "PENDING", feedback: String? = null) = buildJsonObject {
        put("id", RemoteFixtures.id(1)); put("reference", "R-00000000"); put("category", "WATER_SUPPLY"); put("urgency", "ROUTINE"); put("area_label", "Area A")
        put("created_at", "2026-10-17T08:00:00+00:00"); put("observed_date", "2026-10-17"); put("revision_no", number); put("status", status)
        put("variant_id", JsonNull); put("feedback", feedback?.let(::JsonPrimitive) ?: JsonNull)
    }
    private fun page(row: JsonObject) = CanonicalJson.bytes(buildJsonObject {
        put("results", JsonArray(listOf(row))); put("count", 1); put("page", 1); put("page_size", 10); put("total_pages", 1)
    })
    private fun revision(number: Int = 1, status: String = "PENDING", correct: Boolean = false) = CanonicalJson.bytes(buildJsonObject {
        put("report", report(number, status)); put("payload", RequestPolicy.payload(MaintenanceContent("2026-10-17T08:00:00Z", "WATER_SUPPLY", "ROUTINE", "Area A", "Synthetic site", "Synthetic reporter", "Synthetic maintenance", "Inspection")))
        putJsonObject("receipt") {
            put("operation_id", RemoteFixtures.id(2)); put("report_id", RemoteFixtures.id(1)); put("revision_id", RemoteFixtures.id(3)); put("revision_no", number)
            put("delivery_status", "RECEIVED"); put("processing_status", "PENDING"); put("shared", false)
        }
        put("can_correct", correct)
        put("history", JsonArray((number downTo 1).map { buildJsonObject { put("revision_no", it); put("received_at", "2026-10-17T08:00:00+00:00"); put("status", status) } }))
        putJsonObject("workflow") { put("discarded", true) }
    })
}

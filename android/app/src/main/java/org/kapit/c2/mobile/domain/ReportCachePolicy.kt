package org.kapit.c2.mobile.domain

import kotlinx.serialization.json.*

/** Persist only the small own-report UI projection; arbitrary workflow data never enters the cache. */
object ReportCachePolicy {
    private val summaryFields = setOf("id", "reference", "category", "urgency", "area_label", "created_at", "observed_date", "revision_no", "status", "variant_id", "feedback")
    private val statuses = setOf("PENDING", "PROCESSING", "AWAITING_REVIEW", "FAILED", "APPROVED", "RETURNED", "REJECTED")
    fun validate(report: CachedReport, opened: Boolean): CachedReport {
        canonicalUuid(report.reportId); requireStore(report.revision > 0, StoreCode.VALIDATION_ERROR)
        val input = StrictJson.objectFrom(report.validatedJson.toByteArray(Charsets.UTF_8), 64 * 1024)
        val result = if (!opened) summary(input, report) else {
            requireStore(input.keys.all { it in setOf("report", "payload", "receipt", "can_correct", "history", "workflow") }, StoreCode.VALIDATION_ERROR)
            val summary = summary(input.getValue("report").jsonObject, report)
            val payload = RequestPolicy.payload(RequestPolicy.content(input.getValue("payload").jsonObject))
            val correct = input["can_correct"] as? JsonPrimitive
            requireStore(correct != null && !correct.isString && correct.booleanOrNull != null, StoreCode.VALIDATION_ERROR)
            val history = input["history"] as? JsonArray ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
            requireStore(history.size <= 1000, StoreCode.VALIDATION_ERROR)
            history.forEach { item ->
                val row = item.jsonObject
                requireStore(row.keys == setOf("revision_no", "received_at", "status") && row.requiredLong("revision_no") > 0, StoreCode.VALIDATION_ERROR)
                text(row, "received_at", 50); requireStore(row.requiredString("status") in statuses, StoreCode.VALIDATION_ERROR)
            }
            // Receipt is historical display metadata; verify all its types before preserving it.
            val receipt = input["receipt"] ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
            if (receipt != JsonNull) {
                val row = receipt.jsonObject
                ReceiptPolicy.validate(CanonicalJson.bytes(row), canonicalUuid(row.requiredString("operation_id")), report.reportId, report.revision - 1)
            }
            buildJsonObject { put("report", summary); put("payload", payload); put("receipt", receipt); put("can_correct", correct!!); put("history", history) }
        }
        return report.copy(validatedJson = CanonicalJson.bytes(result).toString(Charsets.UTF_8))
    }
    private fun summary(value: JsonObject, report: CachedReport): JsonObject {
        requireStore(value.keys == summaryFields && value.requiredString("id") == report.reportId && value.requiredLong("revision_no") == report.revision.toLong(), StoreCode.VALIDATION_ERROR)
        listOf("reference", "category", "urgency", "area_label", "created_at", "observed_date").forEach { text(value, it, 100) }
        requireStore(value.requiredString("status") in statuses, StoreCode.VALIDATION_ERROR)
        if (value["variant_id"] != JsonNull) canonicalUuid(value.requiredString("variant_id"))
        if (value["feedback"] != JsonNull) text(value, "feedback", 4000)
        return value
    }
    private fun text(value: JsonObject, key: String, max: Int) {
        val text = value.requiredString(key)
        requireStore(text.codePointCount(0, text.length) <= max && StrictJson.validUnicode(text), StoreCode.VALIDATION_ERROR)
    }
}

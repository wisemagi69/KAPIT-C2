package org.kapit.c2.mobile.domain

import java.text.ParsePosition
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone
import kotlinx.serialization.json.*

object RequestPolicy {
    fun validateDraft(content: MaintenanceContent) {
        listOf(content.observedAt to 50, content.category to 32, content.urgency to 32,
            content.areaLabel to 32, content.siteLabel to 100, content.reporterLabel to 100,
            content.narrative to 2000, content.assistanceRequested to 64).forEach { (value, maximum) ->
            requireStore(StrictJson.validUnicode(value) && value.codePointCount(0, value.length) <= maximum, StoreCode.VALIDATION_ERROR)
        }
    }

    fun validateSubmission(content: MaintenanceContent, serverNowMillis: Long) {
        validateDraft(content)
        requireStore(content.siteLabel.isNotEmpty() && content.reporterLabel.isNotEmpty() && content.narrative.isNotEmpty(), StoreCode.VALIDATION_ERROR)
        requireStore(content.category in setOf("INFRASTRUCTURE", "WATER_SUPPLY", "EQUIPMENT"), StoreCode.VALIDATION_ERROR)
        requireStore(content.urgency in setOf("ROUTINE", "PRIORITY") && content.areaLabel in setOf("Area A", "Area B", "Area C"), StoreCode.VALIDATION_ERROR)
        requireStore(content.assistanceRequested in setOf("Repair assistance", "Inspection", "Replacement parts"), StoreCode.VALIDATION_ERROR)
        val observed = parseObservation(content.observedAt) ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
        requireStore(observed <= serverNowMillis || observed - serverNowMillis <= 300_000L, StoreCode.VALIDATION_ERROR)
    }

    fun payload(content: MaintenanceContent) = buildJsonObject {
        put("observed_at", content.observedAt); put("category", content.category); put("urgency", content.urgency)
        put("area_label", content.areaLabel); put("site_label", content.siteLabel); put("reporter_label", content.reporterLabel)
        put("narrative", content.narrative); put("assistance_requested", content.assistanceRequested)
    }

    fun content(json: JsonObject): MaintenanceContent {
        requireStore(json.keys == setOf("observed_at", "category", "urgency", "area_label", "site_label", "reporter_label", "narrative", "assistance_requested"), StoreCode.VALIDATION_ERROR)
        return MaintenanceContent(json.requiredString("observed_at"), json.requiredString("category"), json.requiredString("urgency"),
            json.requiredString("area_label"), json.requiredString("site_label"), json.requiredString("reporter_label"),
            json.requiredString("narrative"), json.requiredString("assistance_requested")).also(::validateDraft)
    }

    fun request(operationId: String, reportId: String, expectedRevision: Int, content: MaintenanceContent, serverNowMillis: Long): JsonObject {
        canonicalUuid(operationId); canonicalUuid(reportId)
        requireStore(expectedRevision in 0..2147483646, StoreCode.VALIDATION_ERROR)
        validateSubmission(content, serverNowMillis)
        return buildJsonObject {
            put("operation_id", operationId); put("report_id", reportId); put("expected_revision", expectedRevision)
            put("template_version", MAINTENANCE_TEMPLATE); put("payload", payload(content))
        }.also { requireStore(CanonicalJson.bytes(it).size <= 20 * 1024, StoreCode.VALIDATION_ERROR) }
    }

    fun requestHash(request: JsonObject): String = CanonicalJson.sha256(buildJsonObject {
        put("body", request); put("route", "POST /sync/operations/")
    })

    private fun parseObservation(value: String): Long? {
        val matched = Regex("([0-9]{4}-[0-9]{2}-[0-9]{2})[T ]([0-9]{2}:[0-9]{2})(?::([0-9]{2})(?:[.,]([0-9]+))?)?(Z|[+-][0-9]{2}(?::?[0-9]{2})?)").matchEntire(value) ?: return null
        val (date, minute, second, fraction, zone) = matched.destructured
        val offset = if (zone == "Z") "+0000" else zone.replace(":", "").let { if (it.length == 3) "${it}00" else it }
        if (offset.substring(1, 3).toInt() > 23 || offset.substring(3, 5).toInt() > 59) return null
        val temporary = "${date}T${minute}:${second.ifEmpty { "00" }}.${fraction.take(3).padEnd(3, '0')}$offset"
        val parser = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.ROOT).apply { isLenient = false; timeZone = TimeZone.getTimeZone("UTC") }
        val position = ParsePosition(0)
        val parsed = parser.parse(temporary, position)
        return if (parsed != null && position.index == temporary.length) parsed.time else null
    }
}

internal data class ReceiptValues(val operationId: String, val reportId: String, val revisionId: String, val revisionNo: Int)
internal object ReceiptPolicy {
    fun validate(body: ByteArray, operationId: String, reportId: String, expectedRevision: Int): ReceiptValues {
        try {
            requireStore(expectedRevision in 0..2147483646, StoreCode.RECEIPT_INVALID)
            val value = StrictJson.objectFrom(body)
            requireStore(value.keys == setOf("operation_id", "report_id", "revision_id", "revision_no", "delivery_status", "processing_status", "shared"), StoreCode.RECEIPT_INVALID)
            val operation = canonicalUuid(value.requiredString("operation_id"))
            val report = canonicalUuid(value.requiredString("report_id"))
            val revision = canonicalUuid(value.requiredString("revision_id"))
            val number = value.requiredLong("revision_no")
            requireStore(operation == operationId && report == reportId && number == expectedRevision.toLong() + 1, StoreCode.RECEIPT_INVALID)
            requireStore(value.requiredString("delivery_status") == "RECEIVED" && value.requiredString("processing_status") == "PENDING", StoreCode.RECEIPT_INVALID)
            val shared = value["shared"] as? JsonPrimitive
            requireStore(shared != null && !shared.isString && shared.booleanOrNull == false, StoreCode.RECEIPT_INVALID)
            return ReceiptValues(operation, report, revision, number.toInt())
        } catch (_: Exception) { throw StoreFailure(StoreCode.RECEIPT_INVALID) }
    }
}

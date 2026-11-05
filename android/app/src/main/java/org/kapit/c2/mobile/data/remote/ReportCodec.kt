package org.kapit.c2.mobile.data.remote

import androidx.annotation.RequiresApi
import java.time.LocalDate
import java.time.OffsetDateTime
import kotlinx.serialization.json.*
import org.kapit.c2.mobile.domain.*

@RequiresApi(35)
internal object ReportCodec {
    const val PAGE_LIMIT = 1024 * 1024
    const val REVISION_LIMIT = 256 * 1024

    fun page(bytes: ByteArray, query: ReportQuery): RemoteReportPage = wire {
        query.parameters()
        val value = StrictJson.objectFrom(bytes, PAGE_LIMIT)
        value.exact("results", "count", "page", "page_size", "total_pages")
        val count = value.requiredLong("count")
        val page = value.requiredLong("page")
        val size = value.requiredLong("page_size")
        val total = value.requiredLong("total_pages")
        checkWire(count in 0..Int.MAX_VALUE.toLong() && page == query.page.toLong() && size == query.pageSize.toLong())
        checkWire(total == maxOf(1L, (count + size - 1) / size))
        val rows = value["results"] as? JsonArray ?: throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE)
        val remaining = maxOf(0L, count - (page - 1) * size)
        checkWire(rows.size.toLong() == minOf(size, remaining))
        val reports = rows.map { summary(it as? JsonObject ?: throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE)) }
        checkWire(reports.map { it.id }.toSet().size == reports.size)
        checkWire(query.status == RemoteReportStatus.ALL || reports.all { it.status == query.status })
        RemoteReportPage(reports, count, page.toInt(), size.toInt(), total)
    }

    fun revision(bytes: ByteArray, expectedReport: String, expectedRevision: Int): RemoteRevision = wire {
        canonicalUuid(expectedReport); checkWire(expectedRevision > 0)
        val value = StrictJson.objectFrom(bytes, REVISION_LIMIT)
        value.exact("report", "payload", "receipt", "can_correct", "history", "workflow")
        val report = summary(value.obj("report"))
        checkWire(report.id == expectedReport && report.revision == expectedRevision)
        val payload = RequestPolicy.content(value.obj("payload"))
        RequestPolicy.validateSubmission(payload, Long.MAX_VALUE)
        checkWire(payload.category == report.category && payload.urgency == report.urgency && payload.areaLabel == report.areaLabel)
        val receiptObject = value.obj("receipt")
        val checked = ReceiptPolicy.validate(CanonicalJson.bytes(receiptObject), receiptObject.uuid("operation_id"), expectedReport, expectedRevision - 1)
        val receiptModel = RemoteReceipt(checked.operationId, checked.reportId, checked.revisionId, checked.revisionNo)
        val rows = value["history"] as? JsonArray ?: throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE)
        checkWire(rows.size in 1..1000)
        val history = rows.map {
            val row = it as? JsonObject ?: throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE)
            row.exact("revision_no", "received_at", "status")
            val revision = row.requiredLong("revision_no"); checkWire(revision in 1..Int.MAX_VALUE.toLong())
            RemoteRevisionHistory(revision.toInt(), timestamp(row.text("received_at", 50)), status(row.text("status", 24)))
        }
        checkWire(history.any { it.revision == expectedRevision })
        checkWire(history.zipWithNext().all { (first, next) -> first.revision > next.revision })
        val correct = value.bool("can_correct")
        checkWire(!correct || report.status == RemoteReportStatus.RETURNED && history.first().revision == expectedRevision)
        // This surface deliberately does not expose or persist workflow. Its root remains bounded JSON.
        value.obj("workflow")
        val projection = JsonObject(value.filterKeys { it != "workflow" })
        RemoteRevision(report, payload, receiptModel, correct, history, projection)
    }

    private fun summary(value: JsonObject): RemoteReport {
        value.exact("id", "reference", "category", "urgency", "area_label", "created_at", "observed_date", "revision_no", "status", "variant_id", "feedback")
        val revision = value.requiredLong("revision_no"); checkWire(revision in 1..Int.MAX_VALUE.toLong())
        val category = value.text("category", 32)
        val urgency = value.text("urgency", 32)
        val area = value.text("area_label", 32)
        checkWire(category in setOf("INFRASTRUCTURE", "WATER_SUPPLY", "EQUIPMENT"))
        checkWire(urgency in setOf("ROUTINE", "PRIORITY") && area in setOf("Area A", "Area B", "Area C"))
        val reference = value.text("reference", 100)
        val observed = value.text("observed_date", 10)
        checkWire(observed.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}"))); LocalDate.parse(observed)
        return RemoteReport(value.uuid("id"), revision.toInt(), status(value.text("status", 24)), reference, category, urgency, area,
            timestamp(value.text("created_at", 50)), observed, if (value["feedback"] == JsonNull) null else value.text("feedback", 4000, false),
            value.nullableUuid("variant_id"), value)
    }

    private fun status(value: String): RemoteReportStatus = RemoteReportStatus.valueOf(value).also { checkWire(it != RemoteReportStatus.ALL) }
    private fun timestamp(value: String): String = value.also { OffsetDateTime.parse(it) }
}

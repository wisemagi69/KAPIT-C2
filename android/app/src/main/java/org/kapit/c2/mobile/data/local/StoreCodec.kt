package org.kapit.c2.mobile.data.local

import kotlinx.serialization.json.*
import org.kapit.c2.mobile.domain.*

internal object StoreCodec {
    fun encode(value: JsonObject) = CanonicalJson.bytes(value).toString(Charsets.UTF_8)
    fun decode(value: String) = StrictJson.objectFrom(value.toByteArray(Charsets.UTF_8), 128 * 1024)
    fun capture(value: CaptureContext) = buildJsonObject {
        put("organization", value.account.organizationId); put("user", value.account.userId); put("enrollment", value.account.enrollmentId)
        put("unit", value.unitId); put("channel", value.channelId); put("profile", value.profile); put("template", value.templateVersion)
    }
    fun capture(value: JsonObject) = CaptureContext(AccountIdentity(value.requiredString("organization"), value.requiredString("user"), value.requiredString("enrollment")),
        value.requiredString("unit"), value.requiredString("channel"), value.requiredString("profile"), value.requiredString("template"))
    fun context(value: AuthorizedContext) = encode(buildJsonObject {
        put("capture", capture(value.capture)); put("family", value.familyId); put("permission_version", value.permissionVersion)
        put("display", value.displayName); put("organization_label", value.organizationLabel); put("unit_label", value.unitLabel)
        put("channel_label", value.channelLabel); put("role", value.role)
    })
    fun context(value: String): AuthorizedContext = decode(value).let {
        AuthorizedContext(capture(it.getValue("capture").jsonObject), it.requiredString("family"), it.requiredLong("permission_version"),
            it.requiredString("display"), it.requiredString("organization_label"), it.requiredString("unit_label"), it.requiredString("channel_label"), it.requiredString("role"))
    }
    fun lease(value: OfflineLease) = encode(buildJsonObject {
        put("start", value.requestStartElapsed); put("arrival", value.responseElapsed); put("deadline", value.deadlineElapsed)
        put("boot", value.bootId); put("server", value.serverTimeMillis); put("family_expires", value.familyExpiresServerMillis)
    })
    fun lease(value: String): OfflineLease = decode(value).let { OfflineLease(it.requiredLong("start"), it.requiredLong("arrival"), it.requiredLong("deadline"), it.requiredString("boot"), it.requiredLong("server"), it.requiredLong("family_expires")) }
    fun draft(value: DraftRecord) = encode(buildJsonObject {
        put("id", value.id); put("revision", value.revision); put("content", RequestPolicy.payload(value.content)); put("report", value.reportId)
        put("expected", value.expectedReportRevision); put("predecessor", value.predecessorOperationId); put("capture", capture(value.capture)); put("saved", value.savedAtServerMillis)
    })
    fun draft(value: String): DraftRecord = decode(value).let {
        DraftRecord(it.requiredString("id"), it.requiredLong("revision"), RequestPolicy.content(it.getValue("content").jsonObject), it.optionalString("report"),
            it.requiredLong("expected").toInt(), it.optionalString("predecessor"), capture(it.getValue("capture").jsonObject), it.requiredLong("saved"))
    }
    fun outbox(submitted: SubmittedRow, row: OutboxRow) = OutboxRecord(submitted.operationId, submitted.reportId, submitted.expectedRevision,
        RequestPolicy.content(decode(submitted.contentJson)), capture(decode(submitted.captureJson)), submitted.requestHash,
        DeliveryState.valueOf(row.delivery), row.pause?.let(PauseReason::valueOf), row.attempts, row.nextAttemptElapsed, submitted.queuedAtServerMillis, submitted.predecessorOperation)
    fun commandHash(kind: String, input: JsonObject) = CanonicalJson.sha256(buildJsonObject { put("kind", kind); put("input", input) })
    private fun JsonObject.optionalString(key: String): String? = if (get(key) == JsonNull) null else requiredString(key)
}

package org.kapit.c2.mobile.ui

import java.text.ParsePosition
import java.text.SimpleDateFormat
import java.util.Locale
import java.util.TimeZone

/** Early field guidance only. The controller validates the complete immutable request and 20 KiB bound. */
fun validateMaintenanceForm(form: MaintenanceForm, serverTimeMillis: Long? = null): Map<MaintenanceField, String> = buildMap {
    fun text(field: MaintenanceField, value: String, limit: Int) {
        when {
            value.isEmpty() -> put(field, "Enter ${field.label.lowercase(Locale.ROOT)}.")
            !hasValidUnicode(value) -> put(field, "Remove the unsupported character.")
            value.codePointCount(0, value.length) > limit -> put(field, "Use $limit characters or fewer.")
        }
    }
    text(MaintenanceField.OBSERVED_AT, form.observedAt, 50)
    if (MaintenanceField.OBSERVED_AT !in this) {
        val observed = parseObservation(form.observedAt)
        if (observed == null) put(MaintenanceField.OBSERVED_AT, "Use a valid date and time with a timezone, such as UTC ending in Z.")
        else if (serverTimeMillis != null && observed > serverTimeMillis && observed - serverTimeMillis > 300_000L)
            put(MaintenanceField.OBSERVED_AT, "Observation cannot be more than five minutes ahead.")
    }
    if (form.category == null) put(MaintenanceField.CATEGORY, "Choose a category.")
    if (form.urgency == null) put(MaintenanceField.URGENCY, "Choose an urgency.")
    if (form.area == null) put(MaintenanceField.AREA, "Choose an area.")
    text(MaintenanceField.SITE, form.siteLabel, 100)
    text(MaintenanceField.REPORTER, form.reporterLabel, 100)
    text(MaintenanceField.NARRATIVE, form.narrative, 2000)
    if (form.assistance == null) put(MaintenanceField.ASSISTANCE, "Choose the assistance requested.")
}

private fun parseObservation(value: String): Long? {
    // New drafts are initialized as UTC seconds by the controller. Historical returned sources may
    // contain fractions/offsets. Parse a temporary representation; NEVER rewrite the actual field.
    val matched = Regex("([0-9]{4}-[0-9]{2}-[0-9]{2})[T ]([0-9]{2}:[0-9]{2})(?::([0-9]{2})(?:[.,]([0-9]+))?)?(Z|[+-][0-9]{2}(?::?[0-9]{2})?)").matchEntire(value) ?: return null
    val (date, minute, second, fraction, zone) = matched.destructured
    val offset = if (zone == "Z") "+0000" else zone.replace(":", "").let { if (it.length == 3) "${it}00" else it }
    if (offset.substring(1, 3).toInt() > 23 || offset.substring(3, 5).toInt() > 59) return null
    val temporary = "${date}T${minute}:${second.ifEmpty { "00" }}.${fraction.take(3).padEnd(3, '0')}$offset"
    val parser = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ", Locale.ROOT).apply {
        isLenient = false
        timeZone = TimeZone.getTimeZone("UTC")
    }
    val position = ParsePosition(0)
    val result = parser.parse(temporary, position)
    return if (result != null && position.index == temporary.length) result.time else null
}

internal fun validCredentialText(value: String, maximumScalars: Int): Boolean =
    value.isNotEmpty() && hasValidUnicode(value) && value.codePointCount(0, value.length) <= maximumScalars

internal fun hasValidUnicode(value: String): Boolean {
    var index = 0
    while (index < value.length) {
        val character = value[index]
        if (character.isHighSurrogate()) {
            if (index + 1 >= value.length || !value[index + 1].isLowSurrogate()) return false
            index += 2
        } else {
            if (character.isLowSurrogate()) return false
            index++
        }
    }
    return true
}

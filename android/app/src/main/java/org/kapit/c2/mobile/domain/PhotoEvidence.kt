package org.kapit.c2.mobile.domain

import java.io.Closeable
import java.security.MessageDigest
import java.text.SimpleDateFormat
import java.text.ParsePosition
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import kotlinx.serialization.json.*

/** Private, device-reported metadata. Neither location nor mock status is verified. */
class PhotoFix(val latitudeE7: Long, val longitudeE7: Long, val accuracyMm: Long,
    val wallMillis: Long, val elapsedMillis: Long, val mock: Boolean) {
    override fun toString() = "PhotoFix(redacted)"
}

data class PhotoPending(val operationId: String, val reportId: String, val revisionId: String,
    val revisionNo: Int, val evidenceId: String?) {
    override fun toString() = "PhotoPending(redacted)"
}

class PhotoUpload(val pending: PhotoPending, val capture: String, bytes: ByteArray) : Closeable {
    private val original = bytes.also { requireStore(it.size in 4..PhotoPolicy.LOCAL_BYTES, StoreCode.VALIDATION_ERROR) }.copyOf()
    private var closed = false
    @Synchronized fun copyBytes(): ByteArray { requireStore(!closed, StoreCode.STALE_GENERATION); return original.copyOf() }
    @Synchronized override fun close() { original.fill(0); closed = true }
    override fun toString() = "PhotoUpload(redacted)"
}

data class PhotoReceipt(val id: String, val operationId: String)
data class PhotoStatus(val evidenceId: String, val state: String, val validationCode: String) {
    override fun toString() = "PhotoStatus(redacted)"
}

object PhotoPolicy {
    const val MAX_BYTES = 5 * 1024 * 1024
    const val LOCAL_BYTES = 768 * 1024 // Stay below CursorWindow row limits; server ceiling is separate.
    const val MAX_PIXELS = 2_000_000
    const val QUEUE_BYTES = 20 * 1024 * 1024
    const val QUEUE_ITEMS = 8
    // Pure min-API23-compatible strict UTC millisecond codec. No host locale or
    // newer Android java.time availability is needed by protected storage.
    private fun utcFormat() = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'", Locale.ROOT).apply {
        timeZone = TimeZone.getTimeZone("UTC"); isLenient = false
    }
    private fun utc(millis: Long) = utcFormat().format(Date(millis))
    fun digest(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }

    fun jpeg(bytes: ByteArray) {
        requireStore(bytes.size in 4..MAX_BYTES && bytes[0] == 0xff.toByte() && bytes[1] == 0xd8.toByte()
            && bytes[bytes.size - 2] == 0xff.toByte() && bytes.last() == 0xd9.toByte(), StoreCode.VALIDATION_ERROR)
    }

    fun capture(wallMillis: Long, elapsedMillis: Long, fix: PhotoFix?): String {
        val location = fix?.let {
            val age = elapsedMillis - it.elapsedMillis
            requireStore(age in 0..30000, StoreCode.VALIDATION_ERROR)
            buildJsonObject {
                put("latitude_e7", it.latitudeE7); put("longitude_e7", it.longitudeE7); put("accuracy_mm", it.accuracyMm)
                put("fix_at", utc(it.wallMillis)); put("age_ms", age); put("mock", it.mock)
            }
        } ?: JsonNull
        val value = buildJsonObject { put("version", 1); put("captured_at", utc(wallMillis)); put("location", location) }
        return CanonicalJson.bytes(value).toString(Charsets.US_ASCII).also { validateCapture(it) }
    }

    fun validateCapture(text: String) {
        requireStore(text.length <= 1024 && text.all { it.code in 32..126 }, StoreCode.VALIDATION_ERROR)
        val obj = StrictJson.objectFrom(text.toByteArray(Charsets.US_ASCII), 1024)
        fun exact(value: JsonObject, vararg names: String) = requireStore(value.keys == names.toSet(), StoreCode.VALIDATION_ERROR)
        fun number(value: JsonObject, name: String): Long {
            val item = value[name] as? JsonPrimitive ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
            requireStore(!item.isString && item.content.matches(Regex("-?(0|[1-9][0-9]*)")), StoreCode.VALIDATION_ERROR)
            return item.longOrNull ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
        }
        fun timestamp(value: JsonObject, name: String): Long {
            val item = value[name] as? JsonPrimitive ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
            requireStore(item.isString && item.content.matches(Regex("[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(\\.[0-9]{1,3})?Z")), StoreCode.VALIDATION_ERROR)
            val source = item.content
            val fraction = source.substring(19).removeSuffix("Z").removePrefix(".")
            val normalized = source.substring(0, 19) + "." + fraction.padEnd(3, '0') + "Z"
            val position = ParsePosition(0)
            val parsed = utcFormat().parse(normalized, position)
            requireStore(parsed != null && position.index == normalized.length && utc(parsed.time) == normalized, StoreCode.VALIDATION_ERROR)
            return parsed!!.time
        }
        exact(obj, "version", "captured_at", "location"); requireStore(number(obj, "version") == 1L, StoreCode.VALIDATION_ERROR)
        val captured = timestamp(obj, "captured_at")
        if (obj["location"] != JsonNull) {
            val location = obj["location"] as? JsonObject ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
            exact(location, "latitude_e7", "longitude_e7", "accuracy_mm", "fix_at", "age_ms", "mock")
            requireStore(number(location, "latitude_e7") in -900000000..900000000 && number(location, "longitude_e7") in -1800000000..1800000000
                && number(location, "accuracy_mm") in 1..100000000, StoreCode.VALIDATION_ERROR)
            val age = number(location, "age_ms"); val delta = captured - timestamp(location, "fix_at")
            requireStore(age in 0..30000 && delta in 0..30000 && kotlin.math.abs(delta - age) <= 1000, StoreCode.VALIDATION_ERROR)
            val mock = location["mock"] as? JsonPrimitive ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
            requireStore(!mock.isString && mock.booleanOrNull != null, StoreCode.VALIDATION_ERROR)
        }
    }
}

/** One originating permission request; a recomposed callback cannot rebind it. */
class PhotoPermissionFence {
    private class Ticket(val owner: Any, val generation: Long, val revision: String)
    private var ticket: Ticket? = null
    @Synchronized fun begin(owner: Any, generation: Long, revision: String): Boolean {
        if (ticket != null) return false
        ticket = Ticket(owner, generation, revision); return true
    }
    @Synchronized fun consume(owner: Any, generation: Long, revision: String, foreground: Boolean): Boolean {
        val old = ticket; ticket = null
        return foreground && old != null && old.owner === owner && old.generation == generation && old.revision == revision
    }
}

/** Serialize native handle adoption with closure; late handles are never owned. */
class PhotoOwnership {
    private var closed = false
    @Synchronized fun withOpen(action: () -> Unit): Boolean {
        if (closed) return false
        action(); return true
    }
    @Synchronized fun close(detach: () -> Unit) {
        if (closed) return
        closed = true; detach()
    }
}

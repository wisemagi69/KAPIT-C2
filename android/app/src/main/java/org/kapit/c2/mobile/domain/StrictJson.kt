package org.kapit.c2.mobile.domain

import java.nio.ByteBuffer
import java.nio.charset.CodingErrorAction
import kotlinx.serialization.json.*

/** Bounded integer-only JSON grammar with duplicate decoded-key and invalid UTF-8 rejection. */
object StrictJson {
    fun objectFrom(bytes: ByteArray, maxBytes: Int = 20 * 1024): JsonObject {
        requireStore(bytes.size <= maxBytes, StoreCode.VALIDATION_ERROR)
        return try {
            val text = Charsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString()
            Parser(text).read() as? JsonObject ?: throw StoreFailure(StoreCode.VALIDATION_ERROR)
        } catch (_: Exception) { throw StoreFailure(StoreCode.VALIDATION_ERROR) }
    }

    fun validUnicode(value: String): Boolean {
        var index = 0
        while (index < value.length) {
            val char = value[index++]
            if (char.isHighSurrogate()) {
                if (index >= value.length || !value[index++].isLowSurrogate()) return false
            } else if (char.isLowSurrogate()) return false
        }
        return true
    }

    private class Parser(private val text: String) {
        private var index = 0
        private fun bad(): Nothing = throw StoreFailure(StoreCode.VALIDATION_ERROR)
        private fun space() { while (index < text.length && text[index] in " \t\r\n") index++ }
        private fun take(char: Char): Boolean { space(); return if (index < text.length && text[index] == char) { index++; true } else false }
        fun read(): JsonElement { val result = value(0); space(); if (index != text.length) bad(); return result }
        private fun value(depth: Int): JsonElement {
            space(); if (depth > 16 || index >= text.length) bad()
            return when (text[index]) {
                '{' -> {
                    index++; val entries = linkedMapOf<String, JsonElement>()
                    if (!take('}')) {
                        do {
                            space(); val key = string()
                            if (entries.containsKey(key) || !take(':')) bad()
                            entries[key] = value(depth + 1)
                        } while (take(','))
                        if (!take('}')) bad()
                    }
                    JsonObject(entries)
                }
                '[' -> {
                    index++; val entries = mutableListOf<JsonElement>()
                    if (!take(']')) {
                        do { entries += value(depth + 1) } while (take(','))
                        if (!take(']')) bad()
                    }
                    JsonArray(entries)
                }
                '"' -> JsonPrimitive(string())
                't' -> literal("true", JsonPrimitive(true))
                'f' -> literal("false", JsonPrimitive(false))
                'n' -> literal("null", JsonNull)
                else -> {
                    val start = index
                    if (text[index] == '-') index++
                    while (index < text.length && text[index] in '0'..'9') index++
                    val token = text.substring(start, index)
                    if (!Regex("-?(0|[1-9][0-9]*)").matches(token)) bad()
                    JsonPrimitive(token.toLongOrNull() ?: bad())
                }
            }
        }
        private fun literal(token: String, value: JsonElement): JsonElement {
            if (!text.startsWith(token, index)) bad()
            index += token.length; return value
        }
        private fun string(): String {
            if (index >= text.length || text[index] != '"') bad()
            val start = index++
            while (index < text.length) {
                val char = text[index++]
                if (char.code < 32) bad()
                if (char == '\\') { if (index >= text.length) bad(); index++ }
                else if (char == '"') {
                    val value = Json.parseToJsonElement(text.substring(start, index)).jsonPrimitive.content
                    if (!validUnicode(value)) bad()
                    return value
                }
            }
            bad()
        }
    }
}

internal fun JsonObject.requiredString(key: String): String {
    val item = this[key] as? JsonPrimitive
    requireStore(item != null && item.isString, StoreCode.VALIDATION_ERROR)
    return item!!.content
}

internal fun JsonObject.requiredLong(key: String): Long {
    val item = this[key] as? JsonPrimitive
    requireStore(item != null && !item.isString && item.longOrNull != null, StoreCode.VALIDATION_ERROR)
    return item!!.long
}

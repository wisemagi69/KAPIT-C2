package org.kapit.c2.mobile.domain

import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import java.security.MessageDigest

/** Matches the server's bounded report grammar, without rewriting string spelling. */
object CanonicalJson {
    private val integer = Regex("-?(0|[1-9][0-9]*)")

    fun bytes(value: JsonElement): ByteArray = encode(value).toByteArray(Charsets.UTF_8)
    fun sha256(value: JsonElement): String = MessageDigest.getInstance("SHA-256")
        .digest(bytes(value)).joinToString("") { "%02x".format(it.toInt() and 255) }

    private fun encode(value: JsonElement): String = when (value) {
        is JsonObject -> value.entries.sortedWith { a, b -> compareCodePoints(a.key, b.key) }
            .joinToString(",", "{", "}") { "${string(it.key)}:${encode(it.value)}" }
        is JsonArray -> value.joinToString(",", "[", "]") { encode(it) }
        JsonNull -> "null"
        is JsonPrimitive -> if (value.isString) string(value.content) else {
            require(value.content == "true" || value.content == "false" || integer.matches(value.content)) {
                "Only finite integer numbers are supported by the report protocol"
            }
            if (value.content == "-0") "0" else value.content
        }
    }

    private fun string(text: String): String = buildString {
        append('"')
        var index = 0
        while (index < text.length) {
            val char = text[index]
            when (char) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\b' -> append("\\b")
                '\u000C' -> append("\\f")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> when {
                    char.code < 32 -> append("\\u%04x".format(char.code))
                    char.isHighSurrogate() -> {
                        require(index + 1 < text.length && text[index + 1].isLowSurrogate()) { "Invalid Unicode scalar" }
                        append(char); append(text[++index])
                    }
                    char.isLowSurrogate() -> error("Invalid Unicode scalar")
                    else -> append(char)
                }
            }
            index++
        }
        append('"')
    }

    private fun compareCodePoints(a: String, b: String): Int {
        var left = 0
        var right = 0
        while (left < a.length && right < b.length) {
            val x = a.codePointAt(left)
            val y = b.codePointAt(right)
            if (x != y) return x.compareTo(y)
            left += Character.charCount(x)
            right += Character.charCount(y)
        }
        return (a.length - left).compareTo(b.length - right)
    }
}


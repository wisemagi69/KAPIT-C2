package org.kapit.c2.mobile

import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.domain.CanonicalJson
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.spec.X509EncodedKeySpec
import java.util.Base64

class ProtocolCompatibilityTest {
    private fun fixture(name: String): JsonObject = Json.parseToJsonElement(
        javaClass.getResourceAsStream("/$name")!!.bufferedReader().use { it.readText() },
    ).jsonObject
    private fun JsonElement.text() = jsonPrimitive.content
    private fun hex(bytes: ByteArray) = bytes.joinToString("") { "%02x".format(it.toInt() and 255) }

    @Test fun eightCanonicalFixturesMatchIndependentPythonBytesAndHashes() {
        val document = fixture("mobile-canonical.json")
        val vectors = document.getValue("vectors").jsonArray
        assertEquals(8, vectors.size)
        for (entry in vectors) {
            val vector = entry.jsonObject
            val envelope = buildJsonObject {
                put("body", vector.getValue("body")); put("route", document.getValue("logical_route"))
            }
            assertEquals(vector.getValue("id").text(), vector.getValue("canonical_utf8").text(), CanonicalJson.bytes(envelope).toString(Charsets.UTF_8))
            assertEquals(vector.getValue("canonical_utf8_hex").text(), hex(CanonicalJson.bytes(envelope)))
            assertEquals(vector.getValue("sha256").text(), CanonicalJson.sha256(envelope))
        }
    }

    @Test fun nonfiniteFloatsAndInvalidUnicodeCannotBeFrozen() {
        listOf(JsonPrimitive(Double.NaN), JsonPrimitive(1.5), JsonPrimitive("\uD800")).forEach {
            var rejected = false
            try { CanonicalJson.bytes(it) } catch (_: IllegalArgumentException) { rejected = true }
            catch (_: IllegalStateException) { rejected = true }
            assertTrue(rejected)
        }
    }

    @Test fun escapedWireUnicodeAndDifferentKeyOrderRecoverSameHash() {
        val document = fixture("mobile-canonical.json")
        val vectors = document.getValue("vectors").jsonArray.associate { it.jsonObject.getValue("id").text() to it.jsonObject }
        val wires = document.getValue("equivalent_wire_forms").jsonArray
        assertEquals(1, wires.size)
        wires.forEach { entry ->
            val wire = entry.jsonObject
            val envelope = buildJsonObject {
                put("body", Json.parseToJsonElement(wire.getValue("raw_json").text()))
                put("route", document.getValue("logical_route"))
            }
            assertEquals(vectors.getValue(wire.getValue("vector_id").text()).getValue("sha256").text(), CanonicalJson.sha256(envelope))
        }
    }

    @Test fun integerNegativeZeroMatchesPythonIntegerEncoding() {
        assertArrayEquals("0".toByteArray(), CanonicalJson.bytes(Json.parseToJsonElement("-0")))
        assertEquals(CanonicalJson.sha256(JsonPrimitive(0)), CanonicalJson.sha256(Json.parseToJsonElement("-0")))
    }

    @Test fun pythonP256DerSignaturesVerifyAndAllChangedBindingsFail() {
        val document = fixture("mobile-proof.json")
        val decode = Base64.getUrlDecoder()
        val spki = decode.decode(document.getValue("public_key_spki_base64url").text())
        assertEquals(document.getValue("public_key_sha256").text(), hex(MessageDigest.getInstance("SHA-256").digest(spki)))
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(spki))
        fun verify(message: String, signature: ByteArray): Boolean = Signature.getInstance("SHA256withECDSA").run {
            initVerify(key); update(message.toByteArray(Charsets.UTF_8)); verify(signature)
        }
        val vectors = document.getValue("vectors").jsonArray
        assertEquals(2, vectors.size)
        for (entry in vectors) {
            val vector = entry.jsonObject
            val binding = vector.getValue("binding").jsonObject
            val lines = listOf("KAPIT-C2-MOBILE-PROOF-V1", "action", "challenge_id", "user_id", "organization_id",
                "enrollment_id", "installation_id", "key_fingerprint", "nonce", "expires_unix")
            val message = lines.mapIndexed { index, field ->
                if (index == 0) field else binding.getValue(field).let { if (it == JsonNull) "-" else it.text() }
            }.joinToString("\n", postfix = "\n")
            val signature = decode.decode(vector.getValue("signature_der_base64url").text())
            assertEquals(vector.getValue("proof_message").text(), message)
            assertEquals(vector.getValue("proof_utf8_hex").text(), hex(message.toByteArray(Charsets.UTF_8)))
            assertEquals(0x30, signature.first().toInt())
            assertTrue(verify(message, signature))
            assertFalse(verify(message + "altered", signature))
        }
        val original = vectors.first().jsonObject
        val message = original.getValue("proof_message").text()
        val signature = decode.decode(original.getValue("signature_der_base64url").text())
        for (entry in document.getValue("tamper_cases").jsonArray) {
            val tamper = entry.jsonObject
            val altered = when {
                "replace_line" in tamper -> message.split('\n').toMutableList().apply {
                    this[tamper.getValue("replace_line").jsonPrimitive.int] = tamper.getValue("replacement").text()
                }.joinToString("\n")
                "remove_final_lf" in tamper -> message.dropLast(1)
                "replace_lf_with_crlf" in tamper -> message.replace("\n", "\r\n")
                else -> error("Unknown interoperability case")
            }
            assertFalse(tamper.getValue("id").text(), verify(altered, signature))
        }
    }
}

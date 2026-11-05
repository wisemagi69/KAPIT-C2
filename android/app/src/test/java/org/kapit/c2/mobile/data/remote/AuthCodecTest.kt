package org.kapit.c2.mobile.data.remote

import java.time.Instant
import kotlinx.serialization.json.*
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.domain.*

class AuthCodecTest {
    @Test fun acceptedSharedProofVectorsReconstructExactlyAndVerifyWithPlatformCrypto() {
        RemoteFixtures.proof.getValue("vectors").jsonArray.forEach { item ->
            val vector = item.jsonObject
            RemoteFixtures.request(vector).use { request ->
                val challenge = AuthCodec.challenge(RemoteFixtures.challenge(vector), request, RemoteFixtures.start, RemoteFixtures.arrival)
                assertArrayEquals(vector.getValue("proof_message").jsonPrimitive.content.toByteArray(), challenge.copyProofBytes())
                val token = StrictJson.objectFrom(AuthCodec.tokenRequest(challenge, decode64(vector.getValue("signature_der_base64url").jsonPrimitive.content, 100), RemoteFixtures.arrival))
                assertEquals(setOf("challenge_id", "nonce", "signature"), token.keys)
            }
        }
    }

    @Test fun proofCannotSignSubstitutedInstallAccountEnrollmentKeyOrMessage() {
        RemoteFixtures.request().use { request ->
            val original = StrictJson.objectFrom(RemoteFixtures.challenge())
            val mutations = listOf("installation_id" to JsonPrimitive(RemoteFixtures.id(90)), "user_id" to JsonPrimitive(RemoteFixtures.id(91)),
                "enrollment_id" to JsonPrimitive(RemoteFixtures.id(92)), "action" to JsonPrimitive("REAUTHENTICATE"),
                "key_fingerprint" to JsonPrimitive("0".repeat(64)), "proof_message" to JsonPrimitive(original.text("proof_message", 2048).replace("\n", "\r\n")),
                "nonce" to JsonPrimitive(original.text("nonce", 43) + "="))
            mutations.forEach { (name, value) -> RemoteFixtures.reject { AuthCodec.challenge(CanonicalJson.bytes(JsonObject(original + (name to value))), request, RemoteFixtures.start, RemoteFixtures.arrival) } }
            RemoteFixtures.reject { AuthCodec.challenge(CanonicalJson.bytes(JsonObject(original + ("unexpected" to JsonPrimitive(true)))), request, RemoteFixtures.start, RemoteFixtures.arrival) }
        }
    }

    @Test fun challengeExpiresAtEqualityAndRejectsRebootOrReversedClock() {
        RemoteFixtures.request().use { request ->
            listOf(ClockStamp(120_100, "boot"), ClockStamp(101, "other"), ClockStamp(99, "boot")).forEach {
                assertEquals(RemoteFailureKind.EXPIRED_RESPONSE, RemoteFixtures.reject { AuthCodec.challenge(RemoteFixtures.challenge(), request, RemoteFixtures.start, it) }.kind)
            }
        }
    }

    @Test fun requestPreservesUnicodeAndWhitespaceButRejectsSurrogatesAndControlLabels() {
        val username = " " + "\uD83D\uDE80".repeat(148) + " "
        ChallengeRequest(username, " password ".toCharArray(), RemoteFixtures.install, null, RemoteFixtures.key, "Synthetic phone").use {
            val encoded = StrictJson.objectFrom(AuthCodec.challengeRequest(it))
            assertEquals(username, encoded.text("username", 150))
            assertEquals(" password ", encoded.text("password", 128))
        }
        listOf("bad\nlabel", "bad\u200Blabel", "\uD800").forEach { label ->
            ChallengeRequest("synthetic", charArrayOf('x'), RemoteFixtures.install, null, RemoteFixtures.key, label).use { request ->
                assertEquals(RemoteFailureKind.INVALID_REQUEST, RemoteFixtures.reject { AuthCodec.challengeRequest(request) }.kind)
            }
        }
        ChallengeRequest("\uD800", charArrayOf('x'), RemoteFixtures.install, null, RemoteFixtures.key, "Phone").use { RemoteFixtures.reject { AuthCodec.challengeRequest(it) } }
    }

    @Test fun keyAndSignatureRejectTrailingBytesWrongCurveAndRawSignature() {
        ChallengeRequest("synthetic", charArrayOf('x'), RemoteFixtures.install, null, RemoteFixtures.key + byteArrayOf(0), "Phone").use { RemoteFixtures.reject { AuthCodec.challengeRequest(it) } }
        val generator = java.security.KeyPairGenerator.getInstance("EC").apply { initialize(java.security.spec.ECGenParameterSpec("secp384r1")) }
        ChallengeRequest("synthetic", charArrayOf('x'), RemoteFixtures.install, null, generator.generateKeyPair().public.encoded, "Phone").use { RemoteFixtures.reject { AuthCodec.challengeRequest(it) } }
        RemoteFixtures.request().use { request ->
            val challenge = AuthCodec.challenge(RemoteFixtures.challenge(), request, RemoteFixtures.start, RemoteFixtures.arrival)
            listOf(ByteArray(64), decode64(RemoteFixtures.vector.text("signature_der_base64url", 100), 100) + byteArrayOf(0)).forEach { signature ->
                RemoteFixtures.reject { AuthCodec.tokenRequest(challenge, signature, RemoteFixtures.arrival) }
            }
        }
    }

    @Test fun sessionChecksExactTypesAndTokenContextBindingsWithoutPretendingToVerifyHmac() {
        AuthCodec.session(RemoteFixtures.sessionBytes(), RemoteFixtures.start, RemoteFixtures.arrival).use {
            assertEquals(0L, it.context.authority.permissionVersion)
            assertEquals(RemoteFixtures.user, it.context.authority.capture.account.userId)
            assertFalse(it.toString().contains("synthetic"))
            assertFalse(it.secrets.toString().contains("."))
        }
        listOf("pv" to JsonPrimitive(true), "aud" to JsonArray(listOf(JsonPrimitive("kapit-android"))),
            "org" to JsonPrimitive(RemoteFixtures.id(90)), "exp" to JsonPrimitive(RemoteFixtures.serverSeconds + 601),
            "nbf" to JsonPrimitive(RemoteFixtures.serverSeconds + 1), "iat" to JsonPrimitive(RemoteFixtures.serverSeconds + 1)).forEach { (key, value) ->
            RemoteFixtures.reject { AuthCodec.session(RemoteFixtures.sessionBytes(claimChanges = mapOf(key to value)), RemoteFixtures.start, RemoteFixtures.arrival) }
        }
        RemoteFixtures.reject { AuthCodec.session(RemoteFixtures.sessionBytes(headerChanges = mapOf("alg" to JsonPrimitive("none"))), RemoteFixtures.start, RemoteFixtures.arrival) }
        RemoteFixtures.reject { AuthCodec.session(RemoteFixtures.sessionBytes(headerChanges = mapOf("jku" to JsonPrimitive("https://invalid.example/"))), RemoteFixtures.start, RemoteFixtures.arrival) }
    }

    @Test fun sessionTransitNeverRebasesLeaseAndAccessExpiresThirtySecondsEarly() {
        val body = RemoteFixtures.sessionBytes()
        AuthCodec.session(body, RemoteFixtures.start, ClockStamp(570_099, "boot")).close()
        assertEquals(RemoteFailureKind.EXPIRED_RESPONSE, RemoteFixtures.reject { AuthCodec.session(body, RemoteFixtures.start, ClockStamp(570_100, "boot")) }.kind)
        assertEquals(RemoteFailureKind.EXPIRED_RESPONSE, RemoteFixtures.reject { AuthCodec.session(body, RemoteFixtures.start, ClockStamp(86_400_100, "boot")) }.kind)
        val invalid = RemoteFixtures.context().toMutableMap().apply { put("offline_lease_seconds", JsonPrimitive(86401)) }
        RemoteFixtures.reject { AuthCodec.session(RemoteFixtures.sessionBytes(context = JsonObject(invalid)), RemoteFixtures.start, RemoteFixtures.arrival) }
    }

    @Test fun refreshAndMeRejectDifferentFamilyScopePermissionAndUnsupportedTemplate() {
        val session = AuthCodec.session(RemoteFixtures.sessionBytes(), RemoteFixtures.start, RemoteFixtures.arrival)
        session.use {
            val expected = it.context.authority
            listOf("family_id" to JsonPrimitive(RemoteFixtures.id(99)), "permission_version" to JsonPrimitive(1),
                "template_version" to JsonPrimitive("future-template")).forEach { (key, value) ->
                val context = JsonObject(RemoteFixtures.context() + (key to value))
                assertEquals(RemoteFailureKind.CONTEXT_CHANGED, RemoteFixtures.reject { AuthCodec.context(CanonicalJson.bytes(context), RemoteFixtures.start, RemoteFixtures.arrival, expected) }.kind)
            }
        }
    }

    @Test fun sessionAndContextNeverGrantAnUnknownOrFullDisclosureProfile() {
        AuthCodec.session(RemoteFixtures.sessionBytes(), RemoteFixtures.start, RemoteFixtures.arrival).use { session ->
            for (profile in listOf("FULL", "DEMO-FULL", "UNKNOWN")) {
                val original = RemoteFixtures.context()
                val user = JsonObject(original.obj("user") + ("profile" to JsonPrimitive(profile)))
                val context = JsonObject(original + ("user" to user))
                assertEquals(RemoteFailureKind.CONTEXT_CHANGED, RemoteFixtures.reject {
                    AuthCodec.session(RemoteFixtures.sessionBytes(context), RemoteFixtures.start, RemoteFixtures.arrival)
                }.kind)
                assertEquals(RemoteFailureKind.CONTEXT_CHANGED, RemoteFixtures.reject {
                    AuthCodec.context(CanonicalJson.bytes(context), RemoteFixtures.start, RemoteFixtures.arrival, session.context.authority)
                }.kind)
            }
        }
    }

    @Test fun duplicateKeysMalformedUtf8LoneSurrogatesAndExtraResponseFieldsFailClosed() {
        val valid = RemoteFixtures.sessionBytes().toString(Charsets.UTF_8)
        listOf(valid.replaceFirst("{", "{\"token_type\":\"Bearer\",").toByteArray(), byteArrayOf(123, 34, -61, 40, 34, 58, 48, 125),
            valid.replace("Bearer", "\\uD800").toByteArray(), valid.replace("\"token_type\"", "\"extra\":true,\"token_type\"").toByteArray()).forEach {
            RemoteFixtures.reject { AuthCodec.session(it, RemoteFixtures.start, RemoteFixtures.arrival) }
        }
    }
}

/** Synthetic wire data only; these JWT signatures do not prove server authentication. */
internal object RemoteFixtures {
    val proof: JsonObject = StrictJson.objectFrom(javaClass.classLoader!!.getResourceAsStream("mobile-proof.json")!!.use { it.readBytes() })
    val vector = proof.getValue("vectors").jsonArray.first().jsonObject
    val key = decode64(proof.text("public_key_spki_base64url", 200), 200)
    val install = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    val user = "cccccccc-cccc-4ccc-8ccc-cccccccccccc"
    val org = "dddddddd-dddd-4ddd-8ddd-dddddddddddd"
    val enrollment = "11111111-aaaa-4aaa-8aaa-aaaaaaaaaaaa"
    val family = "22222222-bbbb-4bbb-8bbb-bbbbbbbbbbbb"
    val start = ClockStamp(100, "boot")
    val arrival = ClockStamp(200, "boot")
    val serverSeconds = vector.obj("binding").requiredLong("expires_unix") - 120
    fun id(number: Int) = "00000000-0000-4000-8000-${number.toString().padStart(12, '0')}"
    fun time(seconds: Long) = Instant.ofEpochSecond(seconds).toString().removeSuffix("Z") + ".000000Z"
    fun request(vector: JsonObject = this.vector): ChallengeRequest {
        val binding = vector.obj("binding")
        val enrollment = binding.nullableUuid("enrollment_id")
        return ChallengeRequest("synthetic", "synthetic-fixture".toCharArray(), install, enrollment, key, "Synthetic phone",
            enrollment?.let { AccountIdentity(org, user, it) })
    }
    fun challenge(vector: JsonObject = this.vector): ByteArray {
        val binding = vector.obj("binding")
        return CanonicalJson.bytes(buildJsonObject {
            binding.filterKeys { it != "expires_unix" }.forEach { (key, value) -> put(key, value) }
            put("protocol", MOBILE_PROTOCOL); put("server_time", time(serverSeconds)); put("expires_at", time(serverSeconds + 120))
            put("proof_message", vector.getValue("proof_message"))
        })
    }
    fun context(): JsonObject = buildJsonObject {
        put("protocol", MOBILE_PROTOCOL); put("organization_id", org); put("enrollment_id", enrollment); put("family_id", family)
        put("permission_version", 0); put("template_version", MAINTENANCE_TEMPLATE); put("server_time", time(serverSeconds))
        put("family_expires_at", time(serverSeconds + 604800)); put("offline_lease_expires_at", time(serverSeconds + 86400)); put("offline_lease_seconds", 86400)
        putJsonObject("user") {
            put("id", user); put("username", "synthetic"); put("display_name", "Synthetic Submitter"); put("role", "submitter"); put("profile", "DEMO-REDUCED")
            putJsonObject("unit") { put("id", id(10)); put("code", "SIM"); put("name", "Synthetic unit") }
            putJsonObject("channel") { put("id", id(11)); put("code", "SIM"); put("name", "Synthetic channel") }
        }
    }
    fun sessionBytes(context: JsonObject = context(), claimChanges: Map<String, JsonElement> = emptyMap(), headerChanges: Map<String, JsonElement> = emptyMap()): ByteArray {
        val claims = buildJsonObject {
            put("iss", "kapit-local-mobile"); put("aud", "kapit-android"); put("sub", user); put("org", org); put("did", enrollment); put("sid", family)
            put("pv", 0); put("role", "submitter"); put("iat", serverSeconds); put("nbf", serverSeconds); put("exp", serverSeconds + 600); put("jti", id(50)); put("token_type", "access")
        }
        val header = buildJsonObject { put("alg", "HS256"); put("typ", "JWT") }
        val token = encode64(CanonicalJson.bytes(JsonObject(header + headerChanges))) + "." + encode64(CanonicalJson.bytes(JsonObject(claims + claimChanges))) + "." + encode64(ByteArray(32))
        return CanonicalJson.bytes(buildJsonObject {
            put("token_type", "Bearer"); put("access_token", token); put("access_expires_at", time(serverSeconds + 600))
            put("refresh_token", id(51) + "." + encode64(ByteArray(32))); put("refresh_expires_at", time(serverSeconds + 604800)); put("context", context)
        })
    }
    fun reject(action: () -> Unit): RemoteFailure {
        try { action(); fail("Expected sanitized remote failure") } catch (failure: RemoteFailure) { return failure }
        error("unreachable")
    }
}

package org.kapit.c2.mobile.data.remote

import androidx.annotation.RequiresApi
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.MessageDigest
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.X509EncodedKeySpec
import java.time.Duration
import kotlinx.serialization.json.*
import org.kapit.c2.mobile.domain.*

@RequiresApi(35)
internal object AuthCodec {
    fun challengeRequest(request: ChallengeRequest): ByteArray = try {
        canonicalUuid(request.installationId)
        request.enrollmentId?.let(::canonicalUuid)
        checkWire((request.expectedAccount == null) == (request.enrollmentId == null))
        checkWire(request.expectedAccount == null || request.expectedAccount.enrollmentId == request.enrollmentId)
        scalar(request.username, 150)
        scalar(request.label, 80)
        checkWire(request.label.isNotBlank())
        request.label.codePoints().forEach { point ->
            checkWire(Character.getType(point) !in setOf(Character.CONTROL.toInt(), Character.FORMAT.toInt(), Character.SURROGATE.toInt()))
        }
        val key = request.keyCopy()
        val password = request.passwordCopy()
        try {
            publicKey(key)
            val passwordText = String(password)
            scalar(passwordText, 128)
            CanonicalJson.bytes(buildJsonObject {
                put("username", request.username); put("password", passwordText); put("installation_id", request.installationId)
                put("enrollment_id", request.enrollmentId?.let(::JsonPrimitive) ?: JsonNull)
                put("public_key_spki", encode64(key)); put("label", request.label)
            }).also { checkWire(it.size <= 20 * 1024) }
        } finally { password.fill('\u0000'); key.fill(0) }
    } catch (_: Exception) { throw RemoteFailure(RemoteFailureKind.INVALID_REQUEST) }

    fun challenge(bytes: ByteArray, request: ChallengeRequest, start: ClockStamp, arrival: ClockStamp): ValidatedChallenge = wire {
        val value = StrictJson.objectFrom(bytes)
        value.exact("protocol", "challenge_id", "action", "user_id", "organization_id", "enrollment_id", "installation_id", "key_fingerprint", "nonce", "server_time", "expires_at", "proof_message")
        checkWire(value.text("protocol", 32) == MOBILE_PROTOCOL)
        val id = value.uuid("challenge_id")
        val user = value.uuid("user_id")
        val org = value.uuid("organization_id")
        val enrollment = value.nullableUuid("enrollment_id")
        val action = if (request.enrollmentId == null) "NEW_ENROLLMENT" else "REAUTHENTICATE"
        checkWire(value.text("action", 20) == action && enrollment == request.enrollmentId)
        checkWire(value.uuid("installation_id") == request.installationId)
        request.expectedAccount?.let {
            if (it.userId != user || it.organizationId != org || it.enrollmentId != enrollment) throw RemoteFailure(RemoteFailureKind.CONTEXT_CHANGED)
        }
        val key = request.keyCopy()
        publicKey(key)
        val fingerprint = MessageDigest.getInstance("SHA-256").digest(key).joinToString("") { "%02x".format(it) }
        checkWire(value.text("key_fingerprint", 64) == fingerprint)
        val nonce = value.text("nonce", 43)
        checkWire(nonce.length == 43 && decode64(nonce, 43).size == 32)
        val server = authTime(value.text("server_time", 40))
        val expires = authTime(value.text("expires_at", 40))
        checkWire(Duration.between(server, expires) == Duration.ofSeconds(120))
        val deadline = Math.addExact(start.elapsedMillis, 120_000)
        if (start.bootId == null || start.bootId != arrival.bootId || start.elapsedMillis < 0 || arrival.elapsedMillis < start.elapsedMillis || arrival.elapsedMillis >= deadline)
            throw RemoteFailure(RemoteFailureKind.EXPIRED_RESPONSE)
        val proof = listOf("KAPIT-C2-MOBILE-PROOF-V1", action, id, user, org, enrollment ?: "-", request.installationId,
            fingerprint, nonce, expires.epochSecond.toString()).joinToString("\n", postfix = "\n")
        checkWire(value.text("proof_message", 2048) == proof)
        ValidatedChallenge(id, nonce, user, org, enrollment, deadline, arrival.elapsedMillis, start.bootId!!, proof.toByteArray(Charsets.US_ASCII), key)
    }

    fun tokenRequest(challenge: ValidatedChallenge, signature: ByteArray, now: ClockStamp): ByteArray = wire {
        challenge.requireCurrent(now)
        val encoded = encode64(signature)
        checkWire(encoded.length in 1..100)
        val verifier = Signature.getInstance("SHA256withECDSA")
        verifier.initVerify(publicKey(challenge.publicKey))
        verifier.update(challenge.copyProofBytes())
        checkWire(verifier.verify(signature))
        CanonicalJson.bytes(buildJsonObject { put("challenge_id", challenge.challengeId); put("nonce", challenge.nonce); put("signature", encoded) })
    }

    fun refreshRequest(token: ByteArray): ByteArray = wire {
        val text = ascii(token, 80)
        refreshToken(text)
        CanonicalJson.bytes(buildJsonObject { put("refresh_token", text) })
    }

    fun session(bytes: ByteArray, start: ClockStamp, arrival: ClockStamp,
        challenge: ValidatedChallenge? = null, expected: AuthorizedContext? = null): RemoteSession = wire {
        val value = StrictJson.objectFrom(bytes)
        value.exact("token_type", "access_token", "access_expires_at", "refresh_token", "refresh_expires_at", "context")
        checkWire(value.text("token_type", 10) == "Bearer")
        val context = context(value.obj("context"), start, arrival, expected)
        challenge?.let {
            val account = context.authority.capture.account
            if (account.userId != it.accountUserId || account.organizationId != it.organizationId || (it.enrollmentId != null && account.enrollmentId != it.enrollmentId))
                throw RemoteFailure(RemoteFailureKind.CONTEXT_CHANGED)
        }
        val access = value.text("access_token", 8192)
        val refresh = value.text("refresh_token", 80)
        refreshToken(refresh)
        val expires = authTime(value.text("access_expires_at", 40))
        val refreshExpires = authTime(value.text("refresh_expires_at", 40))
        checkWire(refreshExpires.toEpochMilli() == context.lease.familyExpiresMillis && refreshExpires.nano == 0)
        checkWire(expires.nano == 0)
        validateJwtShape(access, context, expires.epochSecond)
        // Conservative request-start estimate includes transit and a30-second expiry margin.
        val remaining = Math.subtractExact(expires.toEpochMilli(), context.lease.serverTimeMillis)
        if (remaining <= Math.addExact(arrival.elapsedMillis - start.elapsedMillis, 30_000)) throw RemoteFailure(RemoteFailureKind.EXPIRED_RESPONSE)
        val accessBytes = access.toByteArray(Charsets.US_ASCII)
        val refreshBytes = refresh.toByteArray(Charsets.US_ASCII)
        try { RemoteSession(context, SessionSecrets(accessBytes, refreshBytes, expires.toEpochMilli(), refreshExpires.toEpochMilli())) }
        finally { accessBytes.fill(0); refreshBytes.fill(0) }
    }

    fun context(bytes: ByteArray, start: ClockStamp, arrival: ClockStamp, expected: AuthorizedContext): RemoteContext =
        wire { context(StrictJson.objectFrom(bytes), start, arrival, expected) }

    private fun context(value: JsonObject, start: ClockStamp, arrival: ClockStamp, expected: AuthorizedContext?): RemoteContext {
        value.exact("protocol", "user", "organization_id", "enrollment_id", "family_id", "permission_version", "template_version", "server_time", "family_expires_at", "offline_lease_expires_at", "offline_lease_seconds")
        checkWire(value.text("protocol", 32) == MOBILE_PROTOCOL)
        if (value.text("template_version", 64) != MAINTENANCE_TEMPLATE) throw RemoteFailure(RemoteFailureKind.CONTEXT_CHANGED, code = RemoteCode.TEMPLATE_UNSUPPORTED)
        val user = value.obj("user")
        user.exact("id", "username", "display_name", "role", "unit", "channel", "profile")
        checkWire(user.text("role", 16) == "submitter")
        user.text("username", 150)
        val unit = user.obj("unit"); unit.exact("id", "code", "name"); unit.text("code", 40)
        val channel = user.obj("channel"); channel.exact("id", "code", "name"); channel.text("code", 40)
        val profile = user.text("profile", 16)
        if (profile != "DEMO-REDUCED") throw RemoteFailure(RemoteFailureKind.CONTEXT_CHANGED)
        val org = value.uuid("organization_id")
        val context = AuthorizedContext(CaptureContext(AccountIdentity(org, user.uuid("id"), value.uuid("enrollment_id")),
            unit.uuid("id"), channel.uuid("id"), profile, MAINTENANCE_TEMPLATE),
            value.uuid("family_id"), value.requiredLong("permission_version"), user.text("display_name", 120, false),
            "Organization $org", unit.text("name", 160), channel.text("name", 160))
        if (expected != null && (context.capture != expected.capture || context.familyId != expected.familyId || context.permissionVersion != expected.permissionVersion))
            throw RemoteFailure(RemoteFailureKind.CONTEXT_CHANGED)
        val server = authTime(value.text("server_time", 40))
        val family = authTime(value.text("family_expires_at", 40))
        val lease = authTime(value.text("offline_lease_expires_at", 40))
        val seconds = value.requiredLong("offline_lease_seconds")
        checkWire(seconds in 1..86400 && Duration.between(server, lease) == Duration.ofSeconds(seconds))
        checkWire(family >= lease && Duration.between(server, family) <= Duration.ofDays(7))
        val offer = LeaseOffer(server.toEpochMilli(), lease.toEpochMilli(), family.toEpochMilli(), seconds)
        try { LeasePolicy.accept(start, arrival, offer) } catch (_: Exception) { throw RemoteFailure(RemoteFailureKind.EXPIRED_RESPONSE) }
        return RemoteContext(context, offer)
    }

    /** Structural/binding validation only. HTTPS and live server authorization remain the authority. */
    private fun validateJwtShape(token: String, context: RemoteContext, expiry: Long) {
        val parts = token.split('.')
        checkWire(parts.size == 3)
        val header = StrictJson.objectFrom(decode64(parts[0], 1024), 1024)
        header.exact("alg", "typ")
        checkWire(header.text("alg", 16) == "HS256" && header.text("typ", 16) == "JWT")
        checkWire(decode64(parts[2], 43).size == 32)
        val claims = StrictJson.objectFrom(decode64(parts[1], 7000), 6000)
        claims.exact("iss", "aud", "sub", "org", "did", "sid", "pv", "role", "iat", "nbf", "exp", "jti", "token_type")
        val authority = context.authority
        val account = authority.capture.account
        checkWire(claims.text("iss", 32) == "kapit-local-mobile" && claims.text("aud", 32) == "kapit-android")
        checkWire(claims.uuid("sub") == account.userId && claims.uuid("org") == account.organizationId && claims.uuid("did") == account.enrollmentId)
        checkWire(claims.uuid("sid") == authority.familyId && claims.requiredLong("pv") == authority.permissionVersion)
        checkWire(claims.text("role", 16) == "submitter" && claims.text("token_type", 16) == "access")
        claims.uuid("jti")
        val issued = claims.requiredLong("iat")
        checkWire(issued >= 0 && claims.requiredLong("nbf") == issued && claims.requiredLong("exp") == expiry)
        checkWire(issued <= context.lease.serverTimeMillis / 1000 && expiry > context.lease.serverTimeMillis / 1000)
        checkWire(expiry == minOf(Math.addExact(issued, 600), context.lease.familyExpiresMillis / 1000))
    }

    private fun refreshToken(value: String) {
        checkWire(value.length == 80 && value[36] == '.')
        canonicalUuid(value.substring(0, 36))
        checkWire(decode64(value.substring(37), 43).size == 32)
    }
    private fun publicKey(bytes: ByteArray): ECPublicKey {
        checkWire(encode64(bytes).length <= 200)
        val key = KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(bytes)) as? ECPublicKey
            ?: throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE)
        checkWire(key.encoded.contentEquals(bytes))
        val parameters = AlgorithmParameters.getInstance("EC").apply { init(ECGenParameterSpec("secp256r1")) }.getParameterSpec(ECParameterSpec::class.java)
        checkWire(key.params.curve == parameters.curve && key.params.generator == parameters.generator && key.params.order == parameters.order && key.params.cofactor == parameters.cofactor)
        return key
    }
    private fun scalar(value: String, maximum: Int) = checkWire(value.isNotEmpty() && StrictJson.validUnicode(value) && value.codePointCount(0, value.length) <= maximum)
    internal fun ascii(bytes: ByteArray, maximum: Int): String {
        checkWire(bytes.size in 1..maximum && bytes.all { it.toInt() in 33..126 })
        return bytes.toString(Charsets.US_ASCII)
    }
}

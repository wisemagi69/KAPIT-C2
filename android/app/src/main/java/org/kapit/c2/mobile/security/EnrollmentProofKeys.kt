package org.kapit.c2.mobile.security

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.AtomicFile
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import org.kapit.c2.mobile.domain.*

/** Opaque alias reference, retained by online enrollment recovery; contains no account or credential. */
data class ProofKeyReference(val opaqueId: String) {
    init { canonicalUuid(opaqueId) }
    override fun toString(): String = "ProofKeyReference(redacted)"
}

/** Separate per-enrollment P-256 aliases. Binding is write-once and can never adopt another account. */
class EnrollmentProofKeys internal constructor(private val root: File, private val environment: StoreEnvironment) {
    companion object { private val processFence = Any() }
    constructor(context: Context) : this(File(context.noBackupFilesDir, "proof-v1"), AndroidAccessEnvironment(context))
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun alias(reference: ProofKeyReference) = "kapit.proof.v1.${reference.opaqueId}"
    internal class PreparedBinding internal constructor(internal val reference: ProofKeyReference, internal val account: AccountIdentity)
    internal fun hasAnyProofAlias(): Boolean = safe { store().aliases().toList().any { it.startsWith("kapit.proof.v1.") } }
    fun createCandidate(): ProofKeyReference = createReservedCandidate(ProofKeyReference(UUID.randomUUID().toString()))
    internal fun createReservedCandidate(reference: ProofKeyReference): ProofKeyReference = safe {
        environment.requireEligibleUnlockedDevice()
        requireStore(root.isDirectory || root.mkdirs(), StoreCode.STORAGE_UNAVAILABLE)
        val files = root.listFiles() ?: throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
        requireStore(files.none { it.name.endsWith(".creation") && !File(root, it.name.removeSuffix(".creation") + ".candidate").isFile }, StoreCode.KEY_UNAVAILABLE)
        requireStore(store().aliases().toList().count { it.startsWith("kapit.proof.v1.") } < 100, StoreCode.STORAGE_UNAVAILABLE)
        requireStore(!store().containsAlias(alias(reference)) && !File(root, "${reference.opaqueId}.candidate").exists() &&
            !File(root, "${reference.opaqueId}.creation").exists(), StoreCode.KEY_UNAVAILABLE)
        // If anything after this write fails, retain the intent and refuse another
        // candidate until explicit recovery. No repeated orphan-key generation.
        atomicWrite(File(root, "${reference.opaqueId}.creation"), byteArrayOf(1))
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(KeyGenParameterSpec.Builder(alias(reference), KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1")).setDigests(KeyProperties.DIGEST_SHA256)
            .setUserAuthenticationRequired(false).build())
        generator.generateKeyPair()
        atomicWrite(File(root, "${reference.opaqueId}.candidate"), byteArrayOf(1))
        reference
    }
    fun bind(reference: ProofKeyReference, account: AccountIdentity) = safe { commitBinding(prepareBinding(reference, account)) }
    internal fun prepareBinding(reference: ProofKeyReference, account: AccountIdentity): PreparedBinding = safe {
        environment.requireEligibleUnlockedDevice(); publicKey(reference)
        checkBindingMetadata(reference, account)
        PreparedBinding(reference, account)
    }
    /** No Keystore work here; the repository linearizes these bounded writes with its fence. */
    internal fun commitBinding(prepared: PreparedBinding) = safe {
        val reference = prepared.reference; val account = prepared.account
        checkBindingMetadata(reference, account)
        val binding = File(root, "${account.storeRef}.binding")
        val owner = File(root, "${reference.opaqueId}.owner")
        // Owner first: interruption can leave an unusable/recoverable candidate, never cross-account reuse.
        atomicWrite(owner, account.storeRef.toByteArray(Charsets.US_ASCII))
        atomicWrite(binding, reference.opaqueId.toByteArray(Charsets.US_ASCII))
    }
    private fun checkBindingMetadata(reference: ProofKeyReference, account: AccountIdentity) {
        val binding = File(root, "${account.storeRef}.binding")
        val owner = File(root, "${reference.opaqueId}.owner")
        if (binding.exists()) requireStore(readMetadata(binding, 36) == reference.opaqueId, StoreCode.SCOPE_DENIED)
        if (owner.exists()) requireStore(readMetadata(owner, 64) == account.storeRef, StoreCode.SCOPE_DENIED)
    }
    private fun readMetadata(file: File, expected: Int): String {
        val bytes = AtomicFile(file).openRead().use { input ->
            val buffer = ByteArray(expected + 1); var count = 0
            while (count < buffer.size) {
                val read = input.read(buffer, count, buffer.size - count)
                if (read < 0) break
                requireStore(read > 0, StoreCode.KEY_UNAVAILABLE); count += read
            }
            requireStore(count == expected, StoreCode.KEY_UNAVAILABLE)
            buffer.copyOf(count)
        }
        return bytes.toString(Charsets.US_ASCII)
    }
    fun bound(account: AccountIdentity): ProofKeyReference = safe {
        environment.requireEligibleUnlockedDevice()
        val reference = ProofKeyReference(AtomicFile(File(root, "${account.storeRef}.binding")).readFully().toString(Charsets.US_ASCII))
        requireStore(AtomicFile(File(root, "${reference.opaqueId}.owner")).readFully().toString(Charsets.US_ASCII) == account.storeRef, StoreCode.SCOPE_DENIED)
        publicKey(reference); reference
    }
    fun publicKey(reference: ProofKeyReference): ByteArray = safe {
        environment.requireEligibleUnlockedDevice()
        requireStore(File(root, "${reference.opaqueId}.candidate").isFile, StoreCode.KEY_UNAVAILABLE)
        store().getCertificate(alias(reference))?.publicKey?.encoded ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
    }
    /** Transport must first reconstruct and validate all challenge bindings from the frozen protocol. */
    fun sign(reference: ProofKeyReference, validatedMessage: ByteArray): ByteArray = safe {
        environment.requireEligibleUnlockedDevice(); publicKey(reference)
        requireStore(validatedMessage.size in 1..2048 && validatedMessage.all { it.toInt() in 0..127 }, StoreCode.VALIDATION_ERROR)
        val key = store().getKey(alias(reference), null) as? PrivateKey ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
        Signature.getInstance("SHA256withECDSA").run { initSign(key); update(validatedMessage); sign() }
    }
    private fun <T> safe(body: () -> T): T = synchronized(processFence) {
        try { body() } catch (failure: StoreFailure) { throw failure }
        catch (_: Exception) { throw StoreFailure(StoreCode.KEY_UNAVAILABLE) }
    }
}

package org.kapit.c2.mobile.security

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.UserNotAuthenticatedException
import android.util.AtomicFile
import java.io.File
import java.io.FileOutputStream
import java.nio.ByteBuffer
import java.security.KeyStore
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec
import org.kapit.c2.mobile.domain.*

/** Only wraps random SQLCipher keys; proof signing has separate aliases and policy. */
internal class AndroidKeyVault(private val root: File, private val environment: StoreEnvironment) {
    private fun keys() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun alias(ref: String): String = "kapit.wrap.v1.$ref"
    fun directory(ref: String): File {
        requireStore(Regex("[0-9a-f]{64}").matches(ref), StoreCode.STORAGE_UNAVAILABLE)
        return File(root, ref)
    }
    fun envelope(ref: String) = File(directory(ref), "key.envelope")
    fun database(ref: String) = File(directory(ref), "protected.db")

    fun create(ref: String): ByteArray {
        if (android.os.Build.VERSION.SDK_INT < 35) throw StoreFailure(StoreCode.UNSUPPORTED_DEVICE)
        environment.requireEligibleUnlockedDevice()
        requireStore(!envelope(ref).exists() && !database(ref).exists(), StoreCode.KEY_UNAVAILABLE)
        val passphrase = ByteArray(32).also(SecureRandom()::nextBytes)
        try {
            val store = keys()
            // A failed first authentication may leave only our key alias, never a database/envelope.
            val key = if (store.containsAlias(alias(ref))) existing(ref) else {
                KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                    init(KeyGenParameterSpec.Builder(alias(ref), KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setKeySize(256).setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                        .setRandomizedEncryptionRequired(true).setUserAuthenticationRequired(true)
                        .setUserAuthenticationParameters(60, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)
                        .setUnlockedDeviceRequired(true).build())
                    generateKey()
                }
            }
            val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.ENCRYPT_MODE, key); updateAAD(aad(ref))
            }
            val encrypted = cipher.doFinal(passphrase)
            requireStore(cipher.iv.size == 12, StoreCode.KEY_UNAVAILABLE)
            requireStore(directory(ref).isDirectory || directory(ref).mkdirs(), StoreCode.STORAGE_UNAVAILABLE)
            atomicWrite(envelope(ref), ByteBuffer.allocate(4 + 12 + encrypted.size).putInt(1).put(cipher.iv).put(encrypted).array())
            return passphrase
        } catch (failure: Exception) {
            passphrase.fill(0); throw safeKeyFailure(failure)
        }
    }

    fun unwrap(ref: String): ByteArray {
        environment.requireEligibleUnlockedDevice()
        try {
            requireStore(envelope(ref).isFile && database(ref).isFile, StoreCode.KEY_UNAVAILABLE)
            val bytes = AtomicFile(envelope(ref)).readFully()
            requireStore(bytes.size == 64 && ByteBuffer.wrap(bytes, 0, 4).int == 1, StoreCode.KEY_UNAVAILABLE)
            return Cipher.getInstance("AES/GCM/NoPadding").run {
                init(Cipher.DECRYPT_MODE, existing(ref), GCMParameterSpec(128, bytes.copyOfRange(4, 16)))
                updateAAD(aad(ref)); doFinal(bytes.copyOfRange(16, bytes.size))
            }.also { requireStore(it.size == 32, StoreCode.KEY_UNAVAILABLE) }
        } catch (failure: Exception) { throw safeKeyFailure(failure) }
    }

    private fun existing(ref: String): SecretKey {
        if (android.os.Build.VERSION.SDK_INT < 35) throw StoreFailure(StoreCode.UNSUPPORTED_DEVICE)
        val key = keys().getKey(alias(ref), null) as? SecretKey ?: throw StoreFailure(StoreCode.KEY_UNAVAILABLE)
        val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
        requireStore(info.keySize == 256 && info.isUserAuthenticationRequired && info.userAuthenticationValidityDurationSeconds == 60 &&
            info.userAuthenticationType == (KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG), StoreCode.KEY_UNAVAILABLE)
        return key
    }

    private fun aad(ref: String) = "$MOBILE_PROTOCOL\nwrap-v1\n$ref\n".toByteArray(Charsets.UTF_8)
    private fun safeKeyFailure(error: Exception): StoreFailure = when (error) {
        is StoreFailure -> error
        is UserNotAuthenticatedException -> StoreFailure(StoreCode.UNLOCK_REQUIRED)
        else -> StoreFailure(StoreCode.KEY_UNAVAILABLE)
    }
}

internal fun atomicWrite(file: File, bytes: ByteArray) {
    val atomic = AtomicFile(file)
    var stream: FileOutputStream? = null
    try {
        stream = atomic.startWrite(); stream.write(bytes); stream.fd.sync(); atomic.finishWrite(stream)
        // AtomicFile logs some sync/rename failures instead of throwing. Never accept
        // a durable denial/key-binding write until its committed bytes match.
        atomic.openRead().use { input ->
            val persisted = ByteArray(bytes.size + 1)
            try {
                var count = 0
                while (count < persisted.size) {
                    val read = input.read(persisted, count, persisted.size - count)
                    if (read == -1) break
                    count += read
                }
                requireStore(count == bytes.size && bytes.indices.all { bytes[it] == persisted[it] }, StoreCode.STORAGE_UNAVAILABLE)
            } finally { persisted.fill(0) }
        }
    } catch (_: Exception) {
        atomic.failWrite(stream); throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
    }
}

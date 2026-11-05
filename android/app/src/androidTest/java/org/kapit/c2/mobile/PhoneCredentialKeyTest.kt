package org.kapit.c2.mobile

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.UserNotAuthenticatedException
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import net.zetetic.database.Logger
import net.zetetic.database.NoopTarget
import net.zetetic.database.sqlcipher.SQLiteDatabase
import org.junit.Assert.*
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyStore
import java.security.InvalidKeyException
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.AEADBadTagException
import javax.crypto.BadPaddingException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * TASK-075 phone-safe credential-bound key lifecycle on the user's own phone.
 *
 * Same policy phases as [CredentialKeyCompatibilityTest] except "invalidated": this test never sets, changes or
 * removes the device credential. The user locks and unlocks the phone themselves with their own credential, which
 * never reaches the test or the host. Only this test's own alias and files inside the synthetic spike package are
 * created or removed.
 */
@RunWith(AndroidJUnit4::class)
class PhoneCredentialKeyTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val alias = "kapit_phone_credential_bound_v1"
    private val wrappedFile get() = File(context.noBackupFilesDir, "phone-credential.wrapped")
    private val wrappedDigestFile get() = File(context.noBackupFilesDir, "phone-credential.wrapped.digest")
    private val hashFile get() = File(context.noBackupFilesDir, "phone-credential.digest")
    private val databaseFile get() = context.getDatabasePath("phone-credential.db")
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun digest() = MessageDigest.getInstance("SHA-256").digest(databaseFile.readBytes())
    private fun ownedFiles() = listOf(wrappedFile, wrappedDigestFile, hashFile, databaseFile,
        File(databaseFile.path + "-journal"), File(databaseFile.path + "-wal"), File(databaseFile.path + "-shm"))

    @Test fun phoneCredentialBoundKeyLifecyclePhase() {
        val arguments = InstrumentationRegistry.getArguments()
        check(context.packageName.endsWith(".spike") && arguments.getString("ownedPhone") == "true") { "PHONE_OWNERSHIP" }
        check(Build.VERSION.SDK_INT >= 35 && Build.HARDWARE !in setOf("ranchu", "goldfish")) { "PHONE_HARDWARE" }
        System.loadLibrary("sqlcipher")
        Logger.setTarget(NoopTarget())
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        assertTrue("The phone's own secure screen lock is required; this test never creates one", keyguard.isDeviceSecure)
        when (arguments.getString("phase")) {
            "provision" -> {
                assertFalse("Unlock the phone before provisioning", keyguard.isDeviceLocked)
                assertFalse("Fresh fixture required; run phase=cleanup first", store().containsAlias(alias) || ownedFiles().any { it.exists() })
                val key = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                    init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256)
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationParameters(60, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)
                        .setUnlockedDeviceRequired(true).build())
                    generateKey()
                }
                val info = SecretKeyFactory.getInstance(key.algorithm, "AndroidKeyStore").getKeySpec(key, KeyInfo::class.java) as KeyInfo
                // Fixed, non-identifying metadata only: hardware-backed security level of the real key.
                println("PHONE_KEY_SECURITY_LEVEL=" + when (info.securityLevel) {
                    KeyProperties.SECURITY_LEVEL_STRONGBOX -> "STRONGBOX"
                    KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> "TRUSTED_ENVIRONMENT"
                    KeyProperties.SECURITY_LEVEL_SOFTWARE -> "SOFTWARE"
                    else -> "OTHER"
                })
                assertTrue("Key must be hardware-backed on the phone", info.securityLevel in
                    setOf(KeyProperties.SECURITY_LEVEL_STRONGBOX, KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT))
                val passphrase = ByteArray(32).also(SecureRandom()::nextBytes)
                var unwrapped: ByteArray? = null
                try {
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
                    val ciphertext = cipher.doFinal(passphrase)
                    assertEquals(12, cipher.iv.size)
                    wrappedFile.writeBytes(cipher.iv + ciphertext)
                    wrappedDigestFile.writeBytes(MessageDigest.getInstance("SHA-256").digest(wrappedFile.readBytes()))
                    SQLiteDatabase.openOrCreateDatabase(databaseFile, passphrase, null, null).use {
                        it.execSQL("CREATE TABLE pending (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
                        it.execSQL("INSERT INTO pending VALUES (1, ?)", arrayOf("synthetic retained pending row"))
                    }
                    hashFile.writeBytes(digest())
                    val recovered = unwrap()
                    unwrapped = recovered
                    assertTrue("PHONE_PASSPHRASE_ROUNDTRIP", MessageDigest.isEqual(passphrase, recovered))
                } finally {
                    unwrapped?.fill(0)
                    passphrase.fill(0)
                }
                assertFalse("Database file must not contain the plaintext row", String(databaseFile.readBytes(), Charsets.ISO_8859_1).contains("synthetic retained pending row"))
            }
            "locked" -> {
                assertTrue("Lock the phone (power button) before this phase", keyguard.isDeviceLocked)
                assertDeniedUnwrap()
                assertArrayEquals(hashFile.readBytes(), digest())
            }
            "unlocked", "reauthenticated" -> {
                assertFalse("Unlock the phone with your own credential before this phase", keyguard.isDeviceLocked)
                val passphrase = unwrap()
                try {
                    SQLiteDatabase.openDatabase(databaseFile.path, passphrase, null, SQLiteDatabase.OPEN_READONLY, null).use {
                        it.rawQuery("SELECT COUNT(*) FROM pending", emptyArray<String>()).use { cursor ->
                            assertTrue(cursor.moveToFirst()); assertEquals(1, cursor.getInt(0))
                        }
                    }
                } finally { passphrase.fill(0) }
                assertArrayEquals(hashFile.readBytes(), digest())
            }
            "expired" -> {
                assertFalse("Expiry is tested while the phone stays unlocked", keyguard.isDeviceLocked)
                assertDeniedUnwrap()
                assertArrayEquals(hashFile.readBytes(), digest())
            }
            "cleanup" -> {
                // Removes only this test's own alias and files inside the synthetic package.
                if (store().containsAlias(alias)) store().deleteEntry(alias)
                ownedFiles().forEach { if (it.exists()) assertTrue(it.delete()) }
                assertFalse(store().containsAlias(alias) || ownedFiles().any { it.exists() })
            }
            else -> error("An explicit phone phase is required")
        }
    }

    private fun unwrap(): ByteArray {
        val key = store().getKey(alias, null) as? SecretKey ?: error("Key unavailable")
        val envelope = wrappedFile.readBytes()
        return Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, envelope.copyOfRange(0, 12)))
            doFinal(envelope.copyOfRange(12, envelope.size))
        }
    }

    private fun assertDeniedUnwrap() {
        val keys = store()
        assertTrue("PHONE_DENIAL_ALIAS_REQUIRED", keys.containsAlias(alias))
        val key = keys.getKey(alias, null) as? SecretKey
        assertNotNull("PHONE_DENIAL_SECRET_KEY_REQUIRED", key)
        val info = SecretKeyFactory.getInstance(key!!.algorithm, "AndroidKeyStore")
            .getKeySpec(key, KeyInfo::class.java) as KeyInfo
        assertTrue("PHONE_DENIAL_AUTH_REQUIRED", info.isUserAuthenticationRequired)
        assertTrue("PHONE_DENIAL_AUTH_WINDOW", info.userAuthenticationValidityDurationSeconds == 60)
        assertTrue("PHONE_DENIAL_AUTH_TYPES", info.userAuthenticationType ==
            (KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG))
        assertTrue("PHONE_DENIAL_KEY_POLICY", key.algorithm == KeyProperties.KEY_ALGORITHM_AES && info.keySize == 256 &&
            info.purposes == (KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT) &&
            info.blockModes.contentEquals(arrayOf(KeyProperties.BLOCK_MODE_GCM)) &&
            info.encryptionPaddings.contentEquals(arrayOf(KeyProperties.ENCRYPTION_PADDING_NONE)))
        assertTrue("PHONE_DENIAL_HARDWARE_KEY", info.securityLevel in
            setOf(KeyProperties.SECURITY_LEVEL_STRONGBOX, KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT))
        assertTrue("PHONE_DENIAL_ENVELOPE_REQUIRED", wrappedFile.isFile && wrappedFile.length() == 60L)
        assertTrue("PHONE_DENIAL_ENVELOPE_DIGEST_REQUIRED", wrappedDigestFile.isFile && wrappedDigestFile.length() == 32L)
        assertTrue("PHONE_DENIAL_RETAINED_DATA_REQUIRED", databaseFile.isFile && hashFile.isFile && hashFile.length() == 32L)
        assertTrue("PHONE_DENIAL_DATABASE_INTACT", MessageDigest.isEqual(hashFile.readBytes(), digest()))
        val envelope = wrappedFile.readBytes()
        val envelopeDigest = wrappedDigestFile.readBytes()
        assertTrue("PHONE_DENIAL_ENVELOPE_INTACT", MessageDigest.isEqual(envelopeDigest,
            MessageDigest.getInstance("SHA-256").digest(envelope)))
        var denied = false
        var unexpectedPlaintext: ByteArray? = null
        try {
            unexpectedPlaintext = unwrap()
        } catch (failure: Exception) {
            denied = isAuthenticationDenial(failure)
        } finally {
            unexpectedPlaintext?.fill(0)
        }
        assertTrue("PHONE_DENIAL_ALIAS_RETAINED", store().containsAlias(alias))
        assertTrue("PHONE_DENIAL_ENVELOPE_RETAINED", wrappedFile.isFile &&
            MessageDigest.isEqual(envelope, wrappedFile.readBytes()))
        assertTrue("PHONE_DENIAL_ENVELOPE_DIGEST_RETAINED", wrappedDigestFile.isFile &&
            MessageDigest.isEqual(envelopeDigest, wrappedDigestFile.readBytes()))
        assertTrue("PHONE_DENIAL_DATABASE_RETAINED", MessageDigest.isEqual(hashFile.readBytes(), digest()))
        assertTrue("PHONE_EXPECTED_AUTHENTICATION_DENIAL", denied)
    }

    // Do not infer authentication from exception text, an arbitrary security
    // failure, a missing alias, or an unrelated exception's nested cause.
    private fun isAuthenticationDenial(failure: Exception) = failure is UserNotAuthenticatedException

    @Test fun authenticationDenialClassificationIsSpecific() {
        assertTrue("PHONE_AUTH_CLASSIFICATION_POSITIVE", isAuthenticationDenial(UserNotAuthenticatedException()))
        listOf(
            InvalidKeyException(), KeyPermanentlyInvalidatedException(),
            AEADBadTagException(), BadPaddingException(),
            IllegalStateException("Key unavailable"),
            java.security.GeneralSecurityException(UserNotAuthenticatedException())
        ).forEach { unrelated ->
            assertFalse("PHONE_AUTH_CLASSIFICATION_UNRELATED", isAuthenticationDenial(unrelated))
        }
    }
}

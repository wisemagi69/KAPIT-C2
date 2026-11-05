package org.kapit.c2.mobile

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
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
import java.security.MessageDigest
import java.security.SecureRandom
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/** Independently reported policy phases on the runner's fresh owned emulator only. */
@RunWith(AndroidJUnit4::class)
class CredentialKeyCompatibilityTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val alias = "kapit_spike_credential_bound_v1"
    private val wrappedFile get() = File(context.noBackupFilesDir, "credential-spike.wrapped")
    private val hashFile get() = File(context.noBackupFilesDir, "credential-spike.digest")
    private val databaseFile get() = context.getDatabasePath("credential-spike.db")
    private fun store() = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
    private fun digest() = MessageDigest.getInstance("SHA-256").digest(databaseFile.readBytes())

    @Test fun credentialBoundKeyLifecyclePhase() {
        val arguments = InstrumentationRegistry.getArguments()
        check(context.packageName.endsWith(".spike") && arguments.getString("ownedEmulator") == "true")
        check(Build.VERSION.SDK_INT >= 35 && Build.HARDWARE in setOf("ranchu", "goldfish"))
        System.loadLibrary("sqlcipher")
        Logger.setTarget(NoopTarget())
        val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        when (arguments.getString("phase")) {
            "provision" -> {
                assertTrue(keyguard.isDeviceSecure)
                assertFalse(keyguard.isDeviceLocked)
                assertFalse("Fresh owned fixture required", store().containsAlias(alias) || wrappedFile.exists() || databaseFile.exists())
                val key = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore").run {
                    init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
                        .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                        .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE).setKeySize(256)
                        .setUserAuthenticationRequired(true)
                        .setUserAuthenticationParameters(60, KeyProperties.AUTH_DEVICE_CREDENTIAL or KeyProperties.AUTH_BIOMETRIC_STRONG)
                        .setUnlockedDeviceRequired(true).build())
                    generateKey()
                }
                val passphrase = ByteArray(32).also(SecureRandom()::nextBytes)
                try {
                    val cipher = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
                    val ciphertext = cipher.doFinal(passphrase)
                    assertEquals(12, cipher.iv.size)
                    wrappedFile.writeBytes(cipher.iv + ciphertext)
                    SQLiteDatabase.openOrCreateDatabase(databaseFile, passphrase, null, null).use {
                        it.execSQL("CREATE TABLE pending (id INTEGER PRIMARY KEY, value TEXT NOT NULL)")
                        it.execSQL("INSERT INTO pending VALUES (1, ?)", arrayOf("synthetic retained pending row"))
                    }
                    hashFile.writeBytes(digest())
                    assertArrayEquals(passphrase, unwrap())
                } finally { passphrase.fill(0) }
            }
            "locked" -> {
                assertTrue("Harness must lock this owned emulator", keyguard.isDeviceLocked)
                assertDeniedUnwrap()
                assertArrayEquals(hashFile.readBytes(), digest())
            }
            "unlocked", "reauthenticated" -> {
                assertTrue(keyguard.isDeviceSecure)
                assertFalse(keyguard.isDeviceLocked)
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
                assertTrue(keyguard.isDeviceSecure)
                assertFalse("Expiry is tested while the device remains unlocked", keyguard.isDeviceLocked)
                assertDeniedUnwrap()
                assertArrayEquals(hashFile.readBytes(), digest())
            }
            "invalidated" -> {
                assertFalse("Harness removes only its own synthetic AVD credential", keyguard.isDeviceSecure)
                assertDeniedUnwrap()
                assertArrayEquals("Invalidated key must not erase pending ciphertext", hashFile.readBytes(), digest())
                assertTrue(wrappedFile.exists())
            }
            else -> error("An explicit owned-emulator phase is required")
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
        var denied = false
        try { unwrap().fill(0) } catch (_: java.security.GeneralSecurityException) { denied = true }
        catch (missing: IllegalStateException) { denied = missing.message == "Key unavailable" }
        assertTrue("OS key policy must deny unwrap", denied)
    }
}

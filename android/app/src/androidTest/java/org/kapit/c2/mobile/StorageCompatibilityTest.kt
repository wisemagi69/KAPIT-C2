package org.kapit.c2.mobile

import android.content.Context
import android.content.pm.ApplicationInfo
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.room.ColumnInfo
import androidx.room.Dao
import androidx.room.Database
import androidx.room.Entity
import androidx.room.Insert
import androidx.room.PrimaryKey
import androidx.room.Query
import androidx.room.Room
import androidx.room.RoomDatabase
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import net.zetetic.database.Logger
import net.zetetic.database.NoopTarget
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.junit.After
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.SecureRandom
import java.security.Signature
import java.security.spec.ECGenParameterSpec
import java.util.UUID
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

@Entity(tableName = "pending")
data class SpikePendingV1(@PrimaryKey val id: String, val frozen: ByteArray)

@Entity(tableName = "pending")
data class SpikePendingV2(
    @PrimaryKey val id: String,
    val frozen: ByteArray,
    @ColumnInfo(defaultValue = "0") val attempts: Int = 0,
)

@Dao
interface SpikeDaoV1 {
    @Insert fun insert(row: SpikePendingV1)
    @Query("SELECT * FROM pending WHERE id=:id") fun get(id: String): SpikePendingV1?
}

@Dao
interface SpikeDaoV2 {
    @Query("SELECT * FROM pending WHERE id=:id") fun get(id: String): SpikePendingV2?
}

@Database(entities = [SpikePendingV1::class], version = 1, exportSchema = true)
abstract class SpikeDatabaseV1 : RoomDatabase() { abstract fun pending(): SpikeDaoV1 }

@Database(entities = [SpikePendingV2::class], version = 2, exportSchema = true)
abstract class SpikeDatabaseV2 : RoomDatabase() { abstract fun pending(): SpikeDaoV2 }

/** Real Android tests. Each run owns only randomly named spike files/keys. */
@RunWith(AndroidJUnit4::class)
class StorageCompatibilityTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val prefix = "kapit_spike_${UUID.randomUUID()}"
    private val databaseNames = mutableListOf<String>()
    private val aliases = mutableListOf<String>()
    private val handles = mutableListOf<RoomDatabase>()
    private val random = SecureRandom()
    private val passphrase = ByteArray(32).also(random::nextBytes)
    // Only synthetic data. No account/report data is used in this compatibility package.
    private val canary = "SYNTHETIC_KAPIT_ENCRYPTION_CANARY_${UUID.randomUUID()}".toByteArray()

    @Before fun initialize() {
        check(context.packageName.endsWith(".spike")) { "Compatibility tests require the isolated spike application" }
        System.loadLibrary("sqlcipher")
        Logger.setTarget(NoopTarget())
    }

    @After fun cleanupOwnedFixtures() {
        handles.forEach { it.close() }
        databaseNames.forEach { context.deleteDatabase(it) }
        val store = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        aliases.forEach { store.deleteEntry(it) }
        passphrase.fill(0)
        canary.fill(0)
    }

    private fun newName(): String = "${prefix}_${databaseNames.size}.db".also(databaseNames::add)

    private fun open(name: String, key: ByteArray = passphrase): SpikeDatabaseV1 =
        Room.databaseBuilder(context, SpikeDatabaseV1::class.java, name)
            .openHelperFactory(SupportOpenHelperFactory(key.copyOf()))
            .setJournalMode(RoomDatabase.JournalMode.WRITE_AHEAD_LOGGING)
            .build().also(handles::add)

    private fun expectDenied(action: () -> Unit) {
        var denied = false
        try { action() } catch (_: Exception) { denied = true }
        assertTrue("Access must fail closed", denied)
    }

    private fun assertCanaryAbsent(file: File) {
        if (!file.isFile) return
        val bytes = file.readBytes()
        val found = (0..(bytes.size - canary.size)).any { offset ->
            canary.indices.all { bytes[offset + it] == canary[it] }
        }
        assertFalse("Synthetic plaintext must not occur in protected storage", found)
    }

    @Test fun correctKeyReopensDurableRow() {
        val name = newName()
        open(name).also { it.pending().insert(SpikePendingV1("operation", canary)); it.close() }
        val reopened = open(name)
        assertArrayEquals(canary, reopened.pending().get("operation")!!.frozen)
        reopened.openHelper.readableDatabase.query("PRAGMA cipher_version").use {
            assertTrue(it.moveToFirst()); assertTrue(it.getString(0).isNotBlank())
        }
    }

    @Test fun wrongKeyAndPlainSQLiteCannotReadExistingCiphertext() {
        val name = newName()
        open(name).also { it.pending().insert(SpikePendingV1("operation", canary)); it.close() }
        val before = context.getDatabasePath(name).readBytes()
        expectDenied { open(name, ByteArray(32).also(random::nextBytes)).pending().get("operation") }
        expectDenied {
            android.database.sqlite.SQLiteDatabase.openDatabase(
                context.getDatabasePath(name).path, null, android.database.sqlite.SQLiteDatabase.OPEN_READONLY,
            ).use { it.rawQuery("SELECT * FROM pending", null).use { cursor -> cursor.moveToFirst() } }
        }
        assertArrayEquals("Failed unlock must not replace encrypted data", before, context.getDatabasePath(name).readBytes())
        assertArrayEquals(canary, open(name).pending().get("operation")!!.frozen)
    }

    @Test fun closingHandleBlocksStaleDaoThenExplicitReopenPreservesQueue() {
        val name = newName()
        val db = open(name)
        val stale = db.pending()
        stale.insert(SpikePendingV1("operation", canary))
        db.close()
        assertFalse(db.isOpen)
        expectDenied { stale.get("operation") }
        assertArrayEquals(canary, open(name).pending().get("operation")!!.frozen)
    }

    @Test fun databaseAndLiveWalContainNoPlaintextCanary() {
        val name = newName()
        val db = open(name)
        db.openHelper.writableDatabase.query("PRAGMA wal_autocheckpoint=0").use {
            assertTrue(it.moveToFirst()); assertEquals(0, it.getInt(0))
        }
        db.pending().insert(SpikePendingV1("operation", canary))
        val path = context.getDatabasePath(name)
        val wal = File(path.path + "-wal")
        assertTrue("WAL must exist so this test exercises its contents", wal.exists() && wal.length() > 0)
        listOf(path, wal, File(path.path + "-shm"), File(path.path + "-journal")).forEach(::assertCanaryAbsent)
        assertFalse(path.readBytes().take(16).toByteArray().contentEquals("SQLite format 3\u0000".toByteArray()))
        context.cacheDir.walkTopDown().filter { it.isFile }.forEach(::assertCanaryAbsent)
    }

    @Test fun migrationPreservesFrozenPendingBytes() {
        val name = newName()
        open(name).also { it.pending().insert(SpikePendingV1("operation", canary)); it.close() }
        val migration = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("ALTER TABLE pending ADD COLUMN attempts INTEGER NOT NULL DEFAULT 0")
            }
        }
        val upgraded = Room.databaseBuilder(context, SpikeDatabaseV2::class.java, name)
            .openHelperFactory(SupportOpenHelperFactory(passphrase.copyOf()))
            .addMigrations(migration).build().also(handles::add)
        assertArrayEquals(canary, upgraded.pending().get("operation")!!.frozen)
        assertEquals(0, upgraded.pending().get("operation")!!.attempts)
    }

    @Test fun failedLocalTransactionDoesNotLeaveHalfQueuedSnapshot() {
        val db = open(newName())
        expectDenied {
            db.runInTransaction {
                db.pending().insert(SpikePendingV1("operation", canary))
                throw IllegalStateException("synthetic transaction interruption")
            }
        }
        assertNull(db.pending().get("operation"))
    }

    private fun wrappingKey(): Pair<String, SecretKey> {
        val alias = "${prefix}_wrap_${aliases.size}".also(aliases::add)
        val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore")
        generator.init(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM).setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).setRandomizedEncryptionRequired(true)
            // Primitive compatibility only. Credential policy has separate owned-emulator and phone gates.
            .setUserAuthenticationRequired(false).build())
        return alias to generator.generateKey()
    }

    @Test fun keystoreWrapUnwrapAndTamperDenial() {
        val (_, key) = wrappingKey()
        assertNull("Android Keystore key must be non-exportable", key.encoded)
        val encrypt = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        val wrapped = encrypt.doFinal(passphrase)
        fun unwrap(bytes: ByteArray) = Cipher.getInstance("AES/GCM/NoPadding").run {
            init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(128, encrypt.iv)); doFinal(bytes)
        }
        assertArrayEquals(passphrase, unwrap(wrapped))
        wrapped[0] = (wrapped[0].toInt() xor 1).toByte()
        expectDenied { unwrap(wrapped) }
    }

    @Test fun missingKeystoreKeyDoesNotRegenerateOrEraseEncryptedQueue() {
        val (alias, key) = wrappingKey()
        val encrypt = Cipher.getInstance("AES/GCM/NoPadding").apply { init(Cipher.ENCRYPT_MODE, key) }
        val wrapped = encrypt.doFinal(passphrase)
        val name = newName()
        open(name).also { it.pending().insert(SpikePendingV1("operation", canary)); it.close() }
        val before = context.getDatabasePath(name).readBytes()
        KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry(alias) }
        expectDenied {
            val existing = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }.getKey(alias, null)
                ?: error("Key unavailable; preserve encrypted data")
            Cipher.getInstance("AES/GCM/NoPadding").apply {
                init(Cipher.DECRYPT_MODE, existing, GCMParameterSpec(128, encrypt.iv))
            }.doFinal(wrapped)
        }
        assertArrayEquals(before, context.getDatabasePath(name).readBytes())
    }

    @Test fun enrollmentProofKeySignsP256DerAndRejectsChangedChallenge() {
        val alias = "${prefix}_proof".also(aliases::add)
        val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, "AndroidKeyStore")
        generator.initialize(KeyGenParameterSpec.Builder(alias, KeyProperties.PURPOSE_SIGN or KeyProperties.PURPOSE_VERIFY)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            .setDigests(KeyProperties.DIGEST_SHA256).build())
        val pair = generator.generateKeyPair()
        assertNull(pair.private.encoded)
        val challenge = "KAPIT synthetic compatibility challenge".toByteArray()
        val signature = Signature.getInstance("SHA256withECDSA").run { initSign(pair.private); update(challenge); sign() }
        fun verify(message: ByteArray): Boolean = Signature.getInstance("SHA256withECDSA").run {
            initVerify(pair.public); update(message); this.verify(signature)
        }
        assertTrue(verify(challenge))
        assertFalse(verify("different challenge".toByteArray()))
        assertEquals("X.509", pair.public.format)
        assertEquals(0x30, signature[0].toInt())
    }

    @Test fun backupFlagIsDisabledAndFixturesUseCredentialProtectedStorage() {
        assertEquals(0, context.applicationInfo.flags and ApplicationInfo.FLAG_ALLOW_BACKUP)
        if (android.os.Build.VERSION.SDK_INT >= 24) assertFalse(context.isDeviceProtectedStorage)
        assertTrue(context.noBackupFilesDir.isDirectory)
    }
}

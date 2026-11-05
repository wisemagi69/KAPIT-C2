package org.kapit.c2.mobile.data.local

import android.content.Context
import androidx.room.*
import androidx.room.migration.Migration
import androidx.sqlite.db.SupportSQLiteDatabase
import java.io.File
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory

@Entity(tableName = "authority")
internal data class AuthorityRow(@PrimaryKey val singleton: Int = 1, val contextJson: String, val leaseJson: String,
    val accessToken: ByteArray, val refreshToken: ByteArray, val accessExpires: Long, val refreshExpires: Long)
@Entity(tableName = "drafts")
internal data class DraftRow(@PrimaryKey val id: String, val revision: Long, val recordJson: String, val submittedOperation: String?)
@Entity(tableName = "submitted")
internal data class SubmittedRow(@PrimaryKey val operationId: String, val reportId: String, val expectedRevision: Int,
    val requestBytes: ByteArray, val requestHash: String, val contentJson: String, val captureJson: String,
    val queuedAtServerMillis: Long, val predecessorOperation: String?)
@Entity(tableName = "outbox", foreignKeys = [ForeignKey(entity = SubmittedRow::class, parentColumns = ["operationId"], childColumns = ["operationId"], onDelete = ForeignKey.RESTRICT)])
internal data class OutboxRow(@PrimaryKey val operationId: String, val delivery: String, val pause: String?, val attempts: Int = 0,
    val nextAttemptElapsed: Long? = null, val retryBoot: String? = null, val claimToken: String? = null,
    val claimSession: String? = null, val claimBoot: String? = null, val claimDeadline: Long? = null,
    val claimGeneration: Long? = null, @ColumnInfo(defaultValue = "NULL") val lastErrorCode: String? = null)
@Entity(tableName = "receipts", foreignKeys = [ForeignKey(entity = SubmittedRow::class, parentColumns = ["operationId"], childColumns = ["operationId"], onDelete = ForeignKey.RESTRICT)])
internal data class ReceiptRow(@PrimaryKey val operationId: String, val reportId: String, val revisionId: String, val revisionNo: Int)
@Entity(tableName = "commands")
internal data class CommandRow(@PrimaryKey val commandId: String, val kind: String, val inputHash: String, val resultId: String, val resultJson: String?)
@Entity(tableName = "report_cache")
internal data class CacheRow(@PrimaryKey val key: String, val reportId: String, val revision: Int, val validatedJson: String, val checkedAt: Long, val opened: Boolean)

/** A committed marker means the server may have consumed this refresh credential. */
@Entity(tableName = "refresh_attempts")
internal data class RefreshAttemptRow(@PrimaryKey val singleton: Int = 1, val attemptId: String, val capabilityId: String,
    val generation: Long, val authorityRevision: Long, val familyId: String, val credentialHash: String,
    val requestStartElapsed: Long, val bootId: String)

@Dao
internal interface ProtectedDao {
    @Insert fun insertPhoto(row: PhotoRow)
    @Query("SELECT * FROM photo_pending WHERE operationId=:id") fun photo(id: String): PhotoRow?
    @Query("SELECT operationId,reportId,revisionId,revisionNo,evidenceId FROM photo_pending WHERE reportId=:report AND revisionId=:revision AND scopeJson=:scope ORDER BY operationId") fun photos(report: String, revision: String, scope: String): List<PhotoSummaryRow>
    @Query("SELECT count(*) FROM photo_pending WHERE reportId=:report AND revisionId=:revision") fun photoRevisionCount(report: String, revision: String): Int
    @Query("SELECT count(*) FROM photo_pending WHERE evidenceId IS NULL") fun pendingPhotoCount(): Int
    @Query("SELECT COALESCE(sum(length(bytes)),0) FROM photo_pending") fun pendingPhotoBytes(): Long
    @Query("UPDATE photo_pending SET evidenceId=:evidence,bytes=NULL WHERE operationId=:operation AND evidenceId IS NULL") fun receivePhoto(operation: String, evidence: String)
    @Query("SELECT * FROM refresh_attempts WHERE singleton=1") fun refreshAttempt(): RefreshAttemptRow?
    @Insert fun insertRefreshAttempt(row: RefreshAttemptRow)
    @Query("DELETE FROM refresh_attempts WHERE singleton=1") fun clearRefreshAttempt()
    @Query("SELECT * FROM authority WHERE singleton=1") fun authority(): AuthorityRow?
    @Insert(onConflict = OnConflictStrategy.REPLACE) fun authority(row: AuthorityRow)
    @Query("SELECT * FROM drafts WHERE submittedOperation IS NULL ORDER BY id") fun drafts(): List<DraftRow>
    @Query("SELECT * FROM drafts WHERE id=:id") fun draft(id: String): DraftRow?
    @Insert fun insertDraft(row: DraftRow)
    @Update fun updateDraft(row: DraftRow)
    @Insert fun insertSubmitted(row: SubmittedRow)
    @Query("SELECT * FROM submitted WHERE operationId=:id") fun submitted(id: String): SubmittedRow?
    @Query("SELECT * FROM submitted ORDER BY queuedAtServerMillis, operationId") fun submissions(): List<SubmittedRow>
    @Insert fun insertOutbox(row: OutboxRow)
    @Update fun updateOutbox(row: OutboxRow)
    @Query("SELECT * FROM outbox WHERE operationId=:id") fun outbox(id: String): OutboxRow?
    @Insert fun receipt(row: ReceiptRow)
    @Query("SELECT * FROM receipts WHERE operationId=:id") fun receipt(id: String): ReceiptRow?
    @Query("SELECT * FROM receipts WHERE reportId=:report AND revisionId=:revision AND revisionNo=:number LIMIT 1") fun photoBinding(report: String, revision: String, number: Int): ReceiptRow?
    @Insert fun command(row: CommandRow)
    @Query("SELECT * FROM commands WHERE commandId=:id") fun command(id: String): CommandRow?
    @Insert(onConflict = OnConflictStrategy.REPLACE) fun cache(rows: List<CacheRow>)
    @Query("DELETE FROM report_cache WHERE opened=:opened") fun clearCache(opened: Boolean)
    @Query("DELETE FROM report_cache") fun clearAllCache()
    @Query("SELECT * FROM report_cache WHERE opened=:opened ORDER BY key") fun cached(opened: Boolean): List<CacheRow>
}

@Entity(tableName = "photo_pending")
internal data class PhotoRow(@PrimaryKey val operationId: String, val reportId: String, val revisionId: String, val revisionNo: Int,
    val captureJson: String, val bytes: ByteArray?, val bytesHash: String, val evidenceId: String?,
    val mediaType: String, val filename: String, val scopeJson: String)
internal data class PhotoSummaryRow(val operationId: String, val reportId: String, val revisionId: String, val revisionNo: Int, val evidenceId: String?)

@Database(entities = [AuthorityRow::class, DraftRow::class, SubmittedRow::class, OutboxRow::class, ReceiptRow::class, CommandRow::class, CacheRow::class, RefreshAttemptRow::class, PhotoRow::class], version = 4, exportSchema = true)
internal abstract class ProtectedDatabase : RoomDatabase() {
    abstract fun dao(): ProtectedDao
    // SQLCipher4.19.1 shares this array with its pool configuration. Keep exactly
    // one owned copy until every connection closes; an early wipe breaks later WAL readers.
    private var ownedPassphrase: ByteArray? = null
    internal fun retainsKeyMaterial(): Boolean = ownedPassphrase?.any { it != 0.toByte() } == true
    override fun close() {
        try { super.close() } finally { ownedPassphrase?.fill(0) }
    }
    companion object {
        val MIGRATION_3_4 = object : Migration(3, 4) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS photo_pending (operationId TEXT NOT NULL, reportId TEXT NOT NULL, revisionId TEXT NOT NULL, revisionNo INTEGER NOT NULL, captureJson TEXT NOT NULL, bytes BLOB, bytesHash TEXT NOT NULL, evidenceId TEXT, mediaType TEXT NOT NULL, filename TEXT NOT NULL, scopeJson TEXT NOT NULL, PRIMARY KEY(operationId))")
            }
        }
        // Explicit prototype-schema upgrade; no released historical Android schema is claimed.
        val MIGRATION_1_2 = object : Migration(1, 2) {
            override fun migrate(db: SupportSQLiteDatabase) { db.execSQL("ALTER TABLE outbox ADD COLUMN lastErrorCode TEXT DEFAULT NULL") }
        }
        val MIGRATION_2_3 = object : Migration(2, 3) {
            override fun migrate(db: SupportSQLiteDatabase) {
                db.execSQL("CREATE TABLE IF NOT EXISTS refresh_attempts (singleton INTEGER NOT NULL, attemptId TEXT NOT NULL, capabilityId TEXT NOT NULL, generation INTEGER NOT NULL, authorityRevision INTEGER NOT NULL, familyId TEXT NOT NULL, credentialHash TEXT NOT NULL, requestStartElapsed INTEGER NOT NULL, bootId TEXT NOT NULL, PRIMARY KEY(singleton))")
            }
        }
        fun open(context: Context, file: File, passphrase: ByteArray): ProtectedDatabase {
            System.loadLibrary("sqlcipher")
            net.zetetic.database.Logger.setTarget(net.zetetic.database.NoopTarget())
            val key = passphrase.copyOf()
            var opened: ProtectedDatabase? = null
            try {
                val database = Room.databaseBuilder(context, ProtectedDatabase::class.java, file.absolutePath)
                    .openHelperFactory(SupportOpenHelperFactory(key))
                    .addMigrations(MIGRATION_1_2, MIGRATION_2_3, MIGRATION_3_4).setJournalMode(JournalMode.WRITE_AHEAD_LOGGING)
                    .addCallback(object : Callback() {
                        override fun onOpen(db: SupportSQLiteDatabase) {
                            db.execSQL("CREATE TRIGGER IF NOT EXISTS immutable_photo_delete BEFORE DELETE ON photo_pending BEGIN SELECT RAISE(ABORT,'immutable photo'); END")
                            db.execSQL("CREATE TRIGGER IF NOT EXISTS immutable_photo_update BEFORE UPDATE ON photo_pending WHEN NOT (NEW.operationId=OLD.operationId AND NEW.reportId=OLD.reportId AND NEW.revisionId=OLD.revisionId AND NEW.revisionNo=OLD.revisionNo AND NEW.captureJson=OLD.captureJson AND NEW.bytesHash=OLD.bytesHash AND NEW.mediaType=OLD.mediaType AND NEW.filename=OLD.filename AND NEW.scopeJson=OLD.scopeJson AND OLD.evidenceId IS NULL AND NEW.evidenceId IS NOT NULL AND NEW.bytes IS NULL) BEGIN SELECT RAISE(ABORT,'immutable photo'); END")
                            listOf("submitted", "receipts").forEach { table ->
                                listOf("UPDATE", "DELETE").forEach { action ->
                                    db.execSQL("CREATE TRIGGER IF NOT EXISTS immutable_${table}_${action.lowercase()} BEFORE $action ON $table BEGIN SELECT RAISE(ABORT, 'immutable local record'); END")
                                }
                            }
                        }
                    })
                    .build()
                opened = database
                database.ownedPassphrase = key
                database.openHelper.writableDatabase.query("PRAGMA secure_delete=ON").use { cursor -> check(cursor.moveToFirst() && cursor.getInt(0) == 1) }
                database.openHelper.writableDatabase.execSQL("PRAGMA temp_store=MEMORY")
                database.openHelper.writableDatabase.query("PRAGMA temp_store").use { cursor -> check(cursor.moveToFirst() && cursor.getInt(0) == 2) }
                return database
            } catch (failure: Throwable) {
                try { opened?.close() } finally { key.fill(0) }
                throw failure
            }
        }
    }
}

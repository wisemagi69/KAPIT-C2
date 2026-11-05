package org.kapit.c2.mobile.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.sqlite.db.SupportSQLiteDatabase
import androidx.sqlite.db.SupportSQLiteOpenHelper
import java.io.File
import java.security.KeyStore
import java.util.UUID
import kotlinx.serialization.json.*
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.kapit.c2.mobile.data.local.*
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.security.*

/** Real credential-bound stores with explicitly synthetic server authority. */
@RunWith(AndroidJUnit4::class)
class WorkerStoreTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val root = File(context.noBackupFilesDir, "worker-test-${UUID.randomUUID()}")
    private val actual = AndroidAccessEnvironment(context)
    private val env = object : StoreEnvironment {
        @Volatile var stamp: ClockStamp? = null
        @Volatile var denied = false
        override fun clock() = stamp ?: actual.clock()
        override fun requireEligibleUnlockedDevice() { if (denied) throw StoreFailure(StoreCode.UNLOCK_REQUIRED); actual.requireEligibleUnlockedDevice() }
    }
    private val server = 1792195200000L
    private fun uuid() = UUID.randomUUID().toString()
    private val identity = AuthorizedContext(CaptureContext(AccountIdentity(uuid(), uuid(), uuid()), uuid(), uuid(), "private", MAINTENANCE_TEMPLATE),
        uuid(), 0, "Synthetic author", "Synthetic organization", "Synthetic unit", "Synthetic channel")
    private val repositories = mutableListOf<AndroidProtectedRepository>()
    private lateinit var repo: AndroidProtectedRepository
    private fun repository() = AndroidProtectedRepository(context, root, env, false).also(repositories::add)
    private fun secrets(rotated: Boolean = false) = SessionSecrets((if (rotated) "rotated-access" else "synthetic-access").toByteArray(),
        (if (rotated) "rotated-refresh" else "synthetic-refresh").toByteArray(), server + 3600000, server + 86400000)
    private fun offer() = LeaseOffer(server, server + 86400000, server + 172800000, 86400)
    private fun activate(): Long = secrets().use { repo.activateOnline(repo.beginOnlineRequest(repo.access.value.generation), identity, offer(), it).generation }
    private fun queue(generation: Long): OutboxRecord {
        val content = MaintenanceContent("2026-10-17T00:00:00Z", "WATER_SUPPLY", "ROUTINE", "Area A", "Synthetic site", "Synthetic author", "Synthetic inspection", "Inspection")
        val draft = repo.createDraft(generation, uuid(), content)
        return repo.queueDraft(generation, uuid(), draft.id, draft.revision, 0, content)
    }
    private fun worker(): WorkerStoreCapability {
        repo.fence(StoreCode.LOCKED)
        return repo.openWorker(repo.access.value.generation, identity.capture.account.storeRef)
    }
    private fun database(field: String): ProtectedDatabase {
        val state = AndroidProtectedRepository::class.java.getDeclaredField(field).apply { isAccessible = true }.get(repo)!!
        return state.javaClass.getDeclaredField("database").apply { isAccessible = true }.get(state) as ProtectedDatabase
    }
    private fun denied(code: StoreCode? = null, action: () -> Unit) {
        try { action(); fail("Expected fail-closed operation") } catch (failure: StoreFailure) { if (code != null) assertEquals(code, failure.code) }
    }
    private fun closed(db: ProtectedDatabase) { assertFalse(db.isOpen); assertFalse(db.retainsKeyMaterial()) }
    private fun <T> inspect(block: (ProtectedDatabase) -> T): T {
        val vault = AndroidKeyVault(root, env); val pass = vault.unwrap(identity.capture.account.storeRef)
        val db = try { ProtectedDatabase.open(context, vault.database(identity.capture.account.storeRef), pass) } finally { pass.fill(0) }
        return try { block(db) } finally { db.close() }
    }
    @Before fun prepare() {
        check(context.packageName.endsWith(".spike") && InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        check(android.os.Build.HARDWARE in setOf("ranchu", "goldfish")); check(!root.exists())
        actual.requireEligibleUnlockedDevice(); repo = repository()
    }
    @After fun cleanup() {
        repositories.forEach { try { it.close() } catch (_: Exception) {} }
        KeyStore.getInstance("AndroidKeyStore").apply { load(null); deleteEntry("kapit.wrap.v1.${identity.capture.account.storeRef}") }
        check(root.parentFile.canonicalFile == context.noBackupFilesDir.canonicalFile && root.name.startsWith("worker-test-")); root.deleteRecursively()
    }
    @Test fun workerNeverPublishesReadyAndCloseErasesItsActualHandleAndSecrets() {
        val queued = queue(activate()); val cap = worker(); val db = database("worker"); val credentials = cap.credentials()
        assertFalse(repo.access.value.ready); assertEquals(StoreCode.LOCKED, repo.access.value.reason)
        denied(StoreCode.LOCKED) { repo.snapshot(cap.generation) }
        cap.claimNext()!!.use { assertEquals(queued.operationId, it.claim.operationId); assertEquals(1, it.attempt) }
        cap.close(); closed(db); denied(StoreCode.AUTH_REQUIRED) { credentials.copyRefreshToken() }
        denied(StoreCode.STALE_GENERATION) { cap.context }
        assertFalse(repo.access.value.ready)
    }
    @Test fun foregroundTakeoverRetiresWorkerWithoutLosingImmutableQueue() {
        val queued = queue(activate()); val cap = worker(); val db = database("worker")
        val claimed = cap.claimNext()!!; val generation = repo.unlock(repo.access.value.generation).generation
        closed(db); denied(StoreCode.CLAIM_LOST) { claimed.claim.copyRequestBytes() }
        denied(StoreCode.STALE_GENERATION) { cap.nextDeliveryDelayMillis() }
        assertEquals(queued.operationId, repo.snapshot(generation).outbox.single().operationId)
        cap.close(); assertTrue(repo.access.value.ready)
    }
    @Test fun exactWorkerDeadlineRollsBackCommitAndErasesCapability() {
        queue(activate()); env.stamp = actual.clock(); val start = env.clock(); val cap = worker(); val db = database("worker")
        val credentials = cap.credentials()
        repo.beforeCommit = { env.stamp = ClockStamp(start.elapsedMillis + WorkerWindow.MAX_MILLIS, start.bootId) }
        denied(StoreCode.LOCKED) { cap.claimNext() }
        repo.beforeCommit = null; closed(db); denied(StoreCode.AUTH_REQUIRED) { credentials.copyAccessToken() }
        env.stamp = start
        inspect { assertEquals(0, it.dao().outbox(it.dao().submissions().single().operationId)!!.attempts) }
        assertFalse(repo.access.value.ready)
    }
    @Test fun workerBootDiscontinuityClosesHandleAndForbidsFreshAcquisition() {
        activate(); val cap = worker(); val db = database("worker"); env.stamp = ClockStamp(env.clock().elapsedMillis, "other-boot")
        denied(StoreCode.CLOCK_UNTRUSTED) { cap.clock() }; closed(db)
        denied(StoreCode.CLOCK_UNTRUSTED) { repo.openWorker(repo.access.value.generation, identity.capture.account.storeRef) }
    }
    @Test fun workerDeviceChangeAtCommitRollsBackAndClosesHandle() {
        queue(activate()); val cap = worker(); val db = database("worker")
        repo.beforeCommit = { env.denied = true }
        denied(StoreCode.UNLOCK_REQUIRED) { cap.claimNext() }; closed(db); repo.beforeCommit = null; env.denied = false
        inspect { assertEquals(0, it.dao().outbox(it.dao().submissions().single().operationId)!!.attempts) }
    }
    @Test fun periodicMonitorClosesLeakedWorkerAtDeadlineWithoutCapabilityCall() {
        repo.close(); repo = AndroidProtectedRepository(context, root, env, true).also(repositories::add)
        activate(); env.stamp = actual.clock(); val start = env.clock(); val cap = worker(); val db = database("worker"); val credentials = cap.credentials()
        env.stamp = ClockStamp(start.elapsedMillis + WorkerWindow.MAX_MILLIS, start.bootId)
        val deadline = android.os.SystemClock.elapsedRealtime() + 10_000
        while (android.os.SystemClock.elapsedRealtime() < deadline && db.isOpen) Thread.sleep(50)
        closed(db); assertFalse(repo.access.value.ready); denied(StoreCode.AUTH_REQUIRED) { credentials.copyRefreshToken() }
        assertEquals(StoreCode.LOCKED, repo.access.value.reason)
    }
    @Test fun workerRefreshRotatesPrivatelyAndRenewalDoesNotExtendCapabilityDeadline() {
        activate(); env.stamp = actual.clock(); val start = env.clock(); val cap = worker(); val db = database("worker")
        val anchor = cap.beginOnlineRequest(); val attempt = cap.beginRefresh(anchor)
        env.stamp = ClockStamp(start.elapsedMillis + 30_000, start.bootId)
        secrets(true).use { cap.completeRefresh(attempt, anchor, identity, offer(), it) }
        assertFalse(repo.access.value.ready); assertNull(db.dao().refreshAttempt())
        cap.credentials().use { assertArrayEquals("rotated-access".toByteArray(), it.copyAccessToken()) }
        env.stamp = ClockStamp(start.elapsedMillis + WorkerWindow.MAX_MILLIS, start.bootId)
        denied(StoreCode.LOCKED) { cap.context }; closed(db)
    }
    @Test fun workerScopeDenialClearsActualCacheAndRetainsQueueBeforeReauthentication() {
        val generation = activate(); val queued = queue(generation)
        database("active").dao().cache(listOf(CacheRow("fixture", uuid(), 1, "{}", server, false)))
        val cap = worker(); val db = database("worker")
        cap.deny(StoreCode.SCOPE_DENIED); closed(db)
        inspect { assertTrue(it.dao().cached(false).isEmpty()); assertEquals(queued.requestHash, it.dao().submitted(queued.operationId)!!.requestHash) }
        denied(StoreCode.SCOPE_DENIED) { repo.unlock(repo.access.value.generation) }
    }
    @Test fun markerIsCommittedBeforeDispatchAndRestartCannotReuseOldRefresh() {
        val generation = activate(); val queued = queue(generation); val cap = repo.foregroundSync(generation)
        val old = cap.credentials(); val anchor = cap.beginOnlineRequest(); cap.beginRefresh(anchor)
        assertNotNull(database("active").dao().refreshAttempt()); denied(StoreCode.AUTH_REQUIRED) { old.copyRefreshToken() }
        repo.close(); repo = repository(); repo.restoreSelection(repo.access.value.generation)
        denied(StoreCode.AUTH_REQUIRED) { repo.unlock(repo.access.value.generation) }
        inspect { assertNotNull(it.dao().refreshAttempt()); assertEquals(queued.operationId, it.dao().submissions().single().operationId) }
        val restored = activate(); assertEquals(queued.operationId, repo.snapshot(restored).outbox.single().operationId)
        assertNull(database("active").dao().refreshAttempt())
    }
    @Test fun exactRefreshRotationCommitsOnceWithoutChangingPublicGeneration() {
        val generation = activate(); queue(generation); val cap = repo.foregroundSync(generation)
        val anchor = cap.beginOnlineRequest(); val attempt = cap.beginRefresh(anchor)
        secrets(true).use { cap.completeRefresh(attempt, anchor, identity, offer(), it) }
        assertEquals(generation, repo.access.value.generation); assertNull(database("active").dao().refreshAttempt())
        cap.credentials().use { assertArrayEquals("rotated-refresh".toByteArray(), it.copyRefreshToken()) }
        secrets(true).use { denied(StoreCode.STALE_GENERATION) { cap.completeRefresh(attempt, anchor, identity, offer(), it) } }
        assertTrue(repo.access.value.ready); cap.close()
    }
    @Test fun ordinaryRenewalCannotClearCommittedRefreshUncertainty() {
        val generation = activate(); val cap = repo.foregroundSync(generation); val anchor = cap.beginOnlineRequest(); cap.beginRefresh(anchor)
        secrets().use { denied(StoreCode.AUTH_REQUIRED) { cap.renewOnline(anchor, identity, offer(), it) } }
        inspect { assertNotNull(it.dao().refreshAttempt()); val row = it.dao().authority()!!
            try { assertArrayEquals("synthetic-refresh".toByteArray(), row.refreshToken) } finally { row.accessToken.fill(0); row.refreshToken.fill(0) } }
        assertFalse(repo.access.value.ready)
    }
    @Test fun failedRotationTransactionRetainsMarkerAndOriginalCredentialsAtomically() {
        val generation = activate(); val cap = repo.foregroundSync(generation); val anchor = cap.beginOnlineRequest(); val attempt = cap.beginRefresh(anchor)
        repo.beforeCommit = { throw StoreFailure(StoreCode.VALIDATION_ERROR) }
        secrets(true).use { denied(StoreCode.VALIDATION_ERROR) { cap.completeRefresh(attempt, anchor, identity, offer(), it) } }
        repo.beforeCommit = null
        val dao = database("active").dao(); assertNotNull(dao.refreshAttempt())
        val row = dao.authority()!!; try { assertArrayEquals("synthetic-refresh".toByteArray(), row.refreshToken) } finally { row.accessToken.fill(0); row.refreshToken.fill(0) }
        repo.close(); repo = repository(); repo.restoreSelection(repo.access.value.generation)
        denied(StoreCode.AUTH_REQUIRED) { repo.unlock(repo.access.value.generation) }
    }
    @Test fun mismatchedRefreshCapabilityCannotClearMarker() {
        val generation = activate(); val first = repo.foregroundSync(generation); val second = repo.foregroundSync(generation)
        val anchor = first.beginOnlineRequest(); val attempt = first.beginRefresh(anchor)
        secrets(true).use { denied(StoreCode.AUTH_REQUIRED) { second.completeRefresh(attempt, anchor, identity, offer(), it) } }
        inspect { assertNotNull(it.dao().refreshAttempt()) }
    }
    @Test fun undispatchedRefreshAbandonKeepsOriginalCredentialsAndLaterUnlock() {
        val generation = activate(); val queued = queue(generation); val cap = repo.foregroundSync(generation)
        val anchor = cap.beginOnlineRequest(); val attempt = cap.beginRefresh(anchor)
        cap.abandonRefresh(attempt)
        assertNull(database("active").dao().refreshAttempt()); assertTrue(repo.access.value.ready)
        cap.credentials().use { assertArrayEquals("synthetic-refresh".toByteArray(), it.copyRefreshToken()) }
        cap.close(); repo.fence(StoreCode.LOCKED, null)
        val unlocked = repo.unlock(repo.access.value.generation)
        assertTrue(unlocked.ready); assertEquals(queued.operationId, repo.snapshot(unlocked.generation).outbox.single().operationId)
    }
    @Test fun anotherSessionCannotAbandonRefreshMarker() {
        val generation = activate(); val first = repo.foregroundSync(generation); val second = repo.foregroundSync(generation)
        val attempt = first.beginRefresh(first.beginOnlineRequest())
        denied(StoreCode.AUTH_REQUIRED) { second.abandonRefresh(attempt) }
        inspect { assertNotNull(it.dao().refreshAttempt()) }
    }
    @Test fun schedulingCheckDuringAnotherSessionsLiveRefreshDoesNotDenyAccount() {
        // TASK-089 F1: AppContainer's scheduling check runs outside the authority gate, between beginRefresh and completeRefresh.
        val generation = activate(); val refreshing = repo.foregroundSync(generation); val scheduling = repo.foregroundSync(generation)
        val anchor = refreshing.beginOnlineRequest(); val attempt = refreshing.beginRefresh(anchor)
        assertNull(scheduling.nextDeliveryDelayMillis())
        assertTrue(repo.access.value.ready); assertEquals(generation, repo.access.value.generation)
        secrets(true).use { refreshing.completeRefresh(attempt, anchor, identity, offer(), it) }
        assertNull(database("active").dao().refreshAttempt()); assertTrue(repo.access.value.ready)
        refreshing.credentials().use { assertArrayEquals("rotated-refresh".toByteArray(), it.copyRefreshToken()) }
        refreshing.close(); scheduling.close()
    }
    @Test fun orphanedRefreshMarkerStillRequiresRecoveryOnSchedulingCheck() {
        val generation = activate(); val refreshing = repo.foregroundSync(generation)
        refreshing.beginRefresh(refreshing.beginOnlineRequest()); refreshing.close()
        val scheduling = repo.foregroundSync(generation)
        denied(StoreCode.AUTH_REQUIRED) { scheduling.nextDeliveryDelayMillis() }
        assertFalse(repo.access.value.ready); inspect { assertNotNull(it.dao().refreshAttempt()) }
    }
    @Test fun persistedAttemptAndDelayAndConservativeTokenClockSurviveReopen() {
        env.stamp = actual.clock(); val begin = env.clock(); val anchor = repo.beginOnlineRequest(repo.access.value.generation)
        env.stamp = ClockStamp(begin.elapsedMillis + 20_000, begin.bootId)
        secrets().use { repo.activateOnline(anchor, identity, offer(), it) }
        queue(repo.access.value.generation)
        val cap = worker()
        assertEquals(server, cap.serverTimeLowerMillis()); assertEquals(server + 20_000, cap.serverTimeUpperMillis())
        assertTrue(cap.accessTokenUsable()); val claim = cap.claimNext()!!; assertEquals(1, claim.attempt)
        cap.recordFailure(claim.claim, DeliveryState.QUEUED, null, 60_000)
        assertEquals(60_000L, cap.nextDeliveryDelayMillis()); cap.close()
        repo.openWorker(repo.access.value.generation, identity.capture.account.storeRef).use { next ->
            assertNull(next.claimNext()); env.stamp = ClockStamp(begin.elapsedMillis + 80_000, begin.bootId)
            next.claimNext()!!.use { assertEquals(2, it.attempt) }
        }
    }
    @Test fun versionTwoMigrationAddsEmptyMarkerWithoutChangingPendingBytes() {
        val queued = queue(activate()); repo.fence(StoreCode.LOCKED)
        val vault = AndroidKeyVault(root, env); val pass = vault.unwrap(identity.capture.account.storeRef)
        try {
            val factoryKey = pass.copyOf()
            val helper = SupportOpenHelperFactory(factoryKey).create(SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(vault.database(identity.capture.account.storeRef).absolutePath).callback(object : SupportSQLiteOpenHelper.Callback(4) {
                    override fun onCreate(db: SupportSQLiteDatabase) = error("Existing fixture required")
                    override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = error("No fixture upgrade")
                }).build())
            // A real version-2 store predates both the refresh marker (v3) and private photo queue (v4) tables.
            try { helper.writableDatabase.execSQL("DROP TABLE refresh_attempts"); helper.writableDatabase.execSQL("DROP TABLE photo_pending")
                helper.writableDatabase.execSQL("DELETE FROM room_master_table"); helper.writableDatabase.version = 2 }
            finally { helper.close(); factoryKey.fill(0) }
            inspect { assertNull(it.dao().refreshAttempt()); assertEquals(queued.requestHash, it.dao().submitted(queued.operationId)!!.requestHash)
                assertEquals(DeliveryState.QUEUED.name, it.dao().outbox(queued.operationId)!!.delivery) }
        } finally { pass.fill(0) }
    }
}

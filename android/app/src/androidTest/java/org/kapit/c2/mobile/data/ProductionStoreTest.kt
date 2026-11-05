package org.kapit.c2.mobile.data

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.platform.app.InstrumentationRegistry
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.sqlite.db.SupportSQLiteOpenHelper
import androidx.sqlite.db.SupportSQLiteDatabase
import net.zetetic.database.sqlcipher.SupportOpenHelperFactory
import java.io.File
import java.security.KeyStore
import java.util.UUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.serialization.json.*
import org.junit.*
import org.junit.Assert.*
import org.junit.runner.RunWith
import org.kapit.c2.mobile.data.local.*
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.security.*

/** Synthetic contexts exercise the actual store; these are not authenticated-server acceptance. */
@RunWith(AndroidJUnit4::class)
class ProductionStoreTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val root = File(context.noBackupFilesDir, "storage-test-${UUID.randomUUID()}")
    private val actual = AndroidAccessEnvironment(context)
    private val env = object : StoreEnvironment {
        var offset = 0L; var boot: String? = null; var eligibilityDenied = false
        override fun clock() = actual.clock().let { ClockStamp(it.elapsedMillis + offset, boot ?: it.bootId) }
        override fun requireEligibleUnlockedDevice() {
            if (eligibilityDenied) throw StoreFailure(StoreCode.UNLOCK_REQUIRED)
            actual.requireEligibleUnlockedDevice()
        }
    }
    private val accounts = mutableListOf<AuthorizedContext>()
    private val repositories = mutableListOf<AndroidProtectedRepository>()
    private val unexpectedFailures = mutableListOf<String>()
    private lateinit var repo: AndroidProtectedRepository
    private val server = 1792195200000L
    private val canary = "SYNTHETIC_PROTECTED_STORE_CANARY_${UUID.randomUUID()}"
    private fun uuid() = UUID.randomUUID().toString()
    private fun authority() = AuthorizedContext(CaptureContext(AccountIdentity(uuid(), uuid(), uuid()), uuid(), uuid(), "private", MAINTENANCE_TEMPLATE), uuid(), 0,
        "Synthetic author", "Synthetic organization", "Synthetic unit", "Synthetic channel").also(accounts::add)
    private fun content() = MaintenanceContent("2026-10-17T00:00:00Z", "WATER_SUPPLY", "ROUTINE", "Area A", "Synthetic site", "Synthetic author", canary, "Inspection")
    private fun repository() = AndroidProtectedRepository(context, root, env, false).also {
        repositories += it
        it.unexpectedFailureObserver = { type, ownMethods -> unexpectedFailures += "$type at ${ownMethods.joinToString()}" }
    }
    private fun activate(value: AuthorizedContext = authority()): Long {
        val anchor = repo.beginOnlineRequest(repo.access.value.generation)
        SessionSecrets("synthetic-access".toByteArray(), "synthetic-refresh".toByteArray(), server + 3600000, server + 86400000).use {
            return repo.activateOnline(anchor, value, LeaseOffer(server, server + 86400000, server + 172800000, 86400), it).generation
        }
    }
    private fun queue(generation: Long): OutboxRecord {
        val draft = repo.createDraft(generation, uuid(), content())
        return repo.queueDraft(generation, uuid(), draft.id, draft.revision, 0, draft.content)
    }
    private fun denied(code: StoreCode? = null, action: () -> Unit) {
        try { action(); fail("Expected fail-closed operation") } catch (failure: StoreFailure) { if (code != null) assertEquals(code, failure.code) }
    }
    private fun receipt(claim: DeliveryClaim) = AcceptedReceipt.parse(CanonicalJson.bytes(buildJsonObject {
        put("operation_id", claim.operationId); put("report_id", claim.reportId); put("revision_id", uuid()); put("revision_no", claim.expectedRevision + 1)
        put("delivery_status", "RECEIVED"); put("processing_status", "PENDING"); put("shared", false)
    }), claim)
    @Before fun prepare() {
        check(context.packageName.endsWith(".spike"))
        check(InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        check(android.os.Build.HARDWARE in setOf("ranchu", "goldfish"))
        check(!root.exists()); actual.requireEligibleUnlockedDevice(); repo = repository()
    }
    @After fun closeOwnedFixtures() {
        repositories.forEach { try { it.close() } catch (_: Exception) {} }
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }
        accounts.map { it.capture.account.storeRef }.distinct().forEach { keys.deleteEntry("kapit.wrap.v1.$it") }
        // Only this randomly named fixture directory inside the freshly owned emulator package.
        check(root.parentFile.canonicalFile == context.noBackupFilesDir.canonicalFile && root.name.startsWith("storage-test-"))
        root.deleteRecursively()
        assertEquals("Unexpected exception classes and own methods only", emptyList<String>(), unexpectedFailures)
    }
    @Test fun submitFreezesExactlyOneOperationAcrossTwentyCommandReplays() {
        val generation = activate(); val draft = repo.createDraft(generation, uuid(), content()); val command = uuid()
        val queued = repo.queueDraft(generation, command, draft.id, draft.revision, 0, draft.content)
        repeat(20) { assertEquals(queued.operationId, repo.queueDraft(generation, command, draft.id, draft.revision, 0, draft.content).operationId) }
        denied(StoreCode.COMMAND_CONFLICT) { repo.queueDraft(generation, command, draft.id, draft.revision, 0, draft.content.copy(narrative = "changed synthetic")) }
        denied(StoreCode.STALE_DRAFT) { repo.saveDraft(generation, uuid(), draft.id, draft.revision, content()) }
        assertEquals(1, repo.snapshot(generation).outbox.size); assertTrue(repo.snapshot(generation).drafts.isEmpty())
        repo.claimNext(generation)!!.use { claim ->
            val request = StrictJson.objectFrom(claim.copyRequestBytes())
            assertEquals(queued.requestHash, RequestPolicy.requestHash(request)); assertEquals(canary, request.getValue("payload").jsonObject.requiredString("narrative"))
        }
    }
    @Test fun failedSubmitRollsBackSnapshotOutboxAndCommandTogether() {
        val generation = activate(); val draft = repo.createDraft(generation, uuid(), content()); val command = uuid()
        repo.beforeCommit = { throw StoreFailure(StoreCode.VALIDATION_ERROR) }
        denied(StoreCode.VALIDATION_ERROR) { repo.queueDraft(generation, command, draft.id, draft.revision, 0, content()) }
        repo.beforeCommit = null
        assertTrue(repo.snapshot(generation).outbox.isEmpty()); assertEquals(draft, repo.openDraft(generation, draft.id))
        assertNotNull(repo.queueDraft(generation, command, draft.id, draft.revision, 0, content()))
    }
    @Test fun failedDenialCleanupCannotCloseReplacementAccount() {
        val original = authority(); val generation = activate(original); val queued = queue(generation)
        // Inspect only this owned fixture's actual handle; do not add a production DAO accessor.
        val activeField = AndroidProtectedRepository::class.java.getDeclaredField("active").apply { isAccessible = true }
        val active = checkNotNull(activeField.get(repo))
        val databaseField = active.javaClass.getDeclaredField("database").apply { isAccessible = true }
        val database = databaseField.get(active) as ProtectedDatabase
        assertTrue(database.isOpen); assertTrue(database.retainsKeyMaterial())
        val state = File(root, "${original.capture.account.storeRef}/access.state")
        val originalState = state.readBytes()
        check(state.delete()); check(state.mkdir())
        val obstruction = File(state, "owned-fixture-blocker").apply { writeText("fixture") }
        val fencedGeneration = generation + 1
        try {
            denied(StoreCode.STORAGE_UNAVAILABLE) { repo.fence(StoreCode.SIGNED_OUT) }
            assertFalse(repo.access.value.ready)
            assertEquals(fencedGeneration, repo.access.value.generation)
            assertEquals(StoreCode.SIGNED_OUT, repo.access.value.reason)
            assertFalse("Direct failed fence closes its actual handle immediately", database.isOpen)
            assertFalse("Direct failed fence erases the handle-owned key", database.retainsKeyMaterial())
            var denied = false
            try { database.dao().drafts() } catch (_: Exception) { denied = true }
            assertTrue("Closed handle cannot reopen after failed durable denial", denied)
        } finally {
            check(obstruction.delete()); check(state.delete()); state.writeBytes(originalState); originalState.fill(0)
        }
        val replacement = activate()
        repo.closeFailedFence(fencedGeneration) // delayed asynchronous fallback after the replacement committed
        assertTrue(repo.access.value.ready); assertTrue(repo.snapshot(replacement).outbox.isEmpty())
        val restored = activate(original)
        assertEquals(queued.operationId, repo.snapshot(restored).outbox.single().operationId)
    }
    @Test fun freshWalReaderUsesHandleOwnedKeyAndCloseErasesIt() {
        val identity = authority(); val generation = activate(identity)
        val draft = repo.createDraft(generation, uuid(), content()); repo.fence(StoreCode.LOCKED)
        val vault = AndroidKeyVault(root, env); val pass = vault.unwrap(identity.capture.account.storeRef)
        val database = try { ProtectedDatabase.open(context, vault.database(identity.capture.account.storeRef), pass) } finally { pass.fill(0) }
        val reader = Executors.newSingleThreadExecutor()
        try {
            assertTrue(database.retainsKeyMaterial())
            val sql = database.openHelper.writableDatabase
            // Close any existing read pool, then require a fresh encrypted reader while
            // the primary connection is held by this uncommitted write transaction.
            sql.disableWriteAheadLogging(); assertTrue(sql.enableWriteAheadLogging())
            sql.beginTransactionNonExclusive()
            try {
                val rows = reader.submit<List<DraftRow>> { database.dao().drafts() }.get(15, TimeUnit.SECONDS)
                assertEquals(draft.id, rows.single().id)
                assertEquals(draft, StoreCodec.draft(rows.single().recordJson))
            } finally { sql.endTransaction() }
        } finally { reader.shutdownNow(); database.close() }
        assertFalse(database.retainsKeyMaterial())
        var denied = false
        try { database.dao().drafts() } catch (_: Exception) { denied = true }
        assertTrue("Closed protected handle cannot reopen its wiped key", denied)
    }
    @Test fun saveRevisionAndCommandReplayPreventLostUpdates() {
        val generation = activate(); val draft = repo.createDraft(generation, uuid()); val command = uuid()
        assertTrue(draft.content.observedAt.endsWith("Z"))
        val saved = repo.saveDraft(generation, command, draft.id, draft.revision, content())
        assertEquals(saved, repo.saveDraft(generation, command, draft.id, draft.revision, content()))
        denied(StoreCode.STALE_DRAFT) { repo.saveDraft(generation, uuid(), draft.id, draft.revision, content()) }
        assertEquals(saved, repo.openDraft(generation, draft.id))
    }
    @Test fun accountAndEnrollmentIsolationPreserveOriginalQueue() {
        val a = authority(); val first = activate(a); val original = queue(first)
        val b = authority(); val second = activate(b)
        assertTrue(repo.snapshot(second).outbox.isEmpty()); denied(StoreCode.STALE_GENERATION) { repo.snapshot(first) }
        queue(second)
        val third = activate(a)
        assertEquals(listOf(original.operationId), repo.snapshot(third).outbox.map { it.operationId })
        assertNotEquals(a.capture.account.storeRef, b.capture.account.storeRef)
        assertTrue(File(root, "${a.capture.account.storeRef}/protected.db").isFile)
        assertTrue(File(root, "${b.capture.account.storeRef}/protected.db").isFile)
    }
    @Test fun sameBootRestartRestoresButLogoutRemainsDeniedAcrossClose() {
        val generation = activate(); val queued = queue(generation); repo.close(); repo = repository()
        val restored = repo.restoreSelection(repo.access.value.generation)
        assertFalse(restored.ready); assertEquals(StoreCode.LOCKED, restored.reason); assertNotNull(restored.storeRef)
        val unlocked = repo.unlock(restored.generation).generation
        assertEquals(queued.operationId, repo.snapshot(unlocked).outbox.single().operationId)
        val logout = repo.logoutAndInvalidate(unlocked)
        assertNotNull(logout.authorization); logout.authorization!!.close()
        repo.fence(StoreCode.SIGNED_OUT, logout.access.generation); repo.close(); repo = repository()
        denied(StoreCode.SIGNED_OUT) { repo.unlock(repo.access.value.generation) }
        assertTrue(File(root, "${accounts.single().capture.account.storeRef}/protected.db").length() > 0)
    }
    @Test fun leaseExpiryAndBootDiscontinuityNeverUseWallClock() {
        val generation = activate(); queue(generation); val state = repo.fence(StoreCode.LOCKED)
        env.boot = "different-boot"
        denied(StoreCode.CLOCK_UNTRUSTED) { repo.unlock(state.generation) }
        env.boot = null
        val recovered = activate(accounts.single())
        env.offset = 86400000
        denied(StoreCode.LEASE_EXPIRED) { repo.snapshot(recovered) }
        assertFalse(repo.access.value.ready)
    }
    @Test fun contextReassignmentPausesFrozenBytesAndExplicitlyCreatesNewDraft() {
        val originalContext = authority(); val generation = activate(originalContext); val queued = queue(generation)
        val oldBytes = repo.claimNext(generation)!!.use { it.copyRequestBytes() }
        val changed = originalContext.copy(capture = originalContext.capture.copy(unitId = uuid()), permissionVersion = 1)
        val current = activate(changed)
        assertEquals(PauseReason.CONTEXT_CHANGED, repo.snapshot(current).outbox.single().pause); assertNull(repo.claimNext(current))
        val draft = repo.reconcileOperation(current, uuid(), queued.operationId)
        assertEquals(changed.capture, draft.capture); assertEquals(queued.operationId, draft.predecessorOperationId)
        val restored = activate(originalContext)
        repo.claimNext(restored)!!.use { assertArrayEquals(oldBytes, it.copyRequestBytes()) }
    }
    @Test fun staleClaimCannotAcknowledgeAndReopenRecoversSameFrozenOperation() {
        val generation = activate(); val queued = queue(generation); val oldClaim = repo.claimNext(generation)!!; val oldReceipt = receipt(oldClaim)
        val oldBytes = oldClaim.copyRequestBytes(); val fence = repo.invalidate(StoreCode.LOCKED); repo.fence(StoreCode.LOCKED, fence.generation)
        denied(StoreCode.CLAIM_LOST) { oldClaim.copyRequestBytes() }
        val current = repo.unlock(fence.generation).generation
        denied(StoreCode.STALE_GENERATION) { repo.commitReceipt(oldClaim, oldReceipt) }
        repo.claimNext(current)!!.use { fresh ->
            assertEquals(queued.operationId, fresh.operationId); assertArrayEquals(oldBytes, fresh.copyRequestBytes())
            repo.commitReceipt(fresh, receipt(fresh))
        }
        assertEquals(DeliveryState.RECEIVED, repo.snapshot(current).outbox.single().delivery)
        denied(StoreCode.ALREADY_RECEIVED) { repo.retryOperation(current, queued.operationId) }; assertNull(repo.claimNext(current))
    }
    @Test fun persistedClaimTimeoutFencesLateReceiptWithoutChangingBytes() {
        val generation = activate(); queue(generation); val old = repo.claimNext(generation)!!; val accepted = receipt(old); val bytes = old.copyRequestBytes()
        assertNull(repo.claimNext(generation)); env.offset = 120001
        denied(StoreCode.CLAIM_LOST) { repo.commitReceipt(old, accepted) }
        repo.claimNext(generation)!!.use { fresh -> assertArrayEquals(bytes, fresh.copyRequestBytes()); assertNotEquals(old.claimToken, fresh.claimToken) }
        old.close()
    }
    @Test fun manualRetryCannotBypassPersistedRetryAfter() {
        val generation = activate(); val queued = queue(generation)
        repo.claimNext(generation)!!.use { repo.recordFailure(it, DeliveryState.QUEUED, null, 30000) }
        val deadline = repo.snapshot(generation).outbox.single().nextAttemptElapsed
        repo.retryOperation(generation, queued.operationId)
        assertEquals(deadline, repo.snapshot(generation).outbox.single().nextAttemptElapsed); assertNull(repo.claimNext(generation))
        env.offset = 30001; repo.retryOperation(generation, queued.operationId)
        assertNotNull(repo.claimNext(generation))
    }
    @Test fun backgroundInvalidationRollsBackMutationPausedBeforeCommit() {
        val generation = activate(); val draft = repo.createDraft(generation, uuid(), content())
        val reached = CountDownLatch(1); val release = CountDownLatch(1); val executor = Executors.newSingleThreadExecutor()
        repo.beforeCommit = { reached.countDown(); check(release.await(10, TimeUnit.SECONDS)) }
        try {
            val mutation = executor.submit<StoreCode?> {
                try { repo.queueDraft(generation, uuid(), draft.id, draft.revision, 0, content()); null } catch (failure: StoreFailure) { failure.code }
            }
            assertTrue(reached.await(10, TimeUnit.SECONDS))
            val fenced = repo.invalidate(StoreCode.LOCKED)
            assertFalse(repo.access.value.ready); release.countDown()
            assertEquals(StoreCode.STALE_GENERATION, mutation.get(10, TimeUnit.SECONDS)); repo.beforeCommit = null
            repo.fence(StoreCode.LOCKED, fenced.generation)
            val current = repo.unlock(fenced.generation).generation
            assertTrue(repo.snapshot(current).outbox.isEmpty()); assertEquals(draft.id, repo.snapshot(current).drafts.single().id)
        } finally { release.countDown(); repo.beforeCommit = null; executor.shutdownNow() }
    }
    @Test fun changedDeviceEligibilityBeforeCommitRollsBackWithoutWaitingForBroadcast() {
        val generation = activate(); val draft = repo.createDraft(generation, uuid(), content())
        repo.beforeCommit = { env.eligibilityDenied = true }
        denied(StoreCode.UNLOCK_REQUIRED) { repo.queueDraft(generation, uuid(), draft.id, draft.revision, 0, content()) }
        assertFalse(repo.access.value.ready)
        repo.beforeCommit = null; env.eligibilityDenied = false
        val current = repo.unlock(repo.access.value.generation).generation
        assertTrue(repo.snapshot(current).outbox.isEmpty()); assertEquals(draft.id, repo.snapshot(current).drafts.single().id)
    }
    @Test fun missingWrappingKeyRetainsCiphertextAndNeverRegenerates() {
        val identity = authority(); val generation = activate(identity); queue(generation); val fenced = repo.fence(StoreCode.LOCKED)
        val file = File(root, "${identity.capture.account.storeRef}/protected.db"); val before = file.readBytes()
        val keys = KeyStore.getInstance("AndroidKeyStore").apply { load(null) }; val alias = "kapit.wrap.v1.${identity.capture.account.storeRef}"
        keys.deleteEntry(alias)
        denied(StoreCode.KEY_UNAVAILABLE) { repo.unlock(fenced.generation) }
        assertArrayEquals(before, file.readBytes()); assertFalse(keys.containsAlias(alias))
        denied(StoreCode.KEY_UNAVAILABLE) { activate(identity) }; assertArrayEquals(before, file.readBytes()); assertFalse(keys.containsAlias(alias))
    }
    @Test fun lateFenceCleanupCannotCloseNewAccountAndDetachedCredentialsAreCleared() {
        val first = activate(); val observed = repo.beginOnlineRequest(first); val secrets = repo.credentials(first); val fenced = repo.invalidate(StoreCode.LOCKED)
        denied(StoreCode.AUTH_REQUIRED) { secrets.copyAccessToken() }
        repo.fence(StoreCode.LOCKED, fenced.generation)
        val second = activate()
        assertNull(repo.invalidateObservedAuthority(first, observed.authorityRevision, StoreCode.LEASE_EXPIRED))
        repo.fence(StoreCode.LOCKED, fenced.generation)
        assertTrue(repo.access.value.ready); assertEquals(second, repo.snapshot(second).let { repo.access.value.generation })
    }
    @Test fun renewalPreservesGenerationButFencesOldTokensAnchorsAndMonitor() {
        val identity = authority(); val generation = activate(identity); queue(generation)
        val oldSecrets = repo.credentials(generation); val claim = repo.claimNext(generation)!!
        val oldAnchor = repo.beginOnlineRequest(generation); val newAnchor = repo.beginOnlineRequest(generation)
        env.offset = 1000
        val offer = LeaseOffer(server + 1000, server + 86401000, server + 172800000, 86400)
        SessionSecrets("synthetic-access".toByteArray(), "synthetic-refresh".toByteArray(), server + 3600000, server + 86400000).use { fresh ->
            assertEquals(generation, repo.renewOnline(newAnchor, identity, offer, fresh).generation)
            denied(StoreCode.STALE_GENERATION) { repo.renewOnline(oldAnchor, identity, offer, fresh) }
            denied(StoreCode.STALE_GENERATION) { repo.activateOnline(oldAnchor, identity, offer, fresh) }
        }
        denied(StoreCode.AUTH_REQUIRED) { oldSecrets.copyAccessToken() }
        assertNull(repo.invalidateObservedAuthority(generation, oldAnchor.authorityRevision, StoreCode.LEASE_EXPIRED))
        assertTrue(repo.access.value.ready)
        repo.commitReceipt(claim, receipt(claim)); assertEquals(DeliveryState.RECEIVED, repo.snapshot(generation).outbox.single().delivery)
        repo.credentials(generation).use { assertArrayEquals("synthetic-access".toByteArray(), it.copyAccessToken()) }
    }
    @Test fun renewalCannotAdoptChangedFamilyOrAuthority() {
        val identity = authority(); val generation = activate(identity); val queued = queue(generation)
        val anchor = repo.beginOnlineRequest(generation)
        SessionSecrets("synthetic-access".toByteArray(), "synthetic-refresh".toByteArray(), server + 3600000, server + 86400000).use { secrets ->
            denied(StoreCode.CONTEXT_CHANGED) { repo.renewOnline(anchor, identity.copy(familyId = uuid()), LeaseOffer(server, server + 86400000, server + 172800000, 86400), secrets) }
        }
        assertFalse(repo.access.value.ready); assertEquals(StoreCode.AUTH_REQUIRED, repo.access.value.reason)
        val restored = activate(identity)
        assertEquals(queued.operationId, repo.snapshot(restored).outbox.single().operationId)
    }
    @Test fun unsupportedTemplateFencesPreviousAuthorityAndPreservesQueue() {
        val identity = authority(); val generation = activate(identity); val queued = queue(generation)
        val anchor = repo.beginOnlineRequest(generation)
        SessionSecrets("synthetic-access".toByteArray(), "synthetic-refresh".toByteArray(), server + 3600000, server + 86400000).use { secrets ->
            denied(StoreCode.TEMPLATE_UNSUPPORTED) { repo.activateOnline(anchor, identity.copy(capture = identity.capture.copy(templateVersion = "unknown-template")),
                LeaseOffer(server, server + 86400000, server + 172800000, 86400), secrets) }
        }
        assertFalse(repo.access.value.ready); assertEquals(StoreCode.TEMPLATE_UNSUPPORTED, repo.access.value.reason)
        denied(StoreCode.TEMPLATE_UNSUPPORTED) { repo.unlock(repo.access.value.generation) }
        val current = activate(identity)
        assertEquals(queued.operationId, repo.snapshot(current).outbox.single().operationId)
    }
    @Test fun actualScreenOffClosesProductionHandleAndClearsCredentials() {
        repo.close(); repo = AndroidProtectedRepository(context, root, env, true).also(repositories::add)
        val generation = activate(); queue(generation); val secrets = repo.credentials(generation)
        val marker = File(context.noBackupFilesDir, "task060-screen-ready")
        check(!marker.exists())
        try {
            marker.writeText("READY")
            val deadline = android.os.SystemClock.elapsedRealtime() + 30000
            val keyguard = context.getSystemService(Context.KEYGUARD_SERVICE) as android.app.KeyguardManager
            // SCREEN_OFF can fence content before the OS has finished entering its
            // credential-locked state. Require both independently within one bound.
            while ((repo.access.value.ready || !keyguard.isDeviceLocked) && android.os.SystemClock.elapsedRealtime() < deadline) Thread.sleep(100)
            assertFalse("Actual host-triggered screen lock must fence the production store", repo.access.value.ready)
            assertTrue("The owned emulator must actually become credential locked", keyguard.isDeviceLocked)
            val fenced = repo.access.value; repo.fence(fenced.reason, fenced.generation)
            denied(StoreCode.AUTH_REQUIRED) { secrets.copyAccessToken() }
            denied(StoreCode.STALE_GENERATION) { repo.snapshot(generation) }
            assertTrue(File(root, "${accounts.single().capture.account.storeRef}/protected.db").length() > 0)
        } finally { marker.delete(); secrets.close() }
    }
    @Test fun cacheBoundsAndScopeDenialClearCacheWithoutDeletingQueue() {
        val identity = authority(); val generation = activate(identity); val queued = queue(generation)
        fun report(): CachedReport {
            val id = uuid()
            val json = buildJsonObject {
                put("id", id); put("reference", "SYNTHETIC"); put("category", "WATER_SUPPLY"); put("urgency", "ROUTINE"); put("area_label", "Area A")
                put("created_at", "2026-10-17T00:00:00Z"); put("observed_date", "2026-10-17"); put("revision_no", 1); put("status", "PENDING")
                put("variant_id", JsonNull); put("feedback", JsonNull)
            }
            return CachedReport(id, 1, CanonicalJson.bytes(json).toString(Charsets.UTF_8), server)
        }
        repo.cacheReports(generation, List(100) { report() }); assertEquals(100, repo.cachedReports(generation).size)
        denied(StoreCode.VALIDATION_ERROR) { repo.cacheReports(generation, List(101) { report() }) }
        repo.claimNext(generation)!!.use { repo.recordFailure(it, DeliveryState.QUEUED, PauseReason.SCOPE_DENIED) }
        val fenced = repo.access.value
        denied(StoreCode.SCOPE_DENIED) { repo.unlock(fenced.generation) }
        val current = activate(identity)
        assertTrue(repo.cachedReports(current).isEmpty()); assertEquals(queued.operationId, repo.snapshot(current).outbox.single().operationId)
    }
    @Test fun liveDatabaseWalAndMetadataContainNoSourceOrTokenCanary() {
        val generation = activate(); queue(generation)
        val directory = File(root, accounts.single().capture.account.storeRef)
        assertTrue(File(directory, "protected.db-wal").length() > 0)
        root.walkTopDown().filter { it.isFile }.forEach { file ->
            val bytes = file.readBytes().toString(Charsets.ISO_8859_1)
            assertFalse(bytes.contains(canary)); assertFalse(bytes.contains("synthetic-access")); assertFalse(bytes.contains("synthetic-refresh"))
        }
        assertEquals(0, context.applicationInfo.flags and android.content.pm.ApplicationInfo.FLAG_ALLOW_BACKUP)
        assertFalse(context.isDeviceProtectedStorage)
    }
    @Test fun immutableTriggersAndForwardMigrationPreservePendingBytes() {
        val identity = authority(); val generation = activate(identity); val queued = queue(generation); repo.fence(StoreCode.LOCKED)
        val vault = AndroidKeyVault(root, env); val pass = vault.unwrap(identity.capture.account.storeRef)
        try {
            val database = ProtectedDatabase.open(context, vault.database(identity.capture.account.storeRef), pass)
            val bytes = database.dao().submitted(queued.operationId)!!.requestBytes
            try { database.openHelper.writableDatabase.execSQL("UPDATE submitted SET requestHash='changed'"); fail("Immutable trigger missing") } catch (_: android.database.SQLException) {}
            try { database.openHelper.writableDatabase.execSQL("DELETE FROM submitted"); fail("Immutable trigger missing") } catch (_: android.database.SQLException) {}
            database.close()
            val helper = SupportOpenHelperFactory(pass.copyOf()).create(SupportSQLiteOpenHelper.Configuration.builder(context)
                .name(vault.database(identity.capture.account.storeRef).absolutePath).callback(object : SupportSQLiteOpenHelper.Callback(4) {
                    override fun onCreate(db: SupportSQLiteDatabase) = error("Existing fixture required")
                    override fun onUpgrade(db: SupportSQLiteDatabase, oldVersion: Int, newVersion: Int) = error("No fixture upgrade here")
                }).build())
            helper.writableDatabase.execSQL("ALTER TABLE outbox DROP COLUMN lastErrorCode")
            helper.writableDatabase.execSQL("DROP TABLE refresh_attempts")
            helper.writableDatabase.execSQL("DROP TABLE photo_pending")
            helper.writableDatabase.execSQL("DELETE FROM room_master_table")
            helper.writableDatabase.version = 1
            helper.close()
            val migrated = ProtectedDatabase.open(context, vault.database(identity.capture.account.storeRef), pass)
            try {
                assertArrayEquals(bytes, migrated.dao().submitted(queued.operationId)!!.requestBytes)
                assertEquals(DeliveryState.QUEUED.name, migrated.dao().outbox(queued.operationId)!!.delivery)
                assertNull(migrated.dao().outbox(queued.operationId)!!.lastErrorCode)
                assertEquals(0, migrated.dao().pendingPhotoCount())
            } finally { migrated.close() }
        } finally { pass.fill(0) }
    }

    @Test fun photoQueueBindsActualReceiptFreezesRetryAndClearsOnlyOnMatchingCommit() {
        val generation = activate(); queue(generation)
        val claim = repo.claimNext(generation)!!; val accepted = receipt(claim)
        repo.commitReceipt(claim, accepted); claim.close()
        val operation = uuid(); val bytes = byteArrayOf(-1, -40, -1, -39)
        val capture = PhotoPolicy.capture(server, 100, null)
        repo.queuePhoto(generation, operation, accepted.reportId, accepted.revisionId, accepted.revisionNo, capture, bytes)
        repo.queuePhoto(generation, operation, accepted.reportId, accepted.revisionId, accepted.revisionNo, capture, bytes)
        assertEquals(1, repo.photos(generation, accepted.reportId, accepted.revisionId).size)
        denied(StoreCode.COMMAND_CONFLICT) {
            repo.queuePhoto(generation, operation, accepted.reportId, accepted.revisionId, accepted.revisionNo,
                PhotoPolicy.capture(server + 1, 101, null), bytes)
        }
        denied(StoreCode.NOT_FOUND) { repo.queuePhoto(generation, uuid(), uuid(), uuid(), 1, capture, bytes) }
        val upload = repo.photoUpload(generation, operation)
        assertTrue("Exact JPEG retained", upload.copyBytes().contentEquals(bytes))
        denied(StoreCode.RECEIPT_INVALID) { repo.commitPhoto(generation, operation, PhotoReceipt(uuid(), uuid())) }
        assertTrue("Unconfirmed receipt preserves bytes", repo.photoUpload(generation, operation).use { it.copyBytes().contentEquals(bytes) })
        val evidence = uuid()
        repo.commitPhoto(generation, operation, PhotoReceipt(evidence, operation))
        assertEquals(evidence, repo.photos(generation, accepted.reportId, accepted.revisionId).single().evidenceId)
        denied(StoreCode.ALREADY_RECEIVED) { repo.photoUpload(generation, operation) }
        denied(StoreCode.RECEIPT_INVALID) { repo.commitPhoto(generation, operation, PhotoReceipt(uuid(), operation)) }
        upload.close()
    }

    @Test fun photoCommitFenceCannotAttachOldGenerationOrExceedRevisionQuota() {
        val generation = activate(); queue(generation)
        val claim = repo.claimNext(generation)!!; val accepted = receipt(claim)
        repo.commitReceipt(claim, accepted); claim.close()
        val capture = PhotoPolicy.capture(server, 100, null); val bytes = byteArrayOf(-1, -40, -1, -39)
        repeat(2) { repo.queuePhoto(generation, uuid(), accepted.reportId, accepted.revisionId, 1, capture, bytes) }
        denied(StoreCode.VALIDATION_ERROR) { repo.queuePhoto(generation, uuid(), accepted.reportId, accepted.revisionId, 1, capture, bytes) }
        val operation = repo.photos(generation, accepted.reportId, accepted.revisionId).first().operationId
        val detached = repo.photoUpload(generation, operation)
        repo.invalidate(StoreCode.LOCKED)
        denied(StoreCode.STALE_GENERATION) { repo.commitPhoto(generation, operation, PhotoReceipt(uuid(), operation)) }
        denied(StoreCode.STALE_GENERATION) { detached.copyBytes() }
    }
}

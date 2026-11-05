package org.kapit.c2.mobile.sync

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.util.AtomicFile
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkManager
import androidx.work.WorkInfo
import java.io.File
import java.util.UUID
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.collect
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kapit.c2.mobile.AppContainer
import org.kapit.c2.mobile.KapitApplication
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.ui.*

/** Actual local service/store/runtime. Faults belong to the host, credentials to synthetic test data. */
@RunWith(AndroidJUnit4::class)
class LiveRuntimeIntegrationTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val marker get() = File(context.noBackupFilesDir, "m2-live-phase")
    @Before fun ownedEmulatorOnly() {
        check(Build.VERSION.SDK_INT >= 35 && context.packageName.endsWith(".spike"))
        check(InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
    }

    @Test fun enrollAndQueue() = fixture {
        check(!marker.exists())
        val repository = runtime.repository
        val restored = repository.restoreSelection(repository.access.value.generation)
        check(restored.storeRef == null && runtime.live.available)
        val anchor = repository.beginOnlineRequest(restored.generation)
        // Existing isolated harness seed. Never passed to instrumentation or shell arguments.
        runtime.live.authenticate(anchor, SignInPurpose.ENROLL_OR_RECOVER, "submitter", "DemoMaintenance!2026").use {
            val activated = repository.activateOnline(anchor, it.context, it.lease, it.secrets)
            check(activated.ready)
        }
        val generation = repository.access.value.generation
        val draft = repository.createDraft(generation, uuid())
        val content = draft.content.copy(category = "WATER_SUPPLY", urgency = "ROUTINE", areaLabel = "Area A",
            siteLabel = "Synthetic fixture pump", reporterLabel = "Synthetic reporter",
            narrative = "Synthetic maintenance inspection requested.", assistanceRequested = "Inspection")
        val queued = repository.queueDraft(generation, uuid(), draft.id, draft.revision, 0, content)
        check(queued.delivery == DeliveryState.QUEUED)
        saveMarker(queued)
    }

    @Test fun droppedAcknowledgementKeepsImmutableQueue() = fixture {
        val generation = unlock()
        val before = outbox(generation)
        runtime.live.synchronize(generation)
        val after = outbox(generation)
        check(after.delivery != DeliveryState.RECEIVED && after.operationId == before.operationId && after.requestHash == before.requestHash)
    }

    @Test fun reconcileCommittedReceiptAndExactReplay() = fixture {
        val generation = unlock()
        val waiting = outbox(generation)
        val wait = ((waiting.nextAttemptElapsed ?: 0) - SystemClock.elapsedRealtime()).coerceAtLeast(0)
        check(wait <= 30_000) // First persisted attempt is bounded; no clock/lease bypass.
        delay(wait + 50)
        runtime.live.synchronize(generation)
        val row = outbox(generation)
        check(row.delivery == DeliveryState.RECEIVED)
        val snapshot = runtime.repository.snapshot(generation)
        val request = RequestPolicy.request(row.operationId, row.reportId, row.expectedRevision, row.content, snapshot.serverNowMillis)
        check(RequestPolicy.requestHash(request) == row.requestHash)
        val bytes = CanonicalJson.bytes(request)
        val anchor = runtime.repository.beginOnlineRequest(generation)
        // Explicit test-only exact replay; production never retries a RECEIVED row through its outbox.
        val replay = DeliveryClaim(generation, row.capture.account.storeRef, row.operationId, row.reportId, row.expectedRevision,
            row.requestHash, uuid(), uuid(), anchor.clock.bootId!!, anchor.clock.elapsedMillis + 120_000, bytes)
        bytes.fill(0)
        replay.use { claim ->
            container.storageForIntegration().foreground(generation).use { session ->
                session.credentials().use { secrets ->
                    val token = secrets.copyAccessToken()
                    try {
                        val receipt = container.services().protocol.send(claim, token)
                        check(receipt.operationId == row.operationId && receipt.reportId == row.reportId && receipt.revisionNo == 1)
                    } finally { token.fill(0) }
                }
            }
        }
        check(outbox(generation).delivery == DeliveryState.RECEIVED)
    }

    @Test fun refreshRotationKeepsEnrollmentAndReadsOwnReport() = fixture {
        val generation = unlock()
        val original = runtime.repository.snapshot(generation).context
        container.storageForIntegration().foreground(generation).use { session ->
            val anchor = session.beginOnlineRequest()
            session.credentials().use { old ->
                val token = old.copyRefreshToken()
                var completed = false
                try {
                    val attempt = session.beginRefresh(anchor)
                    container.services().protocol.refresh(token, original, anchor.clock).use { response ->
                        check(response.context.authority.capture.account == original.capture.account && response.context.authority.familyId == original.familyId)
                        session.completeRefresh(attempt, anchor, response.context.authority, response.context.lease, response.secrets)
                        completed = true
                    }
                } finally {
                    token.fill(0)
                    if (!completed) session.deny(StoreCode.AUTH_REQUIRED)
                }
            }
        }
        check(runtime.repository.access.value.generation == generation)
        val page = runtime.live.reports(generation, ReportFilterUi.ALL, 1)
        check(page.items.size == 1)
        check(outbox(generation).delivery == DeliveryState.RECEIVED)
    }

    @Test fun backgroundFenceAndAuthorizedRestart() = runBlocking(Dispatchers.IO) {
        withFixture {
            val generation = unlock()
            val closed = runtime.repository.invalidate(StoreCode.LOCKED)
            runtime.live.cancelForFence(generation, StoreCode.LOCKED)
            runtime.repository.fence(StoreCode.LOCKED, closed.generation)
            check(!runtime.repository.access.value.ready)
            try { runtime.repository.snapshot(generation); error("Expected stale generation") }
            catch (failure: StoreFailure) { check(failure.code == StoreCode.STALE_GENERATION) }
        }
        val ref = withFixture {
            val generation = unlock()
            check(outbox(generation).delivery == DeliveryState.RECEIVED)
            runtime.repository.access.value.storeRef!!
        }
        // Test-owned containers released the same real owner before the Application worker opens it.
        val queue = AndroidWorkQueue(context)
        val epoch = ScheduleEpoch(uuid())
        try {
            queue.enqueue(epoch, ref, 0, false)
            withTimeout(60_000) {
                while (true) {
                    val infos = WorkManager.getInstance(context).getWorkInfosForUniqueWork("kapit.sync.${epoch.chainRef}").get(10, TimeUnit.SECONDS)
                    if (infos.isNotEmpty() && infos.all { it.state.isFinished }) {
                        check(infos.single().outputData.getString("outcome") == "completed")
                        break
                    }
                    delay(100)
                }
            }
        } finally {
            queue.cancel(epoch)
            (context as KapitApplication).container.close()
        }
    }

    /** Separate host checkpoint: this new immutable row must still be absent from the server. */
    @Test fun queuePendingBackgroundReport() = runBlocking<Unit>(Dispatchers.IO) {
        check(File(context.noBackupFilesDir, "m2-credential-phase").isFile)
        check(!backgroundMarker.exists())
        // The preceding real Activity may have handed off a no-op worker on final release.
        // Wait for this owned fixture installation's prior mobile work; do not cancel unknown chains.
        withTimeout(30_000) {
            while (WorkManager.getInstance(context).getWorkInfosByTag(MobileSyncWorker::class.java.name)
                    .get(10, TimeUnit.SECONDS).any { !it.state.isFinished }) delay(100)
        }
        (context as KapitApplication).container.close()
        withFixture {
            val generation = unlock()
            check(outbox(generation).delivery == DeliveryState.RECEIVED)
            val repository = runtime.repository
            val draft = repository.createDraft(generation, uuid())
            val content = draft.content.copy(category = "WATER_SUPPLY", urgency = "ROUTINE", areaLabel = "Area B",
                siteLabel = "Synthetic background pump", reporterLabel = "Synthetic reporter",
                narrative = "Synthetic background maintenance inspection requested.", assistanceRequested = "Inspection")
            val queued = repository.queueDraft(generation, uuid(), draft.id, draft.revision, 0, content)
            check(queued.delivery == DeliveryState.QUEUED && queued.attempts == 0 && queued.pause == null)
            val snapshot = repository.snapshot(generation)
            check(snapshot.outbox.size == 2)
            val request = RequestPolicy.request(queued.operationId, queued.reportId, queued.expectedRevision, queued.content, snapshot.serverNowMillis)
            check(RequestPolicy.requestHash(request) == queued.requestHash)
            writeBackgroundMarker(queued)
            val closed = repository.invalidate(StoreCode.LOCKED)
            runtime.live.cancelForFence(generation, StoreCode.LOCKED)
            repository.fence(StoreCode.LOCKED, closed.generation)
            check(!repository.access.value.ready && repository.access.value.reason == StoreCode.LOCKED)
            try { repository.snapshot(generation); error("Expected fenced foreground") }
            catch (failure: StoreFailure) { check(failure.code == StoreCode.STALE_GENERATION) }
        }
    }

    /** Actual pending-row delivery runs only through the Application's production worker/runtime. */
    @Test fun deliverPendingWithActualWorker() = runBlocking<Unit>(Dispatchers.IO) {
        val expected = readBackgroundMarker()
        val original = readMarker()
        check(expected[0] != original[0] && expected[1] != original[1])
        val container = (context as KapitApplication).container
        val queue = AndroidWorkQueue(context)
        val epoch = ScheduleEpoch(uuid())
        var observation: Job? = null
        var reopened: MobileRuntime? = null
        try {
            val repository = container.storageForIntegration().repository
            val selected = repository.restoreSelection(repository.access.value.generation)
            check(!selected.ready && selected.reason in setOf(StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED))
            val ref = checkNotNull(selected.storeRef)
            val observedReady = AtomicBoolean(false)
            val observer = launch(start = CoroutineStart.UNDISPATCHED) {
                repository.access.collect { if (it.ready) observedReady.set(true) }
            }
            observation = observer
            queue.enqueue(epoch, ref, 0, false)
            withTimeout(60_000) {
                while (true) {
                    val infos = WorkManager.getInstance(context).getWorkInfosForUniqueWork("kapit.sync.${epoch.chainRef}")
                        .get(10, TimeUnit.SECONDS)
                    if (infos.isNotEmpty() && infos.all { it.state.isFinished }) {
                        check(infos.single().state == WorkInfo.State.SUCCEEDED)
                        check(infos.single().outputData.getString("outcome") == "completed")
                        break
                    }
                    delay(100)
                }
            }
            check(!observedReady.get() && !repository.access.value.ready)
            try { repository.snapshot(repository.access.value.generation); error("Worker enabled public access") }
            catch (failure: StoreFailure) { check(failure.code in setOf(StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED)) }
            observer.cancelAndJoin()
            observation = null

            // Only after worker completion may a fresh authorized foreground unwrap inspect receipt state.
            val runtime = container.createMobileRuntime().also { reopened = it }
            val restored = runtime.repository.restoreSelection(runtime.repository.access.value.generation)
            val generation = runtime.repository.unlock(restored.generation).also { check(it.ready) }.generation
            val snapshot = runtime.repository.snapshot(generation)
            check(snapshot.outbox.size == 2 && snapshot.outbox.all { it.delivery == DeliveryState.RECEIVED })
            val previous = snapshot.outbox.single { it.operationId == original[0] }
            check(previous.reportId == original[1] && previous.requestHash == original[2])
            val delivered = snapshot.outbox.single { it.operationId == expected[0] }
            check(delivered.reportId == expected[1] && delivered.requestHash == expected[2] && delivered.attempts == 1)
            val request = RequestPolicy.request(delivered.operationId, delivered.reportId, delivered.expectedRevision,
                delivered.content, snapshot.serverNowMillis)
            check(RequestPolicy.requestHash(request) == expected[2])
            val localBytes = CanonicalJson.bytes(request)
            try {
                container.storageForIntegration().foreground(generation).use { session ->
                    val anchor = session.beginOnlineRequest()
                    val lookup = DeliveryClaim(generation, ref, delivered.operationId, delivered.reportId, delivered.expectedRevision,
                        delivered.requestHash, uuid(), uuid(), anchor.clock.bootId!!, anchor.clock.elapsedMillis + 120_000, localBytes)
                    lookup.use { claim ->
                        session.credentials().use { secrets ->
                            val token = secrets.copyAccessToken()
                            try {
                                val protocol = container.services().protocol
                                // Reads only: foreground code cannot create the effect under test.
                                val receipt = protocol.receipt(claim, token)
                                val revision = protocol.revision(token, delivered.reportId, receipt.revisionNo)
                                check(receipt.operationId == expected[0] && receipt.reportId == expected[1] && receipt.revisionNo == 1)
                                check(revision.receipt.operationId == receipt.operationId && revision.receipt.reportId == receipt.reportId &&
                                    revision.receipt.revisionId == receipt.revisionId && revision.receipt.revision == receipt.revisionNo)
                                val serverRequest = RequestPolicy.request(delivered.operationId, delivered.reportId, delivered.expectedRevision,
                                    revision.payload, session.serverTimeLowerMillis())
                                check(RequestPolicy.requestHash(serverRequest) == expected[2])
                                val serverBytes = CanonicalJson.bytes(serverRequest)
                                try { check(localBytes.contentEquals(serverBytes)) } finally { serverBytes.fill(0) }
                            } finally { token.fill(0) }
                        }
                    }
                }
            } finally { localBytes.fill(0) }
        } finally {
            withContext(NonCancellable) {
                observation?.cancelAndJoin()
                try { queue.cancel(epoch) }
                finally { try { reopened?.close() } finally { container.close() } }
            }
        }
    }

    private val backgroundMarker get() = File(context.noBackupFilesDir, "m2-background-phase")
    private fun writeBackgroundMarker(row: OutboxRecord) {
        val bytes = "${row.operationId}|${row.reportId}|${row.requestHash}".toByteArray(Charsets.US_ASCII)
        check(bytes.size == 138)
        val file = AtomicFile(backgroundMarker)
        val stream = file.startWrite()
        try { stream.write(bytes); file.finishWrite(stream) } catch (failure: Exception) { file.failWrite(stream); throw failure }
    }
    private fun readBackgroundMarker(): List<String> {
        check(backgroundMarker.length() == 138L)
        val bytes = AtomicFile(backgroundMarker).readFully()
        check(bytes.size == 138)
        return bytes.toString(Charsets.US_ASCII).split('|').also {
            check(it.size == 3 && UUID.fromString(it[0]).toString() == it[0] && UUID.fromString(it[1]).toString() == it[1] && Regex("[0-9a-f]{64}").matches(it[2]))
        }
    }

    private fun fixture(block: suspend Fixture.() -> Unit) = runBlocking(Dispatchers.IO) { withFixture(block) }
    private suspend fun <T> withFixture(block: suspend Fixture.() -> T): T {
        val container = AppContainer(context, workQueue = PausedFixtureQueue)
        val runtime = container.createMobileRuntime()
        try { return Fixture(container, runtime).block() }
        finally { try { runtime.close() } finally { container.close() } }
    }
    private inner class Fixture(val container: AppContainer, val runtime: MobileRuntime) {
        fun unlock(): Long {
            val repository = runtime.repository
            val restored = repository.restoreSelection(repository.access.value.generation)
            check(restored.storeRef != null && !restored.ready)
            return repository.unlock(restored.generation).also { check(it.ready) }.generation
        }
        fun outbox(generation: Long): OutboxRecord {
            val expected = readMarker()
            return runtime.repository.snapshot(generation).outbox.single().also {
                check(it.operationId == expected[0] && it.reportId == expected[1] && it.requestHash == expected[2])
            }
        }
    }
    private fun saveMarker(row: OutboxRecord) {
        val bytes = "${row.operationId}|${row.reportId}|${row.requestHash}".toByteArray(Charsets.US_ASCII)
        val file = AtomicFile(marker)
        val stream = file.startWrite()
        try { stream.write(bytes); file.finishWrite(stream) } catch (failure: Exception) { file.failWrite(stream); throw failure }
    }
    private fun readMarker(): List<String> {
        val bytes = AtomicFile(marker).readFully()
        check(bytes.size == 138)
        return bytes.toString(Charsets.US_ASCII).split('|').also {
            check(it.size == 3 && UUID.fromString(it[0]).toString() == it[0] && UUID.fromString(it[1]).toString() == it[1] && Regex("[0-9a-f]{64}").matches(it[2]))
        }
    }
    private fun uuid() = UUID.randomUUID().toString()
    /** Suppresses only scheduling until host changes fault phase; network and storage remain real. */
    private object PausedFixtureQueue : WorkQueue {
        override suspend fun enqueue(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long, continuation: Boolean) = Unit
        override suspend fun cancel(epoch: ScheduleEpoch) = Unit
        override suspend fun isRunning(epoch: ScheduleEpoch) = false
        override suspend fun coalesceRerun(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long) = Unit
    }
}

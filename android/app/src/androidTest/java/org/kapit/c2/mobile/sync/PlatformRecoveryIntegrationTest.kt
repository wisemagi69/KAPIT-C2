package org.kapit.c2.mobile.sync

import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.util.AtomicFile
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkInfo
import androidx.work.WorkManager
import java.io.File
import java.security.MessageDigest
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import kotlinx.serialization.json.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.kapit.c2.mobile.KapitApplication
import org.kapit.c2.mobile.data.local.AndroidProtectedRepository
import org.kapit.c2.mobile.data.local.ProtectedDatabase
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.security.AndroidAccessEnvironment

/**
 * PROPOSED ONLY: .pending is deliberately excluded from Kotlin source inputs.
 * Host ownership, interruption and independent launcher/UI driver are not implemented here.
 * Preparation MUST be interrupted after its ready marker; a normal JUnit pass is impossible.
 * Verification runs only AFTER the host-launched, unmodified app delivered the server effect.
 * Starting target instrumentation is a further process transition, never an Activity attachment.
 */
@RunWith(AndroidJUnit4::class)
class PlatformRecoveryIntegrationTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val container get() = (context.applicationContext as KapitApplication).container
    private val manager get() = WorkManager.getInstance(context)

    private enum class Case(val namePart: String, val priorRows: Int, val priorDrafts: Int) {
        ABRUPT("abrupt", 2, 0), FORCE_STOP("stop", 3, 1),
    }

    @Before fun ownedEmulatorOnly() {
        check(Build.VERSION.SDK_INT >= 35 && context.packageName.endsWith(".spike"))
        check(InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        check(File(context.noBackupFilesDir, "m2-background-phase").isFile)
    }

    @Test fun commitBeforeSchedulingAndAwaitAbruptDeath() = runBlocking<Unit>(Dispatchers.IO) {
        prepare(Case.ABRUPT)
    }

    @Test fun verifyAfterUserRelaunchFromAbruptDeath() = runBlocking<Unit>(Dispatchers.IO) {
        verify(Case.ABRUPT)
    }

    @Test fun queueDelayedWorkerAndAwaitForceStop() = runBlocking<Unit>(Dispatchers.IO) {
        check(readPhase(Case.ABRUPT) == "verified")
        prepare(Case.FORCE_STOP)
    }

    @Test fun verifyAfterUserRelaunchFromForceStop() = runBlocking<Unit>(Dispatchers.IO) {
        verify(Case.FORCE_STOP)
    }

    private suspend fun prepare(case: Case) {
        check(!checkpointFile(case).exists() && !phaseFile(case).exists())
        var ownEpoch: ScheduleEpoch? = null
        try {
            phase(case, "preparing")
            // Wait for preceding fixture work; never cancel another fixture's chain.
            withTimeout(30_000) { while (workerInfos().any { !it.state.isFinished }) delay(100) }
            val beforeWorkers = workerInfos().map { it.id.toString() }.sorted()
            check(beforeWorkers.size <= 64)
            val repository = container.storageForIntegration().repository
            val restored = repository.restoreSelection(repository.access.value.generation)
            check(!restored.ready && restored.storeRef != null)
            val generation = repository.unlock(restored.generation).also { check(it.ready) }.generation
            val beforeEvidence = readPersisted(repository, generation)
            val before = beforeEvidence.snapshot
            check(before.outbox.size == case.priorRows && before.outbox.all { it.delivery == DeliveryState.RECEIVED })
            check(before.drafts.size == case.priorDrafts)

            val editable = repository.createDraft(generation, uuid())
            val retained = repository.saveDraft(generation, uuid(), editable.id, editable.revision,
                editable.content.copy(siteLabel = "Synthetic retained maintenance draft",
                    narrative = "Synthetic draft remains editable across process recovery."))
            val submission = repository.createDraft(generation, uuid())
            val queued = repository.queueDraft(generation, uuid(), submission.id, submission.revision, 0,
                submission.content.copy(category = "WATER_SUPPLY", urgency = "ROUTINE", areaLabel = "Area A",
                    siteLabel = "Synthetic recovery fixture pump", reporterLabel = "Synthetic reporter",
                    narrative = "Synthetic maintenance request retained across process recovery.", assistanceRequested = "Inspection"))

            // Actual SQLCipher transaction is complete. Calling beneath the runtime notification
            // deliberately arranges the commit-before-scheduling gap; no production hook exists.
            val committedEvidence = readPersisted(repository, generation)
            val committed = committedEvidence.snapshot
            check(committed.drafts.single { it.id == retained.id } == retained)
            check(committed.drafts.size == before.drafts.size + 1)
            val row = committed.outbox.single { it.operationId == queued.operationId }
            check(row == queued && row.delivery == DeliveryState.QUEUED && row.attempts == 0 && row.pause == null)
            check(committed.outbox.size == before.outbox.size + 1)
            check(draftsHash(committed.drafts.filter { it.id != retained.id }) == draftsHash(before.drafts))
            check(submissionsHash(committedEvidence.submissions.filterKeys { it != row.operationId }) == submissionsHash(beforeEvidence.submissions))
            check(receiptsHash(committedEvidence.receipts.values) == receiptsHash(beforeEvidence.receipts.values))
            check(workerInfos().none { !it.state.isFinished })
            val request = request(row, committed.serverNowMillis)
            check(RequestPolicy.requestHash(request) == row.requestHash)
            val boot = bootHash()

            if (case == Case.FORCE_STOP) {
                ownEpoch = ScheduleEpoch(uuid())
                val enqueueStart = SystemClock.elapsedRealtime()
                AndroidWorkQueue(context).enqueue(ownEpoch, restored.storeRef!!, STOP_DELAY_MILLIS, false)
                val pending = manager.getWorkInfosForUniqueWork("kapit.sync.${ownEpoch.chainRef}")
                    .get(10, TimeUnit.SECONDS).single()
                check(pending.state == WorkInfo.State.ENQUEUED && pending.runAttemptCount == 0)
                check(SystemClock.elapsedRealtime() - enqueueStart in 0..5_000)
                // Host kills before 40-second eligibility, then observes through it while STOPPED.
            }
            val checkpoint = Checkpoint(case, restored.storeRef!!, retained.id, retained.revision,
                draftHash(retained), row.operationId, row.reportId, row.requestHash,
                CanonicalJson.sha256(request), submissionsHash(beforeEvidence.submissions),
                draftsHash(before.drafts), boot, SystemClock.elapsedRealtime(), ownEpoch?.chainRef, beforeWorkers,
                committedEvidence.submissions.getValue(row.operationId), receiptsHash(beforeEvidence.receipts.values))
            writeCheckpoint(checkpoint)
            val lastEvidence = readPersisted(repository, generation)
            val last = lastEvidence.snapshot
            check(last.drafts.single { it.id == retained.id } == retained)
            check(lastEvidence.submissions == committedEvidence.submissions)
            check(receiptsHash(lastEvidence.receipts.values) == checkpoint.priorReceiptHash)
            check(last.outbox.single { it.operationId == row.operationId }.let {
                it.delivery == DeliveryState.QUEUED && it.attempts == 0 && it.requestHash == checkpoint.requestHash
            })
            val active = workerInfos().filter { !it.state.isFinished }
            if (ownEpoch == null) check(active.isEmpty())
            else {
                val owned = manager.getWorkInfosForUniqueWork("kapit.sync.${ownEpoch.chainRef}").get(10, TimeUnit.SECONDS).single()
                check(active.size == 1 && active.single().id == owned.id && owned.state == WorkInfo.State.ENQUEUED)
            }
            phase(case, if (case == Case.ABRUPT) "abrupt_ready" else "force_stop_ready")
            // Host must verify exact owned PID/UID/start identity and terminate within ten seconds.
            // Timeout/ordinary return is failure. A real abrupt kill cannot execute this finally.
            withTimeout(20_000) { awaitCancellation() }
        } catch (failure: Throwable) {
            phase(case, "failed")
            throw failure
        } finally {
            withContext(NonCancellable) {
                try { ownEpoch?.let { AndroidWorkQueue(context).cancel(it) } }
                finally { container.close() }
            }
        }
    }

    private suspend fun verify(case: Case) {
        val checkpoint = readCheckpoint(case)
        check(readPhase(case) == if (case == Case.ABRUPT) "abrupt_ready" else "force_stop_ready")
        check(bootHash() == checkpoint.bootHash && SystemClock.elapsedRealtime() >= checkpoint.readyElapsed)
        try {
            // Host already observed the new server effect from the real launcher/credential path.
            // Before any protected unwrap here, require completed persisted normal work. This test
            // contains no Activity launch, runtime facade, enqueue, sync, refresh or source POST.
            val work = workerInfos()
            check(work.none { !it.state.isFinished })
            check(work.any { it.id.toString() !in checkpoint.priorWorkers && it.state == WorkInfo.State.SUCCEEDED &&
                it.outputData.getString("outcome") == "completed" })
            val repository = container.storageForIntegration().repository
            val selected = repository.restoreSelection(repository.access.value.generation)
            check(!selected.ready && selected.storeRef == checkpoint.storeRef)
            val generation = repository.unlock(selected.generation).also { check(it.ready) }.generation
            val persisted = readPersisted(repository, generation)
            val snapshot = persisted.snapshot
            check(snapshot.outbox.size == case.priorRows + 1 && snapshot.outbox.all { it.delivery == DeliveryState.RECEIVED })
            check(snapshot.drafts.size == case.priorDrafts + 1)
            val retained = snapshot.drafts.single { it.id == checkpoint.draftId }
            check(retained.revision == checkpoint.draftRevision && draftHash(retained) == checkpoint.draftHash)
            check(draftsHash(snapshot.drafts.filter { it.id != checkpoint.draftId }) == checkpoint.priorDraftHash)
            check(submissionsHash(persisted.submissions.filterKeys { it != checkpoint.operationId }) == checkpoint.priorOutboxHash)
            check(persisted.submissions.getValue(checkpoint.operationId) == checkpoint.submissionHash)
            check(receiptsHash(persisted.receipts.filterKeys { it != checkpoint.operationId }.values) == checkpoint.priorReceiptHash)
            val localReceipt = persisted.receipts.getValue(checkpoint.operationId)
            val row = snapshot.outbox.single { it.operationId == checkpoint.operationId }
            check(row.reportId == checkpoint.reportId && row.requestHash == checkpoint.requestHash && row.expectedRevision == 0)
            val request = request(row, snapshot.serverNowMillis)
            check(RequestPolicy.requestHash(request) == checkpoint.requestHash && CanonicalJson.sha256(request) == checkpoint.bodyHash)
            val originalBytes = CanonicalJson.bytes(request)
            try {
                container.storageForIntegration().foreground(generation).use { session ->
                    val anchor = session.beginOnlineRequest()
                    DeliveryClaim(generation, checkpoint.storeRef, row.operationId, row.reportId, row.expectedRevision,
                        row.requestHash, uuid(), uuid(), anchor.clock.bootId!!, anchor.clock.elapsedMillis + 120_000,
                        originalBytes).use { lookup ->
                        session.credentials().use { secrets ->
                            val token = secrets.copyAccessToken()
                            try {
                                val protocol = container.services().protocol
                                val receipt = protocol.receipt(lookup, token)
                                val revision = protocol.revision(token, row.reportId, receipt.revisionNo)
                                check(receipt.operationId == checkpoint.operationId && receipt.reportId == checkpoint.reportId && receipt.revisionNo == 1)
                                check(localReceipt.operationId == receipt.operationId && localReceipt.reportId == receipt.reportId &&
                                    localReceipt.revisionId == receipt.revisionId && localReceipt.revisionNo == receipt.revisionNo)
                                check(revision.receipt.operationId == receipt.operationId && revision.receipt.reportId == receipt.reportId &&
                                    revision.receipt.revisionId == receipt.revisionId && revision.receipt.revision == 1)
                                val serverRequest = RequestPolicy.request(row.operationId, row.reportId, row.expectedRevision,
                                    revision.payload, session.serverTimeLowerMillis())
                                check(RequestPolicy.requestHash(serverRequest) == checkpoint.requestHash)
                                val serverBytes = CanonicalJson.bytes(serverRequest)
                                try { check(originalBytes.contentEquals(serverBytes)) } finally { serverBytes.fill(0) }
                            } finally { token.fill(0) }
                        }
                    }
                }
            } finally { originalBytes.fill(0) }
            phase(case, "verified")
        } catch (failure: Throwable) {
            phase(case, "failed")
            throw failure
        } finally {
            withContext(NonCancellable) {
                try { checkpoint.chainRef?.let { AndroidWorkQueue(context).cancel(ScheduleEpoch(it)) } }
                finally { container.close() }
            }
        }
    }

    private fun workerInfos(): List<WorkInfo> = manager.getWorkInfosByTag(MobileSyncWorker::class.java.name)
        .get(10, TimeUnit.SECONDS).also { check(it.size <= 64) }
    private fun request(row: OutboxRecord, now: Long) = RequestPolicy.request(row.operationId, row.reportId,
        row.expectedRevision, row.content, now)
    private fun contentHash(content: MaintenanceContent) = CanonicalJson.sha256(RequestPolicy.payload(content))
    private fun capture(value: CaptureContext) = buildJsonObject {
        put("organization", value.account.organizationId); put("user", value.account.userId)
        put("enrollment", value.account.enrollmentId); put("unit", value.unitId); put("channel", value.channelId)
        put("profile", value.profile); put("template", value.templateVersion)
    }
    private fun draftMetadata(row: DraftRecord) = buildJsonObject {
        put("id", row.id); put("revision", row.revision); put("content", contentHash(row.content))
        put("report", row.reportId); put("expected_report_revision", row.expectedReportRevision)
        put("predecessor", row.predecessorOperationId); put("capture", capture(row.capture)); put("saved_at", row.savedAtServerMillis)
    }
    private fun draftHash(row: DraftRecord) = CanonicalJson.sha256(draftMetadata(row))
    private fun draftsHash(rows: List<DraftRecord>) = CanonicalJson.sha256(JsonArray(rows.sortedBy { it.id }.map(::draftMetadata)))
    private fun submissionsHash(rows: Map<String, String>) = CanonicalJson.sha256(buildJsonObject {
        rows.forEach { (operation, hash) -> put(operation, hash) }
    })
    private class LocalReceipt(val operationId: String, val reportId: String, val revisionId: String, val revisionNo: Int) {
        fun metadata() = buildJsonObject {
            put("operation", operationId); put("report", reportId); put("revision_id", revisionId); put("revision_no", revisionNo)
        }
        override fun toString() = "LocalReceipt(opaque)"
    }
    private fun receiptsHash(rows: Collection<LocalReceipt>) = CanonicalJson.sha256(JsonArray(rows.sortedBy { it.operationId }.map { it.metadata() }))
    private class PersistedEvidence(val snapshot: LocalSnapshot, val submissions: Map<String, String>, val receipts: Map<String, LocalReceipt>) {
        override fun toString() = "PersistedEvidence(redacted)"
    }

    /**
     * Test-only inspection of the ALREADY legitimately opened handle. This helper cannot open a
     * DB, unwrap a key, create authority, modify rows or make a fenced repository readable.
     * Reflection stays in this ignored fixture; no production accessor or alternate owner exists.
     */
    private fun readPersisted(repository: ProtectedRepository, generation: Long): PersistedEvidence {
        check(repository is AndroidProtectedRepository)
        val type = AndroidProtectedRepository::class.java
        fun field(name: String): Any = checkNotNull(type.getDeclaredField(name).apply { isAccessible = true }.get(repository))
        // Match the real owner's lock order and revalidate the public protected read on both sides.
        return synchronized(field("ioLock")) {
            synchronized(field("commitFence")) {
                val snapshot = repository.snapshot(generation)
                check(snapshot.outbox.size in 1..4 && snapshot.drafts.size in 0..2)
                check(repository.access.value.let { it.ready && it.generation == generation && it.storeRef == snapshot.context.capture.account.storeRef })
                val active = field("active")
                val database = active.javaClass.getDeclaredField("database").apply { isAccessible = true }.get(active) as ProtectedDatabase
                check(database.isOpen)
                val dao = database.dao()
                val submissions = linkedMapOf<String, String>()
                val receipts = linkedMapOf<String, LocalReceipt>()
                snapshot.outbox.forEach { row ->
                    val stored = checkNotNull(dao.submitted(row.operationId))
                    val canonical = request(row, snapshot.serverNowMillis)
                    val canonicalBytes = CanonicalJson.bytes(canonical)
                    try {
                        check(stored.operationId == row.operationId && stored.reportId == row.reportId && stored.expectedRevision == row.expectedRevision)
                        check(stored.requestHash == row.requestHash && RequestPolicy.requestHash(canonical) == stored.requestHash)
                        check(stored.queuedAtServerMillis == row.queuedAtServerMillis && stored.predecessorOperation == row.predecessorOperationId)
                        check(stored.requestBytes.contentEquals(canonicalBytes))
                        // Include every immutable SubmittedRow field. Mutable delivery, attempts,
                        // claims and retry deadlines are deliberately asserted separately.
                        submissions[row.operationId] = CanonicalJson.sha256(buildJsonObject {
                            put("operation", stored.operationId); put("report", stored.reportId); put("expected_revision", stored.expectedRevision)
                            put("request_hash", stored.requestHash); put("request_bytes", bytesHash(stored.requestBytes))
                            put("content_json", stored.contentJson); put("capture_json", stored.captureJson)
                            put("content", contentHash(row.content)); put("capture", capture(row.capture))
                            put("queued_at", stored.queuedAtServerMillis); put("predecessor", stored.predecessorOperation)
                        })
                    } finally { canonicalBytes.fill(0); stored.requestBytes.fill(0) }
                    val receipt = dao.receipt(row.operationId)
                    if (row.delivery == DeliveryState.RECEIVED) {
                        checkNotNull(receipt)
                        check(receipt.operationId == row.operationId && receipt.reportId == row.reportId && receipt.revisionNo == row.expectedRevision + 1)
                        check(UUID.fromString(receipt.revisionId).toString() == receipt.revisionId)
                        receipts[row.operationId] = LocalReceipt(receipt.operationId, receipt.reportId, receipt.revisionId, receipt.revisionNo)
                    } else check(receipt == null)
                }
                // A matching queried tuple must not conceal extra unrelated or orphan receipt rows.
                database.query("SELECT COUNT(*) FROM receipts", emptyArray()).use { cursor ->
                    check(cursor.moveToFirst() && cursor.getLong(0) == receipts.size.toLong())
                }
                val after = repository.snapshot(generation)
                check(after.context == snapshot.context && after.drafts == snapshot.drafts && after.outbox == snapshot.outbox)
                PersistedEvidence(snapshot, submissions, receipts)
            }
        }
    }

    private fun bytesHash(bytes: ByteArray) = MessageDigest.getInstance("SHA-256").digest(bytes)
        .joinToString("") { "%02x".format(it.toInt() and 255) }
    private fun bootHash(): String {
        val boot = requireNotNull(AndroidAccessEnvironment(context).clock().bootId)
        return bytesHash(boot.toByteArray(Charsets.US_ASCII))
    }

    /** Fixed bounded opaque evidence only; never report content, identity labels or credentials. */
    private class Checkpoint(val case: Case, val storeRef: String, val draftId: String, val draftRevision: Long,
        val draftHash: String, val operationId: String, val reportId: String, val requestHash: String,
        val bodyHash: String, val priorOutboxHash: String, val priorDraftHash: String, val bootHash: String,
        val readyElapsed: Long, val chainRef: String?, val priorWorkers: List<String>, val submissionHash: String,
        val priorReceiptHash: String) {
        override fun toString() = "PlatformCheckpoint(opaque)"
        fun encode() = listOf("2", case.namePart, storeRef, draftId, draftRevision.toString(), draftHash,
            operationId, reportId, requestHash, bodyHash, priorOutboxHash, priorDraftHash, bootHash,
            readyElapsed.toString(), chainRef ?: "none", priorWorkers.joinToString(","), submissionHash, priorReceiptHash).joinToString("|")
    }
    private fun checkpointFile(case: Case) = File(context.noBackupFilesDir, "m2-platform-${case.namePart}.checkpoint")
    private fun phaseFile(case: Case) = File(context.noBackupFilesDir, "m2-platform-${case.namePart}.phase")
    private fun writeCheckpoint(value: Checkpoint) {
        val bytes = value.encode().toByteArray(Charsets.US_ASCII)
        check(bytes.size in 1..4096)
        writeAtomic(checkpointFile(value.case), bytes)
        check(readCheckpoint(value.case).encode() == value.encode())
    }
    private fun readCheckpoint(case: Case): Checkpoint {
        val file = checkpointFile(case)
        check(file.length() in 1..4096)
        val bytes = AtomicFile(file).readFully()
        check(bytes.size in 1..4096)
        val values = bytes.toString(Charsets.US_ASCII).split('|')
        check(values.size == 18 && values[0] == "2" && values[1] == case.namePart)
        listOf(2, 5, 8, 9, 10, 11, 12, 16, 17).forEach { check(Regex("[0-9a-f]{64}").matches(values[it])) }
        listOf(3, 6, 7).forEach { check(UUID.fromString(values[it]).toString() == values[it]) }
        val revision = values[4].toLong().also { check(it > 0 && it.toString() == values[4]) }
        val elapsed = values[13].toLong().also { check(it >= 0 && it.toString() == values[13]) }
        val chain = values[14].takeUnless { it == "none" }?.also { check(UUID.fromString(it).toString() == it) }
        check((case == Case.FORCE_STOP) == (chain != null))
        val workers = if (values[15].isEmpty()) emptyList() else values[15].split(',')
        check(workers.size <= 64 && workers.distinct().sorted() == workers)
        workers.forEach { check(UUID.fromString(it).toString() == it) }
        return Checkpoint(case, values[2], values[3], revision, values[5], values[6], values[7], values[8],
            values[9], values[10], values[11], values[12], elapsed, chain, workers, values[16], values[17])
    }
    private fun phase(case: Case, value: String) {
        check(value in setOf("preparing", "abrupt_ready", "force_stop_ready", "verified", "failed"))
        writeAtomic(phaseFile(case), value.toByteArray(Charsets.US_ASCII))
    }
    private fun readPhase(case: Case): String {
        check(phaseFile(case).length() in 1..32)
        val bytes = AtomicFile(phaseFile(case)).readFully()
        check(bytes.size in 1..32)
        return bytes.toString(Charsets.US_ASCII)
    }
    private fun writeAtomic(path: File, bytes: ByteArray) {
        val file = AtomicFile(path)
        val stream = file.startWrite()
        try { stream.write(bytes); stream.fd.sync(); file.finishWrite(stream) }
        catch (failure: Exception) { file.failWrite(stream); throw failure }
    }
    private fun uuid() = UUID.randomUUID().toString()
    private companion object { const val STOP_DELAY_MILLIS = 40_000L }
}

package org.kapit.c2.mobile.sync

import android.content.Context
import android.os.Build
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import androidx.work.WorkInfo
import androidx.work.WorkManager
import androidx.work.Configuration
import androidx.work.CoroutineWorker
import androidx.work.ExistingWorkPolicy
import androidx.work.ListenableWorker
import androidx.work.OneTimeWorkRequestBuilder
import androidx.work.WorkerFactory
import androidx.work.WorkerParameters
import androidx.work.workDataOf
import androidx.work.Data
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith

/** Actual WorkManager graph behavior; delayed work never opens protected storage in these tests. */
@RunWith(AndroidJUnit4::class)
class AndroidSchedulingIntegrationTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val ref = "a".repeat(64)
    @Before fun ownedEmulatorOnly() {
        check(Build.VERSION.SDK_INT >= 35 && context.packageName.endsWith(".spike"))
        check(InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
    }
    @Test fun oldChainCancellationCannotCancelReplacementChain() = runBlocking(Dispatchers.IO) {
        val queue = AndroidWorkQueue(context)
        val old = ScheduleEpoch(UUID.randomUUID().toString())
        val next = ScheduleEpoch(UUID.randomUUID().toString())
        try {
            queue.enqueue(old, ref, 86_400_000, false)
            queue.enqueue(next, ref, 86_400_000, false)
            queue.cancel(old)
            check(infos(old).all { it.state == WorkInfo.State.CANCELLED })
            check(infos(next).single().state == WorkInfo.State.ENQUEUED)
        } finally { queue.cancel(old); queue.cancel(next) }
    }
    @Test fun cancelledParentCannotResurrectThroughContinuation() = runBlocking(Dispatchers.IO) {
        val queue = AndroidWorkQueue(context)
        val epoch = ScheduleEpoch(UUID.randomUUID().toString())
        try {
            queue.enqueue(epoch, ref, 86_400_000, false)
            queue.cancel(epoch)
            queue.enqueue(epoch, ref, 86_400_000, true)
            val states = infos(epoch)
            check(states.size >= 2 && states.all { it.state == WorkInfo.State.CANCELLED })
        } finally { queue.cancel(epoch) }
    }
    @Test fun earlierOwnedWakeupReplacesDelayedKeepRequest() = runBlocking(Dispatchers.IO) {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
        val queue = AndroidWorkQueue(context)
        val scheduler = OwnedScheduler(queue, scope, android.os.SystemClock::elapsedRealtime)
        val old = scheduler.capture()
        var next: ScheduleEpoch? = null
        try {
            scheduler.schedule(old, ref, 86_400_000)
            next = scheduler.schedule(old, ref, 600_000)!!
            check(next.chainRef != old.chainRef)
            check(infos(old).all { it.state == WorkInfo.State.CANCELLED })
            check(infos(next).single().state == WorkInfo.State.ENQUEUED)
        } finally { queue.cancel(old); next?.let { queue.cancel(it) }; scope.cancel() }
    }

    /** Invoke this method alone in a fresh instrumentation process; singleton configuration is test-only. */
    @Test fun coalescedRerunPreservesRunningParentAndUpdatesBlockedSuccessor() = runBlocking(Dispatchers.IO) {
        requireIsolatedMethod("coalescedRerunPreservesRunningParentAndUpdatesBlockedSuccessor")
        val parentStarted = CompletableDeferred<Unit>()
        val parentCancelled = CompletableDeferred<Unit>()
        val factory = object : WorkerFactory() {
            override fun createWorker(appContext: Context, workerClassName: String, workerParameters: WorkerParameters): ListenableWorker? =
                if (workerClassName == ControlledGraphWorker::class.java.name)
                    ControlledGraphWorker(appContext, workerParameters) {
                        parentStarted.complete(Unit)
                        try { awaitCancellation() } finally { parentCancelled.complete(Unit) }
                    }
                else MobileWorkerFactory().createWorker(appContext, workerClassName, workerParameters)
        }
        WorkManager.initialize(context, Configuration.Builder().setWorkerFactory(factory)
            .setMinimumLoggingLevel(android.util.Log.ERROR).build())
        val manager = WorkManager.getInstance(context)
        val queue = AndroidWorkQueue(context)
        val epoch = ScheduleEpoch(UUID.randomUUID().toString())
        val parent = OneTimeWorkRequestBuilder<ControlledGraphWorker>().build()
        try {
            manager.enqueueUniqueWork("kapit.sync.${epoch.chainRef}", ExistingWorkPolicy.KEEP, parent).result.get(30, TimeUnit.SECONDS)
            withTimeout(30_000) { parentStarted.await() }
            awaitGraph(epoch) { it.singleOrNull { info -> info.id == parent.id }?.state == WorkInfo.State.RUNNING }
            queue.coalesceRerun(epoch, ref, 86_400_000)
            val pending = awaitGraph(epoch) { it.size == 2 && it.count { info -> info.state == WorkInfo.State.BLOCKED } == 1 }
                .single { it.id != parent.id }
            queue.coalesceRerun(epoch, ref, 600_000)
            val coalesced = awaitGraph(epoch) { rows ->
                rows.size == 2 &&
                rows.singleOrNull { it.id == parent.id }?.state == WorkInfo.State.RUNNING &&
                    rows.singleOrNull { it.id == pending.id }?.let { it.state == WorkInfo.State.BLOCKED && it.generation > pending.generation } == true
            }
            check(!parentCancelled.isCompleted)
            check(coalesced.single { it.id != parent.id }.id == pending.id)
            queue.cancel(epoch)
            awaitGraph(epoch) { it.all { info -> info.state == WorkInfo.State.CANCELLED } }
            withTimeout(30_000) { parentCancelled.await() }
        } finally { queue.cancel(epoch) }
    }

    /** Actual dependency input merge; test worker replacement observes input only, never grants access. */
    @Test fun continuationReceivesOnlyOpaqueInputAfterParentCompletion() = runBlocking(Dispatchers.IO) {
        requireIsolatedMethod("continuationReceivesOnlyOpaqueInputAfterParentCompletion")
        val parentStarted = CompletableDeferred<Unit>()
        val releaseParent = CompletableDeferred<Unit>()
        val childInput = CompletableDeferred<Data>()
        val childCancelled = CompletableDeferred<Unit>()
        val factory = object : WorkerFactory() {
            override fun createWorker(appContext: Context, workerClassName: String, workerParameters: WorkerParameters): ListenableWorker? = when (workerClassName) {
                ControlledGraphWorker::class.java.name -> ControlledGraphWorker(appContext, workerParameters) {
                    parentStarted.complete(Unit)
                    releaseParent.await()
                    ListenableWorker.Result.success(workDataOf("outcome" to "completed"))
                }
                MobileSyncWorker::class.java.name -> ControlledGraphWorker(appContext, workerParameters) {
                    childInput.complete(workerParameters.inputData)
                    try { awaitCancellation() } finally { childCancelled.complete(Unit) }
                }
                else -> null
            }
        }
        WorkManager.initialize(context, Configuration.Builder().setWorkerFactory(factory)
            .setMinimumLoggingLevel(android.util.Log.ERROR).build())
        val manager = WorkManager.getInstance(context)
        val queue = AndroidWorkQueue(context)
        val epoch = ScheduleEpoch(UUID.randomUUID().toString())
        val parent = OneTimeWorkRequestBuilder<ControlledGraphWorker>().build()
        try {
            manager.enqueueUniqueWork("kapit.sync.${epoch.chainRef}", ExistingWorkPolicy.KEEP, parent).result.get(30, TimeUnit.SECONDS)
            withTimeout(30_000) { parentStarted.await() }
            queue.enqueue(epoch, ref, 0, true)
            awaitGraph(epoch) { it.size == 2 && it.single { row -> row.id != parent.id }.state == WorkInfo.State.BLOCKED }
            releaseParent.complete(Unit)
            val input = withTimeout(30_000) { childInput.await() }
            check(input.keyValueMap.keys == setOf("store_ref", "chain_ref"))
            check(input.getString("store_ref") == ref && input.getString("chain_ref") == epoch.chainRef)
            queue.cancel(epoch)
            awaitGraph(epoch) { it.single { row -> row.id == parent.id }.state == WorkInfo.State.SUCCEEDED &&
                it.single { row -> row.id != parent.id }.state == WorkInfo.State.CANCELLED }
            withTimeout(30_000) { childCancelled.await() }
        } finally { queue.cancel(epoch) }
    }

    private fun requireIsolatedMethod(method: String) = check(InstrumentationRegistry.getArguments().getString("class") ==
        "${AndroidSchedulingIntegrationTest::class.java.name}#$method")

    private suspend fun awaitGraph(epoch: ScheduleEpoch, predicate: (List<WorkInfo>) -> Boolean): List<WorkInfo> = withTimeout(30_000) {
        while (true) {
            val rows = infos(epoch)
            if (predicate(rows)) return@withTimeout rows
            delay(50)
        }
        @Suppress("UNREACHABLE_CODE") emptyList()
    }
    private fun infos(epoch: ScheduleEpoch) = WorkManager.getInstance(context)
        .getWorkInfosForUniqueWork("kapit.sync.${epoch.chainRef}").get(30, TimeUnit.SECONDS)

    /** Actual WorkManager RUNNING state only; no storage, credentials, network or synthetic success. */
    private class ControlledGraphWorker(context: Context, parameters: WorkerParameters,
        private val work: suspend () -> Result) : CoroutineWorker(context, parameters) {
        override suspend fun doWork(): Result = work()
    }
}

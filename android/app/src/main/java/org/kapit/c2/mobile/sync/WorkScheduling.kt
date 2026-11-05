package org.kapit.c2.mobile.sync

import android.content.Context
import android.os.Build
import androidx.work.*
import java.util.UUID
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kapit.c2.mobile.KapitApplication
import org.kapit.c2.mobile.domain.StoreFailure

/** No newer facade becomes a descendant of this scheduling epoch. */
internal class AndroidWorkQueue(private val context: Context) : WorkQueue {
    companion object { private val mutations = Mutex() }
    override suspend fun enqueue(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long, continuation: Boolean) = withContext(Dispatchers.IO) {
        mutations.withLock { enqueueNow(epoch, storeRef, delayMillis, if (continuation) ExistingWorkPolicy.APPEND else ExistingWorkPolicy.KEEP) }
    }
    private fun request(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long, id: UUID? = null): OneTimeWorkRequest {
        require(Regex("[0-9a-f]{64}").matches(storeRef) && delayMillis in 0..86_400_000L)
        return OneTimeWorkRequestBuilder<MobileSyncWorker>()
            .setInputData(workDataOf("store_ref" to storeRef, "chain_ref" to epoch.chainRef))
            .setInputMerger(MobileWorkInputMerger::class.java)
            .setConstraints(Constraints.Builder().setRequiredNetworkType(NetworkType.CONNECTED).build())
            .setInitialDelay(delayMillis, TimeUnit.MILLISECONDS).apply { if (id != null) setId(id) }.build()
    }
    private fun enqueueNow(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long, policy: ExistingWorkPolicy) {
        if (Build.VERSION.SDK_INT < 35) return
        WorkManager.getInstance(context).enqueueUniqueWork("kapit.sync.${epoch.chainRef}",
            policy, request(epoch, storeRef, delayMillis)).result.get(30, TimeUnit.SECONDS)
    }
    override suspend fun cancel(epoch: ScheduleEpoch) = withContext(Dispatchers.IO) {
        mutations.withLock {
            WorkManager.getInstance(context).cancelUniqueWork("kapit.sync.${epoch.chainRef}").result.get(30, TimeUnit.SECONDS)
            Unit
        }
    }
    override suspend fun isRunning(epoch: ScheduleEpoch): Boolean = withContext(Dispatchers.IO) {
        mutations.withLock { infos(epoch).any { it.state == WorkInfo.State.RUNNING } }
    }
    override suspend fun coalesceRerun(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long) = withContext(Dispatchers.IO) {
        mutations.withLock {
            currentCoroutineContext().ensureActive()
            val manager = WorkManager.getInstance(context)
            var retainedFuture = false
            infos(epoch).filter { it.state in setOf(WorkInfo.State.ENQUEUED, WorkInfo.State.BLOCKED) }.forEach {
                // Update keeps the original dependency graph and enqueue time. Earlier eligibility
                // is safe: storage still enforces each operation's persisted retry deadline.
                when (manager.updateWork(request(epoch, storeRef, delayMillis, it.id)).get(30, TimeUnit.SECONDS)) {
                    WorkManager.UpdateResult.APPLIED_IMMEDIATELY -> retainedFuture = true
                    WorkManager.UpdateResult.APPLIED_FOR_NEXT_RUN, WorkManager.UpdateResult.NOT_APPLIED -> Unit
                }
            }
            // A request that raced into RUNNING is not interrupted, but still needs a successor.
            if (!retainedFuture) enqueueNow(epoch, storeRef, delayMillis, ExistingWorkPolicy.APPEND)
        }
    }
    private fun infos(epoch: ScheduleEpoch) = WorkManager.getInstance(context)
        .getWorkInfosForUniqueWork("kapit.sync.${epoch.chainRef}").get(30, TimeUnit.SECONDS)
}

/** Preserve exactly one opaque request pair; predecessor output cannot become worker input. */
class MobileWorkInputMerger : InputMerger() {
    override fun merge(inputs: List<Data>): Data {
        var own: Data? = null
        inputs.forEach { input ->
            when (input.keyValueMap.keys) {
                setOf("store_ref", "chain_ref") -> { require(own == null); own = input }
                setOf("outcome") -> require(input.getString("outcome") in setOf("completed", "paused"))
                else -> throw IllegalArgumentException("Invalid mobile work input")
            }
        }
        val ref = requireNotNull(own).getString("store_ref")
        val chain = own!!.getString("chain_ref")
        require(ref != null && Regex("[0-9a-f]{64}").matches(ref))
        require(chain != null && UUID.fromString(chain).toString() == chain)
        return workDataOf("store_ref" to ref, "chain_ref" to chain)
    }
}

class MobileWorkerFactory : WorkerFactory() {
    override fun createWorker(appContext: Context, workerClassName: String, workerParameters: WorkerParameters): ListenableWorker? =
        if (workerClassName == MobileSyncWorker::class.java.name) MobileSyncWorker(appContext, workerParameters) else null
}

class MobileSyncWorker(context: Context, parameters: WorkerParameters) : CoroutineWorker(context, parameters) {
    override suspend fun doWork(): Result = withContext(Dispatchers.IO) {
        if (Build.VERSION.SDK_INT < 35) return@withContext Result.failure()
        if (inputData.keyValueMap.keys != setOf("store_ref", "chain_ref")) return@withContext Result.failure()
        val ref = inputData.getString("store_ref") ?: return@withContext Result.failure()
        if (!Regex("[0-9a-f]{64}").matches(ref)) return@withContext Result.failure()
        val epoch = try { ScheduleEpoch(inputData.getString("chain_ref") ?: return@withContext Result.failure()) }
            catch (_: IllegalArgumentException) { return@withContext Result.failure() }
        val application = applicationContext as? KapitApplication ?: return@withContext Result.failure()
        try {
            val result = application.container.runWorker(ref)
            result.nextDelayMillis?.let { delay ->
                currentCoroutineContext().ensureActive()
                AndroidWorkQueue(applicationContext).enqueue(epoch, ref, delay, continuation = true)
            }
            // Invocation completion is distinct from committed receipt acceptance.
            Result.success(workDataOf("outcome" to "completed"))
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: StoreFailure) { Result.success(workDataOf("outcome" to "paused")) }
        catch (_: Exception) { Result.failure() }
    }
}

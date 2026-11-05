package org.kapit.c2.mobile.sync

import java.util.UUID
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock

internal class ScheduleEpoch(val chainRef: String) {
    init { require(UUID.fromString(chainRef).toString() == chainRef) }
    override fun toString() = "ScheduleEpoch(opaque)"
}

internal interface WorkQueue {
    suspend fun enqueue(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long, continuation: Boolean)
    suspend fun cancel(epoch: ScheduleEpoch)
    suspend fun isRunning(epoch: ScheduleEpoch): Boolean
    suspend fun coalesceRerun(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long)
}

/** One current chain; historical request IDs never accumulate in memory. */
internal class OwnedScheduler(private val queue: WorkQueue, private val scope: CoroutineScope,
    private val elapsedMillis: () -> Long = { System.nanoTime() / 1_000_000 }) : DeliveryScheduler {
    private val monitor = Any()
    private val operations = Mutex()
    private var epoch = ScheduleEpoch(UUID.randomUUID().toString())
    private var store: String? = null
    private var deadline: Long? = null
    override fun capture(): ScheduleEpoch = synchronized(monitor) { epoch }
    override suspend fun schedule(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long): ScheduleEpoch? {
        require(Regex("[0-9a-f]{64}").matches(storeRef) && delayMillis in 0..86_400_000L)
        return operations.withLock {
            currentCoroutineContext().ensureActive()
            val now = elapsedMillis()
            val requested = Math.addExact(now, delayMillis)
            if (synchronized(monitor) { this.epoch !== epoch }) return@withLock null
            val running = queue.isRunning(epoch)
            val selected = synchronized(monitor) {
                if (this.epoch !== epoch) null else {
                    require(store == null || store == storeRef)
                    store = storeRef
                    // A due chain may be running or have appended its own delayed continuation.
                    // A fresh bounded chain prevents a newly eligible row being lost behind it.
                    val previousDeadline = deadline
                    if (!running && previousDeadline != null && (requested < previousDeadline || previousDeadline <= now))
                        this.epoch = ScheduleEpoch(UUID.randomUUID().toString())
                    if (running) deadline = minOf(requested, previousDeadline ?: requested)
                    else if (this.epoch !== epoch || previousDeadline == null) deadline = requested
                    this.epoch
                }
            }
            if (selected == null) return@withLock null
            if (selected !== epoch) queue.cancel(epoch)
            if (running) queue.coalesceRerun(selected, storeRef, synchronized(monitor) { ((deadline ?: requested) - now).coerceAtLeast(0) })
            else queue.enqueue(selected, storeRef, delayMillis, continuation = false)
            if (synchronized(monitor) { this.epoch !== selected }) { queue.cancel(selected); null } else selected
        }
    }
    override suspend fun cancel(epoch: ScheduleEpoch) { operations.withLock { queue.cancel(epoch) } }
    override fun cancel() {
        val previous = synchronized(monitor) {
            epoch.also { epoch = ScheduleEpoch(UUID.randomUUID().toString()); store = null; deadline = null }
        }
        scope.launch { try { cancel(previous) } catch (_: Exception) { /* Storage remains fenced. */ } }
    }
}

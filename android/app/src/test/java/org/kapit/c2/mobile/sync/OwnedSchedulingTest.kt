package org.kapit.c2.mobile.sync

import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test

class OwnedSchedulingTest {
    private val ref = "a".repeat(64)

    @Test fun runningRefreshGetsOneCoalescedRerunWithoutCancellation() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val queue = QueueModel()
        val scheduler = OwnedScheduler(queue, scope) { 1_000 }
        val running = scheduler.capture()
        scheduler.schedule(running, ref, 0)
        queue.running += running.chainRef
        repeat(5) { assertSame(running, scheduler.schedule(running, ref, 0)) }
        assertTrue(queue.cancelled.isEmpty())
        assertEquals(mapOf(running.chainRef to 0L), queue.successors)
        scope.cancel()
    }

    @Test fun earlierEligibleRowRotatesDelayedChainInsteadOfBeingIgnoredByKeep() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val queue = QueueModel()
        val scheduler = OwnedScheduler(queue, scope) { 1_000 }
        val delayed = scheduler.capture()
        scheduler.schedule(delayed, ref, 86_400_000)
        val immediate = scheduler.schedule(scheduler.capture(), ref, 0)!!
        assertNotEquals(delayed.chainRef, immediate.chainRef)
        assertTrue(queue.cancelled.contains(delayed.chainRef))
        assertEquals(mapOf(immediate.chainRef to 0L), queue.active)
        scope.cancel()
    }

    @Test fun laterWakeupCoalescesWithoutPostponingExistingEarlierWork() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val queue = QueueModel()
        val scheduler = OwnedScheduler(queue, scope) { 1_000 }
        val original = scheduler.capture()
        scheduler.schedule(original, ref, 5_000)
        val kept = scheduler.schedule(original, ref, 60_000)
        assertSame(original, kept); assertEquals(mapOf(original.chainRef to 5_000L), queue.active)
        assertTrue(queue.cancelled.isEmpty()); scope.cancel()
    }

    @Test fun arrivalAtDrainCompletionGetsFreshWakeupInsteadOfKeepGap() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val queue = QueueModel()
        var now = 1_000L
        val scheduler = OwnedScheduler(queue, scope) { now }
        val running = scheduler.capture()
        scheduler.schedule(running, ref, 0)
        now++
        val newWork = scheduler.schedule(running, ref, 0)!!
        assertNotEquals(running.chainRef, newWork.chainRef)
        assertEquals(mapOf(newWork.chainRef to 0L), queue.active); scope.cancel()
    }

    @Test fun delayedOldCancellationCannotCancelNewEpoch() = runBlocking {
        val dispatcher = QueueDispatcher()
        val scope = CoroutineScope(SupervisorJob() + dispatcher)
        val queue = QueueModel()
        val scheduler = OwnedScheduler(queue, scope)
        val old = scheduler.capture()
        scheduler.schedule(old, ref, 0)
        scheduler.cancel()
        val fresh = scheduler.capture()
        scheduler.schedule(fresh, ref, 0)
        dispatcher.runAll()
        assertNotEquals(old.chainRef, fresh.chainRef)
        assertTrue(queue.cancelled.contains(old.chainRef)); assertFalse(queue.cancelled.contains(fresh.chainRef))
        assertTrue(queue.enqueued.contains(fresh.chainRef)); scope.cancel()
    }

    @Test fun cancellationDuringEnqueueCancelsCapturedChainAndRotatesBeforeNewWork() = runBlocking {
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val queue = QueueModel().apply { enqueueBlock = { entered.complete(Unit); release.await() } }
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val scheduler = OwnedScheduler(queue, scope)
        val old = scheduler.capture()
        val sending = launch { scheduler.schedule(old, ref, 0) }
        entered.await(); scheduler.cancel()
        val next = scheduler.capture()
        release.complete(Unit); sending.join()
        queue.enqueueBlock = null
        scheduler.schedule(next, ref, 0)
        assertTrue(queue.cancelled.contains(old.chainRef)); assertFalse(queue.cancelled.contains(next.chainRef))
        scope.cancel()
    }

    @Test fun retiredCaptureCannotEnqueueAfterCancellation() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val queue = QueueModel()
        val scheduler = OwnedScheduler(queue, scope)
        val old = scheduler.capture(); scheduler.cancel()
        scheduler.schedule(old, ref, 0)
        assertTrue(queue.enqueued.isEmpty()); scope.cancel()
    }

    @Test fun exactCapturedCancellationDoesNotRotateOrCancelReplacement() = runBlocking {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val queue = QueueModel()
        val scheduler = OwnedScheduler(queue, scope)
        val old = scheduler.capture(); scheduler.cancel()
        val current = scheduler.capture()
        scheduler.schedule(current, ref, 0)
        scheduler.cancel(old)
        assertSame(current, scheduler.capture()); assertFalse(queue.cancelled.contains(current.chainRef))
        scope.cancel()
    }

    private class QueueModel : WorkQueue {
        val enqueued = mutableListOf<String>()
        val cancelled = mutableSetOf<String>()
        val active = mutableMapOf<String, Long>()
        val running = mutableSetOf<String>()
        val successors = mutableMapOf<String, Long>()
        var enqueueBlock: (suspend () -> Unit)? = null
        override suspend fun enqueue(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long, continuation: Boolean) {
            enqueueBlock?.invoke(); enqueued += epoch.chainRef
            // Model KEEP: a second request on the same unfinished chain is ignored.
            if (!active.containsKey(epoch.chainRef)) active[epoch.chainRef] = delayMillis
        }
        override suspend fun cancel(epoch: ScheduleEpoch) { cancelled += epoch.chainRef; active.remove(epoch.chainRef); successors.remove(epoch.chainRef) }
        override suspend fun isRunning(epoch: ScheduleEpoch) = epoch.chainRef in running
        override suspend fun coalesceRerun(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long) { successors[epoch.chainRef] = delayMillis }
    }
}

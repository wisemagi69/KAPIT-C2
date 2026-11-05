package org.kapit.c2.mobile.sync

import java.util.ArrayDeque
import kotlin.coroutines.CoroutineContext
import kotlinx.coroutines.*
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.domain.*

internal class QueueDispatcher : CoroutineDispatcher() {
    private val tasks = ArrayDeque<Runnable>()
    override fun dispatch(context: CoroutineContext, block: Runnable) { tasks.add(block) }
    fun runAll() { while (tasks.isNotEmpty()) tasks.removeFirst().run() }
}

class RuntimeRepositoryTest {
    @Test fun oldCleanupCannotScheduleNewLockBeforeItsOwnDurableFence() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val actual = RepositoryFixture().apply { selectReady() }
        val scheduled = mutableListOf<StoreAccess>()
        val owner = RuntimeRepositoryOwner(scope, { storageFixture(actual) }, Dispatchers.Unconfined)
        try {
            val facade = owner.acquire { scheduled += it }
            val older = facade.invalidate(StoreCode.LOCKED)
            val newer = facade.invalidate(StoreCode.LOCKED)
            facade.fence(StoreCode.LOCKED, older.generation)
            assertTrue(scheduled.isEmpty())
            facade.fence(StoreCode.LOCKED, newer.generation)
            assertEquals(listOf(newer), scheduled)
        } finally { owner.close(); scope.cancel() }
    }
    @Test fun creationAndPreInitializationFenceDoNotOpenStorageOnCaller() {
        val dispatcher = QueueDispatcher()
        val scope = CoroutineScope(SupervisorJob() + dispatcher)
        val actual = RepositoryFixture()
        var constructions = 0
        val owner = RuntimeRepositoryOwner(scope, { constructions++; storageFixture(actual) }, dispatcher)
        try {
            val facade = owner.acquire {}
            val fenced = facade.invalidate(StoreCode.SIGNED_OUT)
            assertEquals(0, constructions); assertEquals(2L, fenced.generation)
            dispatcher.runAll()
            assertEquals(1, constructions); assertEquals(fenced, facade.access.value)
            facade.close()
            assertTrue(actual.durableFences.contains(fenced.generation to StoreCode.SIGNED_OUT))
            assertFalse(actual.closed)
        } finally { owner.close(); scope.cancel(); dispatcher.runAll() }
    }

    @Test fun delayedOldCloseCannotFenceOrCloseReplacement() {
        val dispatcher = QueueDispatcher()
        val scope = CoroutineScope(SupervisorJob() + dispatcher)
        val actual = RepositoryFixture().apply { selectReady() }
        val owner = RuntimeRepositoryOwner(scope, { storageFixture(actual) }, dispatcher)
        dispatcher.runAll()
        try {
            val old = owner.acquire {}
            val replacement = owner.acquire {}
            secrets().use { replacement.activateOnline(replacement.beginOnlineRequest(replacement.access.value.generation), testContext, testOffer, it) }
            val ready = replacement.access.value
            old.invalidate(StoreCode.SIGNED_OUT)
            old.close(); dispatcher.runAll()
            assertEquals(ready, replacement.access.value); assertTrue(ready.ready)
            assertFalse(actual.closed); assertFalse(old.access.value.ready)
            assertThrows(StoreFailure::class.java) { old.beginOnlineRequest(ready.generation) }
        } finally { owner.close(); scope.cancel(); dispatcher.runAll() }
    }

    @Test fun finalReleaseHandsOffOnlyAfterExactDurableLockedFence() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val actual = RepositoryFixture().apply { selectReady() }
        val handed = mutableListOf<StoreAccess>()
        val owner = RuntimeRepositoryOwner(scope, { storageFixture(actual) }, Dispatchers.Unconfined, onReleased = {
            assertTrue(actual.durableFences.contains(it.generation to StoreCode.LOCKED)); handed += it
        })
        try {
            val facade = owner.acquire {}
            val captured = facade.invalidate(StoreCode.LOCKED)
            facade.close()
            assertEquals(listOf(captured), handed); assertTrue(owner.isUnowned(captured))
            owner.acquire {}
            // A delayed enqueue callback must reject this same-generation replacement too.
            assertFalse(owner.isUnowned(captured))
        } finally { owner.close(); scope.cancel() }
    }

    @Test fun failedCleanupDoesNotHandoffAndExactRetryCanDrainWithoutTouchingReplacement() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val actual = RepositoryFixture().apply { selectReady(); fenceFailure = true }
        var handoffs = 0
        val owner = RuntimeRepositoryOwner(scope, { storageFixture(actual) }, Dispatchers.Unconfined, onReleased = { handoffs++ })
        try {
            val old = owner.acquire {}
            val fenced = old.invalidate(StoreCode.LOCKED)
            assertThrows(StoreFailure::class.java) { old.close() }
            assertEquals(0, handoffs)
            val replacement = owner.acquire {}
            actual.fenceFailure = false
            old.close()
            assertEquals(0, handoffs); assertEquals(fenced.generation, replacement.access.value.generation)
            assertTrue(actual.durableFences.contains(fenced.generation to StoreCode.LOCKED))
        } finally { actual.fenceFailure = false; owner.close(); scope.cancel() }
    }

    @Test fun terminalReleaseNeverSchedulesBackgroundUnlock() {
        val scope = CoroutineScope(SupervisorJob() + Dispatchers.Unconfined)
        val actual = RepositoryFixture().apply { selectReady() }
        var handoffs = 0
        val owner = RuntimeRepositoryOwner(scope, { storageFixture(actual) }, Dispatchers.Unconfined, onReleased = { handoffs++ })
        try {
            val facade = owner.acquire {}
            facade.invalidate(StoreCode.REVOKED); facade.close()
            assertEquals(0, handoffs); assertEquals(StoreCode.REVOKED, actual.access.value.reason)
        } finally { owner.close(); scope.cancel() }
    }
}

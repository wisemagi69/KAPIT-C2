package org.kapit.c2.mobile.sync

import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.data.remote.*
import org.kapit.c2.mobile.domain.*

class SyncEngineTest {
    @Test fun receiptFirstReplayUsesIdenticalFrozenBytesAndOneCommit() = runBlocking {
        val session = SessionFixture()
        val calls = mutableListOf<String>()
        val expected = claim().use { it.copyRequestBytes() }
        val remote = object : ProtocolFixture() {
            override suspend fun receipt(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt {
                calls += "lookup"; throw RemoteFailure(RemoteFailureKind.HTTP, 404, RemoteCode.NOT_FOUND)
            }
            override suspend fun send(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt {
                calls += "send"; assertArrayEquals(expected, claim.copyRequestBytes()); return acceptedReceipt(claim)
            }
        }
        val result = SyncEngine(remote).drain(session)
        assertEquals(listOf("lookup", "send"), calls)
        assertEquals(1, session.committed); assertEquals(1, result.receiptsCommitted); assertTrue(result.serviceReached)
        session.credentialsDetached.forEach { assertThrows(StoreFailure::class.java) { it.copyAccessToken() } }
    }

    @Test fun originalReceiptNeverPostsAgain() = runBlocking {
        val session = SessionFixture()
        val remote = object : ProtocolFixture() {
            override suspend fun receipt(claim: DeliveryClaim, access: ByteArray) = acceptedReceipt(claim)
        }
        assertEquals(1, SyncEngine(remote).drain(session).receiptsCommitted)
    }

    @Test fun uncertainAcknowledgementPreservesQueueAndNextDrainLooksUpReceipt() = runBlocking {
        val first = SessionFixture()
        var sends = 0
        var committedRemotely = false
        val remote = object : ProtocolFixture() {
            override suspend fun receipt(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt {
                if (committedRemotely) return acceptedReceipt(claim)
                throw RemoteFailure(RemoteFailureKind.HTTP, 404, RemoteCode.NOT_FOUND)
            }
            override suspend fun send(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt {
                sends++; committedRemotely = true
                throw RemoteFailure(RemoteFailureKind.INVALID_RESPONSE, 201, mutationUncertain = true)
            }
        }
        val engine = SyncEngine(remote, { 10 })
        assertEquals(0, engine.drain(first).receiptsCommitted)
        assertEquals(DeliveryState.QUEUED, first.delivery)
        val restarted = SessionFixture()
        assertEquals(1, engine.drain(restarted).receiptsCommitted)
        assertEquals(1, sends)
    }

    @Test fun persistedAttemptControlsJitterAndRetryAfterIsLowerBound() = runBlocking {
        val session = SessionFixture().apply { attempts = 9 }
        var bound = 0L
        val remote = object : ProtocolFixture() {
            override suspend fun receipt(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt =
                throw RemoteFailure(RemoteFailureKind.HTTP, 429, RemoteCode.THROTTLED, retryAfterSeconds = 2_000)
        }
        SyncEngine(remote, { bound = it; 500_000 }).drain(session)
        assertEquals(900_001L, bound); assertEquals(2_000_000L, session.delay)
    }

    @Test fun conflictAndCorrectionRetainDistinctStates() = runBlocking {
        for ((status, expected) in listOf(409 to DeliveryState.CONFLICT, 422 to DeliveryState.NEEDS_CORRECTION)) {
            val session = SessionFixture()
            val remote = object : ProtocolFixture() {
                override suspend fun receipt(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt = throw RemoteFailure(RemoteFailureKind.HTTP, status)
            }
            SyncEngine(remote).drain(session)
            assertEquals(expected, session.delivery); assertEquals(0, session.committed)
        }
    }

    @Test fun usableBearer401DoesNotAttemptRefresh() = runBlocking {
        val session = SessionFixture()
        try {
            SyncEngine(ProtocolFixture()).protectedRead(session) { throw RemoteFailure(RemoteFailureKind.HTTP, 401, RemoteCode.AUTH_REQUIRED) }
            fail("denial expected")
        } catch (_: RemoteFailure) { }
        assertEquals(StoreCode.AUTH_REQUIRED, session.denied)
        assertNull(session.durable.marker)
    }

    @Test fun ordinaryExpiryDuringReadAllowsOneRotationThenRepeatsRead() = runBlocking {
        val session = SessionFixture()
        var refreshes = 0
        var reads = 0
        val remote = object : ProtocolFixture() {
            override suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteSession {
                assertNotNull(session.durable.marker); refreshes++; return remoteSession()
            }
        }
        val result = SyncEngine(remote).protectedRead(session) {
            reads++
            if (reads == 1) { session.usable = false; throw RemoteFailure(RemoteFailureKind.HTTP, 401, RemoteCode.AUTH_REQUIRED) }
            "read"
        }
        assertEquals("read", result); assertEquals(2, reads); assertEquals(1, refreshes)
        assertNull(session.durable.marker); assertEquals(1, session.durable.replacements)
    }

    @Test fun unresolvedRefreshSurvivesSessionRecreationAndIsNeverResent() = runBlocking {
        val durable = DurableRefreshModel()
        val first = SessionFixture(durable).apply { usable = false }
        var refreshes = 0
        val remote = object : ProtocolFixture() {
            override suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteSession {
                assertNotNull(durable.marker); refreshes++
                throw RemoteFailure(RemoteFailureKind.TIMEOUT, mutationUncertain = true)
            }
        }
        try { SyncEngine(remote).drain(first); fail() } catch (_: RemoteFailure) { }
        assertEquals(StoreCode.AUTH_REQUIRED, first.denied); assertNotNull(durable.marker)
        first.close()
        val reopened = SessionFixture(durable).apply { usable = false }
        try { SyncEngine(remote).drain(reopened); fail() } catch (failure: StoreFailure) { assertEquals(StoreCode.AUTH_REQUIRED, failure.code) }
        assertEquals(1, refreshes); assertEquals(0, durable.replacements)
    }

    @Test fun undispatchedRefreshReleasesItsMarkerWithoutRequiringSignIn() = runBlocking {
        val durable = DurableRefreshModel()
        val first = SessionFixture(durable).apply { usable = false }
        var refreshes = 0
        var reachable = false
        val remote = object : ProtocolFixture() {
            override suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteSession {
                assertNotNull(durable.marker); refreshes++
                if (!reachable) throw RemoteFailure(RemoteFailureKind.NETWORK, notDispatched = true)
                return remoteSession()
            }
        }
        try { SyncEngine(remote).drain(first); fail() } catch (failure: RemoteFailure) { assertTrue(failure.notDispatched) }
        assertNull(first.denied); assertNull(durable.marker); assertEquals(1, first.abandons); assertEquals(0, first.committed)
        first.close()
        reachable = true
        val reopened = SessionFixture(durable).apply { usable = false }
        assertEquals("read", SyncEngine(remote).protectedRead(reopened) { "read" })
        assertEquals(2, refreshes); assertEquals(1, durable.replacements); assertNull(reopened.denied)
    }

    @Test fun undispatchedRefreshStillRequiresSignInWhenItsMarkerCannotBeReleased() = runBlocking {
        val session = SessionFixture().apply { usable = false; failAbandon = true }
        val remote = object : ProtocolFixture() {
            override suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteSession =
                throw RemoteFailure(RemoteFailureKind.NETWORK, notDispatched = true)
        }
        try { SyncEngine(remote).drain(session); fail() } catch (_: RemoteFailure) { }
        assertNotNull(session.durable.marker); assertEquals(StoreCode.AUTH_REQUIRED, session.denied)
    }

    @Test fun refreshCommitFailureRetainsUncertainMarkerAndClosesResponse() = runBlocking<Unit> {
        val session = SessionFixture().apply { usable = false; failCommit = true }
        val response = remoteSession()
        val remote = object : ProtocolFixture() {
            override suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp) = response
        }
        try { SyncEngine(remote).drain(session); fail() } catch (_: StoreFailure) { }
        assertNotNull(session.durable.marker); assertEquals(StoreCode.AUTH_REQUIRED, session.denied)
        assertThrows(StoreFailure::class.java) { response.secrets.copyRefreshToken() }
    }

    @Test fun cancellationAfterRefreshDispatchRetainsUncertainty() = runBlocking {
        val session = SessionFixture().apply { usable = false }
        val entered = CompletableDeferred<Unit>()
        val remote = object : ProtocolFixture() {
            override suspend fun refresh(refresh: ByteArray, expected: AuthorizedContext, start: ClockStamp): RemoteSession {
                entered.complete(Unit); awaitCancellation()
            }
        }
        val job = launch { SyncEngine(remote).drain(session) }
        entered.await(); job.cancelAndJoin()
        assertNotNull(session.durable.marker); assertEquals(StoreCode.AUTH_REQUIRED, session.denied)
        assertEquals(0, session.committed)
    }

    @Test fun lateNonCooperativeReceiptCannotCommitAfterFence() = runBlocking {
        val session = SessionFixture()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val remote = object : ProtocolFixture() {
            override suspend fun receipt(claim: DeliveryClaim, access: ByteArray): AcceptedReceipt = withContext(NonCancellable) {
                entered.complete(Unit); release.await(); acceptedReceipt(claim)
            }
        }
        val job = launch { SyncEngine(remote).drain(session) }
        entered.await(); session.stale = true; job.cancel(); release.complete(Unit); job.join()
        assertEquals(0, session.committed)
    }

    @Test fun sharedAuthorityGateSerializesForegroundAndWorker() = runBlocking {
        val gate = Mutex()
        val entered = CompletableDeferred<Unit>()
        val release = CompletableDeferred<Unit>()
        val first = launch { SyncEngine(ProtocolFixture(), gate = gate).protectedRead(SessionFixture()) { entered.complete(Unit); release.await() } }
        entered.await()
        var secondEntered = false
        val second = launch { SyncEngine(ProtocolFixture(), gate = gate).protectedRead(SessionFixture()) { secondEntered = true } }
        yield(); assertFalse(secondEntered)
        release.complete(Unit); first.join(); second.join(); assertTrue(secondEntered)
    }
}

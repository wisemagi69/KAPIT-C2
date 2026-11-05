package org.kapit.c2.mobile.sync

import androidx.annotation.RequiresApi
import kotlin.random.Random
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kapit.c2.mobile.data.remote.*
import org.kapit.c2.mobile.domain.*

/** One process gate serializes authority rotation and immutable delivery across all entry points. */
@RequiresApi(35)
internal class SyncEngine(private val remote: RemoteProtocol, private val randomLong: (Long) -> Long = { Random.nextLong(it) },
    private val gate: Mutex = Mutex()) {

    suspend fun <T> protectedRead(session: SyncSession, block: suspend (ByteArray) -> T): T = gate.withLock {
        authorized(session, block = block)
    }

    suspend fun drain(session: SyncSession, budget: DrainBudget = DrainBudget()): SyncOutcome = gate.withLock {
        val start = session.clock()
        var reached = false
        var receipts = 0
        repeat(budget.maxOperations) {
            currentCoroutineContext().ensureActive()
            val now = session.clock()
            if (now.bootId != start.bootId || now.elapsedMillis < start.elapsedMillis) throw StoreFailure(StoreCode.CLOCK_UNTRUSTED)
            if (now.elapsedMillis - start.elapsedMillis >= budget.maxElapsedMillis)
                return@withLock SyncOutcome(reached, receipts, session.nextDeliveryDelayMillis())
            // Refresh before claiming: the120-second claim does not pay for credential rotation.
            if (ensureAccess(session)) reached = true
            val owned = session.claimNext() ?: return@withLock SyncOutcome(reached, receipts, session.nextDeliveryDelayMillis())
            owned.use { item ->
                try {
                    authorized(session, { reached = true }) { access ->
                        val receipt = try {
                            remote.receipt(item.claim, access).also { reached = true }
                        } catch (failure: RemoteFailure) {
                            if (failure.status != null) reached = true
                            if (failure.status != 404) throw failure
                            session.beginOnlineRequest()
                            currentCoroutineContext().ensureActive()
                            if (!session.accessTokenUsable()) throw AccessExpired()
                            remote.send(item.claim, access).also { reached = true }
                        }
                        currentCoroutineContext().ensureActive()
                        session.beginOnlineRequest()
                        session.commitReceipt(item.claim, receipt)
                        receipts++
                    }
                } catch (cancelled: CancellationException) { throw cancelled }
                catch (failure: RemoteFailure) {
                    if (failure.status != null) reached = true
                    recordFailure(session, item, failure)
                    // A transient failure pauses this drain; do not spin through a zero-jitter row.
                    return@withLock SyncOutcome(reached, receipts, session.nextDeliveryDelayMillis())
                } catch (failure: StoreFailure) {
                    if (failure.code == StoreCode.AUTH_REQUIRED) session.deny(StoreCode.AUTH_REQUIRED)
                    throw failure
                }
            }
        }
        SyncOutcome(reached, receipts, session.nextDeliveryDelayMillis())
    }

    private suspend fun <T> authorized(session: SyncSession, refreshed: () -> Unit = {}, block: suspend (ByteArray) -> T): T {
        var rotated = ensureAccess(session).also { if (it) refreshed() }
        while (true) try { return withAccess(session, block) }
        catch (expired: AccessExpired) {
            if (rotated || session.accessTokenUsable()) { session.deny(StoreCode.AUTH_REQUIRED); throw StoreFailure(StoreCode.AUTH_REQUIRED) }
            rotated = ensureAccess(session)
            if (rotated) refreshed()
        } catch (failure: RemoteFailure) {
            // A live 401 alone is not expiry evidence. Never refresh an otherwise usable bearer.
            if (!rotated && failure.status == 401 && failure.code == RemoteCode.AUTH_REQUIRED && !session.accessTokenUsable()) {
                rotated = ensureAccess(session)
                if (rotated) refreshed()
                continue
            }
            if (failure.status == 401 || failure.status == 403) {
                session.deny(if (failure.status == 403) StoreCode.SCOPE_DENIED else StoreCode.AUTH_REQUIRED)
            } else if (failure.kind == RemoteFailureKind.CONTEXT_CHANGED) {
                session.deny(if (failure.code == RemoteCode.TEMPLATE_UNSUPPORTED) StoreCode.TEMPLATE_UNSUPPORTED else StoreCode.CONTEXT_CHANGED)
            }
            throw failure
        }
    }

    private class AccessExpired : RuntimeException()

    private suspend fun ensureAccess(session: SyncSession): Boolean {
        currentCoroutineContext().ensureActive()
        session.beginOnlineRequest()
        if (session.accessTokenUsable()) return false
        val anchor = session.beginOnlineRequest()
        session.credentials().use { secrets ->
            val refresh = secrets.copyRefreshToken()
            var attempt: RefreshAttempt? = null
            try {
                attempt = session.beginRefresh(anchor)
                currentCoroutineContext().ensureActive()
                remote.refresh(refresh, session.context, anchor.clock).use { response ->
                    currentCoroutineContext().ensureActive()
                    session.completeRefresh(attempt, anchor, response.context.authority, response.context.lease, response.secrets)
                }
                if (!session.accessTokenUsable()) throw StoreFailure(StoreCode.AUTH_REQUIRED)
            } catch (cancelled: CancellationException) {
                // Issuance may have committed. Never reuse this refresh after an uncertain outcome.
                denyIfCurrent(session, StoreCode.AUTH_REQUIRED)
                throw cancelled
            } catch (failure: Exception) {
                // Never connected: the refresh token was not presented, so release the marker and stay offline-usable.
                if (failure is RemoteFailure && failure.notDispatched && attempt != null && abandoned(session, attempt)) throw failure
                denyIfCurrent(session, when {
                    failure is RemoteFailure && failure.status == 403 -> StoreCode.SCOPE_DENIED
                    failure is RemoteFailure && failure.code == RemoteCode.TEMPLATE_UNSUPPORTED -> StoreCode.TEMPLATE_UNSUPPORTED
                    else -> StoreCode.AUTH_REQUIRED
                })
                throw failure
            } finally { refresh.fill(0) }
        }
        return true
    }

    private suspend fun <T> withAccess(session: SyncSession, block: suspend (ByteArray) -> T): T {
        session.beginOnlineRequest()
        return session.credentials().use { secrets ->
            val access = secrets.copyAccessToken()
            try {
                val value = block(access)
                currentCoroutineContext().ensureActive()
                session.beginOnlineRequest()
                value
            } finally { access.fill(0) }
        }
    }

    private fun recordFailure(session: SyncSession, item: ClaimedOperation, failure: RemoteFailure) {
        session.beginOnlineRequest()
        val denied = when {
            failure.status == 401 -> StoreCode.AUTH_REQUIRED
            failure.status == 403 -> StoreCode.SCOPE_DENIED
            failure.code == RemoteCode.ENROLLMENT_REVOKED -> StoreCode.REVOKED
            failure.code == RemoteCode.TEMPLATE_UNSUPPORTED -> StoreCode.TEMPLATE_UNSUPPORTED
            failure.kind == RemoteFailureKind.CONTEXT_CHANGED -> StoreCode.CONTEXT_CHANGED
            else -> null
        }
        if (denied != null) {
            session.deny(denied)
            throw StoreFailure(denied)
        }
        when (failure.status) {
            409 -> session.recordFailure(item.claim, DeliveryState.CONFLICT, null)
            422 -> session.recordFailure(item.claim, DeliveryState.NEEDS_CORRECTION, null)
            else -> {
                val retry = failure.retryDelaySeconds(session.serverTimeLowerMillis())?.times(1000)
                val ceiling = minOf(900_000L, 10_000L * (1L shl minOf(item.attempt, 7)))
                val jitter = randomLong(ceiling + 1).also { require(it in 0..ceiling) }
                session.recordFailure(item.claim, DeliveryState.QUEUED, null, maxOf(jitter, retry ?: 0))
            }
        }
    }

    private fun abandoned(session: SyncSession, attempt: RefreshAttempt): Boolean =
        try { session.abandonRefresh(attempt); true } catch (_: StoreFailure) { false }

    private fun denyIfCurrent(session: SyncSession, reason: StoreCode) {
        try { session.deny(reason) } catch (_: StoreFailure) { /* A newer capability must remain untouched. */ }
    }
}

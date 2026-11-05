package org.kapit.c2.mobile.data.local

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.nio.channels.FileChannel
import java.nio.channels.FileLock
import java.io.RandomAccessFile
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.TimeZone
import java.util.UUID
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.serialization.json.*
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.security.*

/** One process owner; all database work is IO-dispatched by callers. No plaintext storage fallback. */
class AndroidProtectedRepository internal constructor(
    context: Context, private val root: File, private val environment: StoreEnvironment,
    monitorLifecycle: Boolean, internal var beforeCommit: (() -> Unit)? = null,
) : ProtectedRepository {
    constructor(context: Context) : this(context.applicationContext, File(context.noBackupFilesDir, "protected-v1"), AndroidAccessEnvironment(context), true)
    private val app = context.applicationContext
    /** Instrumentation-only diagnosis: no messages, causes, paths, arguments or source values. */
    internal var unexpectedFailureObserver: ((String, List<String>) -> Unit)? = null
    private val ioLock = Any()
    private val commitFence = Any()
    private val session = UUID.randomUUID().toString()
    private val mutableAccess = MutableStateFlow(StoreAccess(1))
    override val access: StateFlow<StoreAccess> = mutableAccess.asStateFlow()
    private val vault = AndroidKeyVault(root, environment)
    val enrollmentJournal: ProtectedEnrollmentJournal = EnrollmentJournalStore(root, environment, object : EnrollmentJournalGuard {
        override fun <T> operation(generation: Long, body: (commit: (() -> Unit) -> Unit) -> T): T = storage {
            requireGeneration(generation); environment.requireEligibleUnlockedDevice(); ensureOwner()
            val result = body { mutation -> synchronized(commitFence) {
                requireGeneration(generation); environment.requireEligibleUnlockedDevice(); mutation()
            } }
            synchronized(commitFence) { requireGeneration(generation); environment.requireEligibleUnlockedDevice() }
            result
        }
    })
    private val pending = linkedMapOf<Long, PendingFence>()
    private val completedFences = mutableSetOf<Long>()
    private val detached = java.util.Collections.newSetFromMap(java.util.WeakHashMap<java.io.Closeable, Boolean>())
    private var active: Active? = null
    private var worker: Active? = null
    private var workerCapability: String? = null
    private val syncSessions = mutableSetOf<RestrictedSession>()
    private var openingRef: String? = null
    private var authorityRevision = 0L
    private var ownerChannel: FileChannel? = null
    private var ownerLock: FileLock? = null
    @Volatile private var closed = false
    private val cleanup = Executors.newSingleThreadScheduledExecutor { runnable -> Thread(runnable, "kapit-store-guard").apply { isDaemon = true } }
    private val lifecycle = if (monitorLifecycle) RepositoryLifecycleBinding(app) { backgroundFence(StoreCode.LOCKED) } else null

    private data class Active(val ref: String, val epoch: Long, val revision: Long, val database: ProtectedDatabase, val context: AuthorizedContext,
        val lease: OfflineLease, val accessToken: ByteArray, val accessExpires: Long, val workerWindow: WorkerWindow? = null)
    private data class PendingFence(val generation: Long, val refs: Set<String>, val oldEpoch: Long?, val reason: StoreCode,
        val oldWorkerCapability: String?)

    init {
        if (monitorLifecycle) cleanup.scheduleWithFixedDelay({
            val current = synchronized(commitFence) { active?.takeIf { access.value.ready } ?: worker }
            if (current != null) try {
                val now = environment.clock(); current.workerWindow?.requireValid(now)
                LeasePolicy.requireValid(current.lease, now); environment.requireEligibleUnlockedDevice()
            }
            catch (failure: Exception) { invalidateObservedAuthority(current.epoch, current.revision, safeFailure(failure).code) }
        }, 1, 1, TimeUnit.SECONDS)
    }

    override fun beginOnlineRequest(expectedGeneration: Long): OnlineRequestAnchor = synchronized(commitFence) {
        requireGeneration(expectedGeneration); OnlineRequestAnchor(expectedGeneration, environment.clock(), active?.revision ?: worker?.revision ?: 0)
    }

    /** A non-owning foreground capability. Its closure cannot close the Activity's current store. */
    fun foregroundSync(expectedGeneration: Long): StoreSyncSession = storage {
        val current = requireActive(expectedGeneration)
        synchronized(commitFence) {
            requireGeneration(expectedGeneration)
            RestrictedSession(current, false, uuid()).also { syncSessions += it }
        }
    }

    /** A fresh authenticated unwrap which never publishes foreground READY. */
    fun openWorker(expectedGeneration: Long, storeRef: String): WorkerStoreCapability = storage {
        drainPending(); requireGeneration(expectedGeneration); ensureOwner(); environment.requireEligibleUnlockedDevice()
        val window = WorkerWindow.begin(environment.clock())
        requireStore(!access.value.ready && active == null && worker == null, StoreCode.STALE_GENERATION)
        requireStore(access.value.storeRef == storeRef && readSelection() == storeRef, StoreCode.STALE_GENERATION)
        val denied = readDenial(storeRef)
        requireStore(access.value.reason in setOf(StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED) &&
            denied in setOf(StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED), denied)
        synchronized(commitFence) { requireGeneration(expectedGeneration); openingRef = storeRef }
        var database: ProtectedDatabase? = null
        var published = false
        try {
            val pass = vault.unwrap(storeRef)
            database = try { ProtectedDatabase.open(app, vault.database(storeRef), pass) } finally { pass.fill(0) }
            val dao = database.dao()
            requireStore(dao.refreshAttempt() == null, StoreCode.AUTH_REQUIRED)
            val row = dao.authority() ?: throw StoreFailure(StoreCode.AUTH_REQUIRED)
            try {
                val context = StoreCodec.context(row.contextJson); val lease = StoreCodec.lease(row.leaseJson)
                requireStore(context.capture.account.storeRef == storeRef, StoreCode.SCOPE_DENIED)
                requireStore(context.capture.templateVersion == MAINTENANCE_TEMPLATE, StoreCode.TEMPLATE_UNSUPPORTED)
                LeasePolicy.requireValid(lease, environment.clock())
                transaction(database, expectedGeneration, lease) { reconcileClaims(dao, context, lease) }
                synchronized(commitFence) {
                    requireGeneration(expectedGeneration); environment.requireEligibleUnlockedDevice(); LeasePolicy.requireValid(lease, environment.clock())
                    val id = uuid()
                    window.requireValid(environment.clock())
                    val authority = Active(storeRef, expectedGeneration, ++authorityRevision, database, context, lease, row.accessToken.copyOf(), row.accessExpires, window)
                    worker = authority; workerCapability = id; openingRef = null
                    RestrictedSession(authority, true, id).also { syncSessions += it; published = true }
                }
            } finally { row.accessToken.fill(0); row.refreshToken.fill(0) }
        } finally {
            if (!published) {
                database?.close()
                synchronized(commitFence) { if (openingRef == storeRef) openingRef = null }
            }
        }
    }

    private inner class RestrictedSession(initial: Active, val privateWorker: Boolean, val id: String) : WorkerStoreCapability {
        override val generation = initial.epoch
        override val storeRef = initial.ref
        var revision = initial.revision
        private var retired = false
        private val ownedDetached = mutableSetOf<java.io.Closeable>()
        override val context: AuthorizedContext get() = checked { it.context }

        fun requireCurrent(): Active {
            requireGeneration(generation)
            requireStore(!retired, StoreCode.STALE_GENERATION)
            val value = if (privateWorker) worker?.takeIf { workerCapability == id && !access.value.ready } else active?.takeIf { access.value.ready }
            requireStore(value != null && value.epoch == generation && value.ref == storeRef && value.revision == revision && access.value.storeRef == storeRef,
                StoreCode.STALE_GENERATION)
            environment.requireEligibleUnlockedDevice()
            val now = environment.clock(); value!!.workerWindow?.requireValid(now); LeasePolicy.requireValid(value.lease, now)
            return value
        }
        private fun <T> checked(body: (Active) -> T): T = storage {
            try {
                val current = synchronized(commitFence) { requireCurrent() }
                val result = body(current)
                synchronized(commitFence) { requireCurrent() }
                result
            } catch (failure: StoreFailure) {
                if (privateWorker && failure.code == StoreCode.LOCKED && workerCapability == id) closeWorker()
                throw failure
            }
        }
        private fun <T : java.io.Closeable> own(value: T): T = synchronized(commitFence) {
            try { requireCurrent(); ownedDetached += value; value } catch (failure: Throwable) { value.close(); throw failure }
        }
        override fun beginOnlineRequest() = checked { OnlineRequestAnchor(generation, environment.clock(), it.revision) }
        override fun clock() = checked { environment.clock() }
        override fun serverTimeLowerMillis() = checked { serverNow(it) }
        override fun serverTimeUpperMillis() = checked { LeasePolicy.expiryTimeUpperBound(it.lease, environment.clock()) }
        override fun accessTokenUsable(marginMillis: Long) = checked {
            requireStore(marginMillis in 0..300_000, StoreCode.VALIDATION_ERROR)
            requireStore(it.database.dao().refreshAttempt() == null, StoreCode.AUTH_REQUIRED)
            it.accessExpires > Math.addExact(LeasePolicy.expiryTimeUpperBound(it.lease, environment.clock()), marginMillis)
        }
        override fun credentials() = checked { own(credentials(it, generation)) }
        override fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets) {
            checked { current -> requireStore(anchor.generation == generation, StoreCode.STALE_GENERATION); renew(current, anchor, context, offer, secrets, this) }
        }
        override fun beginRefresh(anchor: OnlineRequestAnchor): StoreRefreshAttempt = checked { current ->
            requireStore(anchor.generation == generation && anchor.authorityRevision == current.revision, StoreCode.STALE_GENERATION)
            val now = environment.clock()
            requireStore(anchor.clock.bootId != null && anchor.clock.bootId == now.bootId && anchor.clock.elapsedMillis <= now.elapsedMillis,
                StoreCode.CLOCK_UNTRUSTED)
            val dao = current.database.dao()
            val row = dao.authority() ?: throw StoreFailure(StoreCode.AUTH_REQUIRED)
            try {
                requireStore(row.refreshExpires > LeasePolicy.expiryTimeUpperBound(current.lease, now), StoreCode.AUTH_REQUIRED)
                val attempt = StoreRefreshAttempt(uuid(), id, generation, revision, current.context.familyId)
                transaction(current.database, generation, current.lease, commitCheck = { requireCurrent() }) {
                    requireStore(dao.refreshAttempt() == null, StoreCode.AUTH_REQUIRED)
                    dao.insertRefreshAttempt(RefreshAttemptRow(attemptId = attempt.id, capabilityId = id, generation = generation,
                        authorityRevision = revision, familyId = current.context.familyId, credentialHash = credentialHash(row.refreshToken),
                        requestStartElapsed = anchor.clock.elapsedMillis, bootId = anchor.clock.bootId!!))
                }
                // No subsequent detached credential read may reuse this uncertain token.
                synchronized(commitFence) { detached.filterIsInstance<SessionSecrets>().forEach { it.close() } }
                attempt
            } finally { row.accessToken.fill(0); row.refreshToken.fill(0) }
        }
        override fun completeRefresh(attempt: StoreRefreshAttempt, anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets) {
            checked { current -> renew(current, anchor, context, offer, secrets, this, attempt) }
        }
        override fun abandonRefresh(attempt: StoreRefreshAttempt) {
            checked { current ->
                requireStore(attempt.capability == id && attempt.generation == generation && attempt.revision == current.revision &&
                    attempt.familyId == current.context.familyId, StoreCode.AUTH_REQUIRED)
                val dao = current.database.dao()
                transaction(current.database, generation, current.lease, commitCheck = { requireCurrent() }) {
                    // The caller asserts the request never left the device; the marker must still be exactly ours.
                    val marker = dao.refreshAttempt()
                    requireStore(marker != null && marker.attemptId == attempt.id && marker.capabilityId == id &&
                        marker.generation == generation && marker.authorityRevision == current.revision &&
                        marker.familyId == current.context.familyId && marker.bootId == environment.clock().bootId, StoreCode.AUTH_REQUIRED)
                    dao.clearRefreshAttempt()
                }
            }
        }
        override fun claimNext(): ClaimedDelivery? = checked { current ->
            claimNext(current, generation) { requireCurrent() }?.let { claim ->
                own(claim)
                ClaimedDelivery(claim, requireClaim(current, claim).attempts)
            }
        }
        override fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt) {
            checked { current -> requireOwnedClaim(claim); commitReceipt(current, claim, receipt) { requireCurrent() } }
        }
        override fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long?) {
            checked { current -> requireOwnedClaim(claim); recordFailure(current, claim, delivery, pause, retryAfterMillis) { requireCurrent() } }
            denialForPause(pause)?.let(::deny)
        }
        private fun requireOwnedClaim(claim: DeliveryClaim) {
            requireStore(claim.generation == generation && claim.storeRef == storeRef && claim in ownedDetached, StoreCode.CLAIM_LOST)
        }
        override fun nextDeliveryDelayMillis(): Long? = checked { current ->
            current.database.dao().refreshAttempt()?.let { marker ->
                // TASK-089 F1: scheduling runs outside the authority gate. Another open session's in-flight refresh is
                // not an uncertain refresh: skip scheduling instead of durably denying (a later reopen repairs it).
                // Any other marker (interrupted/foreign/previous boot) still requires password/proof recovery.
                requireStore(refreshInFlight(marker, current), StoreCode.AUTH_REQUIRED)
                return@checked null
            }
            val dao = current.database.dao(); val now = environment.clock()
            dao.submissions().mapNotNull { submitted ->
                val row = dao.outbox(submitted.operationId) ?: throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
                if (row.delivery !in setOf(DeliveryState.QUEUED.name, DeliveryState.SENDING.name) || row.pause != null ||
                    StoreCodec.capture(StoreCodec.decode(submitted.captureJson)) != current.context.capture) null
                else {
                    val retry = if (row.retryBoot == now.bootId) row.nextAttemptElapsed ?: now.elapsedMillis else now.elapsedMillis
                    val claim = if (row.delivery == DeliveryState.SENDING.name && row.claimBoot == now.bootId && row.claimSession == session)
                        row.claimDeadline ?: now.elapsedMillis else now.elapsedMillis
                    (maxOf(retry, claim) - now.elapsedMillis).coerceIn(0, 86_400_000)
                }
            }.minOrNull()
        }
        override fun deny(reason: StoreCode) = synchronized(ioLock) {
            try {
                val fenced = synchronized(commitFence) { requireCurrent(); invalidateLocked(reason) }
                fence(reason, fenced.generation)
            } catch (failure: StoreFailure) {
                if (privateWorker && workerCapability == id && failure.code in setOf(StoreCode.LOCKED, StoreCode.CLOCK_UNTRUSTED, StoreCode.LEASE_EXPIRED, StoreCode.UNLOCK_REQUIRED)) closeWorker()
                throw failure
            }
            Unit
        }
        fun invalidateMemory() {
            retired = true; ownedDetached.forEach { it.close() }; ownedDetached.clear(); syncSessions.remove(this)
        }
        override fun close() = synchronized(ioLock) {
            synchronized(commitFence) { invalidateMemory() }
            if (privateWorker && workerCapability == id) closeWorker()
            Unit
        }
        override fun toString() = "StoreSyncSession(redacted)"
    }

    private fun credentialHash(value: ByteArray) = java.security.MessageDigest.getInstance("SHA-256").digest(value)
        .joinToString("") { "%02x".format(it) }

    override fun restoreSelection(expectedGeneration: Long): StoreAccess = storage {
        requireGeneration(expectedGeneration); requireStore(active == null, StoreCode.STALE_GENERATION)
        closeWorker()
        val ref = readSelection() ?: return@storage access.value
        val reason = readDenial(ref)
        synchronized(commitFence) {
            requireGeneration(expectedGeneration)
            mutableAccess.value = StoreAccess(expectedGeneration + 1, false, reason, ref)
            access.value
        }
    }

    override fun activateOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets): StoreAccess = storage {
        drainPending()
        requireGeneration(anchor.generation)
        (active ?: worker)?.let { requireStore(anchor.authorityRevision == it.revision, StoreCode.STALE_GENERATION) }
        environment.requireEligibleUnlockedDevice()
        requireStore(context.capture.templateVersion == MAINTENANCE_TEMPLATE, StoreCode.TEMPLATE_UNSUPPORTED)
        val lease = LeasePolicy.accept(anchor.clock, environment.clock(), offer)
        validateSecrets(lease, offer, secrets)
        ensureOwner()
        val ref = context.capture.account.storeRef
        synchronized(commitFence) { requireGeneration(anchor.generation); openingRef = ref }
        closeWorker()
        closeActive()
        var database: ProtectedDatabase? = null
        var published = false
        val token = secrets.copyAccessToken()
        val refresh = secrets.copyRefreshToken()
        try {
            writeDenial(ref, StoreCode.AUTH_REQUIRED, true)
            val pass = if (vault.database(ref).exists() || vault.envelope(ref).exists()) vault.unwrap(ref) else vault.create(ref)
            database = try { ProtectedDatabase.open(app, vault.database(ref), pass) } finally { pass.fill(0) }
            val dao = database.dao()
            transaction(database, anchor.generation, lease) {
                dao.authority()?.let { old ->
                    try { requireStore(StoreCodec.context(old.contextJson).capture.account == context.capture.account, StoreCode.SCOPE_DENIED) }
                    finally { old.accessToken.fill(0); old.refreshToken.fill(0) }
                }
                dao.authority(AuthorityRow(contextJson = StoreCodec.context(context), leaseJson = StoreCodec.lease(lease),
                    accessToken = token, refreshToken = refresh, accessExpires = secrets.accessExpiresServerMillis, refreshExpires = secrets.refreshExpiresServerMillis))
                // Only explicit validated online activation can recover an interrupted rotation.
                dao.clearRefreshAttempt()
                reconcileClaims(dao, context, lease)
                dao.clearAllCache()
            }
            atomicWrite(File(root, "selection"), ref.toByteArray(Charsets.US_ASCII))
            writeDenial(ref, StoreCode.LOCKED, true) // same-boot unlock allowed only after a committed online activation
            synchronized(commitFence) {
                requireGeneration(anchor.generation); environment.requireEligibleUnlockedDevice(); LeasePolicy.requireValid(lease, environment.clock())
                val next = access.value.generation + 1
                active = Active(ref, next, ++authorityRevision, database, context, lease, token.copyOf(), secrets.accessExpiresServerMillis)
                openingRef = null
                mutableAccess.value = StoreAccess(next, true, StoreCode.READY, ref)
                published = true
                access.value
            }
        } finally {
            token.fill(0); refresh.fill(0)
            if (!published) {
                try { writeDenial(ref, StoreCode.AUTH_REQUIRED) } finally { database?.close() }
                synchronized(commitFence) { if (openingRef == ref) openingRef = null }
            }
        }
    }

    override fun renewOnline(anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer, secrets: SessionSecrets): StoreAccess = protected(anchor.generation) { current ->
        renew(current, anchor, context, offer, secrets)
        access.value
    }

    private fun renew(current: Active, anchor: OnlineRequestAnchor, context: AuthorizedContext, offer: LeaseOffer,
        secrets: SessionSecrets, capability: RestrictedSession? = null, attempt: StoreRefreshAttempt? = null) {
        requireStore(anchor.authorityRevision == current.revision, StoreCode.STALE_GENERATION)
        if (context.capture != current.context.capture || context.familyId != current.context.familyId || context.permissionVersion != current.context.permissionVersion || offer.familyExpiresMillis != current.lease.familyExpiresServerMillis) {
            val denied = invalidate(StoreCode.AUTH_REQUIRED); fence(StoreCode.AUTH_REQUIRED, denied.generation)
            throw StoreFailure(StoreCode.CONTEXT_CHANGED)
        }
        val lease = LeasePolicy.accept(anchor.clock, environment.clock(), offer)
        validateSecrets(lease, offer, secrets)
        val token = secrets.copyAccessToken(); val refresh = secrets.copyRefreshToken()
        val dao = current.database.dao()
        var previous: AuthorityRow? = null
        try {
            val old = dao.authority() ?: throw StoreFailure(StoreCode.AUTH_REQUIRED)
            previous = old
            val marker = dao.refreshAttempt()
            if (attempt == null) {
                requireStore(marker == null, StoreCode.AUTH_REQUIRED)
                // GET context cannot silently rotate or replace credentials.
                requireStore(java.security.MessageDigest.isEqual(old.accessToken, token) && java.security.MessageDigest.isEqual(old.refreshToken, refresh) &&
                    old.accessExpires == secrets.accessExpiresServerMillis && old.refreshExpires == secrets.refreshExpiresServerMillis, StoreCode.AUTH_REQUIRED)
            } else {
                requireStore(capability != null && marker != null && attempt.id == marker.attemptId && attempt.capability == capability.id &&
                    marker.capabilityId == capability.id && attempt.generation == current.epoch && marker.generation == current.epoch &&
                    attempt.revision == current.revision && marker.authorityRevision == current.revision &&
                    attempt.familyId == current.context.familyId && marker.familyId == current.context.familyId &&
                    marker.requestStartElapsed == anchor.clock.elapsedMillis && marker.bootId == anchor.clock.bootId &&
                    marker.credentialHash == credentialHash(old.refreshToken), StoreCode.AUTH_REQUIRED)
                requireStore(!java.security.MessageDigest.isEqual(old.refreshToken, refresh), StoreCode.AUTH_REQUIRED)
            }
            transaction(current.database, anchor.generation, current.lease, afterCommit = {
                current.accessToken.fill(0)
                detached.filterIsInstance<SessionSecrets>().forEach { it.close() }
                val renewed = current.copy(revision = ++authorityRevision, context = context, lease = lease,
                    accessToken = token.copyOf(), accessExpires = secrets.accessExpiresServerMillis)
                if (capability?.privateWorker == true) worker = renewed else active = renewed
                capability?.revision = renewed.revision
            }, commitCheck = capability?.let { { it.requireCurrent() } }) {
                dao.authority(AuthorityRow(contextJson = StoreCodec.context(context), leaseJson = StoreCodec.lease(lease),
                    accessToken = token, refreshToken = refresh, accessExpires = secrets.accessExpiresServerMillis, refreshExpires = secrets.refreshExpiresServerMillis))
                if (attempt != null) dao.clearRefreshAttempt()
            }
        } finally { token.fill(0); refresh.fill(0); previous?.accessToken?.fill(0); previous?.refreshToken?.fill(0) }
    }

    private fun validateSecrets(lease: OfflineLease, offer: LeaseOffer, secrets: SessionSecrets) {
        val upper = LeasePolicy.expiryTimeUpperBound(lease, environment.clock())
        requireStore(secrets.accessExpiresServerMillis > upper && secrets.accessExpiresServerMillis <= offer.familyExpiresMillis &&
            secrets.refreshExpiresServerMillis > upper && secrets.refreshExpiresServerMillis <= offer.familyExpiresMillis, StoreCode.AUTH_REQUIRED)
    }

    override fun unlock(expectedGeneration: Long): StoreAccess = storage {
        drainPending(); requireGeneration(expectedGeneration); environment.requireEligibleUnlockedDevice(); ensureOwner()
        requireStore(active == null, StoreCode.STALE_GENERATION)
        closeWorker()
        val ref = readSelection() ?: throw StoreFailure(StoreCode.AUTH_REQUIRED)
        val denied = readDenial(ref)
        requireStore(denied in setOf(StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED), denied)
        synchronized(commitFence) { requireGeneration(expectedGeneration); openingRef = ref }
        var pass: ByteArray? = null
        var database: ProtectedDatabase? = null
        var published = false
        try {
            pass = vault.unwrap(ref)
            database = try { ProtectedDatabase.open(app, vault.database(ref), pass) } finally { pass.fill(0) }
            requireStore(database.dao().refreshAttempt() == null, StoreCode.AUTH_REQUIRED)
            val authority = database.dao().authority() ?: throw StoreFailure(StoreCode.AUTH_REQUIRED)
            try {
                val context = StoreCodec.context(authority.contextJson)
                val lease = StoreCodec.lease(authority.leaseJson)
                requireStore(context.capture.account.storeRef == ref, StoreCode.SCOPE_DENIED)
                LeasePolicy.requireValid(lease, environment.clock())
                transaction(database, expectedGeneration, lease) { reconcileClaims(database.dao(), context, lease) }
                synchronized(commitFence) {
                    requireGeneration(expectedGeneration); environment.requireEligibleUnlockedDevice(); LeasePolicy.requireValid(lease, environment.clock())
                    val next = access.value.generation + 1
                    active = Active(ref, next, ++authorityRevision, database, context, lease, authority.accessToken.copyOf(), authority.accessExpires)
                    openingRef = null; mutableAccess.value = StoreAccess(next, true, StoreCode.READY, ref); published = true; access.value
                }
            } finally { authority.accessToken.fill(0); authority.refreshToken.fill(0) }
        } finally {
            pass?.fill(0)
            if (!published) { database?.close(); synchronized(commitFence) { if (openingRef == ref) openingRef = null } }
        }
    }

    override fun invalidate(reason: StoreCode): StoreAccess = synchronized(commitFence) { invalidateLocked(reason) }

    override fun logoutAndInvalidate(expectedGeneration: Long): LogoutFence = synchronized(commitFence) {
        requireGeneration(expectedGeneration)
        val current = active
        val authorization = if (access.value.ready && current != null) try {
            val now = LeasePolicy.expiryTimeUpperBound(current.lease, environment.clock())
            if (current.accessExpires > now) LogoutAuthorization(current.accessToken) else null
        } catch (_: Exception) { null } else null
        LogoutFence(invalidateLocked(StoreCode.SIGNED_OUT), authorization)
    }

    private fun invalidateLocked(reason: StoreCode): StoreAccess {
        requireStore(reason != StoreCode.READY, StoreCode.VALIDATION_ERROR)
        val prior = access.value
        val next = prior.generation + 1
        val refs = setOfNotNull(prior.storeRef, active?.ref, worker?.ref, openingRef)
        pending[next] = PendingFence(next, refs, active?.epoch, reason, workerCapability)
        active?.accessToken?.fill(0)
        worker?.accessToken?.fill(0)
        syncSessions.toList().forEach { it.invalidateMemory() }
        detached.forEach { it.close() }; detached.clear()
        mutableAccess.value = StoreAccess(next, false, reason, prior.storeRef ?: active?.ref)
        return access.value
    }

    override fun fence(reason: StoreCode, invalidatedGeneration: Long?): StoreAccess {
        val generation = invalidatedGeneration ?: invalidate(reason).generation
        return synchronized(ioLock) {
            val captured = synchronized(commitFence) {
                if (generation in completedFences) null else {
                    val value = pending[generation] ?: throw StoreFailure(StoreCode.STALE_GENERATION)
                    requireStore(value.reason == reason, StoreCode.STALE_GENERATION); value
                }
            }
            if (captured != null) try {
                completeFence(captured)
            } catch (failure: Throwable) {
                // Durable denial failure must never leave its old SQLCipher handle
                // open. Keep the pending record for retry and close under the same
                // IO lock, so a replacement authority cannot enter this fallback.
                try { closeFailedFence(captured.generation) } finally { throw failure }
            }
            access.value
        }
    }

    private fun completeFence(value: PendingFence) {
        value.refs.forEach { writeDenial(it, persistentReason(value.reason)) }
        val current = active
        if (current != null && current.epoch == value.oldEpoch) {
            if (value.reason == StoreCode.SCOPE_DENIED) current.database.runInTransaction { current.database.dao().clearAllCache() }
            closeActive()
        }
        if (value.oldWorkerCapability != null && workerCapability == value.oldWorkerCapability) {
            if (value.reason == StoreCode.SCOPE_DENIED) worker?.database?.let { database -> database.runInTransaction { database.dao().clearAllCache() } }
            closeWorker()
        }
        synchronized(commitFence) { pending.remove(value.generation); completedFences += value.generation }
    }
    private fun drainPending() {
        val values = synchronized(commitFence) { pending.values.toList() }
        values.forEach(::completeFence)
    }

    override fun snapshot(expectedGeneration: Long): LocalSnapshot = protected(expectedGeneration) { current ->
        val dao = current.database.dao()
        LocalSnapshot(current.context, current.lease.deadlineElapsed, serverNow(current), dao.drafts().map { StoreCodec.draft(it.recordJson) },
            dao.submissions().map { submitted -> StoreCodec.outbox(submitted, dao.outbox(submitted.operationId)!!) })
    }

    override fun queuePhoto(generation: Long, operationId: String, reportId: String, revisionId: String, revision: Int, capture: String, bytes: ByteArray) {
        val owned = bytes.copyOf()
        try { protected(generation) { current ->
            listOf(operationId, reportId, revisionId).forEach(::canonicalUuid)
            requireStore(owned.size <= PhotoPolicy.LOCAL_BYTES, StoreCode.VALIDATION_ERROR)
            PhotoPolicy.jpeg(owned); PhotoPolicy.validateCapture(capture)
            transaction(current.database, generation, current.lease) {
                val dao = current.database.dao()
                // Bind to an acknowledged, validated private original revision in this account store.
                val scope = StoreCodec.encode(StoreCodec.capture(current.context.capture))
                requireStore(revision > 0, StoreCode.VALIDATION_ERROR)
                if (dao.photoBinding(reportId, revisionId, revision) == null) {
                    val cached = dao.cached(true).singleOrNull()?.takeIf { it.reportId == reportId && it.revision == revision }
                        ?: throw StoreFailure(StoreCode.NOT_FOUND)
                    val root = StrictJson.objectFrom(cached.validatedJson.toByteArray(), 65536)
                    val receipt = root["receipt"] as? kotlinx.serialization.json.JsonObject ?: throw StoreFailure(StoreCode.RECEIPT_INVALID)
                    val receiptOp = (receipt["operation_id"] as? kotlinx.serialization.json.JsonPrimitive)?.content ?: throw StoreFailure(StoreCode.RECEIPT_INVALID)
                    val validated = ReceiptPolicy.validate(CanonicalJson.bytes(receipt), receiptOp, reportId, revision - 1)
                    requireStore(validated.revisionId == revisionId && validated.revisionNo == revision, StoreCode.RECEIPT_INVALID)
                }
                val old = dao.photo(operationId)
                if (old != null) {
                    try { requireStore(old.reportId == reportId && old.revisionId == revisionId && old.revisionNo == revision &&
                        old.captureJson == capture && old.bytesHash == PhotoPolicy.digest(owned) && old.mediaType == "image/jpeg" && old.filename == "capture.jpg" && old.scopeJson == scope, StoreCode.COMMAND_CONFLICT) }
                    finally { old.bytes?.fill(0) }
                } else {
                    requireStore(dao.photoRevisionCount(reportId, revisionId) < 2 && dao.pendingPhotoCount() < PhotoPolicy.QUEUE_ITEMS &&
                        dao.pendingPhotoBytes() + owned.size <= PhotoPolicy.QUEUE_BYTES, StoreCode.VALIDATION_ERROR)
                    dao.insertPhoto(PhotoRow(operationId, reportId, revisionId, revision, capture, owned, PhotoPolicy.digest(owned), null, "image/jpeg", "capture.jpg", scope))
                }
            }
        } } finally { owned.fill(0) }
    }

    override fun photos(generation: Long, reportId: String, revisionId: String): List<PhotoPending> = protected(generation) { current ->
        canonicalUuid(reportId); canonicalUuid(revisionId)
        current.database.dao().photos(reportId, revisionId, StoreCodec.encode(StoreCodec.capture(current.context.capture))).map { PhotoPending(it.operationId, it.reportId, it.revisionId, it.revisionNo, it.evidenceId) }
    }

    override fun photoUpload(generation: Long, operationId: String): PhotoUpload = protected(generation) { current ->
        val row = current.database.dao().photo(canonicalUuid(operationId)) ?: throw StoreFailure(StoreCode.NOT_FOUND)
        val data = row.bytes ?: throw StoreFailure(StoreCode.ALREADY_RECEIVED)
        try {
            requireStore(row.scopeJson == StoreCodec.encode(StoreCodec.capture(current.context.capture)), StoreCode.CONTEXT_CHANGED)
            requireStore(row.evidenceId == null && PhotoPolicy.digest(data) == row.bytesHash && row.mediaType == "image/jpeg" && row.filename == "capture.jpg", StoreCode.COMMAND_CONFLICT)
            PhotoPolicy.jpeg(data); PhotoPolicy.validateCapture(row.captureJson)
            PhotoUpload(PhotoPending(row.operationId, row.reportId, row.revisionId, row.revisionNo, null), row.captureJson, data).also {
                synchronized(commitFence) { detached += it }
            }
        } finally { data.fill(0) }
    }

    override fun commitPhoto(generation: Long, operationId: String, receipt: PhotoReceipt) { protected(generation) { current ->
        canonicalUuid(receipt.id)
        requireStore(receipt.operationId == canonicalUuid(operationId), StoreCode.RECEIPT_INVALID)
        transaction(current.database, generation, current.lease) {
            val dao = current.database.dao()
            val row = dao.photo(operationId) ?: throw StoreFailure(StoreCode.NOT_FOUND)
            try {
                requireStore(row.scopeJson == StoreCodec.encode(StoreCodec.capture(current.context.capture)), StoreCode.CONTEXT_CHANGED)
                requireStore(row.evidenceId == null || row.evidenceId == receipt.id, StoreCode.RECEIPT_INVALID)
                dao.receivePhoto(operationId, receipt.id)
            } finally { row.bytes?.fill(0) }
        }
    } }

    override fun createDraft(expectedGeneration: Long, commandId: String, content: MaintenanceContent): DraftRecord = protected(expectedGeneration) { current ->
        newDraft(current, expectedGeneration, commandId, "create", content, null, 0, null)
    }
    override fun createCorrectionDraft(expectedGeneration: Long, commandId: String, reportId: String, expectedReportRevision: Int, content: MaintenanceContent, predecessorOperationId: String?): DraftRecord = protected(expectedGeneration) { current ->
        canonicalUuid(reportId); predecessorOperationId?.let(::canonicalUuid)
        requireStore(expectedReportRevision in 1..2147483646, StoreCode.VALIDATION_ERROR)
        newDraft(current, expectedGeneration, commandId, "correction", content, reportId, expectedReportRevision, predecessorOperationId)
    }
    override fun reconcileOperation(expectedGeneration: Long, commandId: String, operationId: String): DraftRecord = protected(expectedGeneration) { current ->
        val submitted = current.database.dao().submitted(canonicalUuid(operationId)) ?: throw StoreFailure(StoreCode.NOT_FOUND)
        val old = current.database.dao().outbox(operationId)!!
        requireStore(old.delivery != DeliveryState.RECEIVED.name, StoreCode.ALREADY_RECEIVED)
        // Explicit reconciliation starts a new report; correcting a returned source requires fresh live authority.
        newDraft(current, expectedGeneration, commandId, "reconcile", RequestPolicy.content(StoreCodec.decode(submitted.contentJson)), null, 0, operationId)
    }
    private fun newDraft(current: Active, generation: Long, commandId: String, kind: String, content: MaintenanceContent, report: String?, expected: Int, predecessor: String?): DraftRecord {
        RequestPolicy.validateDraft(content)
        val input = buildJsonObject { put("content", RequestPolicy.payload(content)); put("report", report); put("expected", expected); put("predecessor", predecessor) }
        return transaction(current.database, generation, current.lease) {
            val dao = current.database.dao()
            replay(dao, commandId, kind, input)?.let { return@transaction StoreCodec.draft(it.resultJson!!) }
            val now = serverNow(current)
            val initialized = if (content.observedAt.isEmpty()) content.copy(observedAt = utc(now)) else content
            val result = DraftRecord(uuid(), 1, initialized, report, expected, predecessor, current.context.capture, now)
            val encoded = StoreCodec.draft(result)
            dao.insertDraft(DraftRow(result.id, result.revision, encoded, null))
            remember(dao, commandId, kind, input, result.id, encoded)
            result
        }
    }

    override fun openDraft(expectedGeneration: Long, draftId: String): DraftRecord = protected(expectedGeneration) { current -> editable(current.database.dao(), draftId).let { StoreCodec.draft(it.recordJson) } }
    override fun saveDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedRevision: Long, content: MaintenanceContent): DraftRecord = protected(expectedGeneration) { current ->
        RequestPolicy.validateDraft(content)
        val input = draftInput(draftId, expectedRevision, content)
        transaction(current.database, expectedGeneration, current.lease) {
            val dao = current.database.dao()
            replay(dao, commandId, "save", input)?.let { return@transaction StoreCodec.draft(it.resultJson!!) }
            val old = editable(dao, draftId)
            requireStore(old.revision == expectedRevision && expectedRevision < Long.MAX_VALUE, StoreCode.STALE_DRAFT)
            val before = StoreCodec.draft(old.recordJson)
            requireStore(before.capture == current.context.capture, StoreCode.CONTEXT_CHANGED)
            val result = before.copy(revision = expectedRevision + 1, content = content, savedAtServerMillis = serverNow(current))
            val encoded = StoreCodec.draft(result)
            dao.updateDraft(old.copy(revision = result.revision, recordJson = encoded)); remember(dao, commandId, "save", input, result.id, encoded)
            result
        }
    }

    override fun queueDraft(expectedGeneration: Long, commandId: String, draftId: String, expectedDraftRevision: Long, expectedReportRevision: Int, content: MaintenanceContent): OutboxRecord = protected(expectedGeneration) { current ->
        val input = JsonObject(draftInput(draftId, expectedDraftRevision, content) + ("expected_report" to JsonPrimitive(expectedReportRevision)))
        transaction(current.database, expectedGeneration, current.lease) {
            val dao = current.database.dao()
            replay(dao, commandId, "queue", input)?.let { return@transaction StoreCodec.outbox(dao.submitted(it.resultId)!!, dao.outbox(it.resultId)!!) }
            val old = editable(dao, draftId)
            requireStore(old.revision == expectedDraftRevision, StoreCode.STALE_DRAFT)
            val draft = StoreCodec.draft(old.recordJson)
            requireStore(draft.capture == current.context.capture, StoreCode.CONTEXT_CHANGED)
            requireStore(draft.expectedReportRevision == expectedReportRevision, StoreCode.STALE_DRAFT)
            val now = serverNow(current); val operation = uuid(); val report = draft.reportId ?: uuid()
            val request = RequestPolicy.request(operation, report, expectedReportRevision, content, now)
            val submitted = SubmittedRow(operation, report, expectedReportRevision, CanonicalJson.bytes(request), RequestPolicy.requestHash(request),
                StoreCodec.encode(RequestPolicy.payload(content)), StoreCodec.encode(StoreCodec.capture(draft.capture)), now, draft.predecessorOperationId)
            val outbox = OutboxRow(operation, DeliveryState.QUEUED.name, null)
            dao.insertSubmitted(submitted); dao.insertOutbox(outbox); dao.updateDraft(old.copy(submittedOperation = operation))
            remember(dao, commandId, "queue", input, operation, null)
            StoreCodec.outbox(submitted, outbox)
        }
    }

    override fun claimNext(expectedGeneration: Long): DeliveryClaim? = protected(expectedGeneration) { current -> claimNext(current, expectedGeneration) }
    private fun claimNext(current: Active, expectedGeneration: Long, check: (() -> Unit)? = null): DeliveryClaim? {
        var created: DeliveryClaim? = null
        try { return transaction(current.database, expectedGeneration, current.lease, commitCheck = check) {
            requireStore(current.database.dao().refreshAttempt() == null, StoreCode.AUTH_REQUIRED)
            val dao = current.database.dao(); val now = environment.clock()
            for (submitted in dao.submissions()) {
                var row = dao.outbox(submitted.operationId)!!
                if (row.delivery in setOf(DeliveryState.RECEIVED.name, DeliveryState.NEEDS_CORRECTION.name, DeliveryState.CONFLICT.name)) continue
                if (StoreCodec.capture(StoreCodec.decode(submitted.captureJson)) != current.context.capture) {
                    dao.updateOutbox(clearClaim(row).copy(pause = PauseReason.CONTEXT_CHANGED.name)); continue
                }
                if (row.pause != null) continue
                if (row.delivery == DeliveryState.SENDING.name && row.claimSession == session && row.claimBoot == now.bootId && (row.claimDeadline ?: 0) > now.elapsedMillis) continue
                if (row.retryBoot == now.bootId && (row.nextAttemptElapsed ?: 0) > now.elapsedMillis) continue
                requireStore(row.attempts < Int.MAX_VALUE, StoreCode.STORAGE_UNAVAILABLE)
                val deadline = minOf(current.lease.deadlineElapsed, Math.addExact(now.elapsedMillis, 120_000L))
                row = row.copy(delivery = DeliveryState.SENDING.name, attempts = row.attempts + 1, nextAttemptElapsed = null, retryBoot = null,
                    claimToken = uuid(), claimSession = session, claimBoot = now.bootId, claimDeadline = deadline, claimGeneration = expectedGeneration)
                dao.updateOutbox(row)
                val claim = DeliveryClaim(expectedGeneration, current.ref, submitted.operationId, submitted.reportId, submitted.expectedRevision,
                    submitted.requestHash, row.claimToken!!, session, now.bootId!!, deadline, submitted.requestBytes)
                created = claim
                synchronized(commitFence) { detached += claim }
                return@transaction claim
            }
            null
        } } catch (failure: Throwable) {
            created?.let { value -> synchronized(commitFence) { value.close(); detached.remove(value) } }
            throw failure
        }
    }
    override fun commitReceipt(claim: DeliveryClaim, receipt: AcceptedReceipt) { protected(claim.generation) { current -> commitReceipt(current, claim, receipt) } }
    private fun commitReceipt(current: Active, claim: DeliveryClaim, receipt: AcceptedReceipt, check: (() -> Unit)? = null) {
        transaction(current.database, claim.generation, current.lease, commitCheck = check) {
            val dao = current.database.dao(); val row = requireClaim(current, claim)
            requireStore(receipt.operationId == claim.operationId && receipt.reportId == claim.reportId && receipt.revisionNo == claim.expectedRevision + 1, StoreCode.RECEIPT_INVALID)
            dao.receipt(ReceiptRow(receipt.operationId, receipt.reportId, receipt.revisionId, receipt.revisionNo))
            dao.updateOutbox(clearClaim(row).copy(delivery = DeliveryState.RECEIVED.name, pause = null, nextAttemptElapsed = null))
        }
        claim.close()
    }
    override fun recordFailure(claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long?) {
      protected(claim.generation) { current ->
        recordFailure(current, claim, delivery, pause, retryAfterMillis)
      }
      val denied = denialForPause(pause)
      if (denied != null) {
          // Fence only the authority which issued this claim; a delayed error cannot close a new account.
          val fenced = synchronized(commitFence) {
              if (access.value.generation == claim.generation && access.value.ready) invalidateLocked(denied) else null
          }
          if (fenced != null) fence(denied, fenced.generation)
      }
    }
    private fun recordFailure(current: Active, claim: DeliveryClaim, delivery: DeliveryState, pause: PauseReason?, retryAfterMillis: Long?, check: (() -> Unit)? = null) {
        requireStore(delivery in setOf(DeliveryState.QUEUED, DeliveryState.CONFLICT, DeliveryState.NEEDS_CORRECTION), StoreCode.VALIDATION_ERROR)
        requireStore(retryAfterMillis == null || retryAfterMillis in 0..86_400_000L, StoreCode.VALIDATION_ERROR)
        transaction(current.database, claim.generation, current.lease, commitCheck = check) {
            val dao = current.database.dao(); val row = requireClaim(current, claim); val now = environment.clock()
            dao.updateOutbox(clearClaim(row).copy(delivery = delivery.name, pause = pause?.name,
                nextAttemptElapsed = retryAfterMillis?.let { Math.addExact(now.elapsedMillis, it) }, retryBoot = now.bootId))
        }
        claim.close()
    }
    private fun denialForPause(pause: PauseReason?) = when (pause) {
          PauseReason.AUTH_REQUIRED -> StoreCode.AUTH_REQUIRED
          PauseReason.LOCKED -> StoreCode.LOCKED
          PauseReason.LEASE_EXPIRED -> StoreCode.LEASE_EXPIRED
          PauseReason.REVOKED -> StoreCode.REVOKED
          PauseReason.SCOPE_DENIED -> StoreCode.SCOPE_DENIED
          else -> null
    }
    override fun retryOperation(expectedGeneration: Long, operationId: String) { protected(expectedGeneration) { current ->
        transaction(current.database, expectedGeneration, current.lease) {
            val dao = current.database.dao(); val row = dao.outbox(canonicalUuid(operationId)) ?: throw StoreFailure(StoreCode.NOT_FOUND)
            requireStore(row.delivery != DeliveryState.RECEIVED.name, StoreCode.ALREADY_RECEIVED)
            requireStore(row.delivery == DeliveryState.QUEUED.name && row.pause == null, StoreCode.CONTEXT_CHANGED)
            // Manual action cannot bypass a server Retry-After (or conservatively retained backoff).
            val now = environment.clock()
            if (row.retryBoot != now.bootId || (row.nextAttemptElapsed ?: 0) <= now.elapsedMillis)
                dao.updateOutbox(row.copy(nextAttemptElapsed = null, retryBoot = null))
        }
    } }

    override fun credentials(expectedGeneration: Long): SessionSecrets = protected(expectedGeneration) { current -> credentials(current, expectedGeneration) }
    private fun credentials(current: Active, expectedGeneration: Long): SessionSecrets {
        requireStore(current.database.dao().refreshAttempt() == null, StoreCode.AUTH_REQUIRED)
        val authority = current.database.dao().authority() ?: throw StoreFailure(StoreCode.AUTH_REQUIRED)
        try {
            requireStore(authority.refreshExpires > LeasePolicy.expiryTimeUpperBound(current.lease, environment.clock()), StoreCode.AUTH_REQUIRED)
            return SessionSecrets(authority.accessToken, authority.refreshToken, authority.accessExpires, authority.refreshExpires).also {
                synchronized(commitFence) { requireGeneration(expectedGeneration); detached += it }
            }
        } finally { authority.accessToken.fill(0); authority.refreshToken.fill(0) }
    }
    override fun cacheReports(expectedGeneration: Long, reports: List<CachedReport>) { protected(expectedGeneration) { current ->
        requireStore(reports.size <= 100 && reports.map { it.reportId }.distinct().size == reports.size, StoreCode.VALIDATION_ERROR)
        val validated = reports.map { ReportCachePolicy.validate(it, false) }
        transaction(current.database, expectedGeneration, current.lease) {
            current.database.dao().clearCache(false); current.database.dao().cache(validated.map { cacheRow(it, false) })
        }
    } }
    override fun cachedReports(expectedGeneration: Long): List<CachedReport> = protected(expectedGeneration) { current -> current.database.dao().cached(false).map(::cachedReport) }
    override fun cacheOpenedRevision(expectedGeneration: Long, report: CachedReport) { protected(expectedGeneration) { current ->
        val validated = ReportCachePolicy.validate(report, true)
        transaction(current.database, expectedGeneration, current.lease) { current.database.dao().clearCache(true); current.database.dao().cache(listOf(cacheRow(validated, true))) }
    } }
    override fun cachedOpenedRevision(expectedGeneration: Long, reportId: String, revision: Int): CachedReport? = protected(expectedGeneration) { current ->
        current.database.dao().cached(true).singleOrNull()?.takeIf { it.reportId == reportId && it.revision == revision }?.let(::cachedReport)
    }

    private fun requireClaim(current: Active, claim: DeliveryClaim): OutboxRow {
        val row = current.database.dao().outbox(claim.operationId) ?: throw StoreFailure(StoreCode.CLAIM_LOST)
        val now = environment.clock()
        requireStore(current.ref == claim.storeRef && row.delivery == DeliveryState.SENDING.name && row.claimToken == claim.claimToken &&
            row.claimSession == claim.claimSession && row.claimBoot == claim.claimBoot && row.claimGeneration == claim.generation &&
            row.claimDeadline == claim.claimDeadline && now.bootId == claim.claimBoot && now.elapsedMillis < claim.claimDeadline, StoreCode.CLAIM_LOST)
        return row
    }
    private fun reconcileClaims(dao: ProtectedDao, context: AuthorizedContext, lease: OfflineLease) {
        dao.submissions().forEach { submitted ->
            val row = dao.outbox(submitted.operationId)!!
            if (row.delivery != DeliveryState.RECEIVED.name) {
                val same = StoreCodec.capture(StoreCodec.decode(submitted.captureJson)) == context.capture
                dao.updateOutbox(clearClaim(row).copy(pause = if (same) null else PauseReason.CONTEXT_CHANGED.name,
                    nextAttemptElapsed = if (row.retryBoot == lease.bootId) row.nextAttemptElapsed else null))
            }
        }
    }
    private fun clearClaim(row: OutboxRow) = row.copy(delivery = if (row.delivery == DeliveryState.SENDING.name) DeliveryState.QUEUED.name else row.delivery,
        claimToken = null, claimSession = null, claimBoot = null, claimDeadline = null, claimGeneration = null)
    private fun editable(dao: ProtectedDao, id: String): DraftRow {
        val row = dao.draft(canonicalUuid(id)) ?: throw StoreFailure(StoreCode.NOT_FOUND)
        requireStore(row.submittedOperation == null, StoreCode.STALE_DRAFT); return row
    }
    private fun replay(dao: ProtectedDao, id: String, kind: String, input: JsonObject): CommandRow? {
        canonicalUuid(id)
        return dao.command(id)?.also { requireStore(it.kind == kind && it.inputHash == StoreCodec.commandHash(kind, input), StoreCode.COMMAND_CONFLICT) }
    }
    private fun remember(dao: ProtectedDao, id: String, kind: String, input: JsonObject, result: String, encoded: String?) = dao.command(CommandRow(id, kind, StoreCodec.commandHash(kind, input), result, encoded))
    private fun draftInput(id: String, revision: Long, content: MaintenanceContent) = buildJsonObject { put("draft", id); put("revision", revision); put("content", RequestPolicy.payload(content)) }
    private fun cacheRow(report: CachedReport, opened: Boolean) = CacheRow(if (opened) "opened" else report.reportId, report.reportId, report.revision, report.validatedJson, report.checkedAtServerMillis, opened)
    private fun cachedReport(row: CacheRow) = CachedReport(row.reportId, row.revision, row.validatedJson, row.checkedAt)
    private fun serverNow(current: Active) = LeasePolicy.estimatedServerTime(current.lease, environment.clock())
    private fun uuid() = UUID.randomUUID().toString()
    private fun utc(now: Long) = SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'", Locale.ROOT).apply { timeZone = TimeZone.getTimeZone("UTC") }.format(Date(now))

    private fun <T> transaction(database: ProtectedDatabase, generation: Long, lease: OfflineLease?, afterCommit: (() -> Unit)? = null,
        commitCheck: (() -> Unit)? = null, body: () -> T): T {
        database.beginTransaction()
        var ended = false
        try {
            val result = body(); beforeCommit?.invoke()
            synchronized(commitFence) {
                requireGeneration(generation)
                commitCheck?.invoke()
                environment.requireEligibleUnlockedDevice()
                if (lease != null) LeasePolicy.requireValid(lease, environment.clock())
                database.setTransactionSuccessful(); database.endTransaction(); ended = true
                afterCommit?.invoke()
            }
            return result
        } finally { if (!ended) database.endTransaction() }
    }
    private fun <T> protected(generation: Long, body: (Active) -> T): T = storage {
        val current = requireActive(generation)
        val result = body(current)
        synchronized(commitFence) {
            requireGeneration(generation)
            environment.requireEligibleUnlockedDevice()
            val published = active ?: throw StoreFailure(StoreCode.STALE_GENERATION)
            LeasePolicy.requireValid(published.lease, environment.clock())
        }
        result
    }
    private fun requireActive(generation: Long): Active {
        requireGeneration(generation)
        val current = active
        requireStore(access.value.ready && current != null && current.epoch == generation, access.value.reason)
        environment.requireEligibleUnlockedDevice(); LeasePolicy.requireValid(current!!.lease, environment.clock())
        return current
    }
    /** A marker owned by a still-open session of this repository, at the current generation, revision and boot. */
    private fun refreshInFlight(marker: RefreshAttemptRow, current: Active): Boolean = synchronized(commitFence) {
        marker.generation == current.epoch && marker.authorityRevision == current.revision &&
            marker.bootId == environment.clock().bootId &&
            syncSessions.any { it.id == marker.capabilityId && it.generation == marker.generation }
    }
    private fun requireGeneration(generation: Long) { requireStore(!closed && access.value.generation == generation, StoreCode.STALE_GENERATION) }
    private fun <T> storage(body: () -> T): T = synchronized(ioLock) {
        try { requireStore(!closed, StoreCode.STORAGE_UNAVAILABLE); body() }
        catch (failure: Exception) {
            val safe = safeFailure(failure)
            if (safe.code in setOf(StoreCode.LEASE_EXPIRED, StoreCode.CLOCK_UNTRUSTED, StoreCode.KEY_UNAVAILABLE, StoreCode.UNLOCK_REQUIRED,
                    StoreCode.UNSUPPORTED_DEVICE, StoreCode.AUTH_REQUIRED, StoreCode.REVOKED, StoreCode.SCOPE_DENIED, StoreCode.STORAGE_UNAVAILABLE, StoreCode.TEMPLATE_UNSUPPORTED)) {
                val fenced = invalidate(safe.code)
                try { fence(safe.code, fenced.generation) } catch (_: Exception) { closeFailedFence(fenced.generation) }
            }
            throw safe
        }
    }
    private fun safeFailure(failure: Exception): StoreFailure {
        if (failure is StoreFailure) return failure
        val ownFrames = failure.stackTrace.filter { it.className.startsWith("org.kapit.c2.mobile.") }
            .take(5).map { "${it.className}.${it.methodName}" }
        try { unexpectedFailureObserver?.invoke(failure.javaClass.name, ownFrames) } catch (_: Exception) { /* Cannot affect denial. */ }
        return StoreFailure(StoreCode.STORAGE_UNAVAILABLE)
    }
    private fun persistentReason(reason: StoreCode) = when (reason) {
        StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED -> StoreCode.LOCKED
        else -> reason
    }
    private fun writeDenial(ref: String, reason: StoreCode, onlineTransition: Boolean = false) {
        val directory = vault.directory(ref)
        requireStore(directory.isDirectory || directory.mkdirs(), StoreCode.STORAGE_UNAVAILABLE)
        if (!onlineTransition && reason in setOf(StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED) &&
            File(directory, "access.state").exists() && readDenial(ref) !in setOf(StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED)) return
        atomicWrite(File(directory, "access.state"), reason.name.toByteArray(Charsets.US_ASCII))
    }
    private fun readDenial(ref: String): StoreCode = try {
        val bytes = AtomicFile(File(vault.directory(ref), "access.state")).readFully()
        requireStore(bytes.size <= 64, StoreCode.AUTH_REQUIRED); StoreCode.valueOf(bytes.toString(Charsets.US_ASCII))
    } catch (_: Exception) { StoreCode.AUTH_REQUIRED }
    private fun readSelection(): String? {
        if (!File(root, "selection").exists()) return null
        return try { AtomicFile(File(root, "selection")).readFully().toString(Charsets.US_ASCII).also { vault.directory(it) } }
        catch (_: Exception) { throw StoreFailure(StoreCode.AUTH_REQUIRED) }
    }
    private fun ensureOwner() {
        if (ownerLock != null) return
        requireStore(root.isDirectory || root.mkdirs(), StoreCode.STORAGE_UNAVAILABLE)
        val channel = RandomAccessFile(File(root, "owner.lock"), "rw").channel
        try { ownerLock = channel.tryLock() ?: throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE); ownerChannel = channel }
        catch (_: Exception) { channel.close(); throw StoreFailure(StoreCode.STORAGE_UNAVAILABLE) }
    }
    private fun closeActive() {
        val previous = synchronized(commitFence) { active.also {
            syncSessions.filter { capability -> !capability.privateWorker && capability.generation == it?.epoch }.toList().forEach { capability -> capability.invalidateMemory() }
            active = null; it?.accessToken?.fill(0); detached.forEach { secret -> secret.close() }; detached.clear()
        } }
        previous?.database?.close()
    }
    private fun closeWorker() {
        val previous = synchronized(commitFence) {
            val id = workerCapability
            syncSessions.filter { it.privateWorker && it.id == id }.toList().forEach { it.invalidateMemory() }
            worker.also { worker = null; workerCapability = null; it?.accessToken?.fill(0) }
        }
        previous?.database?.close()
    }
    private fun backgroundFence(reason: StoreCode) {
        val fenced = synchronized(commitFence) {
            if (closed || (!access.value.ready && worker == null)) null else invalidateLocked(reason)
        } ?: return
        cleanup.execute { try { fence(reason, fenced.generation) } catch (_: Exception) { closeFailedFence(fenced.generation) } }
    }
    /** Compare both generation and exact authority revision; stale monitoring cannot close a renewal/account. */
    internal fun invalidateObservedAuthority(generation: Long, revision: Long, reason: StoreCode): StoreAccess? {
        val fenced = synchronized(commitFence) {
            val observed = active?.takeIf { access.value.ready } ?: worker
            if (closed || observed?.epoch != generation || observed.revision != revision) null else invalidateLocked(reason)
        } ?: return null
        cleanup.execute { try { fence(reason, fenced.generation) } catch (_: Exception) { closeFailedFence(fenced.generation) } }
        return fenced
    }
    /** A delayed metadata-write failure can only close the handle captured by that fence. */
    internal fun closeFailedFence(generation: Long) = synchronized(ioLock) {
        val captured = synchronized(commitFence) { pending[generation] }
        if (captured?.oldEpoch != null && active?.epoch == captured.oldEpoch) closeActive()
        if (captured?.oldWorkerCapability != null && workerCapability == captured.oldWorkerCapability) closeWorker()
    }
    override fun close() {
        if (closed) return
        val reason = if (access.value.ready || access.value.reason in setOf(StoreCode.READY, StoreCode.LOCKED, StoreCode.UNLOCK_REQUIRED)) StoreCode.LOCKED else access.value.reason
        val fenced = invalidate(reason)
        synchronized(ioLock) {
            try { fence(reason, fenced.generation) } finally {
                closed = true; closeActive(); closeWorker(); lifecycle?.close(); cleanup.shutdownNow(); ownerLock?.release(); ownerChannel?.close()
            }
        }
    }
}

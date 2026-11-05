package org.kapit.c2.mobile

import android.content.Context
import android.os.Build
import android.os.Looper
import androidx.annotation.RequiresApi
import java.io.Closeable
import kotlinx.coroutines.*
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import org.kapit.c2.mobile.data.local.AndroidProtectedRepository
import org.kapit.c2.mobile.data.remote.MobileProtocolClient
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.security.AndroidAccessEnvironment
import org.kapit.c2.mobile.sync.*
import org.kapit.c2.mobile.ui.MobileRuntime

/** One process owner. Constructors/facade creation perform no TLS, Keystore or filesystem opening. */
@RequiresApi(35)
class AppContainer internal constructor(
    context: Context,
    private val storageFactory: () -> RuntimeStorage = { StorageAdapter(AndroidProtectedRepository(context.applicationContext)) },
    private val dispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val workQueue: WorkQueue = AndroidWorkQueue(context.applicationContext),
) : Closeable {
    private val app = context.applicationContext
    private val endpointConfigured = BuildConfig.MOBILE_API_BASE_URL.isNotEmpty()
    private val scope = CoroutineScope(SupervisorJob() + dispatcher)
    private val requireIo = { check(Looper.myLooper() != Looper.getMainLooper()) { "MOBILE_IO_REQUIRED" } }
    private val backgroundScheduler = OwnedScheduler(workQueue, scope, android.os.SystemClock::elapsedRealtime)
    private val owner = RuntimeRepositoryOwner(scope, storageFactory, dispatcher, requireIo, ::scheduleReleased)
    private val networkGate = Mutex()
    private val authorityGate = Mutex()
    private var network: NetworkServices? = null
    private val workerJobs = mutableMapOf<Job, Long>()
    private val workerMonitor = Any()

    init {
        check(Build.VERSION.SDK_INT >= 35)
        scope.launch {
            try {
                owner.storage().repository.access.collect { access ->
                    val stale = synchronized(workerMonitor) { workerJobs.filterValues { it != access.generation }.keys.toList() }
                    stale.forEach(Job::cancel)
                }
            } catch (_: Exception) { /* The lazy repository exposes a safe storage failure to its caller. */ }
        }
    }

    fun createMobileRuntime(): MobileRuntime {
        backgroundScheduler.cancel()
        val scheduler = OwnedScheduler(workQueue, scope, android.os.SystemClock::elapsedRealtime)
        lateinit var lease: RuntimeRepository
        lease = owner.acquire { access ->
            scope.launch {
                try {
                    if (!lease.isCurrent() || !endpointConfigured || lease.access.value != access || access.storeRef == null) return@launch
                    val delay = if (access.ready) owner.storage().foreground(access.generation).use { it.nextDeliveryDelayMillis() }
                        else if (access.reason == StoreCode.LOCKED) 0L else null
                    if (delay == null) return@launch
                    val epoch = scheduler.capture()
                    val scheduled = scheduler.schedule(epoch, access.storeRef, delay)
                    if (scheduled != null && (!lease.isCurrent() || lease.access.value != access)) scheduler.cancel(scheduled)
                } catch (_: Exception) { /* A later authorized reopen repairs scheduling. */ }
            }
        }
        val live = LiveMobilePort(endpointConfigured,
            { owner.storage() }, { services() }, lease::isCurrent, scheduler)
        return MobileRuntime(lease, live)
    }

    private fun scheduleReleased(access: StoreAccess) {
        if (!endpointConfigured) return
        val epoch = backgroundScheduler.capture()
        scope.launch {
            try {
                if (!owner.isUnowned(access)) return@launch
                val scheduled = backgroundScheduler.schedule(epoch, access.storeRef!!, 0)
                if (scheduled != null && !owner.isUnowned(access)) backgroundScheduler.cancel(scheduled)
            } catch (_: Exception) { /* Authorized reopen repairs a missed scheduling attempt. */ }
        }
    }

    internal suspend fun services(): NetworkServices = withContext(dispatcher) {
        requireIo()
        if (!endpointConfigured) throw StoreFailure(StoreCode.AUTH_REQUIRED)
        networkGate.withLock {
            network ?: run {
                val store = owner.storage()
                val environment = AndroidAccessEnvironment(app)
                val protocol = ProtocolAdapter(MobileProtocolClient.configured(environment::clock))
                NetworkServices(protocol, EnrollmentService(store.repository, store.journal, protocol, authorityGate),
                    SyncEngine(protocol, gate = authorityGate)).also { network = it }
            }
        }
    }

    /** Opaque WorkManager input is resolved against the current owner after process restoration. */
    internal suspend fun runWorker(storeRef: String): SyncOutcome = withContext(dispatcher) {
        if (!endpointConfigured || !Regex("[0-9a-f]{64}").matches(storeRef)) throw StoreFailure(StoreCode.AUTH_REQUIRED)
        val store = owner.storage()
        val initial = store.repository.access.value
        if (initial.storeRef == null) store.repository.restoreSelection(initial.generation)
        val access = store.repository.access.value
        if (access.storeRef != storeRef) throw StoreFailure(StoreCode.STALE_GENERATION)
        val session = if (access.ready) store.foreground(access.generation) else store.worker(storeRef)
        session.use {
            val job = currentCoroutineContext()[Job] ?: throw StoreFailure(StoreCode.STALE_GENERATION)
            synchronized(workerMonitor) { workerJobs[job] = session.generation }
            try {
                session.beginOnlineRequest()
                services().sync.drain(session)
            } finally { synchronized(workerMonitor) { workerJobs.remove(job) } }
        }
    }

    internal suspend fun storageForIntegration(): RuntimeStorage = owner.storage()

    /** Explicit final owner teardown, used by owned integration lifecycle tests only. */
    override fun close() {
        requireIo()
        network?.close()
        owner.close()
        scope.cancel()
    }
}


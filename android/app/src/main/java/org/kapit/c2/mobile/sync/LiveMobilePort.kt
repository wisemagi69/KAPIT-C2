package org.kapit.c2.mobile.sync

import androidx.annotation.RequiresApi
import java.io.Closeable
import java.time.Instant
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.ensureActive
import org.kapit.c2.mobile.data.remote.*
import org.kapit.c2.mobile.domain.*
import org.kapit.c2.mobile.ui.*

internal class NetworkServices(val protocol: RemoteProtocol, val enrollment: EnrollmentService, val sync: SyncEngine) : Closeable {
    override fun close() = protocol.close()
}

internal interface DeliveryScheduler {
    fun capture(): ScheduleEpoch
    suspend fun schedule(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long): ScheduleEpoch?
    suspend fun cancel(epoch: ScheduleEpoch)
    /** Rotate immediately; cancel only the captured old chain, including its continuations. */
    fun cancel()
}

internal suspend fun DeliveryScheduler.schedule(storeRef: String, delayMillis: Long) = schedule(capture(), storeRef, delayMillis)

/** A foreground lease owns only its calls; closing it never closes the process HTTP client. */
@RequiresApi(35)
internal class LiveMobilePort(
    override val available: Boolean,
    private val storage: suspend () -> RuntimeStorage,
    private val services: suspend () -> NetworkServices,
    private val leaseIsCurrent: () -> Boolean,
    private val scheduler: DeliveryScheduler,
) : MobileLivePort {
    private val monitor = Any()
    private val calls = mutableMapOf<Long, MutableSet<Job>>()
    private var closed = false
    override suspend fun uploadPhoto(generation: Long, operationId: String) = tracked(generation) {
        val store = storage()
        store.foreground(generation).use { session ->
            store.repository.photoUpload(generation, operationId).use { photo ->
                val network = services()
                val receipt = network.sync.protectedRead(session) { network.protocol.uploadPhoto(it, photo) }
                currentCoroutineContext().ensureActive()
                session.beginOnlineRequest()
                store.repository.commitPhoto(generation, operationId, receipt)
            }
        }
    }
    override suspend fun photoStatus(generation: Long, evidenceId: String) = tracked(generation) {
        storage().foreground(generation).use { session ->
            val network = services()
            network.sync.protectedRead(session) { network.protocol.photoStatus(it, evidenceId) }
        }
    }

    override suspend fun authenticate(anchor: OnlineRequestAnchor, purpose: SignInPurpose, username: String, password: String): MobileSession =
        tracked(anchor.generation) { services().enrollment.authenticate(anchor, purpose, username, password) }

    override suspend fun synchronize(generation: Long): MobileSyncOutcome = tracked(generation) {
        storage().foreground(generation).use { session ->
            val result = services().sync.drain(session)
            result.nextDelayMillis?.let {
                val epoch = scheduler.capture()
                val scheduled = scheduler.schedule(epoch, session.storeRef, it)
                if (scheduled != null && (!leaseIsCurrent() || storage().repository.access.value.generation != generation)) scheduler.cancel(scheduled)
            }
            MobileSyncOutcome(result.serviceReached)
        }
    }

    override suspend fun reports(generation: Long, filter: ReportFilterUi, page: Int): ReportPageUi = tracked(generation) {
        val store = storage()
        store.foreground(generation).use { session ->
            val network = services()
            val result = network.sync.protectedRead(session) { network.protocol.reports(it, ReportQuery(RemoteReportStatus.valueOf(filter.name), page = page)) }
            val checked = session.serverTimeLowerMillis()
            store.repository.cacheReports(generation, result.results.map { it.cached(checked) })
            ReportPageUi(true, result.results.map { item -> ReportSummaryUi(item.id, item.reference, category(item.category), item.areaLabel,
                item.observedDate, item.revision, status(item.status)) }, filter, result.page, result.totalPages.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                result.count.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(), label(checked))
        }
    }

    override suspend fun report(generation: Long, reportId: String, revision: Int): ReportDetailUi = tracked(generation) {
        loadReport(generation, reportId, revision, false)
    }

    override suspend fun correction(generation: Long, reportId: String, revision: Int): ReportDetailUi = tracked(generation) {
        loadReport(generation, reportId, revision, true)
    }

    private suspend fun loadReport(generation: Long, reportId: String, revision: Int, correction: Boolean): ReportDetailUi {
        val store = storage()
        return store.foreground(generation).use { session ->
            val network = services()
            val result = network.sync.protectedRead(session) { network.protocol.revision(it, reportId, revision) }
            if (correction && (!result.canCorrect || result.report.status != RemoteReportStatus.RETURNED)) throw StoreFailure(StoreCode.STALE_DRAFT)
            val checked = session.serverTimeLowerMillis()
            // Large valid online revisions remain visible when intentionally omitted from the64KiB cache.
            result.cacheOrNull(checked)?.let { store.repository.cacheOpenedRevision(generation, it) }
            val report = result.report
            val content = result.payload
            val processing = when (report.status) {
                RemoteReportStatus.PENDING -> ProcessingUi.PENDING
                RemoteReportStatus.PROCESSING -> ProcessingUi.PROCESSING
                RemoteReportStatus.FAILED -> ProcessingUi.FAILED
                else -> ProcessingUi.PREPARED
            }
            val review = when (report.status) {
                RemoteReportStatus.AWAITING_REVIEW -> ReviewUi.AWAITING_REVIEW
                RemoteReportStatus.APPROVED -> ReviewUi.APPROVED
                RemoteReportStatus.RETURNED -> ReviewUi.RETURNED
                RemoteReportStatus.REJECTED -> ReviewUi.REJECTED
                else -> ReviewUi.NOT_READY
            }
            ReportDetailUi(report.id, report.reference, report.revision,
                MaintenanceForm(content.observedAt, MaintenanceCategory.entries.single { it.wireValue == content.category },
                    MaintenanceUrgency.entries.single { it.wireValue == content.urgency }, MaintenanceArea.entries.single { it.wireValue == content.areaLabel },
                    content.siteLabel, content.reporterLabel, content.narrative, MaintenanceAssistance.entries.single { it.wireValue == content.assistanceRequested }),
                DeliveryUi.RECEIVED, processing, review, SharingUi.UNKNOWN, report.feedback, result.canCorrect, label(checked),
                result.history.map { ReportHistoryUi(it.revision, it.receivedAt, status(it.status)) },
                result.receipt.revisionId, store.repository.photos(generation, report.id, result.receipt.revisionId))
        }
    }

    override suspend fun logout(authorization: LogoutAuthorization): LogoutConfirmation {
        // Local generation is already fenced. The narrow detached token is the sole authority here.
        if (!available || synchronized(monitor) { closed }) return LogoutConfirmation.UNCONFIRMED
        val token = authorization.copyAccessToken()
        return try {
            currentCoroutineContext().ensureActive()
            services().protocol.logout(token)
            LogoutConfirmation.CONFIRMED
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (_: Exception) { LogoutConfirmation.UNCONFIRMED }
        finally { token.fill(0) }
    }

    override fun cancelForFence(previousGeneration: Long, reason: StoreCode) {
        val cancel = synchronized(monitor) { calls.remove(previousGeneration)?.toList().orEmpty() }
        cancel.forEach(Job::cancel)
        scheduler.cancel()
    }

    override fun close() {
        val cancel = synchronized(monitor) { closed = true; calls.values.flatten().also { calls.clear() } }
        cancel.forEach(Job::cancel)
    }

    private suspend fun <T> tracked(generation: Long, body: suspend () -> T): T {
        if (!available) throw MobileLiveFailure(LiveFailureCode.UNAVAILABLE)
        val job = currentCoroutineContext()[Job] ?: throw StoreFailure(StoreCode.STALE_GENERATION)
        synchronized(monitor) {
            if (closed || !leaseIsCurrent()) throw StoreFailure(StoreCode.STALE_GENERATION)
            calls.getOrPut(generation) { mutableSetOf() } += job
        }
        try {
            currentCoroutineContext().ensureActive()
            val store = storage()
            if (!leaseIsCurrent() || store.repository.access.value.generation != generation) throw StoreFailure(StoreCode.STALE_GENERATION)
            val result = body()
            try {
                currentCoroutineContext().ensureActive()
                if (!leaseIsCurrent() || store.repository.access.value.generation != generation) throw StoreFailure(StoreCode.STALE_GENERATION)
                return result
            } catch (failure: Throwable) { (result as? MobileSession)?.close(); throw failure }
        } catch (cancelled: CancellationException) { throw cancelled }
        catch (failure: RemoteFailure) { throw failure.forUi() }
        finally { synchronized(monitor) { calls[generation]?.let { it -= job; if (it.isEmpty()) calls.remove(generation) } } }
    }

    private fun RemoteFailure.forUi(): Exception = when {
        code == RemoteCode.TEMPLATE_UNSUPPORTED -> StoreFailure(StoreCode.TEMPLATE_UNSUPPORTED)
        code == RemoteCode.ENROLLMENT_REVOKED -> MobileLiveFailure(LiveFailureCode.REVOKED)
        code == RemoteCode.LOGIN_FAILED -> MobileLiveFailure(LiveFailureCode.CREDENTIALS_REJECTED)
        status == 401 -> MobileLiveFailure(LiveFailureCode.AUTH_REQUIRED)
        status == 403 -> MobileLiveFailure(LiveFailureCode.SCOPE_DENIED)
        kind == RemoteFailureKind.CONTEXT_CHANGED -> MobileLiveFailure(LiveFailureCode.CONTEXT_CHANGED)
        kind == RemoteFailureKind.EXPIRED_RESPONSE -> MobileLiveFailure(LiveFailureCode.AUTH_REQUIRED)
        status == 409 -> MobileLiveFailure(LiveFailureCode.CONFLICT)
        status == 429 -> MobileLiveFailure(LiveFailureCode.THROTTLED)
        kind in setOf(RemoteFailureKind.NETWORK, RemoteFailureKind.TIMEOUT) -> MobileLiveFailure(LiveFailureCode.OFFLINE)
        kind == RemoteFailureKind.UNAVAILABLE -> MobileLiveFailure(LiveFailureCode.UNAVAILABLE)
        else -> MobileLiveFailure(LiveFailureCode.INVALID_RESPONSE)
    }
    private fun label(millis: Long) = Instant.ofEpochMilli(millis).toString()
    private fun category(value: String) = MaintenanceCategory.entries.single { it.wireValue == value }.label
    private fun status(value: RemoteReportStatus) = ReportFilterUi.entries.single { it.name == value.name }.label
}

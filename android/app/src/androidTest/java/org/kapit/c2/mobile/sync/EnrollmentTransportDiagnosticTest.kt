package org.kapit.c2.mobile.sync

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.security.NetworkSecurityPolicy
import android.system.ErrnoException
import android.system.OsConstants
import android.util.AtomicFile
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.EOFException
import java.io.File
import java.io.IOException
import java.io.InterruptedIOException
import java.net.ConnectException
import java.net.InetSocketAddress
import java.net.ProtocolException
import java.net.Proxy
import java.net.SocketException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import javax.net.ssl.SSLException
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import kotlinx.serialization.json.*
import okhttp3.Call
import okhttp3.EventListener
import okhttp3.Protocol
import okhttp3.Response
import org.junit.Test
import org.junit.runner.RunWith
import org.kapit.c2.mobile.AppContainer
import org.kapit.c2.mobile.BuildConfig
import org.kapit.c2.mobile.data.remote.*
import org.kapit.c2.mobile.domain.StoreFailure
import org.kapit.c2.mobile.security.AndroidAccessEnvironment
import org.kapit.c2.mobile.ui.MobileRuntime
import org.kapit.c2.mobile.ui.SignInPurpose

/** TASK102: diagnostic only; no replacement for the original runtime or MainActivity gates. */
@RunWith(AndroidJUnit4::class)
class EnrollmentTransportDiagnosticTest {
    @Test fun diagnoseEnrollmentTransport() = runBlocking(Dispatchers.IO) {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val args = InstrumentationRegistry.getArguments()
        val run = args.getString("diagnosticRun") ?: ""
        check(Build.VERSION.SDK_INT >= 35 && BuildConfig.DEBUG && context.packageName == PACKAGE)
        check(args.getString("ownedEmulator") == "true" && Regex("[0-9a-f]{32}").matches(run))
        val output = File(context.noBackupFilesDir, "m2-enrollment-transport.json")
        check(!output.exists() && !File(output.path + ".bak").exists() && !File(output.path + ".new").exists())
        val capture = Capture()
        var container: AppContainer? = null
        var runtime: MobileRuntime? = null
        var transport: MobileHttpTransport? = null
        var protocol: ProtocolAdapter? = null
        var succeeded = false
        var primary = Failure.NONE
        var failedAt = FailureStage.NONE
        var stage = FailureStage.PRECHECK
        var policies = Policies()
        var teardown = Teardown()
        fun fail(kind: Failure, at: FailureStage) {
            if (primary == Failure.NONE) { primary = kind; failedAt = at }
        }
        try {
            val endpoint = MobileEndpoint.configured()
            policies = Policies(
                targetPackage = context.packageName == PACKAGE,
                internet = context.checkSelfPermission(Manifest.permission.INTERNET) == PackageManager.PERMISSION_GRANTED,
                fixedEndpoint = endpoint.base.toString() == ENDPOINT,
                cleartext = NetworkSecurityPolicy.getInstance().isCleartextTrafficPermitted("127.0.0.1"),
            )
            if (!policies.allowed()) throw DiagnosticStop(Failure.UNAVAILABLE)
            val owned = AppContainer(context, workQueue = PausedDiagnosticQueue).also { container = it }
            val lease = owned.createMobileRuntime().also { runtime = it }
            val restored = lease.repository.restoreSelection(lease.repository.access.value.generation)
            check(restored.storeRef == null && lease.live.available)
            val storage = owned.storageForIntegration() // SAME owner; never call owned.services().
            val anchor = lease.repository.beginOnlineRequest(restored.generation)
            val client = MobileHttpTransport.hardenedClient().newBuilder().eventListenerFactory(capture).build()
            val http = MobileHttpTransport(endpoint, client).also { transport = it }
            check(client.connectTimeoutMillis == 10_000 && client.readTimeoutMillis == 30_000 &&
                client.writeTimeoutMillis == 30_000 && client.callTimeoutMillis == 45_000)
            val remote = ProtocolAdapter(MobileProtocolClient(http, AndroidAccessEnvironment(context)::clock))
                .also { protocol = it }
            val enrollment = EnrollmentService(storage.repository, storage.journal, remote)
            stage = FailureStage.AUTHENTICATE
            val completedWithinBudget = withTimeoutOrNull(150_000) {
                // Same existing isolated synthetic account; never supplied through host arguments.
                enrollment.authenticate(anchor, SignInPurpose.ENROLL_OR_RECOVER,
                    "submitter", "DemoMaintenance!2026").use { }
                true
            }
            if (completedWithinBudget == true) succeeded = true
            else fail(Failure.OUTER_BUDGET, FailureStage.AUTHENTICATE)
        } catch (failure: Throwable) {
            fail(classify(failure), stage)
        } finally {
            // Independent closes retain primary authentication failure and avoid another storage owner.
            val clientClosed = safelyClose { if (protocol != null) protocol!!.close() else transport?.close() }
            val runtimeClosed = safelyClose { runtime?.close() }
            val containerClosed = safelyClose { container?.close() }
            teardown = Teardown(clientClosed, runtimeClosed, containerClosed)
        }
        val rows = capture.snapshot()
        if (succeeded && (!policies.allowed() || capture.overflow.get() || !successfulRows(rows))) {
            fail(Failure.OTHER, FailureStage.VALIDATION)
        }
        if (!teardown.closed()) fail(Failure.OTHER, FailureStage.TEARDOWN)
        if (!succeeded && primary == Failure.NONE) fail(Failure.OTHER, FailureStage.AUTHENTICATE)
        val evidence = buildJsonObject {
            put("schema", 1); put("run", run); put("completed", true)
            put("enrollment_succeeded", succeeded); put("failure_kind", primary.name); put("failed_at", failedAt.name)
            put("policies", policies.json()); put("overflow", capture.overflow.get()); put("teardown", teardown.json())
            put("requests", JsonArray(rows.map(Row::json)))
        }.toString()
        try {
            check(evidence.all { it.code in 32..126 })
            val bytes = evidence.toByteArray(Charsets.US_ASCII)
            check(bytes.size <= 2048)
            val file = AtomicFile(output)
            val stream = file.startWrite()
            try { stream.write(bytes); file.finishWrite(stream) }
            catch (failure: Throwable) { file.failWrite(stream); throw failure }
            finally { bytes.fill(0) }
        } catch (_: Throwable) { throw AssertionError(FAILURE_MARKER) }
        if (primary != Failure.NONE || !succeeded) throw AssertionError(FAILURE_MARKER)
    }

    private enum class Failure { NONE, INVALID_REQUEST, INVALID_RESPONSE, NETWORK, TIMEOUT, HTTP,
        CONTEXT_CHANGED, EXPIRED_RESPONSE, UNAVAILABLE, STORE, OUTER_BUDGET, CANCELLED, OTHER }
    private enum class FailureStage { NONE, PRECHECK, AUTHENTICATE, VALIDATION, TEARDOWN }
    private class DiagnosticStop(val kind: Failure) : RuntimeException("NETWORK_DIAGNOSTIC_STOP")
    private fun classify(failure: Throwable): Failure = when (failure) {
        is DiagnosticStop -> failure.kind
        is RemoteFailure -> when (failure.kind) {
            RemoteFailureKind.INVALID_REQUEST -> Failure.INVALID_REQUEST
            RemoteFailureKind.INVALID_RESPONSE -> Failure.INVALID_RESPONSE
            RemoteFailureKind.NETWORK -> Failure.NETWORK
            RemoteFailureKind.TIMEOUT -> Failure.TIMEOUT
            RemoteFailureKind.HTTP -> Failure.HTTP
            RemoteFailureKind.CONTEXT_CHANGED -> Failure.CONTEXT_CHANGED
            RemoteFailureKind.EXPIRED_RESPONSE -> Failure.EXPIRED_RESPONSE
            RemoteFailureKind.UNAVAILABLE -> Failure.UNAVAILABLE
        }
        is StoreFailure -> Failure.STORE
        is CancellationException -> Failure.CANCELLED
        else -> Failure.OTHER
    }
    private fun safelyClose(close: () -> Unit): Boolean = try { close(); true } catch (_: Throwable) { false }

    private data class Policies(val targetPackage: Boolean = false, val internet: Boolean = false,
        val fixedEndpoint: Boolean = false, val cleartext: Boolean = false) {
        fun allowed() = targetPackage && internet && fixedEndpoint && cleartext
        fun json() = buildJsonObject {
            put("target_package", targetPackage); put("internet_permission", internet)
            put("fixed_endpoint", fixedEndpoint); put("cleartext_loopback", cleartext)
        }
    }
    private data class Teardown(val client: Boolean = false, val runtime: Boolean = false, val container: Boolean = false) {
        fun closed() = client && runtime && container
        fun json() = buildJsonObject {
            put("client_closed", client); put("runtime_closed", runtime); put("container_closed", container)
        }
    }
    private enum class Route { CHALLENGE, TOKEN, OTHER }
    private enum class Progress { START, DNS, CONNECT, CONNECTED, REQUEST_HEADERS, REQUEST_BODY, RESPONSE_HEADERS, RESPONSE_BODY }
    private enum class Terminal { NONE, END, FAIL }
    private enum class Io { NONE, CONNECT, SOCKET_TIMEOUT, INTERRUPTED_IO, UNKNOWN_HOST, TLS, PROTOCOL, SOCKET, EOF, OTHER_IO }
    private enum class Errno { NONE, EACCES, EPERM, ECONNREFUSED, ETIMEDOUT, ENETUNREACH, EHOSTUNREACH, ECONNRESET, EPIPE, OTHER_ERRNO }
    private data class Row(val seq: Int, val route: Route, val stage: Progress = Progress.START,
        val terminal: Terminal = Terminal.NONE, val io: Io = Io.NONE, val errno: Errno = Errno.NONE, val status: Int = 0) {
        fun json() = buildJsonObject {
            put("seq", seq); put("route", route.name); put("stage", stage.name); put("terminal", terminal.name)
            put("io", io.name); put("errno", errno.name); put("status", status)
        }
    }
    private fun successfulRows(rows: List<Row>): Boolean {
        val routes = rows.map { it.route }
        val allowed = listOf(listOf(Route.CHALLENGE, Route.TOKEN), listOf(Route.CHALLENGE, Route.CHALLENGE, Route.TOKEN),
            listOf(Route.CHALLENGE, Route.TOKEN, Route.CHALLENGE, Route.TOKEN),
            listOf(Route.CHALLENGE, Route.CHALLENGE, Route.TOKEN, Route.CHALLENGE, Route.TOKEN))
        return routes in allowed && rows.withIndex().all { (index, row) ->
            row.seq == index + 1 && row.terminal == Terminal.END && row.io == Io.NONE && row.errno == Errno.NONE &&
                row.stage in setOf(Progress.RESPONSE_HEADERS, Progress.RESPONSE_BODY) &&
                row.status == if (row.route == Route.TOKEN && index != rows.lastIndex) 409 else 200
        }
    }

    /** No call/request/response/Throwable retained; only immutable finite rows and bounded atomic state. */
    private class Capture : EventListener.Factory {
        val overflow = AtomicBoolean(false)
        private val rows = AtomicReference<List<Row>>(emptyList())
        fun snapshot(): List<Row> = rows.get().toList()
        private fun open(route: Route): Int {
            repeat(16) {
                val before = rows.get()
                if (before.size >= 5) { overflow.set(true); return 0 }
                val seq = before.size + 1
                if (rows.compareAndSet(before, before + Row(seq, route))) return seq
            }
            overflow.set(true)
            return 0
        }
        private fun update(seq: Int, change: (Row) -> Row) {
            repeat(16) {
                val before = rows.get()
                if (seq !in 1..before.size) { overflow.set(true); return }
                val after = before.toMutableList().also { it[seq - 1] = change(it[seq - 1]) }
                if (rows.compareAndSet(before, after)) return
            }
            overflow.set(true)
        }
        private fun advancing(row: Row, stage: Progress): Boolean {
            val valid = row.terminal == Terminal.NONE && row.io == Io.NONE && row.errno == Errno.NONE &&
                stage.ordinal >= row.stage.ordinal
            if (!valid) overflow.set(true)
            return valid
        }
        private fun observe(block: () -> Unit) { try { block() } catch (_: Throwable) { overflow.set(true) } }
        override fun create(call: Call): EventListener {
            val route = try {
                val url = call.request().url
                if (url.scheme != "http" || url.host != "127.0.0.1" || url.port != 18082 ||
                    url.query != null || url.fragment != null || url.username.isNotEmpty() || url.password.isNotEmpty()) Route.OTHER
                else when (url.encodedPath) {
                    "/api/v1/mobile/auth/challenge/" -> Route.CHALLENGE
                    "/api/v1/mobile/auth/token/" -> Route.TOKEN
                    else -> Route.OTHER
                }
            } catch (_: Throwable) { overflow.set(true); Route.OTHER }
            return object : EventListener() {
                private val seq = AtomicInteger(0)
                private fun progress(value: Progress) = observe {
                    update(seq.get()) { if (advancing(it, value)) it.copy(stage = value) else it }
                }
                private fun failed(error: IOException, terminal: Boolean) = observe {
                    val (io, errno) = categories(error)
                    update(seq.get()) {
                        if (it.terminal != Terminal.NONE) { overflow.set(true); it }
                        else it.copy(io = if (it.io in setOf(Io.NONE, Io.OTHER_IO)) io else it.io,
                            errno = if (it.errno == Errno.NONE) errno else it.errno,
                            terminal = if (terminal) Terminal.FAIL else it.terminal)
                    }
                }
                override fun callStart(call: Call) = observe {
                    if (seq.get() != 0) overflow.set(true) else seq.set(open(route))
                }
                override fun dnsStart(call: Call, domainName: String) = progress(Progress.DNS)
                override fun connectStart(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy) = progress(Progress.CONNECT)
                override fun connectEnd(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy, protocol: Protocol?) = progress(Progress.CONNECTED)
                override fun connectFailed(call: Call, inetSocketAddress: InetSocketAddress, proxy: Proxy, protocol: Protocol?, ioe: IOException) = failed(ioe, false)
                override fun requestHeadersStart(call: Call) = progress(Progress.REQUEST_HEADERS)
                override fun requestBodyStart(call: Call) = progress(Progress.REQUEST_BODY)
                override fun requestFailed(call: Call, ioe: IOException) = failed(ioe, false)
                override fun responseHeadersStart(call: Call) = progress(Progress.RESPONSE_HEADERS)
                override fun responseHeadersEnd(call: Call, response: Response) = observe {
                    val status = response.code
                    if (status !in 100..599) overflow.set(true)
                    update(seq.get()) {
                        if (advancing(it, Progress.RESPONSE_HEADERS) && it.status == 0)
                            it.copy(stage = Progress.RESPONSE_HEADERS, status = status.takeIf { it in 100..599 } ?: 0)
                        else { overflow.set(true); it }
                    }
                }
                override fun responseBodyStart(call: Call) = progress(Progress.RESPONSE_BODY)
                override fun responseFailed(call: Call, ioe: IOException) = failed(ioe, false)
                override fun callFailed(call: Call, ioe: IOException) = failed(ioe, true)
                override fun callEnd(call: Call) = observe {
                    update(seq.get()) {
                        if (it.terminal == Terminal.NONE && it.io == Io.NONE && it.errno == Errno.NONE)
                            it.copy(terminal = Terminal.END)
                        else { overflow.set(true); it }
                    }
                }
            }
        }
        private fun categories(error: IOException): Pair<Io, Errno> {
            var io = Io.OTHER_IO
            var errno = Errno.NONE
            var cursor: Throwable? = error
            repeat(4) { depth ->
                val current = cursor ?: return@repeat
                if (io == Io.OTHER_IO) io = when (current) {
                    is SocketTimeoutException -> Io.SOCKET_TIMEOUT
                    is InterruptedIOException -> Io.INTERRUPTED_IO
                    is ConnectException -> Io.CONNECT
                    is UnknownHostException -> Io.UNKNOWN_HOST
                    is SSLException -> Io.TLS
                    is ProtocolException -> Io.PROTOCOL
                    is SocketException -> Io.SOCKET
                    is EOFException -> Io.EOF
                    else -> Io.OTHER_IO
                }
                if (errno == Errno.NONE && current is ErrnoException) errno = when (current.errno) {
                    OsConstants.EACCES -> Errno.EACCES
                    OsConstants.EPERM -> Errno.EPERM
                    OsConstants.ECONNREFUSED -> Errno.ECONNREFUSED
                    OsConstants.ETIMEDOUT -> Errno.ETIMEDOUT
                    OsConstants.ENETUNREACH -> Errno.ENETUNREACH
                    OsConstants.EHOSTUNREACH -> Errno.EHOSTUNREACH
                    OsConstants.ECONNRESET -> Errno.ECONNRESET
                    OsConstants.EPIPE -> Errno.EPIPE
                    else -> Errno.OTHER_ERRNO
                }
                if (depth < 3) cursor = current.cause
            }
            return io to errno
        }
    }
    private object PausedDiagnosticQueue : WorkQueue {
        override suspend fun enqueue(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long, continuation: Boolean) = Unit
        override suspend fun cancel(epoch: ScheduleEpoch) = Unit
        override suspend fun isRunning(epoch: ScheduleEpoch) = false
        override suspend fun coalesceRerun(epoch: ScheduleEpoch, storeRef: String, delayMillis: Long) = Unit
    }
    private companion object {
        const val PACKAGE = "org.kapit.c2.mobile.spike"
        const val ENDPOINT = "http://127.0.0.1:18082/api/v1/"
        const val FAILURE_MARKER = "ENROLLMENT_TRANSPORT_DIAGNOSTIC_FAILED"
    }
}

package org.kapit.c2.mobile.data.remote

import androidx.annotation.RequiresApi
import java.io.Closeable
import java.io.IOException
import java.io.InterruptedIOException
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.*
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okio.BufferedSink
import org.kapit.c2.mobile.BuildConfig

/** Application creation has no endpoint argument. Release remains disabled until reviewed config. */
internal class MobileEndpoint private constructor(val base: HttpUrl) {
    companion object {
        fun configured(): MobileEndpoint = validate(BuildConfig.MOBILE_API_BASE_URL, BuildConfig.DEBUG)
        internal fun validate(value: String, debug: Boolean): MobileEndpoint {
            return try {
                require(value.isNotEmpty())
                val url = value.toHttpUrl()
                require(url.toString() == value && url.encodedPath == "/api/v1/" && url.query == null && url.fragment == null)
                require(url.username.isEmpty() && url.password.isEmpty())
                if (debug) require(value == "http://127.0.0.1:18082/api/v1/") else require(url.isHttps)
                MobileEndpoint(url)
            } catch (_: Exception) { throw RemoteFailure(RemoteFailureKind.UNAVAILABLE) }
        }
        /** Internal fixture seam; never reachable from the app's no-argument factory. */
        internal fun loopbackFixture(url: HttpUrl): MobileEndpoint {
            require(url.scheme == "http" && url.host == "127.0.0.1" && url.encodedPath == "/api/v1/" && url.query == null && url.fragment == null && url.username.isEmpty() && url.password.isEmpty())
            return MobileEndpoint(url)
        }
    }
    override fun toString() = "MobileEndpoint(configured)"
}

internal class HttpReply(val status: Int, val retryAfter: String?, internal val bytes: ByteArray) : Closeable {
    override fun close() = bytes.fill(0)
    override fun toString() = "HttpReply(status=$status,body=redacted)"
}

@RequiresApi(35)
internal class MobileHttpTransport(
    private val endpoint: MobileEndpoint,
    private val client: OkHttpClient = hardenedClient(),
) : Closeable {
    private val monitor = Any()
    private val calls = mutableSetOf<Call>()
    private var closed = false

    suspend fun exchange(path: String, body: ByteArray? = null, accessToken: ByteArray? = null,
        operationId: String? = null, query: List<Pair<String, String>> = emptyList(), responseLimit: Int = 20 * 1024): HttpReply {
        val ownedBody: OneShotBody?
        val request: Request
        val metadata = ResponseMetadata()
        try {
            require(responseLimit in 1..ReportCodec.PAGE_LIMIT)
            require(validPath(path, body != null))
            require(body == null || body.size in 2..20 * 1024)
            require(query.isEmpty() || path == "reports/" && query.size <= 5 && query.map { it.first }.toSet().size == query.size && query.all { it.first in setOf("status", "date_from", "date_to", "page", "page_size") && it.second.length <= 24 })
            require(operationId == null || path == "sync/operations/" && org.kapit.c2.mobile.domain.canonicalUuid(operationId) == operationId)
            require((path == "sync/operations/") == (operationId != null))
            val publicAuth = path in setOf("auth/challenge/", "auth/token/", "auth/refresh/")
            require(publicAuth == (accessToken == null))
            val url = endpoint.base.newBuilder().addPathSegments("mobile/$path").apply { query.forEach { addQueryParameter(it.first, it.second) } }.build()
            val builder = Request.Builder().url(url).tag(ResponseMetadata::class.java, metadata)
                .header("Accept", "application/json").header("Cache-Control", "no-store")
            // Disable transparent compression so the byte bound applies without decompression allocation.
            builder.header("Accept-Encoding", "identity")
            accessToken?.let {
                val token = AuthCodec.ascii(it, 8192)
                require(token.matches(Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")))
                builder.header("Authorization", "Bearer $token")
            }
            operationId?.let { builder.header("Idempotency-Key", it) }
            ownedBody = body?.let(::OneShotBody)
            request = if (ownedBody == null) builder.get().build() else builder.post(ownedBody).build()
        } catch (_: Exception) { throw RemoteFailure(RemoteFailureKind.INVALID_REQUEST) }
        return suspendCancellableCoroutine { continuation ->
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            synchronized(monitor) {
                if (closed) {
                    ownedBody?.close()
                    continuation.resumeWithException(RemoteFailure(RemoteFailureKind.UNAVAILABLE))
                    return@suspendCancellableCoroutine
                }
                calls += call
                call.enqueue(object : Callback {
                    private fun finish() { ownedBody?.close(); synchronized(monitor) { calls -= call } }
                    override fun onFailure(call: Call, failure: IOException) {
                        finish()
                        // Connection refused/unresolvable fails before any byte is written; retryOnConnectionFailure is off.
                        // Connect timeouts and failures on pooled connections stay uncertain.
                        val notDispatched = failure is java.net.ConnectException || failure is java.net.UnknownHostException
                        if (continuation.isActive) continuation.resumeWithException(RemoteFailure(
                            if (failure is InterruptedIOException) RemoteFailureKind.TIMEOUT else RemoteFailureKind.NETWORK,
                            mutationUncertain = body != null && !notDispatched, notDispatched = notDispatched))
                    }
                    override fun onResponse(call: Call, response: Response) {
                        try {
                            response.use {
                                if (!continuation.isActive) return
                                val type = response.header("Content-Type")?.substringBefore(';')?.trim()?.lowercase()
                                checkWire(type == "application/json")
                                checkWire(response.header("Content-Encoding")?.lowercase() in setOf(null, "identity"))
                                val cache = response.headers.values("Cache-Control").flatMap { it.lowercase().split(',').map(String::trim) }
                                checkWire("private" in cache && "no-store" in cache)
                                val limit = if (response.code in 200..299) responseLimit else 20 * 1024
                                checkWire(response.body.contentLength() <= limit)
                                val buffer = ByteArray(limit + 1)
                                val result: ByteArray
                                try {
                                    var count = 0
                                    val stream = response.body.byteStream()
                                    while (count < buffer.size) {
                                        val read = stream.read(buffer, count, buffer.size - count)
                                        if (read < 0) break
                                        if (read == 0) continue
                                        count += read
                                    }
                                    checkWire(count <= limit)
                                    result = buffer.copyOf(count)
                                } finally { buffer.fill(0) }
                                continuation.resume(HttpReply(response.code, metadata.retryAfter, result)) { _, value, _ -> value.close() }
                            }
                        } catch (failure: Exception) {
                            if (continuation.isActive) {
                                val kind = when (failure) {
                                    is RemoteFailure -> failure.kind
                                    is InterruptedIOException -> RemoteFailureKind.TIMEOUT
                                    is IOException -> RemoteFailureKind.NETWORK
                                    else -> RemoteFailureKind.INVALID_RESPONSE
                                }
                                // Preserve HTTP denial status even if its body/headers are malformed.
                                continuation.resumeWithException(RemoteFailure(kind, status = response.code,
                                    retryAfterSeconds = retryAfter(metadata.retryAfter, null), mutationUncertain = body != null,
                                    retryAfterDate = parseRetryAfterDate(metadata.retryAfter)))
                            }
                        } finally { finish() }
                    }
                })
            }
        }
    }

    fun cancelAll() { synchronized(monitor) { calls.toList() }.forEach(Call::cancel) }

    /** Separate raw-image seam; generic JSON paths/limits remain unchanged. */
    suspend fun evidence(id: String, accessToken: ByteArray, upload: ByteArray? = null,
        operationId: String? = null, capture: String? = null): HttpReply {
        val owned = upload?.let { bytes ->
            org.kapit.c2.mobile.domain.PhotoPolicy.jpeg(bytes)
            require(bytes.size <= org.kapit.c2.mobile.domain.PhotoPolicy.LOCAL_BYTES)
            bytes.copyOf()
        }
        val request = try {
            org.kapit.c2.mobile.domain.canonicalUuid(id)
            val token = AuthCodec.ascii(accessToken, 8192)
            require(token.matches(Regex("[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+")))
            val path = if (owned != null) {
                org.kapit.c2.mobile.domain.canonicalUuid(requireNotNull(operationId))
                org.kapit.c2.mobile.domain.PhotoPolicy.validateCapture(requireNotNull(capture))
                "mobile/revisions/$id/evidence/"
            } else {
                require(operationId == null && capture == null)
                "mobile/evidence/$id/validation/"
            }
            Request.Builder().url(endpoint.base.newBuilder().addPathSegments(path).build())
                .header("Authorization", "Bearer $token").header("Accept", "application/json")
                .header("Cache-Control", "no-store").header("Accept-Encoding", "identity").apply {
                    if (owned != null) {
                        header("Idempotency-Key", operationId!!); header("X-Evidence-Filename", "capture.jpg")
                        header("X-Evidence-Capture", capture!!)
                        post(object : RequestBody() {
                            override fun contentType() = "image/jpeg".toMediaType()
                            override fun contentLength() = owned.size.toLong()
                            override fun isOneShot() = true
                            override fun writeTo(sink: BufferedSink) { synchronized(owned) { sink.write(owned) } }
                        })
                    } else get()
                }.build()
        } catch (_: Exception) { owned?.fill(0); throw RemoteFailure(RemoteFailureKind.INVALID_REQUEST) }
        return suspendCancellableCoroutine { continuation ->
            val call = client.newCall(request)
            continuation.invokeOnCancellation { call.cancel() }
            synchronized(monitor) {
                if (closed) {
                    owned?.fill(0); continuation.resumeWithException(RemoteFailure(RemoteFailureKind.UNAVAILABLE))
                    return@suspendCancellableCoroutine
                }
                calls += call
            }
            fun finished() { owned?.let { synchronized(it) { it.fill(0) } }; synchronized(monitor) { calls -= call } }
            call.enqueue(object : Callback {
                override fun onFailure(call: Call, failure: IOException) {
                    finished()
                    if (continuation.isActive) continuation.resumeWithException(RemoteFailure(RemoteFailureKind.NETWORK, mutationUncertain = upload != null))
                }
                override fun onResponse(call: Call, response: Response) {
                    var raw: ByteArray? = null
                    try {
                        response.use {
                            require(it.header("Content-Encoding") in listOf(null, "identity"))
                            require(it.header("Content-Type")?.substringBefore(';')?.trim() == "application/json")
                            val cache = it.headers.values("Cache-Control").flatMap { value -> value.lowercase().split(',').map(String::trim) }
                            require("private" in cache && "no-store" in cache)
                            val body = requireNotNull(it.body)
                            val source = body.source()
                            source.request(8193)
                            require(source.buffer.size <= 8192)
                            raw = source.readByteArray()
                            val reply = HttpReply(it.code, null, raw!!)
                            raw = null
                            continuation.resume(reply) { _, value, _ -> value.close() }
                        }
                    } catch (_: Exception) {
                        raw?.fill(0)
                        if (continuation.isActive) continuation.resumeWithException(RemoteFailure(RemoteFailureKind.INVALID_RESPONSE,
                            status = response.code, mutationUncertain = upload != null))
                    } finally { finished() }
                }
            })
        }
    }
    override fun close() {
        val pending = synchronized(monitor) { closed = true; calls.toList() }
        pending.forEach(Call::cancel)
        client.connectionPool.evictAll()
        client.dispatcher.executorService.shutdown()
    }

    private class OneShotBody(bytes: ByteArray) : RequestBody(), Closeable {
        private val bytes = bytes.copyOf()
        override fun contentType() = "application/json; charset=utf-8".toMediaType()
        override fun contentLength() = bytes.size.toLong()
        override fun isOneShot() = true
        @Synchronized override fun writeTo(sink: BufferedSink) { sink.write(bytes) }
        @Synchronized override fun close() { bytes.fill(0) }
    }

    private class ResponseMetadata { @Volatile var retryAfter: String? = null }

    /**
     * OkHttp5.5 parses503 Retry-After as Int before checking a one-shot body. Capture the bounded
     * original in local metadata and remove only that follow-up signal, preserving status/body.
     * No marker header, extra request, credential logging or TLS replacement is introduced.
     */
    private object ResponsePolicy : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val response = chain.proceed(chain.request())
            chain.request().tag(ResponseMetadata::class.java)?.retryAfter = response.headers.values("Retry-After").singleOrNull()?.takeIf { it.length <= 128 }
            return if (response.code == 503) response.newBuilder().removeHeader("Retry-After").build() else response
        }
    }

    companion object {
        internal fun hardenedClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS).readTimeout(30, TimeUnit.SECONDS).writeTimeout(30, TimeUnit.SECONDS).callTimeout(45, TimeUnit.SECONDS)
            .followRedirects(false).followSslRedirects(false).retryOnConnectionFailure(false)
            .authenticator(Authenticator.NONE).proxyAuthenticator(Authenticator.NONE)
            .cookieJar(CookieJar.NO_COOKIES).cache(null).proxy(Proxy.NO_PROXY).addNetworkInterceptor(ResponsePolicy).build()

        private fun validPath(path: String, post: Boolean): Boolean {
            if (post) return path in setOf("auth/challenge/", "auth/token/", "auth/refresh/", "auth/logout/", "sync/operations/")
            if (path == "me/" || path == "reports/") return true
            val receipt = Regex("sync/receipts/([a-f0-9-]{36})/").matchEntire(path)
            if (receipt != null) return org.kapit.c2.mobile.domain.canonicalUuid(receipt.groupValues[1]) == receipt.groupValues[1]
            val revision = Regex("reports/([a-f0-9-]{36})/revisions/([1-9][0-9]{0,9})/").matchEntire(path) ?: return false
            return org.kapit.c2.mobile.domain.canonicalUuid(revision.groupValues[1]) == revision.groupValues[1] && (revision.groupValues[2].toLongOrNull() ?: Long.MAX_VALUE) <= Int.MAX_VALUE
        }
    }
}

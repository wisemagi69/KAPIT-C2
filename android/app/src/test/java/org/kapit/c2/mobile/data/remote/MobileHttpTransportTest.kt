package org.kapit.c2.mobile.data.remote

import java.net.InetAddress
import java.net.Proxy
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.*
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import mockwebserver3.SocketEffect
import okhttp3.CookieJar
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.domain.*

/** Real local HTTP sockets with explicit synthetic responses; not live backend acceptance. */
class MobileHttpTransportTest {
    private val bearer = "e30.e30.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".toByteArray()

    @Test fun productionPolicyRejectsArbitraryOriginsAndHasExactTimeoutsWithoutProxyCookiesOrRetry() {
        MobileEndpoint.validate("http://127.0.0.1:18082/api/v1/", true)
        MobileEndpoint.validate("https://configured.example/api/v1/", false)
        listOf("", "http://127.0.0.1:18082/api/v1/", "https://user:pass@configured.example/api/v1/", "https://configured.example/api/v1/?other=1", "https://configured.example/api/v1/#part").forEach {
            RemoteFixtures.reject { MobileEndpoint.validate(it, false) }
        }
        listOf("http://localhost:18082/api/v1/", "http://127.0.0.1:8000/api/v1/", "http://192.168.1.2:18082/api/v1/", "https://configured.example/api/v1/").forEach {
            RemoteFixtures.reject { MobileEndpoint.validate(it, true) }
        }
        val client = MobileHttpTransport.hardenedClient()
        assertEquals(10_000, client.connectTimeoutMillis); assertEquals(30_000, client.readTimeoutMillis)
        assertEquals(30_000, client.writeTimeoutMillis); assertEquals(45_000, client.callTimeoutMillis)
        assertFalse(client.followRedirects); assertFalse(client.followSslRedirects); assertFalse(client.retryOnConnectionFailure)
        assertSame(Proxy.NO_PROXY, client.proxy); assertSame(CookieJar.NO_COOKIES, client.cookieJar)
        assertNull(client.cache); assertTrue(client.interceptors.isEmpty()); assertEquals(1, client.networkInterceptors.size)
        client.dispatcher.executorService.shutdown()
    }

    @Test fun requestHasExactMobilePathNoCookiesAndAResponseDoesNotBecomeAnAuthorityByItself() = runBlocking {
        server().use { server ->
            server.enqueue(json("{}", cookie = true)); server.enqueue(json("{}"))
            transport(server).use { http ->
                http.exchange("me/", accessToken = bearer).close()
                http.exchange("me/", accessToken = bearer).close()
                repeat(2) {
                    val request = server.takeRequest(1, TimeUnit.SECONDS)!!
                    assertEquals("/api/v1/mobile/me/", request.target)
                    assertEquals("Bearer ${bearer.toString(Charsets.US_ASCII)}", request.headers["Authorization"])
                    assertNull(request.headers["Cookie"])
                    assertEquals("identity", request.headers["Accept-Encoding"])
                }
            }
        }
    }

    @Test fun redirects503RetryAfterZeroAnd408NeverResendMutationBody() = runBlocking {
        for (status in listOf(302, 307, 308, 408, 503)) {
            server().use { server ->
                server.enqueue(json("{}", status).newBuilder().addHeader("Retry-After", "0").addHeader("Location", server.url("/other")).build())
                server.enqueue(json("{}"))
                transport(server).use { http ->
                    http.exchange("auth/refresh/", "{\"refresh_token\":\"synthetic\"}".toByteArray()).use { assertEquals(status, it.status) }
                    assertEquals(1, server.requestCount)
                    assertEquals("POST", server.takeRequest(1, TimeUnit.SECONDS)!!.method)
                    assertNull(server.takeRequest(100, TimeUnit.MILLISECONDS))
                }
            }
        }
    }

    @Test fun lostMutationResponseIsUncertainAndNeverAutomaticallyRetried() = runBlocking {
        server().use { server ->
            server.enqueue(MockResponse.Builder().onResponseStart(SocketEffect.CloseSocket()).build())
            server.enqueue(json("{}"))
            transport(server).use { http ->
                val failure = suspendReject { http.exchange("auth/refresh/", "{}".toByteArray()).close() }
                assertTrue(failure.mutationUncertain); assertFalse(failure.notDispatched)
                assertEquals(RemoteFailureKind.NETWORK, failure.kind)
                assertEquals(1, server.requestCount)
                assertNull(server.takeRequest(100, TimeUnit.MILLISECONDS)?.let { server.takeRequest(100, TimeUnit.MILLISECONDS) })
            }
        }
    }

    @Test fun refusedConnectionIsProvablyNotDispatchedAndNotUncertain() = runBlocking {
        val server = server()
        val url = loopbackUrl(server)
        server.close()
        MobileHttpTransport(MobileEndpoint.loopbackFixture(url)).use { http ->
            val failure = suspendReject { http.exchange("auth/refresh/", "{}".toByteArray()).close() }
            assertEquals(RemoteFailureKind.NETWORK, failure.kind)
            assertTrue(failure.notDispatched); assertFalse(failure.mutationUncertain)
            assertSame(failure, failure.uncertain())
        }
    }

    @Test fun huge503DelayIsCappedAndNeitherGetNorPostIsAutomaticallyRepeated() = runBlocking {
        for (post in listOf(false, true)) {
            server().use { server ->
                server.enqueue(json("{\"code\":\"SERVER_ERROR\",\"message\":\"Unavailable\"}", 503)
                    .newBuilder().addHeader("Retry-After", "999999999999999999999999").build())
                server.enqueue(json("{}"))
                MobileProtocolClient(transport(server)) { RemoteFixtures.arrival }.use { client ->
                    AuthCodec.session(RemoteFixtures.sessionBytes(), RemoteFixtures.start, RemoteFixtures.arrival).use { session ->
                        val failure = suspendReject {
                            if (post) client.refresh(session.secrets.copyRefreshToken(), session.context.authority, RemoteFixtures.start).close()
                            else client.me(bearer, session.context.authority, RemoteFixtures.start)
                        }
                        assertEquals(503, failure.status); assertEquals(86400L, failure.retryAfterSeconds)
                        assertEquals(post, failure.mutationUncertain); assertEquals(1, server.requestCount)
                        assertNotNull(server.takeRequest(1, TimeUnit.SECONDS))
                        assertNull(server.takeRequest(100, TimeUnit.MILLISECONDS))
                    }
                }
            }
        }
        server().use { server ->
            server.enqueue(json("{}", 503).newBuilder().addHeader("Retry-After", "0").build())
            server.enqueue(json("{}"))
            transport(server).use { http ->
                http.exchange("me/", accessToken = bearer).use { assertEquals(503, it.status); assertEquals("0", it.retryAfter) }
                assertEquals(1, server.requestCount)
            }
        }
    }

    @Test fun malformedThrottledResponsesKeepServerDelayAndBadHeadersFallBackSafely() = runBlocking {
        server().use { server ->
            server.enqueue(MockResponse(code = 429, body = "not JSON").newBuilder().addHeader("Retry-After", "60").build())
            server.enqueue(json("x".repeat(20 * 1024 + 1), 429).newBuilder().addHeader("Retry-After", "70").build())
            val error = "{\"code\":\"THROTTLED\",\"message\":\"Later\"}"
            server.enqueue(json(error, 429).newBuilder().addHeader("Retry-After", "5").addHeader("Retry-After", "6").build())
            server.enqueue(json(error, 429).newBuilder().addHeader("Retry-After", "9".repeat(129)).build())
            server.enqueue(json(error, 429).newBuilder().addHeader("Retry-After", "invalid").build())
            MobileProtocolClient(transport(server)) { RemoteFixtures.arrival }.use { client ->
                AuthCodec.session(RemoteFixtures.sessionBytes(), RemoteFixtures.start, RemoteFixtures.arrival).use { session ->
                    for (expected in listOf(60L, 70L, null, null, null)) {
                        val failure = suspendReject { client.me(bearer, session.context.authority, RemoteFixtures.start) }
                        assertEquals(429, failure.status); assertEquals(expected, failure.retryAfterSeconds)
                        assertNull(failure.retryAfterServerMillis)
                    }
                }
            }
        }
    }

    @Test fun boundedStreamingRejectsOversizeMissingPrivacyHeadersAndCompressedBodies() = runBlocking {
        server().use { server ->
            server.enqueue(json("{}").newBuilder().chunkedBody("x".repeat(20 * 1024 + 1), 512).build())
            server.enqueue(MockResponse(code = 401, body = "{}"))
            server.enqueue(json("{}").newBuilder().addHeader("Content-Encoding", "gzip").build())
            transport(server).use { http ->
                assertEquals(RemoteFailureKind.INVALID_RESPONSE, suspendReject { http.exchange("me/", accessToken = bearer).close() }.kind)
                val denial = suspendReject { http.exchange("me/", accessToken = bearer).close() }
                assertEquals(401, denial.status)
                assertEquals(RemoteFailureKind.INVALID_RESPONSE, suspendReject { http.exchange("me/", accessToken = bearer).close() }.kind)
            }
        }
    }

    @Test fun totalTimeoutAndCancellationCloseTheCallWithoutLateSuccess() = runBlocking {
        server().use { server ->
            server.enqueue(json("{}").newBuilder().headersDelay(1, TimeUnit.SECONDS).build())
            val shortClient = MobileHttpTransport.hardenedClient().newBuilder().callTimeout(150, TimeUnit.MILLISECONDS).build()
            MobileHttpTransport(MobileEndpoint.loopbackFixture(loopbackUrl(server)), shortClient).use { http ->
                val failure = suspendReject { http.exchange("auth/refresh/", "{}".toByteArray()).close() }
                assertEquals(RemoteFailureKind.TIMEOUT, failure.kind)
                assertTrue(failure.mutationUncertain)
                assertEquals(1, server.requestCount)
            }
        }
        server().use { server ->
            server.enqueue(MockResponse.Builder().onResponseStart(SocketEffect.Stall).build())
            transport(server).use { http ->
                var delivered = false
                val job = launch { http.exchange("me/", accessToken = bearer).use { delivered = true } }
                withContext(Dispatchers.IO) { assertNotNull(server.takeRequest(2, TimeUnit.SECONDS)) }
                job.cancelAndJoin()
                assertFalse(delivered)
            }
        }
    }

    @Test fun invalidPathsMethodsBodyBoundsAndHeaderInjectionNeverReachNetwork() = runBlocking {
        server().use { server ->
            transport(server).use { http ->
                suspendReject { http.exchange("../account/", accessToken = bearer).close() }
                suspendReject { http.exchange("auth/refresh/", accessToken = bearer).close() }
                suspendReject { http.exchange("auth/refresh/", ByteArray(20 * 1024 + 1)).close() }
                suspendReject { http.exchange("me/", accessToken = "token\r\nCookie: synthetic".toByteArray()).close() }
                suspendReject { http.exchange("me/", accessToken = bearer, query = listOf("other" to "value")).close() }
                assertEquals(0, server.requestCount)
            }
        }
    }

    @Test fun reauthenticationCannotOmitKnownAccountBindingOrReachTheNetwork() = runBlocking {
        server().use { server ->
            MobileProtocolClient(transport(server)) { RemoteFixtures.arrival }.use { client ->
                ChallengeRequest("synthetic", charArrayOf('x'), RemoteFixtures.install, RemoteFixtures.enrollment, RemoteFixtures.key, "Phone").use { request ->
                    assertEquals(RemoteFailureKind.INVALID_REQUEST, suspendReject { client.challenge(request, RemoteFixtures.start) }.kind)
                    assertEquals(0, server.requestCount)
                }
            }
        }
    }

    @Test fun sanitizedHttpErrorsKeepDenialStatusButNeverRetainServerMessagesOrForeignEnrollment() = runBlocking {
        server().use { server ->
            server.enqueue(json("{\"code\":\"AUTH_REQUIRED\",\"message\":\"DO_NOT_LOG_CREDENTIAL\",\"enrollment_id\":\"${RemoteFixtures.enrollment}\"}", 401))
            server.enqueue(json("{\"code\":\"THROTTLED\",\"message\":\"Try later\"}", 429).newBuilder().addHeader("Retry-After", "999999999999999999999999").build())
            server.enqueue(json("{\"code\":\"THROTTLED\",\"message\":\"Try later\"}", 429).newBuilder().addHeader("Retry-After", "Sat, 17 Oct 2026 08:00:10 GMT").build())
            MobileProtocolClient(transport(server)) { RemoteFixtures.arrival }.use { client ->
                val context = AuthCodec.session(RemoteFixtures.sessionBytes(), RemoteFixtures.start, RemoteFixtures.arrival).use { it.context.authority }
                val denial = suspendReject { client.me(bearer, context, RemoteFixtures.start) }
                assertEquals(401, denial.status); assertNull(denial.enrollmentId)
                assertFalse(denial.toString().contains("DO_NOT_LOG")); assertNull(denial.cause)
                val throttle = suspendReject { client.me(bearer, context, RemoteFixtures.start) }
                assertEquals(RemoteCode.THROTTLED, throttle.code); assertEquals(86400L, throttle.retryAfterSeconds)
                val dated = suspendReject { client.me(bearer, context, RemoteFixtures.start) }
                assertNull(dated.retryAfterSeconds)
                assertEquals(10L, dated.retryDelaySeconds(java.time.Instant.parse("2026-10-17T08:00:00Z").toEpochMilli()))
            }
        }
    }

    @Test fun enrollmentRecoveryMetadataIsExposedOnlyAfterTheBoundProofTokenAttempt() = runBlocking {
        server().use { server ->
            server.enqueue(json("{\"code\":\"ENROLLMENT_EXISTS\",\"message\":\"Resume enrollment\",\"enrollment_id\":\"${RemoteFixtures.enrollment}\"}", 409))
            RemoteFixtures.request().use { request ->
                val challenge = AuthCodec.challenge(RemoteFixtures.challenge(), request, RemoteFixtures.start, RemoteFixtures.arrival)
                MobileProtocolClient(transport(server)) { RemoteFixtures.arrival }.use { client ->
                    val failure = suspendReject { client.token(challenge, decode64(RemoteFixtures.vector.text("signature_der_base64url", 100), 100), RemoteFixtures.start).close() }
                    assertEquals(RemoteCode.ENROLLMENT_EXISTS, failure.code)
                    assertEquals(RemoteFixtures.enrollment, failure.enrollmentId)
                    assertEquals(1, server.requestCount)
                    val sent = server.takeRequest(1, TimeUnit.SECONDS)!!
                    assertEquals("/api/v1/mobile/auth/token/", sent.target)
                    assertNull(sent.headers["Authorization"])
                }
            }
        }
    }

    @Test fun closedTransportRejectsFurtherCallsWithoutNetwork() = runBlocking {
        server().use { server ->
            val http = transport(server)
            http.close()
            assertEquals(RemoteFailureKind.UNAVAILABLE, suspendReject { http.exchange("me/", accessToken = bearer).close() }.kind)
            assertEquals(0, server.requestCount)
        }
    }

    @Test fun validReceiptBindsExactFrozenRequestAndMalformedSuccessStaysUncertain() = runBlocking {
        val content = MaintenanceContent("2026-10-17T08:00:00Z", "WATER_SUPPLY", "ROUTINE", "Area A", "Synthetic site", "Synthetic reporter", "Synthetic e\u0301", "Inspection")
        val request = RequestPolicy.request(RemoteFixtures.id(70), RemoteFixtures.id(71), 0, content, Long.MAX_VALUE)
        val bytes = CanonicalJson.bytes(request)
        val claim = DeliveryClaim(1, "store", RemoteFixtures.id(70), RemoteFixtures.id(71), 0, RequestPolicy.requestHash(request), "claim", "session", "boot", 120000, bytes)
        claim.use {
            server().use { server ->
                val receipt = "{\"operation_id\":\"${claim.operationId}\",\"report_id\":\"${claim.reportId}\",\"revision_id\":\"${RemoteFixtures.id(72)}\",\"revision_no\":1,\"delivery_status\":\"RECEIVED\",\"processing_status\":\"PENDING\",\"shared\":false}"
                server.enqueue(json(receipt, 201)); server.enqueue(json(receipt.replace("\"shared\":false", "\"shared\":true"), 200))
                MobileProtocolClient(transport(server)) { RemoteFixtures.arrival }.use { client ->
                    assertEquals(claim.operationId, client.send(claim, bearer).operationId)
                    val sent = server.takeRequest(1, TimeUnit.SECONDS)!!
                    assertEquals(claim.operationId, sent.headers["Idempotency-Key"])
                    assertArrayEquals(bytes, sent.body!!.toByteArray())
                    assertTrue(suspendReject { client.send(claim, bearer) }.mutationUncertain)
                    assertEquals(2, server.requestCount)
                }
            }
        }
    }

    @Test fun retryAfterUsesTrustedServerTimeAndCapsWithoutPhoneWallClock() {
        assertEquals(0L, retryAfter("0", null)); assertEquals(86400L, retryAfter("999999999999999999999", null))
        assertNull(retryAfter("-1", 0)); assertNull(retryAfter("not a date", 0))
        assertNull(retryAfter("Sat, 17 Oct 2026 08:00:10 GMT", null))
        val serverNow = java.time.Instant.parse("2026-10-17T08:00:00Z").toEpochMilli()
        assertEquals(10L, retryAfter("Sat, 17 Oct 2026 08:00:10 GMT", serverNow))
        assertEquals(0L, retryAfter("Sat, 17 Oct 2026 07:59:59 GMT", serverNow))
    }

    @Test fun allThreeHttpDateFormsResolveAgainstTrustedServerClockIncludingEquality() {
        val now = java.time.Instant.parse("2026-10-17T08:00:00Z").toEpochMilli()
        for (value in listOf("Sat, 17 Oct 2026 08:00:10 GMT", "Saturday, 17-Oct-26 08:00:10 GMT", "Sat Oct 17 08:00:10 2026")) {
            assertEquals(10L, retryAfter(value, now))
            assertEquals(0L, retryAfter(value, now + 10_000))
            assertNull(retryAfter(value, null))
            val failure = RemoteFailure(RemoteFailureKind.HTTP, 429, retryAfterDate = parseRetryAfterDate(value))
            assertEquals(10L, failure.retryDelaySeconds(now))
        }
        val oldNow = java.time.Instant.parse("1994-11-06T08:49:30Z").toEpochMilli()
        assertEquals(7L, retryAfter("Sun Nov  6 08:49:37 1994", oldNow))
        for (value in listOf("Sat, 30 Feb 2026 08:00:10 GMT", "Saturday, 30-Feb-26 08:00:10 GMT", "Sat Feb 30 08:00:10 2026", "Sat, 17 Oct 2026 08:00:10 UTC"))
            assertNull(retryAfter(value, now))
    }

    @Test fun rfc850RollsBackOnlyBeyondFiftyYearsWithoutAnyLocalWallClock() {
        val now = java.time.Instant.parse("2026-10-17T08:00:00Z").toEpochMilli()
        val format = java.time.format.DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss 'GMT'", java.util.Locale.US)
        val exactly = java.time.LocalDateTime.parse("2076-10-17T08:00:00")
        assertEquals(86400L, retryAfter(exactly.format(format), now))
        assertEquals(86400L, retryAfter(exactly.minusSeconds(1).format(format), now))
        // The identical2-digit year one second past the boundary denotes the previous century.
        val rolled = java.time.LocalDateTime.parse("1976-10-17T08:00:01")
        assertEquals(0L, retryAfter(rolled.format(format), now))
        assertNull(retryAfter("Monday, 17-Oct-26 08:00:10 GMT", now))
    }

    @Test fun rfc850CenturyWindowCanCrossIntoNextCenturyAndValidatesChosenLeapYear() {
        val format = java.time.format.DateTimeFormatter.ofPattern("EEEE, dd-MMM-yy HH:mm:ss 'GMT'", java.util.Locale.US)
        val now = java.time.Instant.parse("2090-10-17T08:00:00Z").toEpochMilli()
        val nextCentury = java.time.LocalDateTime.parse("2100-10-17T08:00:10")
        assertEquals(86400L, retryAfter(nextCentury.format(format), now))
        val priorLeap = java.time.LocalDateTime.parse("2000-02-29T08:00:00")
        val beforeBoundary = java.time.Instant.parse("2050-01-01T00:00:00Z").toEpochMilli()
        assertEquals(0L, retryAfter(priorLeap.format(format), beforeBoundary))
        assertNull(retryAfter(priorLeap.format(format), now))
    }

    @Test fun leapSecondRetainsOriginalWeekdayAndOnlyAllowsEndOfUtcDay() {
        val now = java.time.Instant.parse("2016-12-31T23:59:59Z").toEpochMilli()
        for (value in listOf("Sat, 31 Dec 2016 23:59:60 GMT", "Saturday, 31-Dec-16 23:59:60 GMT", "Sat Dec 31 23:59:60 2016")) {
            assertEquals(1L, retryAfter(value, now))
            assertEquals(0L, retryAfter(value, now + 1_000))
            assertNull(retryAfter(value.replace("23:59:60", "12:59:60"), now))
            assertNull(retryAfter(value.replace("23:59:60", "23:58:60"), now))
        }
        assertNull(retryAfter("Sun, 31 Dec 2016 23:59:60 GMT", now))
        assertNull(retryAfter("Sunday, 31-Dec-16 23:59:60 GMT", now))
        assertNull(retryAfter("Sun Dec 31 23:59:60 2016", now))
    }

    private fun server() = MockWebServer().apply { start(InetAddress.getByName("127.0.0.1"), 0) }
    private fun loopbackUrl(server: MockWebServer) = server.url("/api/v1/").newBuilder().host("127.0.0.1").build()
    private fun transport(server: MockWebServer) = MobileHttpTransport(MobileEndpoint.loopbackFixture(loopbackUrl(server)))
    private fun json(body: String, status: Int = 200, cookie: Boolean = false) = MockResponse.Builder().code(status).body(body)
        .addHeader("Content-Type", "application/json").addHeader("Cache-Control", "private, no-store")
        .apply { if (cookie) addHeader("Set-Cookie", "synthetic=discard; Path=/") }.build()
    private suspend fun suspendReject(action: suspend () -> Unit): RemoteFailure {
        try { action(); fail("Expected sanitized remote failure") } catch (failure: RemoteFailure) { return failure }
        error("unreachable")
    }
}

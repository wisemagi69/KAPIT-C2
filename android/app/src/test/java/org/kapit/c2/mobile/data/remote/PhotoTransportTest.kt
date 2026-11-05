package org.kapit.c2.mobile.data.remote

import java.net.InetAddress
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.runBlocking
import mockwebserver3.MockResponse
import mockwebserver3.MockWebServer
import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.domain.*

class PhotoTransportTest {
    private val id = "00000000-0000-4000-8000-000000000001"
    private val operation = "00000000-0000-4000-8000-000000000002"
    private val token = "e30.e30.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".toByteArray()
    private val capture = PhotoPolicy.capture(1792627200123, 1000, null)
    private fun response(body: String, status: Int = 200) = MockResponse.Builder().code(status).addHeader("Content-Type", "application/json").addHeader("Cache-Control", "private, no-store").body(body).build()
    @Test fun rawJpegAndExactFrozenHeadersUseSeparateSeamWithoutWeakeningJson() = runBlocking {
        MockWebServer().use { server ->
            server.start(InetAddress.getByName("127.0.0.1"), 0)
            server.enqueue(response("{}", 201)); server.enqueue(response("{}", 201))
            MobileHttpTransport(MobileEndpoint.loopbackFixture(server.url("/api/v1/").newBuilder().host("127.0.0.1").build())).use { http ->
                repeat(2) { http.evidence(id, token, byteArrayOf(-1, -40, -1, -39), operation, capture).close() }
                repeat(2) {
                    val request = server.takeRequest(1, TimeUnit.SECONDS)!!
                    assertEquals("/api/v1/mobile/revisions/$id/evidence/", request.target)
                    assertEquals("image/jpeg", request.headers["Content-Type"])
                    assertEquals("capture.jpg", request.headers["X-Evidence-Filename"])
                    assertEquals(operation, request.headers["Idempotency-Key"])
                    assertEquals(capture, request.headers["X-Evidence-Capture"])
                    assertEquals(4L, request.bodySize)
                    assertNull(request.headers["Cookie"])
                }
                try { http.exchange("revisions/$id/evidence/", byteArrayOf(-1, -40, -1, -39), token, operation); fail("Generic JSON cannot upload evidence") }
                catch (failure: RemoteFailure) { assertEquals(RemoteFailureKind.INVALID_REQUEST, failure.kind) }
            }
        }
    }
    @Test fun denialStatusSurvivesMalformedBodyHeadersAndLargeRepliesRefuse() = runBlocking {
        MockWebServer().use { server ->
            server.start(InetAddress.getByName("127.0.0.1"), 0)
            server.enqueue(MockResponse.Builder().code(403).body("denied").build())
            server.enqueue(response("x".repeat(8193)))
            MobileHttpTransport(MobileEndpoint.loopbackFixture(server.url("/api/v1/").newBuilder().host("127.0.0.1").build())).use { http ->
                try { http.evidence(id, token); fail("Malformed denial must fail") }
                catch (failure: RemoteFailure) { assertEquals(403, failure.status) }
                try { http.evidence(id, token); fail("Oversized body must fail") }
                catch (failure: RemoteFailure) { assertEquals(RemoteFailureKind.INVALID_RESPONSE, failure.kind) }
            }
        }
    }
    @Test fun wrongOperationReceiptAndUnknownValidatedStatusFailClosed() = runBlocking {
        MockWebServer().use { server ->
            server.start(InetAddress.getByName("127.0.0.1"), 0)
            server.enqueue(response("""{"id":"$id","operation_id":"$id","state":"QUARANTINED","validation_code":"DECODER_REQUIRED","created_at":"2026-10-22T00:00:00Z"}""", 201))
            server.enqueue(response("""{"evidence_id":"$id","state":"VALIDATED_PRIVATE","validation_code":"UNKNOWN","can_download":true}"""))
            MobileProtocolClient(MobileHttpTransport(MobileEndpoint.loopbackFixture(server.url("/api/v1/").newBuilder().host("127.0.0.1").build()))) { ClockStamp(1, "synthetic") }.use { client ->
                PhotoUpload(PhotoPending(operation, id, id, 1, null), capture, byteArrayOf(-1, -40, -1, -39)).use { queued ->
                    try { client.uploadPhoto(token, queued); fail("Changed operation cannot confirm") } catch (_: RemoteFailure) { }
                }
                try { client.photoStatus(token, id); fail("Unknown verdict cannot be displayed") } catch (_: RemoteFailure) { }
            }
        }
    }
    @Test fun privateNoStoreIsMandatoryForEvidenceReplies() = runBlocking {
        for (cache in listOf<String?>(null, "private", "no-store", "public, max-age=60")) {
            MockWebServer().use { server ->
                server.start(InetAddress.getByName("127.0.0.1"), 0)
                server.enqueue(MockResponse.Builder().code(200).addHeader("Content-Type", "application/json").apply {
                    if (cache != null) addHeader("Cache-Control", cache)
                }.body("{}").build())
                MobileHttpTransport(MobileEndpoint.loopbackFixture(server.url("/api/v1/").newBuilder().host("127.0.0.1").build())).use { http ->
                    try { http.evidence(id, token); fail("Unsafe cache headers cannot confirm") }
                    catch (failure: RemoteFailure) { assertEquals(RemoteFailureKind.INVALID_RESPONSE, failure.kind) }
                }
            }
        }
    }
    @Test fun committedQuarantineReceiptAndCurrentStatusHaveExactShape() = runBlocking {
        MockWebServer().use { server ->
            server.start(InetAddress.getByName("127.0.0.1"), 0)
            server.enqueue(response("""{"id":"$id","operation_id":"$operation","state":"QUARANTINED","validation_code":"DECODER_REQUIRED","created_at":"2026-10-22T00:00:00Z"}""", 201))
            server.enqueue(response("""{"evidence_id":"$id","state":"QUARANTINED","validation_code":"DECODER_REQUIRED","can_download":false}"""))
            MobileProtocolClient(MobileHttpTransport(MobileEndpoint.loopbackFixture(server.url("/api/v1/").newBuilder().host("127.0.0.1").build()))) { ClockStamp(1, "synthetic") }.use { client ->
                PhotoUpload(PhotoPending(operation, id, id, 1, null), capture, byteArrayOf(-1, -40, -1, -39)).use { queued ->
                    val accepted = client.uploadPhoto(token, queued)
                    assertEquals(id, accepted.id); assertEquals(operation, accepted.operationId)
                }
                val status = client.photoStatus(token, id)
                assertEquals("QUARANTINED", status.state); assertEquals("DECODER_REQUIRED", status.validationCode)
            }
        }
    }
}

package org.kapit.c2.mobile

import org.junit.Assert.*
import org.junit.Test
import org.kapit.c2.mobile.domain.*

class PhotoPolicyTest {
    private val wall = 1792627200123L
    private fun reject(body: () -> Unit) {
        try { body(); fail("Expected fixed policy refusal") } catch (failure: StoreFailure) {
            assertEquals(StoreCode.VALIDATION_ERROR, failure.code)
        }
    }
    @Test fun captureWithoutLocationAndAccurateApproximateMockFixRemainExplicit() {
        val none = PhotoPolicy.capture(wall, 10000, null)
        assertTrue(none.contains("\"location\":null")); PhotoPolicy.validateCapture(none)
        val fix = PhotoFix(123456789, -123456789, 850000, wall - 1234, 10000 - 1234, true)
        val captured = PhotoPolicy.capture(wall, 10000, fix)
        assertTrue(captured.contains("\"age_ms\":1234")); assertTrue(captured.contains("\"mock\":true"))
        assertFalse(fix.toString().contains("123456789"))
        PhotoPolicy.validateCapture(captured)
    }
    @Test fun laterAndStaleFixNeverRetimestampAnExistingCapture() {
        reject { PhotoPolicy.capture(wall, 100000, PhotoFix(0, 0, 10, wall + 1, 100001, false)) }
        reject { PhotoPolicy.capture(wall, 100000, PhotoFix(0, 0, 10, wall - 30001, 69999, false)) }
        reject { PhotoPolicy.capture(wall, 100000, PhotoFix(0, 0, 10, wall - 2000, 99999, false)) }
        reject { PhotoPolicy.capture(wall, 100000, PhotoFix(0, 0, 10, wall + 1, 99999, false)) }
    }
    @Test fun strictMetadataRejectsUnknownDuplicateFloatBooleanNumbersAndOutOfRange() {
        val valid = PhotoPolicy.capture(wall, 10000, PhotoFix(1, 2, 3, wall - 1, 9999, false))
        listOf(valid.replace("\"version\":1", "\"version\":true"),
            valid.replace("\"version\":1", "\"version\":1,\"version\":1"),
            valid.replace("\"version\":1", "\"version\":1,\"extra\":1"),
            valid.replace("\"latitude_e7\":1", "\"latitude_e7\":1.0"),
            valid.replace("\"latitude_e7\":1", "\"latitude_e7\":900000001"),
            valid.replace("\"accuracy_mm\":3", "\"accuracy_mm\":0"),
            valid.replace("\"mock\":false", "\"mock\":\"false\""),
            valid.replace(".123Z", ".1234Z"), valid.replace("Z", "+00:00"), "x".repeat(1025)
        ).forEach { value -> reject { PhotoPolicy.validateCapture(value) } }
    }
    @Test fun exactlyThirtySecondsAndOneSecondClockToleranceAreBounded() {
        PhotoPolicy.capture(wall, 100000, PhotoFix(900000000, -1800000000, 100000000, wall - 30000, 70000, false))
        PhotoPolicy.capture(wall, 100000, PhotoFix(0, 0, 1, wall - 1000, 100000, false))
        reject { PhotoPolicy.capture(wall, 100000, PhotoFix(0, 0, 1, wall - 1001, 100000, false)) }
    }
    @Test fun immutableDetachedUploadCopiesAndClosePreventReuse() {
        val bytes = byteArrayOf(-1, -40, -1, -39)
        val queued = PhotoPending("op", "report", "revision", 1, null)
        val upload = PhotoUpload(queued, PhotoPolicy.capture(wall, 1, null), bytes)
        bytes.fill(0)
        assertTrue(upload.copyBytes().contentEquals(byteArrayOf(-1, -40, -1, -39)))
        val copy = upload.copyBytes(); copy.fill(0)
        assertTrue(upload.copyBytes().contentEquals(byteArrayOf(-1, -40, -1, -39)))
        upload.close()
        try { upload.copyBytes(); fail("Closed upload cannot be replayed") } catch (failure: StoreFailure) { assertEquals(StoreCode.STALE_GENERATION, failure.code) }
    }
    @Test fun jpegFramingServerAndSmallerLocalCursorBoundsAreDistinct() {
        PhotoPolicy.jpeg(byteArrayOf(-1, -40, -1, -39))
        reject { PhotoPolicy.jpeg(byteArrayOf(0, 1, 2, 3)) }
        reject { PhotoPolicy.jpeg(ByteArray(PhotoPolicy.MAX_BYTES + 1)) }
        assertTrue(PhotoPolicy.LOCAL_BYTES < 1024 * 1024)
        assertEquals(2_000_000, PhotoPolicy.MAX_PIXELS)
    }
    @Test fun oldPermissionResultCannotStartCameraOrLocationForNewContext() {
        val fence = PhotoPermissionFence(); val original = Any(); val next = Any()
        assertTrue(fence.begin(original, 1, "revision1"))
        assertFalse(fence.begin(next, 2, "revision2")) // Do not overwrite an unresolved platform request.
        assertFalse(fence.consume(next, 2, "revision2", true))
        assertFalse(fence.consume(original, 1, "revision1", true)) // Stale callback was consumed once.
        assertTrue(fence.begin(next, 2, "revision2"))
        assertFalse(fence.consume(next, 2, "revision2", false)) // Background/lock denies.
        assertTrue(fence.begin(next, 2, "revision2"))
        assertFalse(fence.consume(next, 2, "revision3", true))
        assertTrue(fence.begin(next, 2, "revision2"))
        assertTrue(fence.consume(next, 2, "revision2", true))
        assertFalse(fence.consume(next, 2, "revision2", true))
    }
    @Test fun lifecycleCloseSerializesWithNativeAdoptionAndRejectsLateHandles() {
        val owner = PhotoOwnership()
        val entered = java.util.concurrent.CountDownLatch(1)
        val allow = java.util.concurrent.CountDownLatch(1)
        var adopted = false; var closedOwned = false
        val pool = java.util.concurrent.Executors.newFixedThreadPool(2)
        try {
            val callback = pool.submit {
                owner.withOpen { entered.countDown(); check(allow.await(2, java.util.concurrent.TimeUnit.SECONDS)); adopted = true }
            }
            assertTrue(entered.await(2, java.util.concurrent.TimeUnit.SECONDS))
            val closing = pool.submit { owner.close { closedOwned = adopted; adopted = false } }
            allow.countDown(); callback.get(2, java.util.concurrent.TimeUnit.SECONDS); closing.get(2, java.util.concurrent.TimeUnit.SECONDS)
            assertTrue(closedOwned); assertFalse(adopted)
            assertFalse(owner.withOpen { adopted = true })
            assertFalse(adopted)
        } finally { allow.countDown(); pool.shutdownNow() }
    }
}

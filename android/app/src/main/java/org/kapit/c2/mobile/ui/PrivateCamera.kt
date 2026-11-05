package org.kapit.c2.mobile.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.ImageFormat
import android.graphics.SurfaceTexture
import android.hardware.camera2.*
import android.media.ImageReader
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.SystemClock
import android.view.Surface
import android.view.TextureView
import org.kapit.c2.mobile.domain.PhotoFix
import org.kapit.c2.mobile.domain.PhotoPolicy
import org.kapit.c2.mobile.domain.PhotoOwnership

/** In-app camera surfaces and bounded JPEG memory only. No file/gallery/intent API. */
@androidx.annotation.RequiresApi(35)
internal class PrivateCamera(private val context: Context, private val view: TextureView,
    private val result: (ByteArray, String, PhotoFix?) -> Unit, private val failed: () -> Unit) : AutoCloseable {
    private val thread = HandlerThread("private-capture").apply { start() }
    private val handler = Handler(thread.looper)
    private val main = Handler(Looper.getMainLooper())
    @Volatile private var closed = false
    private val ownership = PhotoOwnership()
    private var camera: CameraDevice? = null
    private var session: CameraCaptureSession? = null
    private var reader: ImageReader? = null
    private var preview: Surface? = null
    private var metadata: String? = null
    private var capturedFix: PhotoFix? = null
    private var taking = false

    init {
        view.surfaceTextureListener = object : TextureView.SurfaceTextureListener {
            override fun onSurfaceTextureAvailable(texture: SurfaceTexture, width: Int, height: Int) { open(texture) }
            override fun onSurfaceTextureSizeChanged(texture: SurfaceTexture, width: Int, height: Int) = Unit
            override fun onSurfaceTextureUpdated(texture: SurfaceTexture) = Unit
            override fun onSurfaceTextureDestroyed(texture: SurfaceTexture): Boolean { close(); return true }
        }
        if (view.isAvailable) view.surfaceTexture?.let(::open)
    }

    @Suppress("MissingPermission", "DEPRECATION")
    private fun open(texture: SurfaceTexture) {
        ownership.withOpen { openOwned(texture) }
    }
    @Suppress("MissingPermission", "DEPRECATION")
    private fun openOwned(texture: SurfaceTexture) {
        if (closed || context.checkSelfPermission(Manifest.permission.CAMERA) != PackageManager.PERMISSION_GRANTED) return
        try {
            val manager = context.getSystemService(CameraManager::class.java)
            val id = manager.cameraIdList.firstOrNull { manager.getCameraCharacteristics(it)[CameraCharacteristics.LENS_FACING] == CameraCharacteristics.LENS_FACING_BACK }
                ?: throw IllegalStateException()
            val characteristics = manager.getCameraCharacteristics(id)
            // Sensor REALTIME binds the actual exposure timestamp to elapsedRealtime;
            // unsupported clock domains refuse capture instead of retimestamping.
            check(characteristics[CameraCharacteristics.SENSOR_INFO_TIMESTAMP_SOURCE] == CameraCharacteristics.SENSOR_INFO_TIMESTAMP_SOURCE_REALTIME)
            val streams = checkNotNull(characteristics[CameraCharacteristics.SCALER_STREAM_CONFIGURATION_MAP])
            val sizes = streams.getOutputSizes(ImageFormat.JPEG).orEmpty()
            val size = sizes.filter { it.width <= 1600 && it.height <= 1600 && it.width.toLong() * it.height <= PhotoPolicy.MAX_PIXELS }
                .maxByOrNull { it.width.toLong() * it.height } ?: throw IllegalStateException()
            val previewSize = streams.getOutputSizes(SurfaceTexture::class.java).orEmpty()
                .filter { it.width <= 1600 && it.height <= 1600 && it.width.toLong() * it.height <= PhotoPolicy.MAX_PIXELS }
                .maxByOrNull { it.width.toLong() * it.height } ?: throw IllegalStateException()
            texture.setDefaultBufferSize(previewSize.width, previewSize.height)
            preview = Surface(texture)
            reader = ImageReader.newInstance(size.width, size.height, ImageFormat.JPEG, 1).also { source ->
                source.setOnImageAvailableListener({ sourceReader ->
                    var bytes: ByteArray? = null
                    try {
                        sourceReader.acquireLatestImage()?.use { image ->
                            val buffer = image.planes.single().buffer
                            check(buffer.remaining() in 4..PhotoPolicy.LOCAL_BYTES)
                            bytes = ByteArray(buffer.remaining()).also(buffer::get)
                            PhotoPolicy.jpeg(bytes!!)
                            val capture = checkNotNull(metadata)
                            val fix = capturedFix
                            val owned = bytes!!; bytes = null
                            main.post { if (closed) owned.fill(0) else result(owned, capture, fix) }
                        }
                    } catch (_: Exception) { bytes?.fill(0); error() }
                    finally { taking = false; metadata = null; capturedFix = null }
                }, handler)
            }
            // The process main executor remains alive after our worker stops:
            // a pending open must still deliver its late device for closure.
            manager.openCamera(id, context.mainExecutor, object : CameraDevice.StateCallback() {
                override fun onOpened(device: CameraDevice) {
                    if (!ownership.withOpen {
                    camera = device
                    try { device.createCaptureSession(listOf(preview!!, reader!!.surface), object : CameraCaptureSession.StateCallback() {
                        override fun onConfigured(value: CameraCaptureSession) {
                            if (!ownership.withOpen {
                            session = value
                            try { value.setRepeatingRequest(device.createCaptureRequest(CameraDevice.TEMPLATE_PREVIEW).apply { addTarget(preview!!) }.build(), null, handler) }
                            catch (_: Exception) { error() }
                            }) value.close()
                        }
                        override fun onConfigureFailed(value: CameraCaptureSession) { value.close(); error() }
                    }, main) } catch (_: Exception) { error() }
                    }) device.close()
                }
                override fun onDisconnected(device: CameraDevice) { device.close(); error() }
                override fun onError(device: CameraDevice, code: Int) { device.close(); error() }
            })
        } catch (_: Exception) { error() }
    }

    fun capture(fix: PhotoFix?) {
        handler.post {
            if (closed || taking) return@post
            try {
                val device = checkNotNull(camera); val active = checkNotNull(session); val output = checkNotNull(reader)
                val startElapsed = SystemClock.elapsedRealtime(); val startWall = System.currentTimeMillis()
                taking = true
                active.capture(device.createCaptureRequest(CameraDevice.TEMPLATE_STILL_CAPTURE).apply {
                    addTarget(output.surface); set(CaptureRequest.JPEG_QUALITY, 70.toByte())
                }.build(), object : CameraCaptureSession.CaptureCallback() {
                    override fun onCaptureStarted(value: CameraCaptureSession, request: CaptureRequest, timestamp: Long, frame: Long) {
                        ownership.withOpen {
                        try {
                            val exposureElapsed = timestamp / 1_000_000
                            check(exposureElapsed - startElapsed in 0..5000)
                            val exposureWall = startWall + (exposureElapsed - startElapsed)
                            check(kotlin.math.abs(System.currentTimeMillis() - exposureWall) <= 5000)
                            metadata = PhotoPolicy.capture(exposureWall, exposureElapsed, fix)
                            capturedFix = fix
                        } catch (_: Exception) { metadata = null; error() }
                        }
                    }
                    override fun onCaptureFailed(value: CameraCaptureSession, request: CaptureRequest, failure: CaptureFailure) { taking = false; error() }
                }, handler)
            } catch (_: Exception) { taking = false; error() }
        }
    }

    private fun error() { main.post { if (!closed) failed() } }
    override fun close() {
        val release = mutableListOf<() -> Unit>()
        ownership.close {
            closed = true
            session?.let { owned -> release += { owned.close() } }; session = null
            camera?.let { owned -> release += { owned.close() } }; camera = null
            reader?.let { owned -> release += { owned.close() } }; reader = null
            preview?.let { owned -> release += { owned.release() } }; preview = null
            metadata = null
            capturedFix = null
        }
        // Detach atomically, close outside the ownership monitor. An arriving
        // onOpened/onConfigured must close its own never-adopted handle.
        release.forEach { action -> try { action() } catch (_: Exception) { } }
        thread.quitSafely() // No self-join or process-global camera operation.
    }
}

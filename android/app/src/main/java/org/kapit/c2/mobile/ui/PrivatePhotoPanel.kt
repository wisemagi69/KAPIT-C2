package org.kapit.c2.mobile.ui

import android.Manifest
import android.content.Context
import android.content.pm.PackageManager
import android.graphics.Bitmap
import android.graphics.BitmapFactory
import android.location.LocationManager
import android.os.CancellationSignal
import android.os.SystemClock
import android.view.TextureView
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.Image
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asImageBitmap
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.unit.dp
import androidx.compose.ui.viewinterop.AndroidView
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.LifecycleEventObserver
import androidx.lifecycle.compose.LocalLifecycleOwner
import java.util.Locale
import java.util.UUID
import kotlin.math.roundToLong
import org.kapit.c2.mobile.domain.*

@androidx.annotation.RequiresApi(35)
private class PhotoMemory : AutoCloseable {
    var active = true
    var bytes: ByteArray? = null
    var bitmap: Bitmap? = null
    var capture: String? = null
    var fix: PhotoFix? = null
    var location: CancellationSignal? = null
    var camera: PrivateCamera? = null
    var pendingOperation: String? = null
    fun discard() { bytes?.fill(0); bytes = null; bitmap?.recycle(); bitmap = null; capture = null }
    override fun close() {
        active = false; location?.cancel(); location = null; fix = null
        camera?.close(); camera = null; discard()
    }
}

/** Memory-only preview; saved work goes through the protected repository, never a URI/file. */
@Composable
@androidx.annotation.RequiresApi(35)
internal fun PrivatePhotoPanel(state: MobileUiState, actions: MobileActions, report: ReportDetailUi) {
    val revision = report.revisionId ?: return
    val currentRevision = report.history.firstOrNull()?.revision == report.revision
    val context = LocalContext.current
    val lifecycle = LocalLifecycleOwner.current.lifecycle
    val memory = remember(state.accountGeneration, revision) { PhotoMemory() }
    val cameraTicket = remember { PhotoPermissionFence() }
    val locationTicket = remember { PhotoPermissionFence() }
    var change by remember(memory) { mutableIntStateOf(0) }
    var cameraVisible by remember(memory) { mutableStateOf(false) }
    var message by remember(memory) { mutableStateOf<String?>(null) }
    fun alive() = memory.active && lifecycle.currentState.isAtLeast(Lifecycle.State.STARTED)
    fun permission(name: String) = context.checkSelfPermission(name) == PackageManager.PERMISSION_GRANTED
    val cameraPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestPermission()) { granted ->
        if (cameraTicket.consume(memory, state.accountGeneration, revision, alive())) {
            cameraVisible = granted; if (!granted) message = "Camera permission denied. Text reporting remains available."
        }
    }
    fun location() {
        if (!alive()) return
        memory.location?.cancel(); memory.fix = null; message = "Waiting for a fresh foreground location (up to 15 seconds)."; change++
        try {
            val manager = context.getSystemService(LocationManager::class.java)
            val provider = if (permission(Manifest.permission.ACCESS_FINE_LOCATION) && manager.isProviderEnabled(LocationManager.GPS_PROVIDER)) LocationManager.GPS_PROVIDER
                else if (permission(Manifest.permission.ACCESS_COARSE_LOCATION) && manager.isProviderEnabled(LocationManager.NETWORK_PROVIDER)) LocationManager.NETWORK_PROVIDER
                else throw IllegalStateException()
            val signal = CancellationSignal(); memory.location = signal
            @Suppress("MissingPermission")
            manager.getCurrentLocation(provider, signal, context.mainExecutor) { fix ->
                if (!alive() || memory.location !== signal || signal.isCanceled) return@getCurrentLocation
                memory.location = null
                try {
                    check(fix != null && fix.hasAccuracy() && fix.latitude.isFinite() && fix.longitude.isFinite() && fix.accuracy.isFinite())
                    val elapsed = fix.elapsedRealtimeNanos / 1_000_000
                    check(SystemClock.elapsedRealtime() - elapsed in 0..30000)
                    val value = PhotoFix((fix.latitude * 1e7).roundToLong(), (fix.longitude * 1e7).roundToLong(),
                        (fix.accuracy * 1000).roundToLong(), fix.time, elapsed, fix.isMock)
                    PhotoPolicy.capture(System.currentTimeMillis(), SystemClock.elapsedRealtime(), value)
                    memory.fix = value
                    message = "Device-reported phone location ready. Capture within 30 seconds; check coordinates and accuracy below."
                } catch (_: Exception) { memory.fix = null; message = "A fresh permitted location was unavailable. Capture without location or request a new fix." }
                change++
            }
            // Stop a stalled foreground request; no passive/background listener is installed.
            android.os.Handler(android.os.Looper.getMainLooper()).postDelayed({
                if (memory.location === signal) {
                    signal.cancel(); memory.location = null
                    if (alive()) message = "Location request timed out. No coordinates are attached."
                }
            }, 15000)
        } catch (_: Exception) { message = "Location unavailable with current permissions. No coordinates will be attached." }
    }
    val locationPermission = rememberLauncherForActivityResult(ActivityResultContracts.RequestMultiplePermissions()) {
        if (locationTicket.consume(memory, state.accountGeneration, revision, alive())) {
            if (permission(Manifest.permission.ACCESS_COARSE_LOCATION) || permission(Manifest.permission.ACCESS_FINE_LOCATION)) location()
            else message = "Location permission denied. You can capture without coordinates."
        }
    }
    DisposableEffect(memory, lifecycle) {
        val observer = LifecycleEventObserver { _, event -> if (event == Lifecycle.Event.ON_STOP) memory.close() }
        lifecycle.addObserver(observer)
        onDispose { lifecycle.removeObserver(observer); memory.close() }
    }
    LaunchedEffect(report.photos, memory.pendingOperation) {
        if (memory.pendingOperation != null && report.photos.any { it.operationId == memory.pendingOperation }) {
            memory.discard(); memory.pendingOperation = null; change++
        }
    }
    // Read is intentional: mutable private buffers stay out of Compose saved state.
    @Suppress("UNUSED_VARIABLE") val presentation = change
    ContentCard {
        SectionHeading("Private photo evidence")
        QuietText("Optional in-app JPEG. Photos and phone coordinates remain private; they are not recipient or map content.")
        QuietText("Location describes this phone, not a distant photographed subject. Device mock status is not verified.")
        message?.let { QuietText(it) }
        report.photoStatus?.let { QuietText(it) }
        memory.fix?.let { fix ->
            Fact("Phone coordinates", String.format(Locale.ROOT, "%.7f, %.7f", fix.latitudeE7 / 1e7, fix.longitudeE7 / 1e7))
            Fact("Reported accuracy", String.format(Locale.ROOT, "%.1f m", fix.accuracyMm / 1000.0))
            if (fix.mock) QuietText("Device reports a mock location. This is not proof of presence.")
        }
        if (!currentRevision) QuietText("Historical revision: only existing frozen uploads and their private status can be retried.")
        if (currentRevision && memory.bytes == null && report.photos.size < 2) {
            SecondaryAction("Request optional foreground location", !state.busy) {
                if (permission(Manifest.permission.ACCESS_COARSE_LOCATION) || permission(Manifest.permission.ACCESS_FINE_LOCATION)) location()
                else if (locationTicket.begin(memory, state.accountGeneration, revision)) locationPermission.launch(arrayOf(Manifest.permission.ACCESS_COARSE_LOCATION, Manifest.permission.ACCESS_FINE_LOCATION))
            }
            if (memory.fix != null) SecondaryAction("Capture without location", !state.busy) { memory.fix = null; change++ }
            if (!cameraVisible) SecondaryAction("Open private in-app camera", !state.busy) {
                if (permission(Manifest.permission.CAMERA)) cameraVisible = true
                else if (cameraTicket.begin(memory, state.accountGeneration, revision)) cameraPermission.launch(Manifest.permission.CAMERA)
            }
        }
        if (cameraVisible && memory.bytes == null) {
            Box(Modifier.fillMaxWidth().height(220.dp)) {
                AndroidView(factory = { ctx -> TextureView(ctx).also { view ->
                    memory.camera = PrivateCamera(ctx, view, { bytes, capture, attachedFix ->
                        if (!alive()) bytes.fill(0) else try {
                            val options = BitmapFactory.Options().apply { inJustDecodeBounds = true }
                            BitmapFactory.decodeByteArray(bytes, 0, bytes.size, options)
                            check(options.outWidth > 0 && options.outHeight > 0 && options.outWidth.toLong() * options.outHeight <= PhotoPolicy.MAX_PIXELS)
                            val bitmap = checkNotNull(BitmapFactory.decodeByteArray(bytes, 0, bytes.size))
                            memory.location?.cancel(); memory.location = null
                            memory.discard(); memory.bytes = bytes; memory.bitmap = bitmap; memory.capture = capture; memory.fix = attachedFix
                            memory.camera?.close(); memory.camera = null; cameraVisible = false; change++
                        } catch (_: Exception) { bytes.fill(0); message = "Capture could not be safely previewed. Nothing was saved." }
                    }, {
                        if (alive()) { memory.camera?.close(); memory.camera = null; cameraVisible = false
                            message = "Camera capture unavailable or outside size, timestamp or location limits. Nothing was saved." }
                    })
                } }, modifier = Modifier.fillMaxWidth().height(220.dp))
            }
            PrimaryAction("Capture private JPEG", !state.busy) { memory.camera?.capture(memory.fix) }
            SecondaryAction("Close camera", !state.busy) { memory.camera?.close(); memory.camera = null; cameraVisible = false }
        }
        memory.bitmap?.let { image ->
            Image(image.asImageBitmap(), "Private photo preview", Modifier.fillMaxWidth().height(220.dp))
            QuietText("Not saved or uploaded yet. Retake to change the photo or coordinates.")
            SecondaryAction("Retake private photo", !state.busy && memory.pendingOperation == null) { memory.discard(); cameraVisible = true; change++ }
            SecondaryAction("Discard unsaved photo", !state.busy && memory.pendingOperation == null) { memory.discard(); change++ }
            PrimaryAction(if (memory.pendingOperation == null) "Save to encrypted photo queue" else "Retry saving same private photo", !state.busy) {
                val bytes = memory.bytes; val capture = memory.capture
                if (alive() && bytes != null && capture != null) {
                    val operation = memory.pendingOperation ?: UUID.randomUUID().toString().also { memory.pendingOperation = it }
                    actions.dispatch(MobileAction.QueuePhoto(state.accountGeneration, report.reportId, revision, report.revision, operation, capture, bytes))
                    change++
                }
            }
        }
        report.photos.forEachIndexed { index, photo ->
            Fact("Private photo ${index + 1}", if (photo.evidenceId == null) "Encrypted queue: server receipt not confirmed" else "Upload received privately; validation is separate")
            if (photo.evidenceId == null) {
                QuietText("An uncertain upload stays frozen. Retry uses the same image, coordinates and operation ID.")
                SecondaryAction("Upload or retry same private photo ${index + 1}", !state.busy && state.capabilities.synchronize) {
                    actions.dispatch(MobileAction.UploadPhoto(state.accountGeneration, photo.operationId))
                }
            } else SecondaryAction("Refresh private validation ${index + 1}", !state.busy && state.capabilities.readReports) {
                actions.dispatch(MobileAction.PhotoStatus(state.accountGeneration, photo.evidenceId))
            }
        }
        QuietText("Local JPEG limit 768 KiB; at most two per received revision. No gallery copy, mobile image download or automatic publication.")
    }
}

package org.kapit.c2.mobile

import android.os.Bundle
import android.os.Build
import android.app.Activity
import android.app.KeyguardManager
import android.view.View
import android.view.WindowManager
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.runtime.getValue
import androidx.lifecycle.Lifecycle
import androidx.lifecycle.ViewModel
import androidx.lifecycle.ViewModelProvider
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.lifecycleScope
import androidx.lifecycle.repeatOnLifecycle
import kotlinx.coroutines.flow.filterNotNull
import kotlinx.coroutines.launch
import org.kapit.c2.mobile.data.local.AndroidProtectedRepository
import org.kapit.c2.mobile.ui.KapitMobileApp
import org.kapit.c2.mobile.ui.MobileController
import org.kapit.c2.mobile.ui.MobileControllerModel
import org.kapit.c2.mobile.ui.MobileRuntime
import org.kapit.c2.mobile.ui.MobileRuntimeOwner

class MainActivity : ComponentActivity() {
    private lateinit var controller: MobileController
    // Never placed in saved instance state. Rotation cancels the old controller and prompt ticket.
    private var launchedPromptId: Long? = null
    private val deviceCredential = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) { result ->
        val ticket = launchedPromptId
        launchedPromptId = null
        if (ticket != null && ::controller.isInitialized) {
            val keyguard = getSystemService(KeyguardManager::class.java)
            controller.completeDeviceUnlock(ticket, result.resultCode == Activity.RESULT_OK && keyguard.isDeviceSecure && !keyguard.isDeviceLocked)
        }
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        window.addFlags(WindowManager.LayoutParams.FLAG_SECURE)
        if (Build.VERSION.SDK_INT >= 26) window.decorView.importantForAutofill = View.IMPORTANT_FOR_AUTOFILL_NO_EXCLUDE_DESCENDANTS
        if (Build.VERSION.SDK_INT >= 30) window.decorView.importantForContentCapture = View.IMPORTANT_FOR_CONTENT_CAPTURE_NO_EXCLUDE_DESCENDANTS
        val supported = Build.VERSION.SDK_INT >= 35
        controller = ViewModelProvider(this, object : ViewModelProvider.Factory {
            override fun <T : ViewModel> create(modelClass: Class<T>): T {
                require(modelClass == MobileControllerModel::class.java)
                // No runtime/repository factory on ineligible APIs or when reusing a rotation holder.
                val runtime = if (supported) try {
                    (application as? MobileRuntimeOwner)?.createMobileRuntime()
                        ?: MobileRuntime(AndroidProtectedRepository(applicationContext))
                } catch (_: Exception) { null } else null
                @Suppress("UNCHECKED_CAST")
                return MobileControllerModel(MobileController(supported, runtime)) as T
            }
        })[MobileControllerModel::class.java].controller
        setContent {
            val state by controller.state.collectAsStateWithLifecycle()
            KapitMobileApp(state, controller)
        }
        lifecycleScope.launch {
            repeatOnLifecycle(Lifecycle.State.STARTED) {
                controller.unlockRequest.filterNotNull().collect { request ->
                    if (launchedPromptId == request.id) return@collect
                    val keyguard = getSystemService(KeyguardManager::class.java)
                    @Suppress("DEPRECATION")
                    val intent = if (supported && keyguard.isDeviceSecure)
                        keyguard.createConfirmDeviceCredentialIntent("Unlock KAPIT", "Confirm your device credential to continue.") else null
                    if (intent == null) controller.completeDeviceUnlock(request.id, false)
                    else {
                        launchedPromptId = request.id
                        try { deviceCredential.launch(intent) }
                        catch (_: Exception) { launchedPromptId = null; controller.completeDeviceUnlock(request.id, false) }
                    }
                }
            }
        }
    }

    override fun onStart() {
        super.onStart()
        if (::controller.isInitialized) controller.onForeground()
    }

    override fun onStop() {
        if (::controller.isInitialized) controller.onBackground()
        super.onStop()
    }

    override fun onDestroy() {
        if (::controller.isInitialized) controller.onActivityDestroyed()
        super.onDestroy()
    }
}


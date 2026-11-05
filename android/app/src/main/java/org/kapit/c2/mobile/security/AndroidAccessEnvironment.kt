package org.kapit.c2.mobile.security

import android.app.KeyguardManager
import android.content.Context
import android.os.Build
import android.os.SystemClock
import android.os.UserManager
import android.provider.Settings
import org.kapit.c2.mobile.domain.*

interface StoreEnvironment {
    fun clock(): ClockStamp
    fun requireEligibleUnlockedDevice()
}

class AndroidAccessEnvironment(context: Context) : StoreEnvironment {
    private val app = context.applicationContext
    override fun clock(): ClockStamp {
        val boot = if (Build.VERSION.SDK_INT >= 24) {
            try { Settings.Global.getInt(app.contentResolver, Settings.Global.BOOT_COUNT).takeIf { it >= 0 }?.toString() }
            catch (_: Exception) { null }
        } else null
        return ClockStamp(SystemClock.elapsedRealtime(), boot)
    }

    override fun requireEligibleUnlockedDevice() {
        if (Build.VERSION.SDK_INT < 35) throw StoreFailure(StoreCode.UNSUPPORTED_DEVICE)
        val users = app.getSystemService(Context.USER_SERVICE) as UserManager
        val keyguard = app.getSystemService(Context.KEYGUARD_SERVICE) as KeyguardManager
        requireStore(users.isUserUnlocked && keyguard.isDeviceSecure && !keyguard.isDeviceLocked, StoreCode.UNLOCK_REQUIRED)
    }
}

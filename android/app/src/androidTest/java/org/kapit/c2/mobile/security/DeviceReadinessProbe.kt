package org.kapit.c2.mobile.security

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import org.junit.Test
import org.junit.runner.RunWith

/** Host readiness only: the owned-emulator harness waits until the app itself sees an eligible unlocked device. Never an acceptance gate. */
@RunWith(AndroidJUnit4::class)
class DeviceReadinessProbe {
    @Test fun appSeesEligibleUnlockedDevice() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        check(InstrumentationRegistry.getArguments().getString("ownedEmulator") == "true")
        AndroidAccessEnvironment(context).requireEligibleUnlockedDevice()
    }
}

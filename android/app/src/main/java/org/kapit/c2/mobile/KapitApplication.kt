package org.kapit.c2.mobile

import android.app.Application
import android.os.Build
import androidx.work.Configuration
import org.kapit.c2.mobile.domain.StoreCode
import org.kapit.c2.mobile.domain.StoreFailure
import org.kapit.c2.mobile.sync.MobileWorkerFactory
import org.kapit.c2.mobile.ui.MobileRuntime
import org.kapit.c2.mobile.ui.MobileRuntimeOwner

class KapitApplication : Application(), MobileRuntimeOwner, Configuration.Provider {
    internal val container: AppContainer by lazy {
        if (Build.VERSION.SDK_INT < 35) throw StoreFailure(StoreCode.UNSUPPORTED_DEVICE)
        AppContainer(this)
    }

    override fun createMobileRuntime(): MobileRuntime {
        if (Build.VERSION.SDK_INT < 35) throw StoreFailure(StoreCode.UNSUPPORTED_DEVICE)
        return container.createMobileRuntime()
    }

    /**086 must remove only WorkManagerInitializer and register this Application in the manifest. */
    override val workManagerConfiguration: Configuration
        get() = Configuration.Builder().setMinimumLoggingLevel(android.util.Log.ERROR)
            .setWorkerFactory(MobileWorkerFactory()).build()
}

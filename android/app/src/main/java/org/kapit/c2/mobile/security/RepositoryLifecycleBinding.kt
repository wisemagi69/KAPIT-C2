package org.kapit.c2.mobile.security

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.os.Build
import java.io.Closeable

/** Screen lock fence complements the controller's synchronous app-background fence. */
internal class RepositoryLifecycleBinding(private val context: Context, private val onLock: () -> Unit) : Closeable {
    private val receiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) { if (intent?.action == Intent.ACTION_SCREEN_OFF) onLock() }
    }
    init {
        val filter = IntentFilter(Intent.ACTION_SCREEN_OFF)
        if (Build.VERSION.SDK_INT >= 33) context.registerReceiver(receiver, filter, Context.RECEIVER_NOT_EXPORTED)
        else context.registerReceiver(receiver, filter)
    }
    override fun close() { context.unregisterReceiver(receiver) }
}

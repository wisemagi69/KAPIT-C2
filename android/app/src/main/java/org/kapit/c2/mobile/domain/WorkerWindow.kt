package org.kapit.c2.mobile.domain

/** A fresh background capability expires independently of the offline lease. */
internal class WorkerWindow private constructor(private val start: ClockStamp, private val deadline: Long) {
    companion object {
        const val MAX_MILLIS = 480_000L
        fun begin(now: ClockStamp): WorkerWindow {
            requireStore(now.bootId != null && now.elapsedMillis >= 0 && now.elapsedMillis <= Long.MAX_VALUE - MAX_MILLIS, StoreCode.CLOCK_UNTRUSTED)
            return WorkerWindow(now, now.elapsedMillis + MAX_MILLIS)
        }
    }
    fun requireValid(now: ClockStamp) {
        requireStore(now.bootId != null && now.bootId == start.bootId && now.elapsedMillis >= start.elapsedMillis, StoreCode.CLOCK_UNTRUSTED)
        requireStore(now.elapsedMillis < deadline, StoreCode.LOCKED)
    }
}

package org.kapit.c2.mobile.domain

import org.junit.Assert.*
import org.junit.Test

class WorkerWindowTest {
    private fun denied(code: StoreCode, action: () -> Unit) {
        try { action(); fail("Expected bounded capability denial") } catch (failure: StoreFailure) { assertEquals(code, failure.code) }
    }
    @Test fun exactDeadlineIsExcludedAndCheckingDoesNotExtendIt() {
        val window = WorkerWindow.begin(ClockStamp(100, "boot"))
        window.requireValid(ClockStamp(479_000, "boot"))
        window.requireValid(ClockStamp(480_099, "boot"))
        denied(StoreCode.LOCKED) { window.requireValid(ClockStamp(480_100, "boot")) }
    }
    @Test fun missingChangedOrReversedClockCannotCreateOrResumeAuthority() {
        val window = WorkerWindow.begin(ClockStamp(100, "boot"))
        denied(StoreCode.CLOCK_UNTRUSTED) { window.requireValid(ClockStamp(99, "boot")) }
        denied(StoreCode.CLOCK_UNTRUSTED) { window.requireValid(ClockStamp(101, "other")) }
        denied(StoreCode.CLOCK_UNTRUSTED) { window.requireValid(ClockStamp(101, null)) }
        denied(StoreCode.CLOCK_UNTRUSTED) { WorkerWindow.begin(ClockStamp(0, null)) }
        denied(StoreCode.CLOCK_UNTRUSTED) { WorkerWindow.begin(ClockStamp(Long.MAX_VALUE, "boot")) }
    }
}

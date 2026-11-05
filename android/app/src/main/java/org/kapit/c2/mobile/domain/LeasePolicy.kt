package org.kapit.c2.mobile.domain

/** Request-start monotonic lease: neither transit, wall time, nor an unlock can extend it. */
object LeasePolicy {
    fun accept(start: ClockStamp, arrival: ClockStamp, offer: LeaseOffer): OfflineLease {
        val boot = start.bootId
        requireStore(boot != null && boot == arrival.bootId, StoreCode.CLOCK_UNTRUSTED)
        requireStore(start.elapsedMillis >= 0 && arrival.elapsedMillis >= start.elapsedMillis, StoreCode.CLOCK_UNTRUSTED)
        requireStore(offer.leaseSeconds in 1..86400, StoreCode.LEASE_EXPIRED)
        val duration = Math.multiplyExact(offer.leaseSeconds, 1000)
        val leaseRemaining = try { Math.subtractExact(offer.leaseExpiresMillis, offer.serverTimeMillis) }
            catch (_: ArithmeticException) { throw StoreFailure(StoreCode.LEASE_EXPIRED) }
        val familyRemaining = try { Math.subtractExact(offer.familyExpiresMillis, offer.serverTimeMillis) }
            catch (_: ArithmeticException) { throw StoreFailure(StoreCode.LEASE_EXPIRED) }
        requireStore(leaseRemaining == duration && familyRemaining >= duration, StoreCode.LEASE_EXPIRED)
        val deadline = try { Math.addExact(start.elapsedMillis, minOf(duration, leaseRemaining, familyRemaining)) }
            catch (_: ArithmeticException) { throw StoreFailure(StoreCode.LEASE_EXPIRED) }
        requireStore(arrival.elapsedMillis < deadline, StoreCode.LEASE_EXPIRED)
        return OfflineLease(start.elapsedMillis, arrival.elapsedMillis, deadline, boot!!, offer.serverTimeMillis, offer.familyExpiresMillis)
    }

    fun requireValid(lease: OfflineLease, now: ClockStamp) {
        requireStore(now.bootId != null && now.bootId == lease.bootId && now.elapsedMillis >= lease.responseElapsed, StoreCode.CLOCK_UNTRUSTED)
        requireStore(now.elapsedMillis < lease.deadlineElapsed, StoreCode.LEASE_EXPIRED)
    }

    fun estimatedServerTime(lease: OfflineLease, now: ClockStamp): Long {
        requireValid(lease, now)
        // Display/capture estimate never adds unknown response transit to an observation timestamp.
        return try { Math.addExact(lease.serverTimeMillis, now.elapsedMillis - lease.responseElapsed) }
            catch (_: ArithmeticException) { throw StoreFailure(StoreCode.CLOCK_UNTRUSTED) }
    }

    fun expiryTimeUpperBound(lease: OfflineLease, now: ClockStamp): Long {
        requireValid(lease, now)
        return try { Math.addExact(lease.serverTimeMillis, now.elapsedMillis - lease.requestStartElapsed) }
            catch (_: ArithmeticException) { throw StoreFailure(StoreCode.CLOCK_UNTRUSTED) }
    }
}

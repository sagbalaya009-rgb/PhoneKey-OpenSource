package com.PhoneKey.app

import org.junit.Test

class PhoneKeyFreshnessTest {
    @Test
    fun accepts_measured_two_second_phone_clock_lag() {
        PhoneKeyFreshness.requireFresh(
            issuedAtMs = 12_000L,
            expiresAtMs = 57_000L,
            nowMs = 10_000L
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejects_future_request_beyond_skew_limit() {
        PhoneKeyFreshness.requireFresh(
            issuedAtMs = 15_001L,
            expiresAtMs = 57_000L,
            nowMs = 10_000L
        )
    }

    @Test(expected = IllegalArgumentException::class)
    fun rejects_expired_request_even_with_clock_allowance() {
        PhoneKeyFreshness.requireFresh(
            issuedAtMs = 10_000L,
            expiresAtMs = 11_000L,
            nowMs = 11_000L
        )
    }
}

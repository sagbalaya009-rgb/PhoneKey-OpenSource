package com.PhoneKey.app

internal object PhoneKeyFreshness {
    private const val MAX_CLOCK_SKEW_MS = 5_000L

    fun requireFresh(issuedAtMs: Long, expiresAtMs: Long, nowMs: Long) {
        // The Windows service is authoritative for expiry. This bounded
        // allowance only compensates for ordinary phone/PC clock skew.
        require(
            issuedAtMs <= nowMs ||
                issuedAtMs - nowMs <= MAX_CLOCK_SKEW_MS
        ) {
            "Request is not yet valid"
        }

        require(nowMs < expiresAtMs) {
            "Request has expired"
        }
    }
}

package com.PhoneKey.app

/** Keeps one early file request while the camera opens and scans its matching QR. */
internal class PhoneKeyFileRendezvous {
    private var earlyChallenge: PhoneKeyProtocol.FileOpenChallenge? = null

    fun defer(challenge: PhoneKeyProtocol.FileOpenChallenge, nowMs: Long) {
        PhoneKeyFreshness.requireFresh(challenge.issuedAtMs, challenge.expiresAtMs, nowMs)
        earlyChallenge = challenge
    }

    fun takeMatching(bootstrap: PhoneKeyFileQrBootstrap.Bootstrap, nowMs: Long):
        PhoneKeyProtocol.FileOpenChallenge? {
        val challenge = earlyChallenge ?: return null
        earlyChallenge = null
        val valid = runCatching {
            PhoneKeyFreshness.requireFresh(challenge.issuedAtMs, challenge.expiresAtMs, nowMs)
            PhoneKeyFileQrBootstrap.matchesChallenge(bootstrap, challenge)
        }.getOrDefault(false)
        return if (valid) challenge else null
    }

    fun clear() {
        earlyChallenge = null
    }
}

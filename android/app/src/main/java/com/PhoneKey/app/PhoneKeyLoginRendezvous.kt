package com.PhoneKey.app

/** Holds at most one early BLE login request while the camera reads its QR.
 * No approval occurs here; matching and freshness are checked at scan time. */
internal class PhoneKeyLoginRendezvous {
    private var earlyChallenge: PhoneKeyProtocol.LoginChallenge? = null

    fun defer(challenge: PhoneKeyProtocol.LoginChallenge, nowMs: Long) {
        PhoneKeyFreshness.requireFresh(challenge.issuedAtMs, challenge.expiresAtMs, nowMs)
        earlyChallenge = challenge
    }

    fun takeMatching(bootstrap: PhoneKeyQrBootstrap.Bootstrap, nowMs: Long):
        PhoneKeyProtocol.LoginChallenge? {
        val challenge = earlyChallenge ?: return null
        earlyChallenge = null
        PhoneKeyFreshness.requireFresh(challenge.issuedAtMs, challenge.expiresAtMs, nowMs)
        require(PhoneKeyQrBootstrap.matchesChallenge(bootstrap, challenge)) {
            "BLE challenge does not match the scanned Windows transaction"
        }
        return challenge
    }

    fun clear() {
        earlyChallenge = null
    }
}

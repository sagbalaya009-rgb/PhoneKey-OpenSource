package com.PhoneKey.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class PhoneKeyLoginRendezvousTest {
    private fun challenge(session: Byte = 3) = PhoneKeyProtocol.LoginChallenge(
        windowsDeviceId = ByteArray(16) { 1 },
        sessionId = ByteArray(16) { session },
        nonce = ByteArray(32) { 4 },
        issuedAtMs = 1_000,
        expiresAtMs = 61_000,
        operation = PhoneKeyProtocol.OPERATION_UNLOCK,
        accountBinding = ByteArray(32) { 5 }
    )

    private fun qr(session: Byte = 3) = PhoneKeyQrBootstrap.Bootstrap(
        ByteArray(16) { 1 }, ByteArray(16) { session }, 61_000
    )

    @Test
    fun earlyBleRequestWaitsForMatchingQrAndIsConsumedOnce() {
        val rendezvous = PhoneKeyLoginRendezvous()
        val early = challenge()
        rendezvous.defer(early, 2_000)
        assertEquals(early, rendezvous.takeMatching(qr(), 2_500))
        assertNull(rendezvous.takeMatching(qr(), 2_501))
    }

    @Test
    fun mismatchedOrExpiredQrCannotApproveEarlyRequest() {
        val rendezvous = PhoneKeyLoginRendezvous()
        rendezvous.defer(challenge(), 2_000)
        assertThrows(IllegalArgumentException::class.java) {
            rendezvous.takeMatching(qr(6), 2_500)
        }
        assertNull(rendezvous.takeMatching(qr(), 2_501))
        rendezvous.defer(challenge(), 2_000)
        assertThrows(IllegalArgumentException::class.java) {
            rendezvous.takeMatching(qr(), 61_000)
        }
        assertNull(rendezvous.takeMatching(qr(), 61_001))
    }

    @Test
    fun onlyLatestEarlyRequestCanBeMatched() {
        val rendezvous = PhoneKeyLoginRendezvous()
        rendezvous.defer(challenge(), 2_000)
        val latest = challenge(6)
        rendezvous.defer(latest, 2_000)
        assertEquals(latest, rendezvous.takeMatching(qr(6), 2_500))
    }
}

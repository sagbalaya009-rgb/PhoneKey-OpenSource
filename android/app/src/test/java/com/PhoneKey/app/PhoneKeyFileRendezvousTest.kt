package com.PhoneKey.app

import java.security.MessageDigest
import org.junit.Assert.assertNull
import org.junit.Assert.assertSame
import org.junit.Test

class PhoneKeyFileRendezvousTest {
    private val publicKey = ("041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc589" +
        "6ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3")
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    private fun challenge() = PhoneKeyProtocol.FileOpenChallenge(
        ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 },
        ByteArray(32) { 4 }, ByteArray(32) { 5 }, 1_000, 61_000,
        byteArrayOf(0x50, 0x4b, 0x57, 0x31) + ByteArray(125), publicKey
    )

    private fun qr(challenge: PhoneKeyProtocol.FileOpenChallenge): PhoneKeyFileQrBootstrap.Bootstrap {
        val hash = MessageDigest.getInstance("SHA-256").digest(
            PhoneKeyProtocol.buildFileOpenSigningTranscript(challenge))
        return PhoneKeyFileQrBootstrap.Bootstrap(
            challenge.windowsDeviceId, challenge.sessionId, hash, challenge.expiresAtMs)
    }

    @Test
    fun bleRequestArrivingBeforeCameraOpensStillPromptsAfterMatchingScan() {
        val rendezvous = PhoneKeyFileRendezvous()
        val early = challenge()
        rendezvous.defer(early, 2_000)
        // Opening the scanner must not clear the waiting challenge.
        assertSame(early, rendezvous.takeMatching(qr(early), 2_500))
        assertNull(rendezvous.takeMatching(qr(early), 2_501))
    }

    @Test
    fun staleOrUnrelatedEarlyRequestCannotApproveAnotherFile() {
        val rendezvous = PhoneKeyFileRendezvous()
        val early = challenge()
        rendezvous.defer(early, 2_000)
        assertNull(rendezvous.takeMatching(qr(early.copy(envelopeSha256 = ByteArray(32) { 6 })), 2_500))
        rendezvous.defer(early, 2_000)
        assertNull(rendezvous.takeMatching(qr(early), 61_000))
    }
}

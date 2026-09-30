package com.PhoneKey.app

import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import java.security.MessageDigest

class PhoneKeyFileQrBootstrapTest {
    private val phoneWrap = byteArrayOf(0x50, 0x4b, 0x57, 0x31) + ByteArray(125)
    private val returnPublic = ("041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc589" +
        "6ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3")
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private fun challenge() = PhoneKeyProtocol.FileOpenChallenge(
        ByteArray(16) { 1 }, ByteArray(16) { 2 },
        ByteArray(16) { 3 }, ByteArray(32) { 4 },
        ByteArray(32) { 5 }, 1000, 61000, phoneWrap, returnPublic
    )

    private fun qr(fileChallenge: PhoneKeyProtocol.FileOpenChallenge = challenge()): String {
        val digest = MessageDigest.getInstance("SHA-256").digest(
            PhoneKeyProtocol.buildFileOpenSigningTranscript(fileChallenge))
        val hash = digest.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        assertTrue(hash == "c2de276468e4123408ffdd18ab627c2ff710a339ccacdb953d4b445f776d09bb")
        return "PKF3|" + "01".repeat(16) + "|" + "03".repeat(16) + "|" +
            hash + "|" + "000000000000ee48"
    }

    @Test
    fun scannedQrBindsOneFileChallenge() {
        val bootstrap = PhoneKeyFileQrBootstrap.parse(qr(), 1000)
        val challenge = challenge()
        assertTrue(PhoneKeyFileQrBootstrap.matchesChallenge(bootstrap, challenge))
        assertFalse(PhoneKeyFileQrBootstrap.matchesChallenge(bootstrap,
            challenge.copy(envelopeSha256 = ByteArray(32) { 6 })))
        assertFalse(PhoneKeyFileQrBootstrap.matchesChallenge(bootstrap,
            challenge.copy(phoneDeviceId = ByteArray(16) { 7 })))
        assertFalse(PhoneKeyFileQrBootstrap.matchesChallenge(bootstrap,
            challenge.copy(nonce = ByteArray(32) { 8 })))
        assertFalse(PhoneKeyFileQrBootstrap.matchesChallenge(bootstrap,
            challenge.copy(phoneWrap = phoneWrap.clone().also { it[50] = 1 })))
    }

    @Test
    fun expiredAndNoncanonicalQrAreRejected() {
        assertThrows(IllegalArgumentException::class.java) {
            PhoneKeyFileQrBootstrap.parse(qr(), 61000)
        }
        assertThrows(IllegalArgumentException::class.java) {
            PhoneKeyFileQrBootstrap.parse(qr().uppercase(), 1000)
        }
    }
}

package com.PhoneKey.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PhoneKeyFileOpenProtocolTest {
    private val phoneWrap = byteArrayOf(0x50, 0x4b, 0x57, 0x31) + ByteArray(125)
    private val returnPublic = ("041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc589" +
        "6ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3")
        .chunked(2).map { it.toInt(16).toByte() }.toByteArray()
    private val returnRecord = byteArrayOf(0x50, 0x4b, 0x52, 0x31) + ByteArray(125) { 7 }
    private fun challenge() = PhoneKeyProtocol.FileOpenChallenge(
        windowsDeviceId = ByteArray(16) { 1 },
        phoneDeviceId = ByteArray(16) { 2 },
        sessionId = ByteArray(16) { 3 },
        nonce = ByteArray(32) { 4 },
        envelopeSha256 = ByteArray(32) { 5 },
        issuedAtMs = 1000,
        expiresAtMs = 61000,
        phoneWrap = phoneWrap,
        returnPublicSec1 = returnPublic
    )

    @Test
    fun canonicalMessageMatchesWindowsLayout() {
        val original = challenge()
        val encoded = PhoneKeyProtocol.encodeFileOpenChallenge(original)
        val expected = "ab010102140350" + "01".repeat(16) +
            "0450" + "02".repeat(16) +
            "0550" + "03".repeat(16) +
            "065820" + "04".repeat(32) +
            "075820" + "05".repeat(32) +
            "081903e80919ee480a5881" + PhoneKeyProtocol.bytesToHex(phoneWrap) +
            "0b5841" + PhoneKeyProtocol.bytesToHex(returnPublic)
        assertEquals(expected, PhoneKeyProtocol.bytesToHex(encoded))
        val decoded = PhoneKeyProtocol.decodeFileOpenChallenge(encoded)
        assertArrayEquals(original.envelopeSha256, decoded.envelopeSha256)
        assertArrayEquals(original.phoneDeviceId, decoded.phoneDeviceId)
        assertArrayEquals(original.phoneWrap, decoded.phoneWrap)
        assertArrayEquals(original.returnPublicSec1, decoded.returnPublicSec1)
    }

    @Test
    fun transcriptUsesDistinctPurposeAndRejectsBadLifetime() {
        val transcript = PhoneKeyProtocol.buildFileOpenSigningTranscript(challenge())
        assertEquals("PHONEKEY-FILE-OPEN-SIGNATURE-V2\u0000", transcript.copyOfRange(0, 32).toString(Charsets.UTF_8))
        val invalid = challenge().copy(expiresAtMs = 61001)
        assertThrows(IllegalArgumentException::class.java) {
            PhoneKeyProtocol.buildFileOpenSigningTranscript(invalid)
        }
    }

    @Test
    fun fileProofHasDistinctMessageType() {
        val proof = PhoneKeyProtocol.FileOpenProof(
            ByteArray(16) { 2 }, ByteArray(16) { 3 }, ByteArray(64) { 7 }, returnRecord
        )
        val encoded = PhoneKeyProtocol.encodeFileOpenProof(proof)
        val expected = "a6010102150350" + "02".repeat(16) +
            "0450" + "03".repeat(16) + "055840" + "07".repeat(64) +
            "065881" + PhoneKeyProtocol.bytesToHex(returnRecord)
        assertEquals(expected, PhoneKeyProtocol.bytesToHex(encoded))
    }
}

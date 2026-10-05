package com.PhoneKey.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class PhoneKeyFilePreparedWriteTest {
    @Test
    fun fragmentedLoginAndEnrollmentReachTheChallengeHandlerAtDifferentMtus() {
        val login = PhoneKeyProtocol.encodeLoginChallenge(PhoneKeyProtocol.LoginChallenge(
            ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(32) { 3 },
            1000, 61000, PhoneKeyProtocol.OPERATION_UNLOCK, ByteArray(32) { 4 }
        ))
        val enrollment = PhoneKeyProtocol.encodeEnrollmentChallenge(PhoneKeyProtocol.EnrollmentChallenge(
            ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(32) { 3 }, 1000, 61000
        ))
        val file = PhoneKeyProtocol.encodeFileOpenChallenge(PhoneKeyProtocol.FileOpenChallenge(
            ByteArray(16) { 1 }, ByteArray(16) { 2 }, ByteArray(16) { 3 },
            ByteArray(32) { 4 }, ByteArray(32) { 5 }, 1000, 61000,
            byteArrayOf(0x50, 0x4b, 0x57, 0x31) + ByteArray(125),
            byteArrayOf(4) + ByteArray(64)
        ))
        for (payload in listOf(login, enrollment, file)) {
            // ATT Prepare Write reserves five bytes of the negotiated MTU.
            for (fragmentSize in listOf(18, 180, 242)) {
                val assembler = PhoneKeyFilePreparedWrite()
                for (offset in payload.indices step fragmentSize) {
                    assembler.append("client", offset,
                        payload.copyOfRange(offset, minOf(offset + fragmentSize, payload.size)))
                }
                assertArrayEquals(payload, assembler.finishChallenge("client", true))
                assertThrows(IllegalArgumentException::class.java) {
                    assembler.finishChallenge("client", true)
                }
            }
        }
    }

    @Test
    fun preparedProofAndTruncatedChallengeAreRejectedAndCannotBeReplayed() {
        val proof = PhoneKeyProtocol.encodeLoginProof(PhoneKeyProtocol.LoginProof(
            ByteArray(16), ByteArray(16), ByteArray(64)
        ))
        for (payload in listOf(proof, byteArrayOf(0xa9.toByte(), 1, 1, 2, 1), byteArrayOf(0xbf.toByte()))) {
            val assembler = PhoneKeyFilePreparedWrite()
            assembler.append("client", 0, payload)
            assertThrows(IllegalArgumentException::class.java) {
                assembler.finishChallenge("client", true)
            }
            assertThrows(IllegalArgumentException::class.java) {
                assembler.finishChallenge("client", true)
            }
        }
    }

    @Test
    fun assemblesLongFileChallengeAndClearsAfterExecute() {
        val assembler = PhoneKeyFilePreparedWrite()
        val original = ByteArray(360) { it.toByte() }
        assembler.append("phone", 0, original.copyOfRange(0, 180))
        assembler.append("phone", 180, original.copyOfRange(180, 360))
        assertArrayEquals(original, assembler.finish("phone", true))
        assertThrows(IllegalArgumentException::class.java) {
            assembler.finish("phone", true)
        }
    }

    @Test
    fun rejectsWrongDeviceOffsetAndOverflow() {
        val assembler = PhoneKeyFilePreparedWrite()
        assembler.append("phone", 0, byteArrayOf(1))
        assertThrows(IllegalArgumentException::class.java) {
            assembler.append("other", 1, byteArrayOf(2))
        }
        assertThrows(IllegalArgumentException::class.java) {
            assembler.append("phone", 2, byteArrayOf(2))
        }
        assertNull(assembler.finish("phone", false))
        assertThrows(IllegalArgumentException::class.java) {
            assembler.append("phone", 0, ByteArray(PhoneKeyProtocol.MAX_MESSAGE_SIZE + 1))
        }
    }
}

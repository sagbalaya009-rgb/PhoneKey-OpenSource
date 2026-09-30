package com.PhoneKey.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Test

class PhoneKeyFilePreparedWriteTest {
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

package com.PhoneKey.app

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class PhoneKeyFileBindingTest {
    @Test
    fun exportHasFixedCanonicalFields() {
        val id = ByteArray(16) { 1 }
        val public = byteArrayOf(4) + ByteArray(64) { 2 }
        val signature = ByteArray(64) { 3 }
        val export = PhoneKeyFileBinding.format(id, public, signature)
        assertEquals(297, export.length)
        assertTrue(export.startsWith("PKB1|" + "01".repeat(16) + "|04"))
        assertTrue(export.endsWith("03".repeat(64)))
        assertEquals("PHONEKEY-FILE-BINDING-V1\u0000".toByteArray().size + 81,
            PhoneKeyFileBinding.transcript(id, public).size)
    }
}

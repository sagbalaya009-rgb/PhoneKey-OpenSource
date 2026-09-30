package com.PhoneKey.app

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPrivateKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertThrows
import org.junit.Test

class PhoneKeyFileKeyManagerTest {
    private fun bytes(hex: String) = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    // Frozen from the Windows Rust P-256/HKDF/AES-GCM implementation using
    // dummy, fixed private keys. No production key material appears here.
    private val phonePublic = bytes(
        "041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc589" +
            "6ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3"
    )
    private val record = bytes(
        "504b573104591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61a" +
            "df9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0" +
            "040404040404040404040404c3257f1c750cee75ccd3d96d500acbe2b2551d9f2" +
            "c8342f3de2a632efd0e6132885df777a41de41076747b4d4b200e0a"
    )

    private fun privateKey(): java.security.PrivateKey {
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val curve = parameters.getParameterSpec(ECParameterSpec::class.java)
        return KeyFactory.getInstance("EC").generatePrivate(
            ECPrivateKeySpec(BigInteger(1, ByteArray(32) { 7 }), curve)
        )
    }

    @Test
    fun opensWindowsDummyKeyWrapVector() {
        val manager = PhoneKeyFileKeyManager()
        assertArrayEquals(ByteArray(32) { 5 }, manager.unwrapWithPrivateKey(
            record, ByteArray(32) { 9 }, privateKey(), phonePublic
        ))
    }

    @Test
    fun changedFileHashOrTagIsRejected() {
        val manager = PhoneKeyFileKeyManager()
        assertThrows(Exception::class.java) {
            manager.unwrapWithPrivateKey(record, ByteArray(32) { 1 }, privateKey(), phonePublic)
        }
        val changed = record.clone()
        changed[changed.lastIndex] = (changed.last().toInt() xor 1).toByte()
        assertThrows(Exception::class.java) {
            manager.unwrapWithPrivateKey(changed, ByteArray(32) { 9 }, privateKey(), phonePublic)
        }
    }
}

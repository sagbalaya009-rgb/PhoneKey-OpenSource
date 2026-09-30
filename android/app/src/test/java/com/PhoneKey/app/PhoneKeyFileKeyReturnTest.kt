package com.PhoneKey.app

import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPrivateKeySpec
import java.security.spec.ECPublicKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Test

class PhoneKeyFileKeyReturnTest {
    private fun bytes(hex: String) = hex.chunked(2).map { it.toInt(16).toByte() }.toByteArray()

    @Test
    fun androidReturnMatchesWindowsDummyVector() {
        val laptopPublic = bytes(
            "041e18532fd4754c02f3041d9c75ceb33b83ffd81ac7ce4fe882ccb1c98bc589" +
                "6ea46c311c4e2ff40dd96a3653e6e45445d32dfe486eced75c7a90c6a18881c0a3"
        )
        val ephemeralPublic = bytes(
            "04591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61a" +
                "df9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0"
        )
        val expected = bytes(
            "504b523104591ab771ebbcfd6d9cb9094d106528add1a69d44c2c1f627f089ec58b9c61a" +
                "df9f4e6abf0d045c0c693a3c68ad7c97ca72be64def4a26fecd263dd98a92780f0" +
                "0404040404040404040404042bd0422961469d63d7d5867f4f6554535112f0ce75fa7ec8" +
                "64bec5af40faecd88ecee61ad4e115f630b04f029d0e26fb"
        )
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val curve = parameters.getParameterSpec(ECParameterSpec::class.java)
        val factory = KeyFactory.getInstance("EC")
        val private = factory.generatePrivate(
            ECPrivateKeySpec(BigInteger(1, ByteArray(32) { 3 }), curve))
        val public = factory.generatePublic(ECPublicKeySpec(
            ECPoint(BigInteger(1, ephemeralPublic.copyOfRange(1, 33)),
                BigInteger(1, ephemeralPublic.copyOfRange(33, 65))), curve)) as ECPublicKey
        assertArrayEquals(expected, PhoneKeyFileKeyReturn.sealWithParams(
            ByteArray(32) { 5 }, ByteArray(32) { 9 }, laptopPublic,
            private, public, ByteArray(12) { 4 }
        ))
    }
}

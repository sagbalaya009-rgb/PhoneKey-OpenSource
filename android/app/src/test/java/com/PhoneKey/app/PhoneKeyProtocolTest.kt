package com.PhoneKey.app

import org.junit.Assert.assertEquals
import org.junit.Test

class PhoneKeyProtocolTest {

    @Test
    fun loginChallenge_matchesFrozenRustVector() {
        val challenge =
            PhoneKeyProtocol.LoginChallenge(
                windowsDeviceId =
                    ByteArray(16) {
                        0x11.toByte()
                    },
                sessionId =
                    ByteArray(16) {
                        0x22.toByte()
                    },
                nonce =
                    ByteArray(32) {
                        0x33.toByte()
                    },
                issuedAtMs = 1_000_000L,
                expiresAtMs = 1_060_000L,
                operation =
                    PhoneKeyProtocol.OPERATION_LOGON,
                accountBinding =
                    ByteArray(32) {
                        0x44.toByte()
                    }
            )

        val encoded =
            PhoneKeyProtocol
                .encodeLoginChallenge(
                    challenge
                )

        val actualHex =
            PhoneKeyProtocol.bytesToHex(
                encoded
            )

        val expectedHex =
            "a901010201035011111111111111111111111111111111" +
                    "045022222222222222222222222222222222" +
                    "0558203333333333333333333333333333333333333333333333333333333333333333" +
                    "061a000f4240" +
                    "071a00102ca0" +
                    "0801" +
                    "0958204444444444444444444444444444444444444444444444444444444444444444"

        assertEquals(
            expectedHex,
            actualHex
        )
    }

    @Test
    fun loginTranscript_matchesFrozenRustVector() {
        val challenge =
            PhoneKeyProtocol.LoginChallenge(
                windowsDeviceId =
                    ByteArray(16) {
                        0x11.toByte()
                    },
                sessionId =
                    ByteArray(16) {
                        0x22.toByte()
                    },
                nonce =
                    ByteArray(32) {
                        0x33.toByte()
                    },
                issuedAtMs = 1_000_000L,
                expiresAtMs = 1_060_000L,
                operation =
                    PhoneKeyProtocol.OPERATION_LOGON,
                accountBinding =
                    ByteArray(32) {
                        0x44.toByte()
                    }
            )

        val transcript =
            PhoneKeyProtocol
                .buildLoginSigningTranscript(
                    challenge
                )

        val actualHex =
            PhoneKeyProtocol.bytesToHex(
                transcript
            )

        val expectedHex =
            "50484f4e454b45592d4c4f47494e2d5349474e41545552452d563100" +
                    "a901010201035011111111111111111111111111111111" +
                    "045022222222222222222222222222222222" +
                    "0558203333333333333333333333333333333333333333333333333333333333333333" +
                    "061a000f4240" +
                    "071a00102ca0" +
                    "0801" +
                    "0958204444444444444444444444444444444444444444444444444444444444444444"

        assertEquals(
            expectedHex,
            actualHex
        )
    }

    @Test
    fun loginProof_matchesFrozenRustStructure() {
        val androidDeviceId =
            ByteArray(16) {
                0xAA.toByte()
            }

        val sessionId =
            ByteArray(16) {
                0x22.toByte()
            }

        val signature =
            hexToBytes(
                "333c32a289686862084887c907d9c195" +
                        "037b9655eef895ce4fabab2251932ff5" +
                        "2dca47574e8506e9971075c23d45b560" +
                        "203f9f7e2cfd5792d8e0cf84a5d5db5a"
            )

        val proof =
            PhoneKeyProtocol.LoginProof(
                androidDeviceId =
                    androidDeviceId,
                sessionId =
                    sessionId,
                signature =
                    signature
            )

        val encoded =
            PhoneKeyProtocol
                .encodeLoginProof(
                    proof
                )

        val actualHex =
            PhoneKeyProtocol.bytesToHex(
                encoded
            )

        val expectedHex =
            "a5010102020350aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
                    "045022222222222222222222222222222222" +
                    "055840" +
                    "333c32a289686862084887c907d9c195" +
                    "037b9655eef895ce4fabab2251932ff5" +
                    "2dca47574e8506e9971075c23d45b560" +
                    "203f9f7e2cfd5792d8e0cf84a5d5db5a"

        assertEquals(
            expectedHex,
            actualHex
        )
    }

    private fun hexToBytes(
        value: String
    ): ByteArray {
        require(
            value.length % 2 == 0
        )

        return ByteArray(
            value.length / 2
        ) { index ->

            value.substring(
                index * 2,
                index * 2 + 2
            ).toInt(
                16
            ).toByte()
        }
    }
}
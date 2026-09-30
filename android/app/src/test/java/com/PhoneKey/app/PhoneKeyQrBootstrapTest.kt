package com.PhoneKey.app

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Assert.assertEquals
import org.junit.Test

class PhoneKeyQrBootstrapTest {

    private fun qr(
        expiry: Long
    ): String {
        return "PK1|" +
            "11111111111111111111111111111111" +
            "|" +
            "22222222222222222222222222222222" +
            "|" +
            expiry
                .toString(16)
                .padStart(
                    16,
                    '0'
                )
    }

    @Test
    fun canonical_qr_parses() {
        val parsed =
            PhoneKeyQrBootstrap
                .parse(
                    qr(
                        46_000L
                    ),
                    1_000L
                )

        assertArrayEquals(
            ByteArray(16) {
                0x11
            },
            parsed.windowsDeviceId
        )

        assertArrayEquals(
            ByteArray(16) {
                0x22
            },
            parsed.sessionId
        )

        assertEquals(
            46_000L,
            parsed.expiresAtMs
        )
    }

    @Test(
        expected =
            IllegalArgumentException::class
    )
    fun expired_qr_is_rejected() {
        PhoneKeyQrBootstrap
            .parse(
                qr(
                    1_000L
                ),
                1_000L
            )
    }

    @Test(
        expected =
            IllegalArgumentException::class
    )
    fun excessive_future_lifetime_is_rejected() {
        PhoneKeyQrBootstrap
            .parse(
                qr(
                    61_001L
                ),
                1_000L
            )
    }

    @Test(
        expected =
            IllegalArgumentException::class
    )
    fun uppercase_hex_is_rejected() {
        val bad =
            qr(
                46_000L
            ).replaceFirst(
                "1111",
                "AAAA"
            )

        PhoneKeyQrBootstrap
            .parse(
                bad,
                1_000L
            )
    }

    @Test
    fun challenge_binding_requires_all_qr_fields() {
        val bootstrap =
            PhoneKeyQrBootstrap
                .parse(
                    qr(
                        46_000L
                    ),
                    1_000L
                )

        val challenge =
            PhoneKeyProtocol
                .LoginChallenge(
                    windowsDeviceId =
                        ByteArray(16) {
                            0x11
                        },

                    sessionId =
                        ByteArray(16) {
                            0x22
                        },

                    nonce =
                        ByteArray(32) {
                            0x33
                        },

                    issuedAtMs =
                        1_000L,

                    expiresAtMs =
                        46_000L,

                    operation =
                        PhoneKeyProtocol
                            .OPERATION_LOGON,

                    accountBinding =
                        "S-1-5-21-test"
                            .toByteArray()
                )

        assertTrue(
            PhoneKeyQrBootstrap
                .matchesChallenge(
                    bootstrap,
                    challenge
                )
        )

        assertFalse(
            PhoneKeyQrBootstrap
                .matchesChallenge(
                    bootstrap,
                    challenge.copy(
                        sessionId =
                            ByteArray(16) {
                                0x55
                            }
                    )
                )
        )

        assertFalse(
            PhoneKeyQrBootstrap
                .matchesChallenge(
                    bootstrap,
                    challenge.copy(
                        windowsDeviceId =
                            ByteArray(16) {
                                0x66
                            }
                    )
                )
        )

        assertFalse(
            PhoneKeyQrBootstrap
                .matchesChallenge(
                    bootstrap,
                    challenge.copy(
                        expiresAtMs =
                            45_999L
                    )
                )
        )
    }
}
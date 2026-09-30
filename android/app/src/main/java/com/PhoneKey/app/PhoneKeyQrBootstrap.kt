package com.PhoneKey.app

object PhoneKeyQrBootstrap {

    private const val PREFIX =
        "PK1|"

    private const val TOTAL_LENGTH =
        86

    private const val MAX_FUTURE_MS =
        60_000L

    data class Bootstrap(
        val windowsDeviceId: ByteArray,
        val sessionId: ByteArray,
        val expiresAtMs: Long
    )

    fun parse(
        raw: String,
        nowMs: Long =
            System.currentTimeMillis()
    ): Bootstrap {
        require(nowMs >= 0) {
            "Invalid local clock"
        }

        require(
            raw.length ==
                TOTAL_LENGTH
        ) {
            "Invalid PhoneKey QR length"
        }

        require(
            raw.startsWith(
                PREFIX
            )
        ) {
            "Unsupported PhoneKey QR version"
        }

        require(
            raw[36] == '|' &&
                raw[69] == '|'
        ) {
            "Malformed PhoneKey QR"
        }

        val windowsHex =
            raw.substring(
                4,
                36
            )

        val sessionHex =
            raw.substring(
                37,
                69
            )

        val expiryHex =
            raw.substring(
                70,
                86
            )

        requireLowerHex(
            windowsHex
        )

        requireLowerHex(
            sessionHex
        )

        requireLowerHex(
            expiryHex
        )

        val windowsDeviceId =
            decodeHex(
                windowsHex
            )

        val sessionId =
            decodeHex(
                sessionHex
            )

        require(
            windowsDeviceId.any {
                it != 0.toByte()
            }
        ) {
            "Invalid Windows device ID"
        }

        require(
            sessionId.any {
                it != 0.toByte()
            }
        ) {
            "Invalid session ID"
        }

        /*
         * Unix milliseconds are currently positive signed Long
         * values. Reject the unsigned range beyond Long.MAX_VALUE.
         */
        require(
            expiryHex[0] in
                '0'..'7'
        ) {
            "QR expiry outside supported range"
        }

        val expiresAtMs =
            expiryHex.toLong(
                16
            )

        require(
            expiresAtMs >
                nowMs
        ) {
            "PhoneKey QR has expired"
        }

        require(
            expiresAtMs -
                nowMs <=
                MAX_FUTURE_MS
        ) {
            "PhoneKey QR lifetime is invalid"
        }

        return Bootstrap(
            windowsDeviceId =
                windowsDeviceId,

            sessionId =
                sessionId,

            expiresAtMs =
                expiresAtMs
        )
    }

    fun matchesChallenge(
        bootstrap: Bootstrap,
        challenge:
            PhoneKeyProtocol.LoginChallenge
    ): Boolean {
        return bootstrap
            .windowsDeviceId
            .contentEquals(
                challenge.windowsDeviceId
            ) &&
            bootstrap
                .sessionId
                .contentEquals(
                    challenge.sessionId
                ) &&
            bootstrap
                .expiresAtMs ==
                challenge.expiresAtMs
    }

    private fun requireLowerHex(
        value: String
    ) {
        require(
            value.all {
                character ->

                character in
                    '0'..'9' ||
                    character in
                    'a'..'f'
            }
        ) {
            "PhoneKey QR uses non-canonical hexadecimal"
        }
    }

    private fun decodeHex(
        value: String
    ): ByteArray {
        require(
            value.length % 2 ==
                0
        )

        return ByteArray(
            value.length / 2
        ) {
            index ->

            val offset =
                index * 2

            value.substring(
                offset,
                offset + 2
            )
                .toInt(
                    16
                )
                .toByte()
        }
    }
}
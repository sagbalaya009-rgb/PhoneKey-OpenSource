package com.PhoneKey.app

import java.security.MessageDigest

/** Scanned intent for one encrypted file. The BLE challenge must match all fields. */
object PhoneKeyFileQrBootstrap {
    private const val PREFIX = "PKF3|"
    private const val MAX_FUTURE_MS = 60_000L

    data class Bootstrap(
        val windowsDeviceId: ByteArray,
        val sessionId: ByteArray,
        val challengeSha256: ByteArray,
        val expiresAtMs: Long
    )

    fun parse(raw: String, nowMs: Long = System.currentTimeMillis()): Bootstrap {
        require(nowMs >= 0 && raw.length == 152 && raw.startsWith(PREFIX)) {
            "Invalid PhoneKey file QR"
        }
        val parts = raw.split('|')
        require(parts.size == 5 && parts[0] == "PKF3") { "Malformed PhoneKey file QR" }
        require(parts[1].length == 32 && parts[2].length == 32 &&
            parts[3].length == 64 && parts[4].length == 16) { "Invalid PhoneKey file QR fields" }
        for (part in parts.drop(1)) {
            require(part.all { it in '0'..'9' || it in 'a'..'f' }) {
                "PhoneKey file QR uses non-canonical hexadecimal"
            }
        }
        require(parts[4][0] in '0'..'7') { "File QR expiry outside supported range" }
        val expires = parts[4].toLong(16)
        require(expires > nowMs && expires - nowMs <= MAX_FUTURE_MS) {
            "PhoneKey file QR has expired"
        }
        val windows = parts[1].chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val session = parts[2].chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        val hash = parts[3].chunked(2).map { it.toInt(16).toByte() }.toByteArray()
        require(windows.any { it != 0.toByte() } && session.any { it != 0.toByte() }) {
            "Invalid file QR identity"
        }
        return Bootstrap(windows, session, hash, expires)
    }

    fun matchesChallenge(bootstrap: Bootstrap, challenge: PhoneKeyProtocol.FileOpenChallenge): Boolean =
        bootstrap.windowsDeviceId.contentEquals(challenge.windowsDeviceId) &&
            bootstrap.sessionId.contentEquals(challenge.sessionId) &&
            MessageDigest.isEqual(bootstrap.challengeSha256,
                MessageDigest.getInstance("SHA-256").digest(
                    PhoneKeyProtocol.buildFileOpenSigningTranscript(challenge))) &&
            bootstrap.expiresAtMs == challenge.expiresAtMs
}

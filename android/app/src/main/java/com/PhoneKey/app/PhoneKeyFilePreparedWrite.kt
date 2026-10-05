package com.PhoneKey.app

import java.io.ByteArrayOutputStream

/** Bounded GATT long-write assembly for every supported challenge.
 * Each fragment is acknowledged before execute; approval still requires the
 * application's QR/session validation and biometric authorization.
 */
class PhoneKeyFilePreparedWrite {
    private var writer: String? = null
    private val pending = ByteArrayOutputStream()

    @Synchronized
    fun append(deviceAddress: String, offset: Int, value: ByteArray) {
        require(value.isNotEmpty()) { "Empty prepared write" }
        if (offset == 0) {
            clear()
            writer = deviceAddress
        }
        require(writer == deviceAddress && offset == pending.size()) {
            "Out-of-order prepared write"
        }
        require(value.size <= PhoneKeyProtocol.MAX_MESSAGE_SIZE - pending.size()) {
            "Prepared request is too large"
        }
        pending.write(value)
    }

    @Synchronized
    fun finish(deviceAddress: String, execute: Boolean): ByteArray? {
        if (!execute) {
            clear()
            return null
        }
        require(writer == deviceAddress && pending.size() > 0) {
            "No prepared request"
        }
        val result = pending.toByteArray()
        clear()
        return result
    }

    fun finishChallenge(deviceAddress: String, execute: Boolean): ByteArray? {
        val payload = finish(deviceAddress, execute) ?: return null
        when (PhoneKeyProtocol.readMessageType(payload)) {
            PhoneKeyProtocol.MESSAGE_TYPE_LOGIN_CHALLENGE -> PhoneKeyProtocol.decodeLoginChallenge(payload)
            PhoneKeyProtocol.MESSAGE_TYPE_ENROLLMENT_CHALLENGE -> PhoneKeyProtocol.decodeEnrollmentChallenge(payload)
            PhoneKeyProtocol.MESSAGE_TYPE_FILE_OPEN_CHALLENGE -> PhoneKeyProtocol.decodeFileOpenChallenge(payload)
            else -> throw IllegalArgumentException("Unsupported PhoneKey challenge")
        }
        return payload
    }

    @Synchronized
    fun clear() {
        pending.reset()
        writer = null
    }
}

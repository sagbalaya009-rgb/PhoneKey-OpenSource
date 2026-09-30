package com.PhoneKey.app

import java.nio.charset.StandardCharsets

/** Signed authorization of a distinct Android Keystore file-agreement key.
 * Windows must verify this against the signing key of its already paired phone.
 */
object PhoneKeyFileBinding {
    private val domain = "PHONEKEY-FILE-BINDING-V1\u0000".toByteArray(StandardCharsets.UTF_8)

    fun transcript(deviceId: ByteArray, agreementPublic: ByteArray): ByteArray {
        require(deviceId.size == 16 && agreementPublic.size == 65 && agreementPublic[0] == 4.toByte())
        return domain + deviceId + agreementPublic
    }

    fun format(deviceId: ByteArray, agreementPublic: ByteArray, signature: ByteArray): String {
        require(signature.size == 64)
        transcript(deviceId, agreementPublic)
        fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it.toInt() and 0xff) }
        return "PKB1|${hex(deviceId)}|${hex(agreementPublic)}|${hex(signature)}"
    }

    /** Call only after an explicit file-vault biometric approval. */
    fun create(identityManager: DeviceIdentityManager): String {
        val identity = identityManager.getIdentity()
        val agreementPublic = PhoneKeyFileKeyManager().createIfNeeded()
        val signature = identityManager.sign(transcript(identity.deviceId, agreementPublic))
        return format(identity.deviceId, agreementPublic, signature)
    }
}

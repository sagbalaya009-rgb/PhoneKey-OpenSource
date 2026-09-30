package com.PhoneKey.app

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.PrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import java.security.spec.ECParameterSpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Separate Android Keystore ECDH key for file-key unwrapping. Not yet wired
 * into enrollment or the live file-opening flow. */
class PhoneKeyFileKeyManager {
    companion object {
        private const val ALIAS = "phonekey_file_agreement_v1"
        private const val KEYSTORE = "AndroidKeyStore"
        private val DOMAIN = "PHONEKEY-FILE-WRAP-V1\u0000".toByteArray(StandardCharsets.UTF_8)
        private val MAGIC = byteArrayOf(0x50, 0x4b, 0x57, 0x31)
        private const val RECORD_LENGTH = 129
    }

    fun createIfNeeded(): ByteArray {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            "File-key agreement requires Android 12 or newer"
        }
        val store = KeyStore.getInstance(KEYSTORE)
        store.load(null)
        if (!store.containsAlias(ALIAS)) {
            val generator = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, KEYSTORE)
            val spec = KeyGenParameterSpec.Builder(ALIAS, KeyProperties.PURPOSE_AGREE_KEY)
                .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(
                    15,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
                .build()
            generator.initialize(spec)
            generator.generateKeyPair()
        }
        return publicKeySec1(store)
    }

    fun unwrapFileKey(record: ByteArray, fileSha256: ByteArray): ByteArray {
        require(Build.VERSION.SDK_INT >= Build.VERSION_CODES.S)
        val store = KeyStore.getInstance(KEYSTORE)
        store.load(null)
        val privateKey = store.getKey(ALIAS, null) as? PrivateKey
            ?: error("PhoneKey file agreement key is missing")
        val phonePublic = publicKeySec1(store)
        return unwrapWithPrivateKey(record, fileSha256, privateKey, phonePublic, KEYSTORE)
    }

    internal fun unwrapWithPrivateKey(
        record: ByteArray,
        fileSha256: ByteArray,
        privateKey: PrivateKey,
        phonePublic: ByteArray,
        keyAgreementProvider: String? = null
    ): ByteArray {
        require(record.size == RECORD_LENGTH && record.copyOfRange(0, 4).contentEquals(MAGIC)) {
            "Invalid file-key wrap record"
        }
        require(fileSha256.size == 32 && phonePublic.size == 65)
        val ephemeralPublic = record.copyOfRange(4, 69)
        require(ephemeralPublic[0] == 4.toByte()) { "Invalid ephemeral key" }
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val params = parameters.getParameterSpec(ECParameterSpec::class.java)
        val x = BigInteger(1, ephemeralPublic.copyOfRange(1, 33))
        val y = BigInteger(1, ephemeralPublic.copyOfRange(33, 65))
        val publicKey = KeyFactory.getInstance("EC").generatePublic(
            ECPublicKeySpec(ECPoint(x, y), params)
        )
        val agreement = if (keyAgreementProvider == null) KeyAgreement.getInstance("ECDH")
            else KeyAgreement.getInstance("ECDH", keyAgreementProvider)
        agreement.init(privateKey)
        agreement.doPhase(publicKey, true)
        val shared = agreement.generateSecret()
        val prk = hmac(fileSha256, shared)
        shared.fill(0)
        val info = DOMAIN + ephemeralPublic + phonePublic + byteArrayOf(1)
        val wrappingKey = hmac(prk, info)
        prk.fill(0)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.DECRYPT_MODE, SecretKeySpec(wrappingKey, "AES"),
            GCMParameterSpec(128, record.copyOfRange(69, 81)))
        wrappingKey.fill(0)
        cipher.updateAAD(DOMAIN + fileSha256 + ephemeralPublic + phonePublic)
        val fileKey = cipher.doFinal(record.copyOfRange(81, RECORD_LENGTH))
        require(fileKey.size == 32) { "Invalid unwrapped file key" }
        return fileKey
    }

    private fun publicKeySec1(store: KeyStore): ByteArray {
        val public = store.getCertificate(ALIAS)?.publicKey as? ECPublicKey
            ?: error("PhoneKey file agreement certificate is missing")
        fun fixed32(value: BigInteger): ByteArray {
            val bytes = value.toByteArray()
            require(bytes.size <= 33)
            return bytes.takeLast(32).toByteArray().let {
                ByteArray(32 - it.size) + it
            }
        }
        return byteArrayOf(4) + fixed32(public.w.affineX) + fixed32(public.w.affineY)
    }

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }
}

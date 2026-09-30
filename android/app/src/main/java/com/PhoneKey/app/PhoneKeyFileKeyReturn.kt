package com.PhoneKey.app

import java.io.ByteArrayOutputStream
import java.math.BigInteger
import java.nio.charset.StandardCharsets
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec
import javax.crypto.Cipher
import javax.crypto.KeyAgreement
import javax.crypto.Mac
import javax.crypto.spec.GCMParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Encrypts an approved file key to the one-time Windows return key.
 * Do not call until the QR-bound challenge includes that return public key. */
object PhoneKeyFileKeyReturn {
    private val domain = "PHONEKEY-FILE-RETURN-V1\u0000".toByteArray(StandardCharsets.UTF_8)
    private val magic = byteArrayOf(0x50, 0x4b, 0x52, 0x31)

    fun seal(fileKey: ByteArray, challengeSha256: ByteArray, laptopPublic: ByteArray): ByteArray {
        val generator = KeyPairGenerator.getInstance("EC")
        generator.initialize(ECGenParameterSpec("secp256r1"))
        val ephemeral = generator.generateKeyPair()
        val nonce = ByteArray(12).also { SecureRandom().nextBytes(it) }
        return sealWithParams(fileKey, challengeSha256, laptopPublic,
            ephemeral.private, ephemeral.public as ECPublicKey, nonce)
    }

    internal fun sealWithParams(
        fileKey: ByteArray,
        challengeSha256: ByteArray,
        laptopPublic: ByteArray,
        ephemeralPrivate: PrivateKey,
        ephemeralPublic: ECPublicKey,
        nonce: ByteArray
    ): ByteArray {
        require(fileKey.size == 32 && challengeSha256.size == 32 && nonce.size == 12)
        val laptop = decodePublic(laptopPublic)
        val ephemeralBytes = encodePublic(ephemeralPublic)
        val agreement = KeyAgreement.getInstance("ECDH")
        agreement.init(ephemeralPrivate)
        agreement.doPhase(laptop, true)
        val shared = agreement.generateSecret()
        val prk = hmac(challengeSha256, shared)
        shared.fill(0)
        val info = domain + ephemeralBytes + laptopPublic + byteArrayOf(1)
        val key = hmac(prk, info)
        prk.fill(0)
        val cipher = Cipher.getInstance("AES/GCM/NoPadding")
        cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), GCMParameterSpec(128, nonce))
        key.fill(0)
        cipher.updateAAD(domain + challengeSha256 + ephemeralBytes + laptopPublic)
        val ciphertext = cipher.doFinal(fileKey)
        return ByteArrayOutputStream(129).apply {
            write(magic)
            write(ephemeralBytes)
            write(nonce)
            write(ciphertext)
        }.toByteArray()
    }

    private fun decodePublic(bytes: ByteArray): ECPublicKey {
        require(bytes.size == 65 && bytes[0] == 4.toByte())
        val parameters = AlgorithmParameters.getInstance("EC")
        parameters.init(ECGenParameterSpec("secp256r1"))
        val curve = parameters.getParameterSpec(ECParameterSpec::class.java)
        val point = ECPoint(BigInteger(1, bytes.copyOfRange(1, 33)),
            BigInteger(1, bytes.copyOfRange(33, 65)))
        return KeyFactory.getInstance("EC").generatePublic(ECPublicKeySpec(point, curve)) as ECPublicKey
    }

    private fun encodePublic(key: ECPublicKey): ByteArray {
        fun fixed32(value: BigInteger): ByteArray {
            val source = value.toByteArray().takeLast(32).toByteArray()
            require(source.size <= 32)
            return ByteArray(32 - source.size) + source
        }
        return byteArrayOf(4) + fixed32(key.w.affineX) + fixed32(key.w.affineY)
    }

    private fun hmac(key: ByteArray, message: ByteArray): ByteArray {
        val mac = Mac.getInstance("HmacSHA256")
        mac.init(SecretKeySpec(key, "HmacSHA256"))
        return mac.doFinal(message)
    }
}

package com.PhoneKey.app

import android.content.Context
import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import android.util.Base64
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.MessageDigest
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

class DeviceIdentityManager(
    private val context: Context
) {

    companion object {
        private const val KEYSTORE_PROVIDER =
            "AndroidKeyStore"

        private const val KEY_ALIAS =
            "phonekey_signing_key_v3"

        private const val PREFS_NAME =
            "phonekey_identity"

        private const val PREF_DEVICE_ID =
            "device_id"

        private const val DEVICE_ID_LENGTH =
            16

        private const val AUTH_VALIDITY_SECONDS =
            15

        /*
         * secp256r1 / NIST P-256 subgroup order:
         *
         * FFFFFFFF00000000FFFFFFFFFFFFFFFF
         * BCE6FAADA7179E84F3B9CAC2FC632551
         *
         * PhoneKey uses canonical low-S ECDSA.
         */
        private val P256_ORDER =
            BigInteger(
                "FFFFFFFF00000000FFFFFFFFFFFFFFFF" +
                    "BCE6FAADA7179E84F3B9CAC2FC632551",
                16
            )

        private val P256_HALF_ORDER =
            P256_ORDER.shiftRight(1)
    }

    private val preferences =
        context.getSharedPreferences(
            PREFS_NAME,
            Context.MODE_PRIVATE
        )

    fun identityExists(): Boolean {
        return preferences.contains(
            PREF_DEVICE_ID
        ) && signingKeyExists()
    }

    fun createIdentity(): PhoneKeyIdentity {
        if (
            !preferences.contains(
                PREF_DEVICE_ID
            )
        ) {
            createDeviceId()
        }

        if (!signingKeyExists()) {
            generateSigningKey()
        }

        return getIdentity()
    }

    fun getIdentity(): PhoneKeyIdentity {
        val encodedDeviceId =
            preferences.getString(
                PREF_DEVICE_ID,
                null
            ) ?: error(
                "PhoneKey device ID does not exist"
            )

        val deviceId =
            Base64.decode(
                encodedDeviceId,
                Base64.NO_WRAP
            )

        require(
            deviceId.size ==
                DEVICE_ID_LENGTH
        ) {
            "Invalid PhoneKey device ID length"
        }

        val publicKey =
            getPublicKeySec1()

        return PhoneKeyIdentity(
            deviceId =
                deviceId,
            publicKeySec1 =
                publicKey,
            fingerprint =
                fingerprint(
                    publicKey
                )
        )
    }

    fun sign(
        data: ByteArray
    ): ByteArray {
        val keyStore =
            KeyStore.getInstance(
                KEYSTORE_PROVIDER
            )

        keyStore.load(null)

        val privateKey =
            keyStore.getKey(
                KEY_ALIAS,
                null
            ) as? PrivateKey
                ?: error(
                    "PhoneKey private key does not exist"
                )

        val signer =
            Signature.getInstance(
                "SHA256withECDSA"
            )

        signer.initSign(
            privateKey
        )

        signer.update(
            data
        )

        val derSignature =
            signer.sign()

        return derEcdsaToCanonicalRaw64(
            derSignature
        )
    }

    private fun createDeviceId() {
        val deviceId =
            ByteArray(
                DEVICE_ID_LENGTH
            )

        SecureRandom()
            .nextBytes(
                deviceId
            )

        val encoded =
            Base64.encodeToString(
                deviceId,
                Base64.NO_WRAP
            )

        val committed =
            preferences.edit()
                .putString(
                    PREF_DEVICE_ID,
                    encoded
                )
                .commit()

        check(committed) {
            "Unable to save PhoneKey device ID"
        }
    }

    private fun signingKeyExists():
        Boolean {
        val keyStore =
            KeyStore.getInstance(
                KEYSTORE_PROVIDER
            )

        keyStore.load(null)

        return keyStore.containsAlias(
            KEY_ALIAS
        )
    }

    private fun generateSigningKey() {
        val generator =
            KeyPairGenerator.getInstance(
                KeyProperties.KEY_ALGORITHM_EC,
                KEYSTORE_PROVIDER
            )

        val builder =
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_SIGN or
                    KeyProperties.PURPOSE_VERIFY
            )
                .setAlgorithmParameterSpec(
                    ECGenParameterSpec(
                        "secp256r1"
                    )
                )
                .setDigests(
                    KeyProperties.DIGEST_SHA256
                )
                .setUserAuthenticationRequired(
                    true
                )

        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.R
        ) {
            builder
                .setUserAuthenticationParameters(
                    AUTH_VALIDITY_SECONDS,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or
                        KeyProperties.AUTH_DEVICE_CREDENTIAL
                )
        } else {
            @Suppress("DEPRECATION")
            builder
                .setUserAuthenticationValidityDurationSeconds(
                    AUTH_VALIDITY_SECONDS
                )
        }

        generator.initialize(
            builder.build()
        )

        generator.generateKeyPair()
    }

    private fun getPublicKeySec1():
        ByteArray {
        val keyStore =
            KeyStore.getInstance(
                KEYSTORE_PROVIDER
            )

        keyStore.load(null)

        val certificate =
            keyStore.getCertificate(
                KEY_ALIAS
            ) ?: error(
                "PhoneKey certificate does not exist"
            )

        val publicKey =
            certificate.publicKey
                as? ECPublicKey
                ?: error(
                    "PhoneKey public key is not an EC key"
                )

        val x =
            bigIntegerTo32Bytes(
                publicKey.w.affineX
            )

        val y =
            bigIntegerTo32Bytes(
                publicKey.w.affineY
            )

        return ByteArray(65).apply {
            this[0] =
                0x04

            System.arraycopy(
                x,
                0,
                this,
                1,
                32
            )

            System.arraycopy(
                y,
                0,
                this,
                33,
                32
            )
        }
    }

    private fun bigIntegerTo32Bytes(
        value: BigInteger
    ): ByteArray {
        val source =
            value.toByteArray()

        val unsigned =
            if (
                source.size == 33 &&
                source[0] ==
                    0.toByte()
            ) {
                source.copyOfRange(
                    1,
                    source.size
                )
            } else {
                source
            }

        require(
            unsigned.size <= 32
        ) {
            "EC coordinate is too large"
        }

        return ByteArray(32).also {
            output ->

            System.arraycopy(
                unsigned,
                0,
                output,
                32 - unsigned.size,
                unsigned.size
            )
        }
    }

    private fun fingerprint(
        publicKey: ByteArray
    ): String {
        val digest =
            MessageDigest
                .getInstance(
                    "SHA-256"
                )
                .digest(
                    publicKey
                )

        return digest
            .take(8)
            .joinToString(":") {
                byte ->

                "%02X".format(
                    byte.toInt() and 0xFF
                )
            }
    }

    private fun derEcdsaToCanonicalRaw64(
        der: ByteArray
    ): ByteArray {
        require(
            der.size >= 8
        ) {
            "Invalid ECDSA signature"
        }

        var index = 0

        require(
            der[index++]
                .toInt() and 0xFF ==
                0x30
        ) {
            "Invalid ECDSA sequence"
        }

        val sequenceLength =
            readDerLength(
                der,
                index
            )

        index +=
            sequenceLength.second

        require(
            sequenceLength.first ==
                der.size - index
        ) {
            "Invalid ECDSA sequence length"
        }

        require(
            der[index++]
                .toInt() and 0xFF ==
                0x02
        ) {
            "Invalid ECDSA r value"
        }

        val rLength =
            readDerLength(
                der,
                index
            )

        index +=
            rLength.second

        require(
            index + rLength.first <=
                der.size
        ) {
            "Invalid ECDSA r length"
        }

        val rBytes =
            der.copyOfRange(
                index,
                index + rLength.first
            )

        index +=
            rLength.first

        require(
            index < der.size &&
                der[index++]
                    .toInt() and 0xFF ==
                0x02
        ) {
            "Invalid ECDSA s value"
        }

        val sLength =
            readDerLength(
                der,
                index
            )

        index +=
            sLength.second

        require(
            index + sLength.first ==
                der.size
        ) {
            "Invalid ECDSA s length"
        }

        val sBytes =
            der.copyOfRange(
                index,
                index + sLength.first
            )

        val r =
            BigInteger(
                1,
                rBytes
            )

        var s =
            BigInteger(
                1,
                sBytes
            )

        require(
            r.signum() > 0 &&
                r < P256_ORDER
        ) {
            "ECDSA r is outside P-256 range"
        }

        require(
            s.signum() > 0 &&
                s < P256_ORDER
        ) {
            "ECDSA s is outside P-256 range"
        }

        /*
         * ECDSA signatures (r, s) and
         * (r, n-s) are mathematically equivalent.
         *
         * PhoneKey always chooses the low-S form
         * so there is only one canonical signature.
         */
        if (
            s >
            P256_HALF_ORDER
        ) {
            s =
                P256_ORDER.subtract(
                    s
                )
        }

        val raw =
            ByteArray(64)

        val normalizedR =
            bigIntegerTo32Bytes(
                r
            )

        val normalizedS =
            bigIntegerTo32Bytes(
                s
            )

        System.arraycopy(
            normalizedR,
            0,
            raw,
            0,
            32
        )

        System.arraycopy(
            normalizedS,
            0,
            raw,
            32,
            32
        )

        return raw
    }

    private fun readDerLength(
        data: ByteArray,
        offset: Int
    ): Pair<Int, Int> {
        require(
            offset < data.size
        ) {
            "Invalid DER length"
        }

        val first =
            data[offset]
                .toInt() and 0xFF

        if (first < 0x80) {
            return Pair(
                first,
                1
            )
        }

        val byteCount =
            first and 0x7F

        require(
            byteCount in 1..2
        ) {
            "Unsupported DER length"
        }

        require(
            offset + byteCount <
                data.size
        ) {
            "Invalid DER length"
        }

        var length = 0

        for (
            i in 1..byteCount
        ) {
            length =
                (length shl 8) or
                    (
                        data[offset + i]
                            .toInt() and
                            0xFF
                        )
        }

        return Pair(
            length,
            1 + byteCount
        )
    }
}

data class PhoneKeyIdentity(
    val deviceId: ByteArray,
    val publicKeySec1: ByteArray,
    val fingerprint: String
)

package com.PhoneKey.app

import java.io.ByteArrayOutputStream
import java.nio.charset.StandardCharsets
import java.security.MessageDigest

object PhoneKeyProtocol {

    const val PROTOCOL_VERSION = 1

    const val MESSAGE_TYPE_LOGIN_CHALLENGE = 1
    const val MESSAGE_TYPE_LOGIN_PROOF = 2

    const val MESSAGE_TYPE_ENROLLMENT_CHALLENGE = 10
    const val MESSAGE_TYPE_ENROLLMENT_PROOF = 11
    const val MESSAGE_TYPE_FILE_OPEN_CHALLENGE = 20
    const val MESSAGE_TYPE_FILE_OPEN_PROOF = 21

    const val OPERATION_LOGON = 1
    const val OPERATION_UNLOCK = 2

    const val DEVICE_ID_LENGTH = 16
    const val SESSION_ID_LENGTH = 16
    const val NONCE_LENGTH = 32
    const val P256_PUBLIC_KEY_LENGTH = 65
    const val P256_SIGNATURE_LENGTH = 64

    const val MAX_ACCOUNT_BINDING_LENGTH = 256
    const val MAX_LOGIN_SESSION_TTL_MS = 60_000L
    const val MAX_ENROLLMENT_TTL_MS = 185_000L
    const val MAX_MESSAGE_SIZE = 2048

    private val LOGIN_SIGNATURE_DOMAIN =
        "PHONEKEY-LOGIN-SIGNATURE-V1\u0000"
            .toByteArray(StandardCharsets.UTF_8)

    private val FILE_OPEN_SIGNATURE_DOMAIN =
        "PHONEKEY-FILE-OPEN-SIGNATURE-V2\u0000"
            .toByteArray(StandardCharsets.UTF_8)

    private val ENROLLMENT_SIGNATURE_DOMAIN =
        "PHONEKEY-ENROLLMENT-SIGNATURE-V1\u0000"
            .toByteArray(StandardCharsets.UTF_8)

    private val PAIRING_CODE_DOMAIN =
        "PHONEKEY-PAIRING-CODE-V1\u0000"
            .toByteArray(StandardCharsets.UTF_8)

    data class LoginChallenge(
        val windowsDeviceId: ByteArray,
        val sessionId: ByteArray,
        val nonce: ByteArray,
        val issuedAtMs: Long,
        val expiresAtMs: Long,
        val operation: Int,
        val accountBinding: ByteArray
    )

    data class LoginProof(
        val androidDeviceId: ByteArray,
        val sessionId: ByteArray,
        val signature: ByteArray
    )

    data class FileOpenChallenge(
        val windowsDeviceId: ByteArray,
        val phoneDeviceId: ByteArray,
        val sessionId: ByteArray,
        val nonce: ByteArray,
        val envelopeSha256: ByteArray,
        val issuedAtMs: Long,
        val expiresAtMs: Long,
        val phoneWrap: ByteArray,
        val returnPublicSec1: ByteArray
    )

    data class FileOpenProof(
        val phoneDeviceId: ByteArray,
        val sessionId: ByteArray,
        val signature: ByteArray,
        val encryptedFileKey: ByteArray
    )

    fun encodeFileOpenProof(proof: FileOpenProof): ByteArray {
        require(proof.phoneDeviceId.size == DEVICE_ID_LENGTH)
        require(proof.sessionId.size == SESSION_ID_LENGTH)
        require(proof.signature.size == P256_SIGNATURE_LENGTH)
        require(proof.encryptedFileKey.size == 129 && proof.encryptedFileKey.copyOfRange(0, 4)
            .contentEquals(byteArrayOf(0x50, 0x4b, 0x52, 0x31)))
        val output = ByteArrayOutputStream()
        writeMapHeader(output, 6)
        writeUnsignedInteger(output, 1)
        writeUnsignedInteger(output, PROTOCOL_VERSION.toLong())
        writeUnsignedInteger(output, 2)
        writeUnsignedInteger(output, MESSAGE_TYPE_FILE_OPEN_PROOF.toLong())
        writeUnsignedInteger(output, 3)
        writeByteString(output, proof.phoneDeviceId)
        writeUnsignedInteger(output, 4)
        writeByteString(output, proof.sessionId)
        writeUnsignedInteger(output, 5)
        writeByteString(output, proof.signature)
        writeUnsignedInteger(output, 6)
        writeByteString(output, proof.encryptedFileKey)
        return output.toByteArray()
    }

    fun decodeFileOpenChallenge(data: ByteArray): FileOpenChallenge {
        requireMessageSize(data)
        val reader = CborReader(data)
        require(reader.readMapSize() == 11) { "File opening request must contain exactly 11 fields" }
        requireField(reader, 1)
        requireValue(reader, PROTOCOL_VERSION.toLong(), "Unsupported PhoneKey protocol version")
        requireField(reader, 2)
        requireValue(reader, MESSAGE_TYPE_FILE_OPEN_CHALLENGE.toLong(), "Unexpected message type")
        requireField(reader, 3)
        val windowsDeviceId = reader.readByteString()
        requireField(reader, 4)
        val phoneDeviceId = reader.readByteString()
        requireField(reader, 5)
        val sessionId = reader.readByteString()
        requireField(reader, 6)
        val nonce = reader.readByteString()
        requireField(reader, 7)
        val envelopeSha256 = reader.readByteString()
        requireField(reader, 8)
        val issuedAtMs = reader.readUnsigned()
        requireField(reader, 9)
        val expiresAtMs = reader.readUnsigned()
        requireField(reader, 10)
        val phoneWrap = reader.readByteString()
        requireField(reader, 11)
        val returnPublicSec1 = reader.readByteString()
        require(reader.isFinished()) { "Trailing bytes after file opening request" }
        val challenge = FileOpenChallenge(
            windowsDeviceId, phoneDeviceId, sessionId, nonce,
            envelopeSha256, issuedAtMs, expiresAtMs, phoneWrap, returnPublicSec1
        )
        buildFileOpenSigningTranscript(challenge)
        return challenge
    }

    fun encodeFileOpenChallenge(challenge: FileOpenChallenge): ByteArray {
        buildFileOpenSigningTranscript(challenge)
        val output = ByteArrayOutputStream()
        writeMapHeader(output, 11)
        writeUnsignedInteger(output, 1)
        writeUnsignedInteger(output, PROTOCOL_VERSION.toLong())
        writeUnsignedInteger(output, 2)
        writeUnsignedInteger(output, MESSAGE_TYPE_FILE_OPEN_CHALLENGE.toLong())
        for ((field, value) in arrayOf(
            3 to challenge.windowsDeviceId,
            4 to challenge.phoneDeviceId,
            5 to challenge.sessionId,
            6 to challenge.nonce,
            7 to challenge.envelopeSha256
        )) {
            writeUnsignedInteger(output, field.toLong())
            writeByteString(output, value)
        }
        writeUnsignedInteger(output, 8)
        writeUnsignedInteger(output, challenge.issuedAtMs)
        writeUnsignedInteger(output, 9)
        writeUnsignedInteger(output, challenge.expiresAtMs)
        writeUnsignedInteger(output, 10)
        writeByteString(output, challenge.phoneWrap)
        writeUnsignedInteger(output, 11)
        writeByteString(output, challenge.returnPublicSec1)
        return output.toByteArray()
    }

    fun buildFileOpenSigningTranscript(challenge: FileOpenChallenge): ByteArray {
        require(challenge.windowsDeviceId.size == DEVICE_ID_LENGTH)
        require(challenge.phoneDeviceId.size == DEVICE_ID_LENGTH)
        require(challenge.sessionId.size == SESSION_ID_LENGTH)
        require(challenge.nonce.size == NONCE_LENGTH)
        require(challenge.envelopeSha256.size == 32)
        require(challenge.phoneWrap.size == 129 && challenge.phoneWrap.copyOfRange(0, 4)
            .contentEquals(byteArrayOf(0x50, 0x4b, 0x57, 0x31)))
        require(challenge.returnPublicSec1.size == 65 && challenge.returnPublicSec1[0] == 4.toByte())
        require(challenge.issuedAtMs >= 0 && challenge.expiresAtMs > challenge.issuedAtMs)
        require(challenge.expiresAtMs - challenge.issuedAtMs <= MAX_LOGIN_SESSION_TTL_MS)
        val output = ByteArrayOutputStream()
        output.write(FILE_OPEN_SIGNATURE_DOMAIN)
        output.write(challenge.windowsDeviceId)
        output.write(challenge.phoneDeviceId)
        output.write(challenge.sessionId)
        output.write(challenge.nonce)
        output.write(challenge.envelopeSha256)
        for (timestamp in longArrayOf(challenge.issuedAtMs, challenge.expiresAtMs)) {
            for (shift in 56 downTo 0 step 8) {
                output.write(((timestamp ushr shift) and 0xff).toInt())
            }
        }
        output.write(challenge.phoneWrap)
        output.write(challenge.returnPublicSec1)
        return output.toByteArray()
    }

    data class EnrollmentChallenge(
        val windowsDeviceId: ByteArray,
        val enrollmentId: ByteArray,
        val nonce: ByteArray,
        val issuedAtMs: Long,
        val expiresAtMs: Long
    )

    data class EnrollmentProof(
        val androidDeviceId: ByteArray,
        val enrollmentId: ByteArray,
        val publicKeySec1: ByteArray,
        val signature: ByteArray
    )

    fun readMessageType(
        data: ByteArray
    ): Int {
        require(
            data.isNotEmpty() &&
                data.size <= MAX_MESSAGE_SIZE
        ) {
            "Invalid PhoneKey message size"
        }

        val reader =
            CborReader(data)

        val mapSize =
            reader.readMapSize()

        require(mapSize >= 2) {
            "PhoneKey message is missing required fields"
        }

        require(
            reader.readUnsigned() == 1L
        ) {
            "Expected protocol version field"
        }

        require(
            reader.readUnsigned() ==
                PROTOCOL_VERSION.toLong()
        ) {
            "Unsupported PhoneKey protocol version"
        }

        require(
            reader.readUnsigned() == 2L
        ) {
            "Expected message type field"
        }

        return reader
            .readUnsigned()
            .toInt()
    }

    fun decodeLoginChallenge(
        data: ByteArray
    ): LoginChallenge {
        requireMessageSize(data)

        val reader =
            CborReader(data)

        require(
            reader.readMapSize() == 9
        ) {
            "LoginChallenge must contain exactly 9 fields"
        }

        requireField(reader, 1)
        requireValue(
            reader,
            PROTOCOL_VERSION.toLong(),
            "Unsupported PhoneKey protocol version"
        )

        requireField(reader, 2)
        requireValue(
            reader,
            MESSAGE_TYPE_LOGIN_CHALLENGE.toLong(),
            "Unexpected message type"
        )

        requireField(reader, 3)
        val windowsDeviceId =
            reader.readByteString()

        requireField(reader, 4)
        val sessionId =
            reader.readByteString()

        requireField(reader, 5)
        val nonce =
            reader.readByteString()

        requireField(reader, 6)
        val issuedAtMs =
            reader.readUnsigned()

        requireField(reader, 7)
        val expiresAtMs =
            reader.readUnsigned()

        requireField(reader, 8)
        val operation =
            reader.readUnsigned().toInt()

        requireField(reader, 9)
        val accountBinding =
            reader.readByteString()

        require(reader.isFinished()) {
            "Trailing bytes after LoginChallenge"
        }

        val challenge =
            LoginChallenge(
                windowsDeviceId,
                sessionId,
                nonce,
                issuedAtMs,
                expiresAtMs,
                operation,
                accountBinding
            )

        validateLoginChallenge(
            challenge
        )

        return challenge
    }

    fun encodeLoginChallenge(
        challenge: LoginChallenge
    ): ByteArray {
        validateLoginChallenge(
            challenge
        )

        val output =
            ByteArrayOutputStream()

        writeMapHeader(
            output,
            9
        )

        writeUnsignedInteger(output, 1)
        writeUnsignedInteger(
            output,
            PROTOCOL_VERSION.toLong()
        )

        writeUnsignedInteger(output, 2)
        writeUnsignedInteger(
            output,
            MESSAGE_TYPE_LOGIN_CHALLENGE.toLong()
        )

        writeUnsignedInteger(output, 3)
        writeByteString(
            output,
            challenge.windowsDeviceId
        )

        writeUnsignedInteger(output, 4)
        writeByteString(
            output,
            challenge.sessionId
        )

        writeUnsignedInteger(output, 5)
        writeByteString(
            output,
            challenge.nonce
        )

        writeUnsignedInteger(output, 6)
        writeUnsignedInteger(
            output,
            challenge.issuedAtMs
        )

        writeUnsignedInteger(output, 7)
        writeUnsignedInteger(
            output,
            challenge.expiresAtMs
        )

        writeUnsignedInteger(output, 8)
        writeUnsignedInteger(
            output,
            challenge.operation.toLong()
        )

        writeUnsignedInteger(output, 9)
        writeByteString(
            output,
            challenge.accountBinding
        )

        return output.toByteArray()
    }

    fun buildLoginSigningTranscript(
        challenge: LoginChallenge
    ): ByteArray {
        val encodedChallenge =
            encodeLoginChallenge(
                challenge
            )

        return concatenate(
            LOGIN_SIGNATURE_DOMAIN,
            encodedChallenge
        )
    }

    fun encodeLoginProof(
        proof: LoginProof
    ): ByteArray {
        require(
            proof.androidDeviceId.size ==
                DEVICE_ID_LENGTH
        )

        require(
            proof.sessionId.size ==
                SESSION_ID_LENGTH
        )

        require(
            proof.signature.size ==
                P256_SIGNATURE_LENGTH
        )

        val output =
            ByteArrayOutputStream()

        writeMapHeader(
            output,
            5
        )

        writeUnsignedInteger(output, 1)
        writeUnsignedInteger(
            output,
            PROTOCOL_VERSION.toLong()
        )

        writeUnsignedInteger(output, 2)
        writeUnsignedInteger(
            output,
            MESSAGE_TYPE_LOGIN_PROOF.toLong()
        )

        writeUnsignedInteger(output, 3)
        writeByteString(
            output,
            proof.androidDeviceId
        )

        writeUnsignedInteger(output, 4)
        writeByteString(
            output,
            proof.sessionId
        )

        writeUnsignedInteger(output, 5)
        writeByteString(
            output,
            proof.signature
        )

        return output.toByteArray()
    }

    fun decodeEnrollmentChallenge(
        data: ByteArray
    ): EnrollmentChallenge {
        requireMessageSize(data)

        val reader =
            CborReader(data)

        require(
            reader.readMapSize() == 7
        ) {
            "EnrollmentChallenge must contain exactly 7 fields"
        }

        requireField(reader, 1)
        requireValue(
            reader,
            PROTOCOL_VERSION.toLong(),
            "Unsupported PhoneKey protocol version"
        )

        requireField(reader, 2)
        requireValue(
            reader,
            MESSAGE_TYPE_ENROLLMENT_CHALLENGE.toLong(),
            "Unexpected message type"
        )

        requireField(reader, 3)
        val windowsDeviceId =
            reader.readByteString()

        requireField(reader, 4)
        val enrollmentId =
            reader.readByteString()

        requireField(reader, 5)
        val nonce =
            reader.readByteString()

        requireField(reader, 6)
        val issuedAtMs =
            reader.readUnsigned()

        requireField(reader, 7)
        val expiresAtMs =
            reader.readUnsigned()

        require(reader.isFinished()) {
            "Trailing bytes after EnrollmentChallenge"
        }

        val challenge =
            EnrollmentChallenge(
                windowsDeviceId,
                enrollmentId,
                nonce,
                issuedAtMs,
                expiresAtMs
            )

        validateEnrollmentChallenge(
            challenge
        )

        return challenge
    }

    fun encodeEnrollmentChallenge(
        challenge: EnrollmentChallenge
    ): ByteArray {
        validateEnrollmentChallenge(
            challenge
        )

        val output =
            ByteArrayOutputStream()

        writeMapHeader(
            output,
            7
        )

        writeUnsignedInteger(output, 1)
        writeUnsignedInteger(
            output,
            PROTOCOL_VERSION.toLong()
        )

        writeUnsignedInteger(output, 2)
        writeUnsignedInteger(
            output,
            MESSAGE_TYPE_ENROLLMENT_CHALLENGE.toLong()
        )

        writeUnsignedInteger(output, 3)
        writeByteString(
            output,
            challenge.windowsDeviceId
        )

        writeUnsignedInteger(output, 4)
        writeByteString(
            output,
            challenge.enrollmentId
        )

        writeUnsignedInteger(output, 5)
        writeByteString(
            output,
            challenge.nonce
        )

        writeUnsignedInteger(output, 6)
        writeUnsignedInteger(
            output,
            challenge.issuedAtMs
        )

        writeUnsignedInteger(output, 7)
        writeUnsignedInteger(
            output,
            challenge.expiresAtMs
        )

        return output.toByteArray()
    }

    fun buildEnrollmentSigningTranscript(
        challenge: EnrollmentChallenge,
        androidDeviceId: ByteArray,
        publicKeySec1: ByteArray
    ): ByteArray {
        require(
            androidDeviceId.size ==
                DEVICE_ID_LENGTH
        )

        require(
            publicKeySec1.size ==
                P256_PUBLIC_KEY_LENGTH
        )

        return concatenate(
            ENROLLMENT_SIGNATURE_DOMAIN,
            encodeEnrollmentChallenge(
                challenge
            ),
            androidDeviceId,
            publicKeySec1
        )
    }

    fun encodeEnrollmentProof(
        proof: EnrollmentProof
    ): ByteArray {
        require(
            proof.androidDeviceId.size ==
                DEVICE_ID_LENGTH
        )

        require(
            proof.enrollmentId.size ==
                SESSION_ID_LENGTH
        )

        require(
            proof.publicKeySec1.size ==
                P256_PUBLIC_KEY_LENGTH
        )

        require(
            proof.publicKeySec1[0] ==
                0x04.toByte()
        )

        require(
            proof.signature.size ==
                P256_SIGNATURE_LENGTH
        )

        val output =
            ByteArrayOutputStream()

        writeMapHeader(
            output,
            6
        )

        writeUnsignedInteger(output, 1)
        writeUnsignedInteger(
            output,
            PROTOCOL_VERSION.toLong()
        )

        writeUnsignedInteger(output, 2)
        writeUnsignedInteger(
            output,
            MESSAGE_TYPE_ENROLLMENT_PROOF.toLong()
        )

        writeUnsignedInteger(output, 3)
        writeByteString(
            output,
            proof.androidDeviceId
        )

        writeUnsignedInteger(output, 4)
        writeByteString(
            output,
            proof.enrollmentId
        )

        writeUnsignedInteger(output, 5)
        writeByteString(
            output,
            proof.publicKeySec1
        )

        writeUnsignedInteger(output, 6)
        writeByteString(
            output,
            proof.signature
        )

        return output.toByteArray()
    }

    fun derivePairingCode(
        challenge: EnrollmentChallenge,
        proof: EnrollmentProof
    ): Int {
        val digest =
            MessageDigest
                .getInstance("SHA-256")
                .digest(
                    concatenate(
                        PAIRING_CODE_DOMAIN,
                        encodeEnrollmentChallenge(
                            challenge
                        ),
                        encodeEnrollmentProof(
                            proof
                        )
                    )
                )

        val value =
            ((digest[0].toLong() and 0xFFL) shl 24) or
                ((digest[1].toLong() and 0xFFL) shl 16) or
                ((digest[2].toLong() and 0xFFL) shl 8) or
                (digest[3].toLong() and 0xFFL)

        return (
            value % 1_000_000L
            ).toInt()
    }

    fun formatPairingCode(
        code: Int
    ): String {
        require(
            code in 0..999_999
        )

        return String.format(
            "%06d",
            code
        )
    }

    fun bytesToHex(
        value: ByteArray
    ): String {
        return value.joinToString("") {
            "%02x".format(
                it.toInt() and 0xFF
            )
        }
    }

    private fun validateLoginChallenge(
        challenge: LoginChallenge
    ) {
        require(
            challenge.windowsDeviceId.size ==
                DEVICE_ID_LENGTH
        )

        require(
            challenge.sessionId.size ==
                SESSION_ID_LENGTH
        )

        require(
            challenge.nonce.size ==
                NONCE_LENGTH
        )

        require(
            challenge.issuedAtMs >= 0
        )

        require(
            challenge.expiresAtMs >
                challenge.issuedAtMs
        )

        require(
            challenge.expiresAtMs -
                challenge.issuedAtMs <=
                MAX_LOGIN_SESSION_TTL_MS
        )

        require(
            challenge.operation ==
                OPERATION_LOGON ||
                challenge.operation ==
                OPERATION_UNLOCK
        )

        require(
            challenge.accountBinding.isNotEmpty()
        )

        require(
            challenge.accountBinding.size <=
                MAX_ACCOUNT_BINDING_LENGTH
        )
    }

    private fun validateEnrollmentChallenge(
        challenge: EnrollmentChallenge
    ) {
        require(
            challenge.windowsDeviceId.size ==
                DEVICE_ID_LENGTH
        )

        require(
            challenge.enrollmentId.size ==
                SESSION_ID_LENGTH
        )

        require(
            challenge.nonce.size ==
                NONCE_LENGTH
        )

        require(
            challenge.issuedAtMs >= 0
        )

        require(
            challenge.expiresAtMs >
                challenge.issuedAtMs
        )

        require(
            challenge.expiresAtMs -
                challenge.issuedAtMs <=
                MAX_ENROLLMENT_TTL_MS
        )
    }

    private fun requireMessageSize(
        data: ByteArray
    ) {
        require(data.isNotEmpty()) {
            "PhoneKey message cannot be empty"
        }

        require(
            data.size <= MAX_MESSAGE_SIZE
        ) {
            "PhoneKey message exceeds maximum size"
        }
    }

    private fun requireField(
        reader: CborReader,
        expected: Long
    ) {
        require(
            reader.readUnsigned() ==
                expected
        ) {
            "Unexpected or non-canonical field"
        }
    }

    private fun requireValue(
        reader: CborReader,
        expected: Long,
        message: String
    ) {
        require(
            reader.readUnsigned() ==
                expected
        ) {
            message
        }
    }

    private fun concatenate(
        vararg arrays: ByteArray
    ): ByteArray {
        var total = 0

        for (array in arrays) {
            total +=
                array.size
        }

        return ByteArray(total)
            .also { output ->
                var offset = 0

                for (array in arrays) {
                    System.arraycopy(
                        array,
                        0,
                        output,
                        offset,
                        array.size
                    )

                    offset +=
                        array.size
                }
            }
    }

    private fun writeMapHeader(
        output: ByteArrayOutputStream,
        size: Int
    ) {
        writeTypeAndLength(
            output,
            5,
            size.toLong()
        )
    }

    private fun writeByteString(
        output: ByteArrayOutputStream,
        value: ByteArray
    ) {
        writeTypeAndLength(
            output,
            2,
            value.size.toLong()
        )

        output.write(
            value
        )
    }

    private fun writeUnsignedInteger(
        output: ByteArrayOutputStream,
        value: Long
    ) {
        require(
            value >= 0
        )

        writeTypeAndLength(
            output,
            0,
            value
        )
    }

    private fun writeTypeAndLength(
        output: ByteArrayOutputStream,
        majorType: Int,
        value: Long
    ) {
        require(
            majorType in 0..7
        )

        require(
            value >= 0
        )

        when {
            value <= 23 -> {
                output.write(
                    (majorType shl 5) or
                        value.toInt()
                )
            }

            value <= 0xFF -> {
                output.write(
                    (majorType shl 5) or
                        24
                )

                output.write(
                    value.toInt()
                )
            }

            value <= 0xFFFF -> {
                output.write(
                    (majorType shl 5) or
                        25
                )

                output.write(
                    ((value shr 8) and 0xFF)
                        .toInt()
                )

                output.write(
                    (value and 0xFF)
                        .toInt()
                )
            }

            value <= 0xFFFF_FFFFL -> {
                output.write(
                    (majorType shl 5) or
                        26
                )

                for (
                    shift in intArrayOf(
                        24,
                        16,
                        8,
                        0
                    )
                ) {
                    output.write(
                        (
                            value shr shift and
                                0xFF
                            ).toInt()
                    )
                }
            }

            else -> {
                output.write(
                    (majorType shl 5) or
                        27
                )

                for (
                    shift in intArrayOf(
                        56,
                        48,
                        40,
                        32,
                        24,
                        16,
                        8,
                        0
                    )
                ) {
                    output.write(
                        (
                            value shr shift and
                                0xFF
                            ).toInt()
                    )
                }
            }
        }
    }

    private class CborReader(
        private val data: ByteArray
    ) {
        private var index =
            0

        fun isFinished(): Boolean =
            index == data.size

        fun readMapSize(): Int {
            val size =
                readHeader(5)

            require(
                size <= Int.MAX_VALUE
            )

            return size.toInt()
        }

        fun readUnsigned(): Long =
            readHeader(0)

        fun readByteString(): ByteArray {
            val length =
                readHeader(2)

            require(
                length <= Int.MAX_VALUE
            )

            val size =
                length.toInt()

            require(
                index + size <=
                    data.size
            ) {
                "Truncated CBOR byte string"
            }

            val value =
                data.copyOfRange(
                    index,
                    index + size
                )

            index +=
                size

            return value
        }

        private fun readHeader(
            expectedMajorType: Int
        ): Long {
            require(
                index < data.size
            ) {
                "Unexpected end of CBOR"
            }

            val first =
                data[index++]
                    .toInt() and 0xFF

            val majorType =
                first shr 5

            val additional =
                first and 0x1F

            require(
                majorType ==
                    expectedMajorType
            ) {
                "Unexpected CBOR type"
            }

            return when {
                additional < 24 ->
                    additional.toLong()

                additional == 24 -> {
                    val value =
                        readByte()
                            .toLong()

                    require(
                        value >= 24
                    ) {
                        "Non-canonical CBOR integer"
                    }

                    value
                }

                additional == 25 -> {
                    val value =
                        readFixedUnsigned(2)

                    require(
                        value > 0xFF
                    ) {
                        "Non-canonical CBOR integer"
                    }

                    value
                }

                additional == 26 -> {
                    val value =
                        readFixedUnsigned(4)

                    require(
                        value > 0xFFFF
                    ) {
                        "Non-canonical CBOR integer"
                    }

                    value
                }

                additional == 27 -> {
                    val value =
                        readFixedUnsigned(8)

                    require(
                        value >
                            0xFFFF_FFFFL
                    ) {
                        "Non-canonical CBOR integer"
                    }

                    value
                }

                else ->
                    throw IllegalArgumentException(
                        "Unsupported CBOR encoding"
                    )
            }
        }

        private fun readByte(): Int {
            require(
                index < data.size
            )

            return data[index++]
                .toInt() and 0xFF
        }

        private fun readFixedUnsigned(
            count: Int
        ): Long {
            require(
                index + count <=
                    data.size
            ) {
                "Truncated CBOR integer"
            }

            var value =
                0uL

            repeat(count) {
                value =
                    (value shl 8) or
                        readByte()
                            .toULong()
            }

            require(
                value <=
                    Long.MAX_VALUE
                        .toULong()
            ) {
                "CBOR integer exceeds Android Long"
            }

            return value.toLong()
        }
    }
}

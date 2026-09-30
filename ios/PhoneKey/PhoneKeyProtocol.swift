import CryptoKit
import Foundation

enum PhoneKeyError: Error, LocalizedError, Equatable {
    case truncated
    case invalid(String)

    var errorDescription: String? {
        switch self {
        case .truncated: return "Incomplete Bluetooth request"
        case .invalid(let message): return message
        }
    }
}

enum PhoneKeyCBOR {
    enum Value: Equatable {
        case unsigned(UInt64)
        case bytes(Data)
        case map([UInt64: Value])
    }

    static let maximumSize = 2_048

    static func encode(_ value: Value) throws -> Data {
        var output = Data()
        try append(value, to: &output)
        guard output.count <= maximumSize else { throw PhoneKeyError.invalid("PhoneKey message is too large") }
        return output
    }

    static func decode(_ data: Data) throws -> Value {
        guard !data.isEmpty, data.count <= maximumSize else {
            throw PhoneKeyError.invalid("Invalid PhoneKey message size")
        }
        var reader = Reader(bytes: Array(data))
        let value = try reader.read(depth: 0)
        guard reader.position == data.count else { throw PhoneKeyError.invalid("Trailing PhoneKey data") }
        return value
    }

    private static func appendHead(_ major: UInt8, _ count: UInt64, to data: inout Data) {
        if count < 24 {
            data.append(major | UInt8(count))
        } else if count <= UInt64(UInt8.max) {
            data.append(major | 24)
            data.append(UInt8(count))
        } else if count <= UInt64(UInt16.max) {
            data.append(major | 25)
            data.append(contentsOf: UInt16(count).bigEndianBytes)
        } else if count <= UInt64(UInt32.max) {
            data.append(major | 26)
            data.append(contentsOf: UInt32(count).bigEndianBytes)
        } else {
            data.append(major | 27)
            data.append(contentsOf: count.bigEndianBytes)
        }
    }

    private static func append(_ value: Value, to data: inout Data) throws {
        switch value {
        case .unsigned(let number):
            appendHead(0x00, number, to: &data)
        case .bytes(let bytes):
            appendHead(0x40, UInt64(bytes.count), to: &data)
            data.append(bytes)
        case .map(let fields):
            appendHead(0xa0, UInt64(fields.count), to: &data)
            for key in fields.keys.sorted() {
                appendHead(0x00, key, to: &data)
                try append(fields[key]!, to: &data)
            }
        }
        guard data.count <= maximumSize else { throw PhoneKeyError.invalid("PhoneKey message is too large") }
    }

    private struct Reader {
        let bytes: [UInt8]
        var position = 0

        mutating func take(_ count: Int) throws -> [UInt8] {
            guard count >= 0, count <= bytes.count - position else { throw PhoneKeyError.truncated }
            defer { position += count }
            return Array(bytes[position..<(position + count)])
        }

        mutating func argument(_ additional: UInt8) throws -> UInt64 {
            let result: UInt64
            switch additional {
            case 0...23: result = UInt64(additional)
            case 24: result = UInt64(try take(1)[0])
            case 25: result = try take(2).reduce(0) { ($0 << 8) | UInt64($1) }
            case 26: result = try take(4).reduce(0) { ($0 << 8) | UInt64($1) }
            case 27: result = try take(8).reduce(0) { ($0 << 8) | UInt64($1) }
            default: throw PhoneKeyError.invalid("Unsupported CBOR length")
            }
            if (additional == 24 && result < 24) ||
                (additional == 25 && result <= UInt64(UInt8.max)) ||
                (additional == 26 && result <= UInt64(UInt16.max)) ||
                (additional == 27 && result <= UInt64(UInt32.max)) {
                throw PhoneKeyError.invalid("Non-canonical CBOR length")
            }
            return result
        }

        mutating func read(depth: Int) throws -> Value {
            guard depth < 4 else { throw PhoneKeyError.invalid("PhoneKey message is too deeply nested") }
            let initial = try take(1)[0]
            let major = initial >> 5
            let count = try argument(initial & 0x1f)
            switch major {
            case 0: return .unsigned(count)
            case 2:
                guard count <= UInt64(PhoneKeyCBOR.maximumSize) else {
                    throw PhoneKeyError.invalid("Byte field is too large")
                }
                return .bytes(Data(try take(Int(count))))
            case 5:
                guard count <= 32 else { throw PhoneKeyError.invalid("Too many PhoneKey fields") }
                var fields: [UInt64: Value] = [:]
                var previous: UInt64?
                for _ in 0..<count {
                    guard case .unsigned(let key) = try read(depth: depth + 1) else {
                        throw PhoneKeyError.invalid("PhoneKey field key is invalid")
                    }
                    guard previous.map({ key > $0 }) ?? true else {
                        throw PhoneKeyError.invalid("PhoneKey fields are not canonical")
                    }
                    previous = key
                    fields[key] = try read(depth: depth + 1)
                }
                return .map(fields)
            default: throw PhoneKeyError.invalid("Unsupported PhoneKey CBOR type")
            }
        }
    }
}

private extension FixedWidthInteger {
    var bigEndianBytes: [UInt8] {
        (0..<MemoryLayout<Self>.size).reversed().map { shift in UInt8(truncatingIfNeeded: self >> (shift * 8)) }
    }
}

struct PhoneKeyBootstrap: Equatable {
    let windowsDeviceID: Data
    let sessionID: Data
    let expiresAtMS: UInt64

    init(qr text: String, nowMS: UInt64 = PhoneKeyProtocol.nowMS()) throws {
        let parts = text.split(separator: "|", omittingEmptySubsequences: false)
        guard text.count == 86, parts.count == 4, parts[0] == "PK1",
              parts[1].count == 32, parts[2].count == 32, parts[3].count == 16,
              let windows = Data(lowercaseHex: String(parts[1])),
              let session = Data(lowercaseHex: String(parts[2])),
              let expiry = UInt64(parts[3], radix: 16),
              parts[3].utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }),
              windows.contains(where: { $0 != 0 }), session.contains(where: { $0 != 0 }),
              expiry > nowMS, expiry - nowMS <= 60_000 else {
            throw PhoneKeyError.invalid("Windows QR is invalid or expired")
        }
        windowsDeviceID = windows
        sessionID = session
        expiresAtMS = expiry
    }
}

extension Data {
    init?(lowercaseHex: String) {
        guard lowercaseHex.count.isMultiple(of: 2),
              lowercaseHex.utf8.allSatisfy({ ($0 >= 48 && $0 <= 57) || ($0 >= 97 && $0 <= 102) }) else { return nil }
        var bytes: [UInt8] = []
        let characters = Array(lowercaseHex.utf8)
        for index in stride(from: 0, to: characters.count, by: 2) {
            func nibble(_ byte: UInt8) -> UInt8 { byte <= 57 ? byte - 48 : byte - 87 }
            bytes.append((nibble(characters[index]) << 4) | nibble(characters[index + 1]))
        }
        self = Data(bytes)
    }
}

enum PhoneKeyProtocol {
    static func nowMS() -> UInt64 { UInt64(Date().timeIntervalSince1970 * 1_000) }
    static let loginDomain = Data("PHONEKEY-LOGIN-SIGNATURE-V1\0".utf8)
    static let enrollmentDomain = Data("PHONEKEY-ENROLLMENT-SIGNATURE-V1\0".utf8)
    static let pairingDomain = Data("PHONEKEY-PAIRING-CODE-V1\0".utf8)

    enum Challenge: Equatable {
        case login(Login)
        case enrollment(Enrollment)
    }

    struct Login: Equatable {
        let windowsDeviceID: Data
        let sessionID: Data
        let nonce: Data
        let issuedAtMS: UInt64
        let expiresAtMS: UInt64
        let operation: UInt64
        let accountBinding: Data
    }

    struct Enrollment: Equatable {
        let windowsDeviceID: Data
        let enrollmentID: Data
        let nonce: Data
        let issuedAtMS: UInt64
        let expiresAtMS: UInt64
    }

    static func decodeChallenge(_ bytes: Data, nowMS: UInt64 = PhoneKeyProtocol.nowMS()) throws -> Challenge {
        guard case .map(let map) = try PhoneKeyCBOR.decode(bytes),
              case .some(.unsigned(1)) = map[1],
              case .some(.unsigned(let kind)) = map[2] else {
            throw PhoneKeyError.invalid("Unsupported Windows request")
        }
        let device = try fieldBytes(map, 3, length: 16)
        let session = try fieldBytes(map, 4, length: 16)
        let nonce = try fieldBytes(map, 5, length: 32)
        let issued = try fieldUnsigned(map, 6)
        let expires = try fieldUnsigned(map, 7)
        guard device.contains(where: { $0 != 0 }), session.contains(where: { $0 != 0 }),
              expires > issued, issued <= nowMS + 5_000, nowMS < expires else {
            throw PhoneKeyError.invalid("Windows request is invalid or expired")
        }
        switch kind {
        case 1:
            guard map.count == 9, expires - issued <= 60_000 else {
                throw PhoneKeyError.invalid("Invalid login request lifetime")
            }
            let operation = try fieldUnsigned(map, 8)
            guard operation == 1 || operation == 2 else { throw PhoneKeyError.invalid("Unsupported Windows operation") }
            let account = try fieldBytes(map, 9)
            guard !account.isEmpty, account.count <= 256 else { throw PhoneKeyError.invalid("Invalid Windows account binding") }
            return .login(Login(windowsDeviceID: device, sessionID: session, nonce: nonce,
                                issuedAtMS: issued, expiresAtMS: expires, operation: operation,
                                accountBinding: account))
        case 10:
            guard map.count == 7, expires - issued <= 185_000 else {
                throw PhoneKeyError.invalid("Invalid enrollment request lifetime")
            }
            return .enrollment(Enrollment(windowsDeviceID: device, enrollmentID: session,
                                          nonce: nonce, issuedAtMS: issued, expiresAtMS: expires))
        default: throw PhoneKeyError.invalid("Unsupported PhoneKey request type")
        }
    }

    static func encodeLogin(_ value: Login) throws -> Data {
        try PhoneKeyCBOR.encode(.map([
            1: .unsigned(1), 2: .unsigned(1), 3: .bytes(value.windowsDeviceID),
            4: .bytes(value.sessionID), 5: .bytes(value.nonce),
            6: .unsigned(value.issuedAtMS), 7: .unsigned(value.expiresAtMS),
            8: .unsigned(value.operation), 9: .bytes(value.accountBinding)
        ]))
    }

    static func encodeEnrollment(_ value: Enrollment) throws -> Data {
        try PhoneKeyCBOR.encode(.map([
            1: .unsigned(1), 2: .unsigned(10), 3: .bytes(value.windowsDeviceID),
            4: .bytes(value.enrollmentID), 5: .bytes(value.nonce),
            6: .unsigned(value.issuedAtMS), 7: .unsigned(value.expiresAtMS)
        ]))
    }

    static func loginTranscript(_ challenge: Login) throws -> Data {
        loginDomain + (try encodeLogin(challenge))
    }

    static func enrollmentTranscript(_ challenge: Enrollment, deviceID: Data, publicKey: Data) throws -> Data {
        guard deviceID.count == 16, publicKey.count == 65, publicKey.first == 4 else {
            throw PhoneKeyError.invalid("Invalid iPhone signing identity")
        }
        return enrollmentDomain + (try encodeEnrollment(challenge)) + deviceID + publicKey
    }

    static func loginProof(deviceID: Data, sessionID: Data, signature: Data) throws -> Data {
        guard deviceID.count == 16, sessionID.count == 16, signature.count == 64 else {
            throw PhoneKeyError.invalid("Invalid iPhone login proof")
        }
        return try PhoneKeyCBOR.encode(.map([
            1: .unsigned(1), 2: .unsigned(2), 3: .bytes(deviceID),
            4: .bytes(sessionID), 5: .bytes(signature)
        ]))
    }

    static func enrollmentProof(deviceID: Data, enrollmentID: Data, publicKey: Data, signature: Data) throws -> Data {
        guard deviceID.count == 16, enrollmentID.count == 16, publicKey.count == 65,
              publicKey.first == 4, signature.count == 64 else {
            throw PhoneKeyError.invalid("Invalid iPhone enrollment proof")
        }
        return try PhoneKeyCBOR.encode(.map([
            1: .unsigned(1), 2: .unsigned(11), 3: .bytes(deviceID),
            4: .bytes(enrollmentID), 5: .bytes(publicKey), 6: .bytes(signature)
        ]))
    }

    static func pairingCode(challenge: Enrollment, proof: Data) throws -> String {
        let digest = SHA256.hash(data: pairingDomain + (try encodeEnrollment(challenge)) + proof)
        let bytes = Array(digest)
        let first = (UInt32(bytes[0]) << 24) | (UInt32(bytes[1]) << 16) |
                    (UInt32(bytes[2]) << 8) | UInt32(bytes[3])
        return String(format: "%06d", first % 1_000_000)
    }

    private static func fieldBytes(_ map: [UInt64: PhoneKeyCBOR.Value], _ key: UInt64, length: Int? = nil) throws -> Data {
        guard case .some(.bytes(let value)) = map[key], length.map({ value.count == $0 }) ?? true else {
            throw PhoneKeyError.invalid("Invalid PhoneKey field \(key)")
        }
        return value
    }

    private static func fieldUnsigned(_ map: [UInt64: PhoneKeyCBOR.Value], _ key: UInt64) throws -> UInt64 {
        guard case .some(.unsigned(let value)) = map[key] else {
            throw PhoneKeyError.invalid("Invalid PhoneKey field \(key)")
        }
        return value
    }
}

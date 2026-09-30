import CryptoKit
import Foundation
import LocalAuthentication
import Security

struct PhoneKeyIdentity {
    let deviceID: Data
    let publicKey: Data
}

final class PhoneKeyIdentityStore {
    private let service = "com.phonekey.ios.identity"
    private let account = "secure-enclave-p256-v1"

    private struct Record: Codable {
        let deviceID: Data
        let keyRepresentation: Data
    }

    func exists() -> Bool { (try? loadRecord()) != nil }

    func createIfNeeded(context: LAContext) throws -> PhoneKeyIdentity {
        if let record = try loadRecord() { return try identity(from: record, context: context) }
        guard SecureEnclave.isAvailable else {
            throw PhoneKeyError.invalid("This iPhone does not have an available Secure Enclave")
        }
        var error: Unmanaged<CFError>?
        guard let control = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            [.privateKeyUsage, .userPresence], &error
        ) else { throw PhoneKeyError.invalid("Cannot protect the signing key") }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            compactRepresentable: false, accessControl: control, authenticationContext: context
        )
        var deviceBytes = [UInt8](repeating: 0, count: 16)
        guard SecRandomCopyBytes(kSecRandomDefault, deviceBytes.count, &deviceBytes) == errSecSuccess else {
            throw PhoneKeyError.invalid("Cannot create iPhone device identity")
        }
        let record = Record(deviceID: Data(deviceBytes), keyRepresentation: key.dataRepresentation)
        let saved = SecItemAdd([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecValueData as String: try JSONEncoder().encode(record)
        ] as CFDictionary, nil)
        guard saved == errSecSuccess else {
            throw PhoneKeyError.invalid("Cannot save iPhone signing identity (\(saved))")
        }
        return PhoneKeyIdentity(deviceID: record.deviceID, publicKey: key.publicKey.x963Representation)
    }

    func identity(context: LAContext) throws -> PhoneKeyIdentity {
        guard let record = try loadRecord() else {
            throw PhoneKeyError.invalid("Enroll this iPhone with Windows first")
        }
        return try identity(from: record, context: context)
    }

    func sign(_ transcript: Data, context: LAContext) throws -> Data {
        guard let record = try loadRecord() else {
            throw PhoneKeyError.invalid("Enroll this iPhone with Windows first")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: record.keyRepresentation, authenticationContext: context
        )
        let raw = try key.signature(for: transcript).rawRepresentation
        return try Self.canonicalLowS(raw)
    }

    private func identity(from record: Record, context: LAContext) throws -> PhoneKeyIdentity {
        guard record.deviceID.count == 16, record.deviceID.contains(where: { $0 != 0 }) else {
            throw PhoneKeyError.invalid("Invalid saved iPhone identity")
        }
        let key = try SecureEnclave.P256.Signing.PrivateKey(
            dataRepresentation: record.keyRepresentation, authenticationContext: context
        )
        let publicKey = key.publicKey.x963Representation
        guard publicKey.count == 65, publicKey.first == 4 else {
            throw PhoneKeyError.invalid("Invalid iPhone public key")
        }
        return PhoneKeyIdentity(deviceID: record.deviceID, publicKey: publicKey)
    }

    private func loadRecord() throws -> Record? {
        var item: CFTypeRef?
        let status = SecItemCopyMatching([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: account,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ] as CFDictionary, &item)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = item as? Data else {
            throw PhoneKeyError.invalid("Cannot read iPhone signing identity (\(status))")
        }
        return try JSONDecoder().decode(Record.self, from: data)
    }

    // Windows accepts only canonical low-S ECDSA signatures. CryptoKit's raw
    // representation is r||s, but its S value is not promised to be low.
    static func canonicalLowS(_ signature: Data) throws -> Data {
        guard signature.count == 64 else { throw PhoneKeyError.invalid("Invalid P-256 signature") }
        let order = Array(Data(lowercaseHex:
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")!)
        let half = Array(Data(lowercaseHex:
            "7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8")!)
        var output = Array(signature)
        let s = Array(output[32..<64])
        if s.lexicographicallyPrecedes(half) || s == half { return signature }
        var borrow = 0
        for index in (0..<32).reversed() {
            var value = Int(order[index]) - Int(s[index]) - borrow
            borrow = value < 0 ? 1 : 0
            if value < 0 { value += 256 }
            output[32 + index] = UInt8(value)
        }
        guard borrow == 0 else { throw PhoneKeyError.invalid("Invalid P-256 signature S value") }
        return Data(output)
    }
}

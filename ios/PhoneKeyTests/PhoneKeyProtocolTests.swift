import XCTest
@testable import PhoneKey

final class PhoneKeyProtocolTests: XCTestCase {
    private let challengeHex = "a901010201035011111111111111111111111111111111" +
        "045022222222222222222222222222222222" +
        "0558203333333333333333333333333333333333333333333333333333333333333333" +
        "061a000f4240071a00102ca008010958204444444444444444444444444444444444444444444444444444444444444444"

    func testWindowsGoldenLoginChallenge() throws {
        let bytes = try XCTUnwrap(Data(lowercaseHex: challengeHex))
        guard case .login(let challenge) = try PhoneKeyProtocol.decodeChallenge(bytes, nowMS: 1_000_001) else {
            return XCTFail("Expected login challenge")
        }
        XCTAssertEqual(challenge.windowsDeviceID, Data(repeating: 0x11, count: 16))
        XCTAssertEqual(challenge.sessionID, Data(repeating: 0x22, count: 16))
        XCTAssertEqual(challenge.operation, 1)
        XCTAssertEqual(try PhoneKeyProtocol.encodeLogin(challenge), bytes)
        let transcript = try PhoneKeyProtocol.loginTranscript(challenge)
        XCTAssertTrue(transcript.starts(with: PhoneKeyProtocol.loginDomain))
        XCTAssertEqual(Data(transcript.dropFirst(PhoneKeyProtocol.loginDomain.count)), bytes)
    }

    func testWindowsGoldenLoginProofEncoding() throws {
        let signature = try XCTUnwrap(Data(lowercaseHex:
            "333c32a289686862084887c907d9c195037b9655eef895ce4fabab2251932ff5" +
            "2dca47574e8506e9971075c23d45b560203f9f7e2cfd5792d8e0cf84a5d5db5a"))
        let proof = try PhoneKeyProtocol.loginProof(
            deviceID: Data(repeating: 0xaa, count: 16),
            sessionID: Data(repeating: 0x22, count: 16), signature: signature
        )
        let expected = try XCTUnwrap(Data(lowercaseHex:
            "a5010102020350aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" +
            "045022222222222222222222222222222222055840" +
            "333c32a289686862084887c907d9c195037b9655eef895ce4fabab2251932ff5" +
            "2dca47574e8506e9971075c23d45b560203f9f7e2cfd5792d8e0cf84a5d5db5a"))
        XCTAssertEqual(proof, expected)
    }

    func testRejectsExpiredAndNonCanonicalQR() throws {
        let text = "PK1|" + String(repeating: "1", count: 32) + "|" +
            String(repeating: "2", count: 32) + "|000000000000ea60"
        XCTAssertNoThrow(try PhoneKeyBootstrap(qr: text, nowMS: 1))
        XCTAssertThrowsError(try PhoneKeyBootstrap(qr: text, nowMS: 60_000))
        XCTAssertThrowsError(try PhoneKeyBootstrap(qr: text.uppercased(), nowMS: 1))
    }

    func testRejectsTruncatedAndNonCanonicalCBOR() throws {
        let bytes = try XCTUnwrap(Data(lowercaseHex: challengeHex))
        XCTAssertThrowsError(try PhoneKeyCBOR.decode(Data(bytes.dropLast())))
        XCTAssertThrowsError(try PhoneKeyCBOR.decode(Data([0x18, 0x01])))
    }

    func testHighSIsNormalizedForWindows() throws {
        var almostOrder = Array(try XCTUnwrap(Data(lowercaseHex:
            "ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551")))
        almostOrder[31] -= 1
        let high = Data([UInt8](repeating: 1, count: 32) + almostOrder)
        let normalized = try PhoneKeyIdentityStore.canonicalLowS(high)
        XCTAssertEqual(Array(normalized.suffix(32)), [UInt8](repeating: 0, count: 31) + [1])
    }
}

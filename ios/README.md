# PhoneKey for iPhone — source preview

This is the iPhone companion for the existing Windows PhoneKey V1 login and enrollment protocol. It is a **source project**, not a built or signed iPhone app. No Mac, Xcode, or iPhone is currently available for compilation and live validation.

The app advertises the same BLE GATT service and challenge/proof characteristics as the Android app. It reads the `PK1|...` Windows QR, requires the Bluetooth challenge to match that QR exactly, asks iOS for Face ID or device-passcode approval, then signs the canonical Windows transcript with a Secure Enclave P-256 key. Enrollment displays the six-digit pairing code for comparison with Windows. A separate Keychain record holds the iPhone device ID and the Secure Enclave key's wrapped representation; private key material is not exported.

To build when a Mac and iPhone are available:

1. Install a current Xcode and [XcodeGen](https://github.com/yonaskolb/XcodeGen), then run `xcodegen generate` from this `ios` directory.
2. Open `PhoneKey.xcodeproj` in Xcode, set a unique bundle identifier and your Apple development team, and run the `PhoneKey` target on a physical iPhone. Bluetooth peripheral mode and Secure Enclave approval require device testing.
3. Run the `PhoneKeyTests` target. Then test enrollment on a **separate clean Windows setup** before testing QR, Face ID, and Windows unlock.

The current installed Windows pilot trusts one phone and is already paired to the TECNO. Do not enroll an iPhone on this laptop, replace its trusted-phone record, or deploy a new Windows service while preserving the current sign-in. Multi-phone support needs separate design and verification before both phones can share one Windows installation.

The iPhone app intentionally works while open in the foreground. Apple places service UUIDs in an overflow area during background advertising, which the current Windows scanner may not discover. Background unlock is therefore not claimed. The Windows pilot's encrypted-password route for Microsoft accounts is also not a public passwordless release.

Sources of platform behavior: [Core Bluetooth peripheral manager](https://developer.apple.com/documentation/corebluetooth/cbperipheralmanager), [advertising behavior](https://developer.apple.com/documentation/corebluetooth/cbperipheralmanager/startadvertising%28_%3A%29), [Secure Enclave P-256 signing](https://developer.apple.com/documentation/cryptokit/secureenclave/p256/signing/privatekey), [Local Authentication](https://developer.apple.com/documentation/localauthentication/lacontext).

# Android Platform Notes

These notes were checked against official Android documentation on 27 August 2026.

## BiometricPrompt and Keystore

The app should use `BiometricManager.Authenticators.BIOMETRIC_STRONG or DEVICE_CREDENTIAL` where supported. `DEVICE_CREDENTIAL` represents the screen-lock PIN, pattern, or password. Availability must be checked with `BiometricManager.canAuthenticate()` using the same authenticator combination. Android 10 and lower have limitations for combining `DEVICE_CREDENTIAL` with strong biometrics.

For cryptographic authorization, use an authentication-gated Keystore key with a `BiometricPrompt.CryptoObject`. The PhoneKey policy requires fresh, per-use authentication and no silent reuse of a previous authentication window.

## Bluetooth permissions

For Android 12 and later, a BLE client that scans and connects must request `BLUETOOTH_SCAN` and `BLUETOOTH_CONNECT` as runtime permissions. Legacy `BLUETOOTH` and `BLUETOOTH_ADMIN` declarations should be limited to SDK 30 and lower. `BLUETOOTH_ADVERTISE` is only required when the phone makes itself discoverable; PhoneKey's Android client does not need that permission for the baseline flow. Location permission should not be requested unless scan results are used to derive physical location.

## Official references

- [Show a biometric authentication dialog](https://developer.android.com/identity/sign-in/biometric-auth)
- [BiometricPrompt API reference](https://developer.android.com/reference/androidx/biometric/BiometricPrompt)
- [Android Keystore system](https://developer.android.com/privacy-and-security/keystore)
- [Bluetooth permissions](https://developer.android.com/develop/connectivity/bluetooth/bt-permissions)

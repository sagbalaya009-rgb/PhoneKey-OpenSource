# BLE sign-in lifecycle hardening

PhoneKey's Windows service begins scanning when it creates a sign-in QR. The
Android app may already be advertising while the user opens the QR scanner.
Stopping and restarting that advertiser on every scan creates a race with the
Windows connection before the phone receives its challenge.

The Android GATT server now keeps an active advertiser running during QR
scanning. If no client connects within eight seconds, one guarded refresh
renews it. Each asynchronous advertising request has its own callback, which
lets cancellation stop an in-flight start and prevents late callbacks from
marking an obsolete advertiser as active. Windows ignores unreadable unrelated
advertisements and reports an aborted advertisement watcher rather than waiting
silently until the challenge expires.

This is transport hardening only. It does not change the QR nonce, challenge,
phone proof, biometric requirement, or service-side signature verification.

Validation completed: Android unit tests and debug build; Windows service's
189 unit tests; and 20 start/stop plus 20 repeated-start cycles on an isolated
Android test package. The updated packages have **not** completed a real
Windows sign-in on the paired production installation. Do not interpret these
tests as proof that every intermittent BLE failure is resolved. A release
should include repeated sign-ins across lock/unlock, reboot, and sleep/resume
on representative devices, with stage traces captured for any failure.

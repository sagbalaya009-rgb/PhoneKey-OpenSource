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

An additional defect affected GATT prepared writes: the execute handler accepted
only file-opening requests, rejecting login and enrollment challenges assembled
from fragments. It now fully decodes each of the three supported challenge
types before dispatching to the existing QR/session/biometric handler. Proofs,
truncated messages and unsupported types are rejected. Regression tests cover
login and enrollment with 18-, 180- and 242-byte fragments, malformed requests,
and attempts to execute the same buffer twice. Whether this path caused a
particular historical incident still requires an aligned device trace.

File challenges are also covered at these fragment sizes. Unsupported CBOR
length encodings produce a normal invalid-request exception so the GATT execute
callback returns failure rather than escaping without a response. Each GATT
server now owns callbacks guarded by its generation: callbacks queued for a
closed server cannot advertise, close or answer requests using its replacement.

Error disconnects now clear the connected flag and pending writes, allowing a
later scan to refresh an idle advertiser. Stopping the server also clears queued
writes. Android traces record negotiated MTU and prepared-write stages without
device addresses or message contents.

The Windows transport previously capped an exchange at 45 seconds while the
login QR allowed 60 seconds. Its cap now uses the protocol's 60-second constant;
the original absolute expiry remains authoritative. Windows Application events
from `PhoneKey BLE` identify discovery, device/service/characteristic acquisition,
challenge acknowledgement and proof receipt using event IDs only. The read-only
diagnostic script maps those IDs without printing event messages or payloads.

Validation completed before these additional changes: Android unit tests and debug build; Windows service's
189 unit tests; and 20 start/stop plus 20 repeated-start cycles on an isolated
Android test package. The updated packages have **not** completed a real
Windows sign-in on the paired production installation. Do not interpret these
tests as proof that every intermittent BLE failure is resolved. A release
should include repeated sign-ins across lock/unlock, reboot, and sleep/resume
on representative devices, with stage traces captured for any failure.

For the additional fixes, all 30 local Android unit tests and the isolated debug
APK build passed. All four CI checks on `fc31d60` passed, including Windows
workspace tests and a release service build. That exact service artifact was
downloaded with its GitHub SHA-256 digest verified, compared against the local
source (line endings excluded), and deployed with a verified rollback copy. The
service is running; the credential provider and existing password were preserved.
The updated Android app is installed under a separate test package because the
original package's signing key is unavailable. Real sign-in tests of the updated
pair are still pending; no never-stall or cross-device reliability claim is made.

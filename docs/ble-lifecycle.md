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

Repeated live testing exposed a separate credential-provider defect. The first
three sign-ins succeeded; on the fourth, Windows logged proof acceptance, then
selected the tile again and created a new QR before credential redemption. The
provider treated an approved transaction as an idle session and overwrote it.
Reselection now returns the existing verified transaction for automatic
submission, while GetSerialization still performs authoritative one-time
redemption. Explicit deselection clears approval. New event IDs distinguish
deselection and retention of an approved transaction.

The regression fixture links the actual credential implementation: 100
reselections must preserve its approved handle; deselection, invalid handles and
unverified selection must not allow automatic submission. The original source
fails this fixture; the corrected source passes, and the native DLL builds.
This is evidence of a real lost-approval defect. The corrected pair still needs
a fresh consecutive live run; the failed four-attempt run is not counted as a
successful reliability test.


The native fix was installed and two fresh sign-ins exercised retained approval
and automatic Windows acceptance. The next attempt failed during uncached GATT
service discovery, before a challenge or biometric request reached the phone.
The repeated test stopped. An additional connection race was removed: starting
an already active advertiser no longer schedules a timed stop/restart. The
previous eight-second refresh could run after Windows selected an advertisement
but before Android reported the client connected, interrupting connection
establishment. Android tests and the separate-package APK build passed after
removing this timer. Further real repeated testing remains required.
Latest device run after timer removal: two real Windows sign-ins succeeded. The
third completed discovery, characteristic acquisition and challenge delivery,
but no proof arrived before timeout. Whether that QR was scanned and approved
has not yet been confirmed; this is not classified as a solved biometric issue
or counted as a successful repeated test. All four CI checks on 8e9a7c7 passed.
Testing stops on failure/timeout and leaves the Windows PIN available. The test
app's temporary pairing remains active during investigation; the original app
and protected trust/account backups are retained for restoration.

Follow-up testing of the original paired Android app with the updated Windows
service/provider completed six consecutive actual sign-ins: one captured run
and five additional user-approved repeated runs, all with verified proof and
Windows credential acceptance. Five phone timing snapshots recorded biometric
launch and success. Scan acceptance to biometric launch ranged from 152 to
2035 ms (mean 634 ms); camera aiming and human approval are outside that metric.
The service is Running/Automatic and Smart App Control remains On. The original
pairing is active. The separately signed Android fixes have not replaced the
original APK, whose signing key is unavailable. These successes establish the
observed run, not a never-stall guarantee or sleep/reboot/cross-device coverage.

package com.PhoneKey.app

import android.Manifest
import android.os.Build
import android.os.Bundle
import android.os.SystemClock
import android.util.Log
import androidx.activity.compose.setContent
import androidx.activity.enableEdgeToEdge
import androidx.biometric.BiometricManager.Authenticators.BIOMETRIC_STRONG
import androidx.biometric.BiometricManager.Authenticators.DEVICE_CREDENTIAL
import androidx.biometric.BiometricPrompt
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.PhoneKey.app.ui.theme.PhoneKeyTheme
import com.google.mlkit.vision.barcode.common.Barcode
import com.google.mlkit.vision.codescanner.GmsBarcodeScanner
import com.google.mlkit.vision.codescanner.GmsBarcodeScannerOptions
import com.google.mlkit.vision.codescanner.GmsBarcodeScanning

class MainActivity :
    FragmentActivity() {

    companion object {
        private const val BLUETOOTH_PERMISSION_REQUEST_CODE =
            1001
    }

    private lateinit var bleCapabilityManager:
        BleCapabilityManager

    private lateinit var phoneKeyGattServer:
        PhoneKeyGattServer

    private lateinit var identityManager:
        DeviceIdentityManager

    private lateinit var biometricPrompt:
        BiometricPrompt

    private lateinit var qrScanner:
        GmsBarcodeScanner

    private var pendingQrBootstrap:
        PhoneKeyQrBootstrap.Bootstrap? =
        null

    private var pendingFileQrBootstrap:
        PhoneKeyFileQrBootstrap.Bootstrap? = null

    private var pendingFileOpenChallenge:
        PhoneKeyProtocol.FileOpenChallenge? = null
    private val fileRendezvous = PhoneKeyFileRendezvous()
    private var pendingLoginChallenge:
        PhoneKeyProtocol.LoginChallenge? =
        null

    private val loginRendezvous = PhoneKeyLoginRendezvous()
    private var loginQrAcceptedAtMs: Long? = null
    private var loginPromptAtMs: Long? = null

    private enum class PromptKind { LOGIN, ENROLLMENT, FILE_OPEN }
    private var pendingPromptKind: PromptKind? = null
    private var biometricPromptInFlight = false

    private var pendingEnrollmentChallenge:
        PhoneKeyProtocol.EnrollmentChallenge? =
        null

    private var capabilityResult by
        mutableStateOf<
            BleCapabilityManager
                .BleCapabilityResult?
        >(null)

    private var bleServerStatus by
        mutableStateOf(
            "PhoneKey BLE server not started"
        )

    private var pairingCode by
        mutableStateOf<String?>(
            null
        )

    override fun onCreate(
        savedInstanceState: Bundle?
    ) {
        super.onCreate(
            savedInstanceState
        )

        bleCapabilityManager =
            BleCapabilityManager(
                this
            )

        identityManager =
            DeviceIdentityManager(
                this
            )

        val identity =
            identityManager
                .createIdentity()


        configureBiometricPrompt()

        val scannerOptions =
            GmsBarcodeScannerOptions
                .Builder()
                .setBarcodeFormats(
                    Barcode.FORMAT_QR_CODE
                )
                .enableAutoZoom()
                .build()

        qrScanner =
            GmsBarcodeScanning
                .getClient(
                    this,
                    scannerOptions
                )

        phoneKeyGattServer =
            PhoneKeyGattServer(
                context = this,

                onStatusChanged = {
                    status ->

                    runOnUiThread {
                        bleServerStatus =
                            status
                    }
                },

                onChallengeReceived = {
                    bytes ->

                    runOnUiThread {
                        handleProtocolMessage(
                            bytes
                        )
                    }
                }
            )

        refreshCapabilities()

        enableEdgeToEdge()

        setContent {
            PhoneKeyTheme {
                PhoneKeyScreen(
                    result =
                        capabilityResult,

                    serverStatus =
                        bleServerStatus,

                    pairingCode =
                        pairingCode,

                    onScanQr = {
                        scanWindowsQr()
                    },

                    onGrantPermissions = {
                        requestBluetoothPermissions()
                    },

                    onRefresh = {
                        refreshCapabilities()
                    },

                    onStartServer = {
                        pairingCode =
                            null

                        phoneKeyGattServer
                            .start()
                    },

                    onStopServer = {
                        pairingCode =
                            null

                        phoneKeyGattServer
                            .stop()
                    }
                )
            }
        }
    }

    private fun scanWindowsQr() {
        // Start BLE while the camera is open. If Windows delivers the
        // challenge first, keep it until the matching QR has been scanned.
        pendingQrBootstrap = null
        pendingFileQrBootstrap = null
        pendingLoginChallenge = null
        pendingFileOpenChallenge = null
        pendingEnrollmentChallenge = null
        loginQrAcceptedAtMs = null
        loginPromptAtMs = null
        pendingPromptKind = null
        phoneKeyGattServer.clearProofPayload()
        phoneKeyGattServer.start()
        qrScanner
            .startScan()
            .addOnSuccessListener {
                barcode ->

                val raw =
                    barcode.rawValue

                if (raw == null) {
                    pendingQrBootstrap =
                        null
                    pendingFileQrBootstrap = null

                    bleServerStatus =
                        "QR contained no PhoneKey data"

                    return@addOnSuccessListener
                }

                try {
                    val fileBootstrap = if (raw.startsWith("PKF3|"))
                        PhoneKeyFileQrBootstrap.parse(raw) else null
                    val bootstrap = if (fileBootstrap == null)
                        PhoneKeyQrBootstrap.parse(raw) else null

                    val earlyLogin = if (bootstrap != null)
                        loginRendezvous.takeMatching(bootstrap, System.currentTimeMillis())
                    else null
                    val earlyFile = if (fileBootstrap != null)
                        fileRendezvous.takeMatching(fileBootstrap, System.currentTimeMillis())
                    else null

                    clearPending()

                    pairingCode =
                        null

                    phoneKeyGattServer
                        .clearProofPayload()

                    pendingQrBootstrap =
                        bootstrap
                    pendingFileQrBootstrap = fileBootstrap
                    if (bootstrap != null) {
                        loginQrAcceptedAtMs = SystemClock.elapsedRealtime()
                    }

                    bleServerStatus =
                        "Windows QR accepted - starting PhoneKey BLE"

                    if (earlyLogin != null) {
                        handleDecodedLoginChallenge(earlyLogin)
                    } else if (bootstrap != null) {
                        // The QR scanner temporarily takes foreground focus and some
                        // Android vendors can leave the pre-scan advertiser stale.
                        // Refresh discovery only when no BLE challenge arrived early.
                        // Authentication still cannot proceed until Windows delivers
                        // a fresh challenge that matches this exact QR transaction.
                        phoneKeyGattServer.start()
                    }
                    if (earlyFile != null) {
                        handleDecodedFileOpenChallenge(earlyFile)
                    }
                } catch (
                    error: Exception
                ) {
                    loginRendezvous.clear()
                    pendingQrBootstrap =
                        null
                    pendingFileQrBootstrap = null
                    fileRendezvous.clear()

                    phoneKeyGattServer
                        .clearProofPayload()

                    bleServerStatus =
                        "Rejected Windows QR: ${error.message}"
                }
            }
            .addOnCanceledListener {
                loginRendezvous.clear()
                pendingQrBootstrap = null
                pendingFileQrBootstrap = null
                fileRendezvous.clear()
                phoneKeyGattServer.clearProofPayload()
                bleServerStatus =
                    "QR scan cancelled"
            }
            .addOnFailureListener {
                error ->

                pendingQrBootstrap =
                    null
                pendingFileQrBootstrap = null
                fileRendezvous.clear()
                loginRendezvous.clear()

                bleServerStatus =
                    "QR scanner failed: ${error.message}"
            }
    }

    private fun configureBiometricPrompt() {
        biometricPrompt =
            BiometricPrompt(
                this,

                ContextCompat
                    .getMainExecutor(
                        this
                    ),

                object :
                    BiometricPrompt
                        .AuthenticationCallback() {

                    override fun onAuthenticationSucceeded(
                        result:
                            BiometricPrompt
                                .AuthenticationResult
                    ) {
                        super
                            .onAuthenticationSucceeded(
                                result
                            )

                        biometricPromptInFlight = false
                        pendingPromptKind = null
                        Log.i("PhoneKeyTiming", "biometric_succeeded")

                        when {
                            pendingEnrollmentChallenge !=
                                null ->
                                createEnrollmentProof()

                            pendingLoginChallenge !=
                                null ->
                                createLoginProof()

                            pendingFileOpenChallenge != null ->
                                createFileOpenProof()

                            else ->
                                bleServerStatus =
                                    "Authentication succeeded but no request is pending"
                        }
                    }

                    override fun onAuthenticationError(
                        errorCode: Int,
                        errString: CharSequence
                    ) {
                        super
                            .onAuthenticationError(
                                errorCode,
                                errString
                            )

                        biometricPromptInFlight = false
                        Log.w("PhoneKeyTiming", "biometric_error_code=$errorCode")

                        if (errorCode == BiometricPrompt.ERROR_CANCELED &&
                            pendingPromptKind != null &&
                            (!lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED) ||
                                !hasWindowFocus())) {
                            // Android cancels a prompt when another app takes
                            // the foreground. Keep the QR-bound challenge only
                            // until its original expiry, then show it on return.
                            bleServerStatus = "PhoneKey interrupted - return to the app to approve"
                            Log.i("PhoneKeyTiming", "biometric_interrupted_retry_on_foreground")
                            return
                        }

                        pendingPromptKind = null

                        clearPending()

                        bleServerStatus =
                            "Authentication cancelled: $errString"
                    }

                    override fun onAuthenticationFailed() {
                        super
                            .onAuthenticationFailed()

                        bleServerStatus =
                            "Authentication failed - try again"
                    }
                }
            )
    }

    private fun handleProtocolMessage(
        bytes: ByteArray
    ) {
        try {
            pairingCode =
                null

            phoneKeyGattServer
                .clearProofPayload()

            when (
                PhoneKeyProtocol
                    .readMessageType(
                        bytes
                    )
            ) {
                PhoneKeyProtocol
                    .MESSAGE_TYPE_LOGIN_CHALLENGE ->
                    handleLoginChallenge(
                        bytes
                    )

                PhoneKeyProtocol
                    .MESSAGE_TYPE_ENROLLMENT_CHALLENGE ->
                    handleEnrollmentChallenge(
                        bytes
                    )

                PhoneKeyProtocol.MESSAGE_TYPE_FILE_OPEN_CHALLENGE ->
                    handleFileOpenChallenge(bytes)

                else ->
                    error(
                        "Unsupported PhoneKey request"
                    )
            }
        } catch (
            error: Exception
        ) {
            clearPending()

            phoneKeyGattServer
                .clearProofPayload()

            bleServerStatus =
                "Rejected PhoneKey request: ${error.message}"
        }
    }

    private fun handleLoginChallenge(
        bytes: ByteArray
    ) {
        val challenge =
            PhoneKeyProtocol
                .decodeLoginChallenge(
                    bytes
                )

        handleDecodedLoginChallenge(challenge)
    }

    private fun handleDecodedLoginChallenge(
        challenge: PhoneKeyProtocol.LoginChallenge
    ) {

        requireFresh(
            challenge.issuedAtMs,
            challenge.expiresAtMs
        )

        val bootstrap = pendingQrBootstrap
        if (bootstrap == null) {
            loginRendezvous.defer(challenge, System.currentTimeMillis())
            Log.i("PhoneKeyTiming", "challenge_arrived_before_qr")
            bleServerStatus = "Windows request received - scan its live QR"
            return
        }

        require(
            PhoneKeyQrBootstrap
                .matchesChallenge(
                    bootstrap,
                    challenge
                )
        ) {
            "BLE challenge does not match the scanned Windows transaction"
        }

        pendingEnrollmentChallenge =
            null

        pendingLoginChallenge =
            challenge

        bleServerStatus =
            "Windows login request - authenticate"
        requestBiometricPrompt(PromptKind.LOGIN)
    }

    private fun handleEnrollmentChallenge(
        bytes: ByteArray
    ) {
        val challenge =
            PhoneKeyProtocol
                .decodeEnrollmentChallenge(
                    bytes
                )

        requireFresh(
            challenge.issuedAtMs,
            challenge.expiresAtMs
        )

        pendingLoginChallenge =
            null

        pendingEnrollmentChallenge =
            challenge

        bleServerStatus =
            "Windows wants to enroll this phone"
        requestBiometricPrompt(PromptKind.ENROLLMENT)
    }

    private fun createLoginProof() {
        val challenge =
            pendingLoginChallenge
                ?: return

        try {
            requireFresh(
                challenge.issuedAtMs,
                challenge.expiresAtMs
            )

            val identity =
                identityManager
                    .getIdentity()

            val transcript =
                PhoneKeyProtocol
                    .buildLoginSigningTranscript(
                        challenge
                    )

            val signature =
                identityManager
                    .sign(
                        transcript
                    )

            val proof =
                PhoneKeyProtocol
                    .LoginProof(
                        androidDeviceId =
                            identity.deviceId,

                        sessionId =
                            challenge.sessionId,

                        signature =
                            signature
                    )

            val proofBytes =
                PhoneKeyProtocol
                    .encodeLoginProof(
                        proof
                    )

            phoneKeyGattServer
                .setProofPayload(
                    proofBytes
                )

            loginPromptAtMs?.let { promptAt ->
                Log.i("PhoneKeyTiming", "prompt_to_proof_ms=${SystemClock.elapsedRealtime() - promptAt}")
            }

            pendingLoginChallenge =
                null

            /*
             * One scanned QR authorizes one signing attempt.
             * Service-side session single-use remains authoritative.
             */
            pendingQrBootstrap =
                null

            bleServerStatus =
                "Login approved - signed proof ready"

        } catch (
            error: Exception
        ) {
            clearPending()

            phoneKeyGattServer
                .clearProofPayload()

            bleServerStatus =
                "Login signing failed: ${error.message}"
        }
    }

    private fun createEnrollmentProof() {
        val challenge =
            pendingEnrollmentChallenge
                ?: return

        try {
            requireFresh(
                challenge.issuedAtMs,
                challenge.expiresAtMs
            )

            val identity =
                identityManager
                    .getIdentity()

            require(
                identity.publicKeySec1.size ==
                    PhoneKeyProtocol
                        .P256_PUBLIC_KEY_LENGTH
            )

            val transcript =
                PhoneKeyProtocol
                    .buildEnrollmentSigningTranscript(
                        challenge =
                            challenge,

                        androidDeviceId =
                            identity.deviceId,

                        publicKeySec1 =
                            identity.publicKeySec1
                    )

            val signature =
                identityManager
                    .sign(
                        transcript
                    )

            val proof =
                PhoneKeyProtocol
                    .EnrollmentProof(
                        androidDeviceId =
                            identity.deviceId,

                        enrollmentId =
                            challenge.enrollmentId,

                        publicKeySec1 =
                            identity.publicKeySec1,

                        signature =
                            signature
                    )

            val proofBytes =
                PhoneKeyProtocol
                    .encodeEnrollmentProof(
                        proof
                    )

            val code =
                PhoneKeyProtocol
                    .derivePairingCode(
                        challenge,
                        proof
                    )

            pairingCode =
                PhoneKeyProtocol
                    .formatPairingCode(
                        code
                    )

            phoneKeyGattServer
                .setProofPayload(
                    proofBytes
                )

            pendingEnrollmentChallenge =
                null

            bleServerStatus =
                "Enrollment proof ready - compare pairing codes"

        } catch (
            error: Exception
        ) {
            clearPending()

            phoneKeyGattServer
                .clearProofPayload()

            pairingCode =
                null

            bleServerStatus =
                "Enrollment failed: ${error.message}"
        }
    }

    private fun requireFresh(
        issuedAtMs: Long,
        expiresAtMs: Long
    ) {
        PhoneKeyFreshness.requireFresh(
            issuedAtMs,
            expiresAtMs,
            System.currentTimeMillis()
        )
    }

    private fun handleFileOpenChallenge(bytes: ByteArray) {
        val challenge = PhoneKeyProtocol.decodeFileOpenChallenge(bytes)
        requireFresh(challenge.issuedAtMs, challenge.expiresAtMs)
        if (pendingFileQrBootstrap == null) {
            fileRendezvous.defer(challenge, System.currentTimeMillis())
            bleServerStatus = "Encrypted-file request received - scan its live QR"
            return
        }
        handleDecodedFileOpenChallenge(challenge)
    }

    private fun handleDecodedFileOpenChallenge(challenge: PhoneKeyProtocol.FileOpenChallenge) {
        requireFresh(challenge.issuedAtMs, challenge.expiresAtMs)
        val bootstrap = pendingFileQrBootstrap
            ?: error("Scan the live encrypted-file QR before approving")
        require(PhoneKeyFileQrBootstrap.matchesChallenge(bootstrap, challenge)) {
            "BLE file request does not match the scanned QR"
        }
        val identity = identityManager.getIdentity()
        require(identity.deviceId.contentEquals(challenge.phoneDeviceId)) {
            "File request is for a different phone"
        }
        pendingLoginChallenge = null
        pendingEnrollmentChallenge = null
        pendingFileOpenChallenge = challenge
        bleServerStatus = "Encrypted file opening request - authenticate"
        requestBiometricPrompt(PromptKind.FILE_OPEN)
    }

    private fun requestBiometricPrompt(kind: PromptKind) {
        pendingPromptKind = kind
        Log.i("PhoneKeyTiming", "biometric_queued kind=$kind resumed=${lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED)} focus=${hasWindowFocus()}")
        showPendingBiometricPrompt()
    }

    private fun showPendingBiometricPrompt() {
        val kind = pendingPromptKind ?: return
        if (biometricPromptInFlight || !::biometricPrompt.isInitialized ||
            !lifecycle.currentState.isAtLeast(androidx.lifecycle.Lifecycle.State.RESUMED) ||
            !hasWindowFocus()) return

        try {
            when (kind) {
                PromptKind.LOGIN -> pendingLoginChallenge?.let {
                    requireFresh(it.issuedAtMs, it.expiresAtMs)
                } ?: return
                PromptKind.ENROLLMENT -> pendingEnrollmentChallenge?.let {
                    requireFresh(it.issuedAtMs, it.expiresAtMs)
                } ?: return
                PromptKind.FILE_OPEN -> pendingFileOpenChallenge?.let {
                    requireFresh(it.issuedAtMs, it.expiresAtMs)
                } ?: return
            }

            val info = BiometricPrompt.PromptInfo.Builder()
                .setTitle(when (kind) {
                    PromptKind.LOGIN -> "Unlock Windows with PhoneKey"
                    PromptKind.ENROLLMENT -> "Enroll PhoneKey"
                    PromptKind.FILE_OPEN -> "Open encrypted file with PhoneKey"
                })
                .setSubtitle(when (kind) {
                    PromptKind.LOGIN -> "Confirm this Windows login"
                    PromptKind.ENROLLMENT -> "Approve pairing with this Windows PC"
                    PromptKind.FILE_OPEN -> "Approve this file opening only"
                })
                .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
            if (kind == PromptKind.ENROLLMENT) {
                info.setDescription("Compare the pairing code with the code shown on Windows.")
            }

            biometricPromptInFlight = true
            val promptAt = SystemClock.elapsedRealtime()
            if (kind == PromptKind.LOGIN) {
                loginPromptAtMs = promptAt
                loginQrAcceptedAtMs?.let { acceptedAt ->
                    Log.i("PhoneKeyTiming", "scan_to_prompt_ms=${promptAt - acceptedAt}")
                }
            }
            Log.i("PhoneKeyTiming", "biometric_launch kind=$kind")
            biometricPrompt.authenticate(info.build())
        } catch (error: Exception) {
            Log.e("PhoneKeyTiming", "biometric_launch_failed kind=$kind", error)
            biometricPromptInFlight = false
            clearPending()
            bleServerStatus = "Could not show fingerprint prompt: ${error.message}"
        }
    }

    private fun createFileOpenProof() {
        val challenge = pendingFileOpenChallenge ?: return
        try {
            requireFresh(challenge.issuedAtMs, challenge.expiresAtMs)
            val identity = identityManager.getIdentity()
            require(identity.deviceId.contentEquals(challenge.phoneDeviceId))
            val transcript = PhoneKeyProtocol.buildFileOpenSigningTranscript(challenge)
            val fileKey = PhoneKeyFileKeyManager().unwrapFileKey(
                challenge.phoneWrap, challenge.envelopeSha256)
            val encryptedFileKey = try {
                PhoneKeyFileKeyReturn.seal(fileKey,
                    java.security.MessageDigest.getInstance("SHA-256").digest(transcript),
                    challenge.returnPublicSec1)
            } finally {
                fileKey.fill(0)
            }
            val signature = identityManager.sign(transcript + encryptedFileKey)
            val proof = PhoneKeyProtocol.FileOpenProof(
                identity.deviceId, challenge.sessionId, signature, encryptedFileKey
            )
            phoneKeyGattServer.setProofPayload(PhoneKeyProtocol.encodeFileOpenProof(proof))
            pendingFileOpenChallenge = null
            pendingFileQrBootstrap = null
            bleServerStatus = "File opening approved - signed proof ready"
        } catch (error: Exception) {
            clearPending()
            phoneKeyGattServer.clearProofPayload()
            bleServerStatus = "File opening approval failed: ${error.message}"
        }
    }

    private fun clearPending() {
        pendingPromptKind = null
        pendingLoginChallenge =
            null

        loginRendezvous.clear()

        pendingFileOpenChallenge = null
        fileRendezvous.clear()

        pendingFileQrBootstrap = null

        pendingEnrollmentChallenge =
            null

        pendingQrBootstrap =
            null
    }

    override fun onResume() {
        super.onResume()
        Log.i("PhoneKeyTiming", "activity_resumed")
        showPendingBiometricPrompt()

        if (
            ::bleCapabilityManager
                .isInitialized
        ) {
            refreshCapabilities()
        }
    }

    override fun onWindowFocusChanged(hasFocus: Boolean) {
        super.onWindowFocusChanged(hasFocus)
        if (hasFocus) {
            Log.i("PhoneKeyTiming", "activity_focused")
            showPendingBiometricPrompt()
        }
    }

    override fun onDestroy() {
        if (
            ::phoneKeyGattServer
                .isInitialized
        ) {
            phoneKeyGattServer
                .stop()
        }

        super.onDestroy()
    }

    private fun refreshCapabilities() {
        capabilityResult =
            bleCapabilityManager
                .checkCapabilities()
    }

    private fun requestBluetoothPermissions() {
        if (
            Build.VERSION.SDK_INT >=
            Build.VERSION_CODES.S
        ) {
            ActivityCompat
                .requestPermissions(
                    this,

                    arrayOf(
                        Manifest.permission
                            .BLUETOOTH_ADVERTISE,

                        Manifest.permission
                            .BLUETOOTH_CONNECT
                    ),

                    BLUETOOTH_PERMISSION_REQUEST_CODE
                )
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions:
            Array<out String>,
        grantResults:
            IntArray
    ) {
        super
            .onRequestPermissionsResult(
                requestCode,
                permissions,
                grantResults
            )

        if (
            requestCode ==
            BLUETOOTH_PERMISSION_REQUEST_CODE
        ) {
            refreshCapabilities()
        }
    }
}

@Composable
fun PhoneKeyScreen(
    result:
        BleCapabilityManager
            .BleCapabilityResult?,

    serverStatus:
        String,

    pairingCode:
        String?,

    onScanQr:
        () -> Unit,

    onGrantPermissions:
        () -> Unit,

    onRefresh:
        () -> Unit,

    onStartServer:
        () -> Unit,

    onStopServer:
        () -> Unit
) {
    Scaffold(
        modifier =
            Modifier.fillMaxSize()
    ) { innerPadding ->

        Surface(
            modifier =
                Modifier
                    .fillMaxSize()
                    .padding(
                        innerPadding
                    ),

            color =
                MaterialTheme
                    .colorScheme
                    .background
        ) {
            Column(
                modifier =
                    Modifier
                        .fillMaxSize()
                        .padding(
                            24.dp
                        ),

                verticalArrangement =
                    Arrangement.Center,

                horizontalAlignment =
                    Alignment.CenterHorizontally
            ) {
                Text(
                    text =
                        "PhoneKey",

                    fontSize =
                        38.sp,

                    fontWeight =
                        FontWeight.Bold
                )

                Spacer(
                    modifier =
                        Modifier.height(
                            8.dp
                        )
                )

                Text(
                    text =
                        "Secure Windows authentication"
                )

                Spacer(
                    modifier =
                        Modifier.height(
                            20.dp
                        )
                )

                pairingCode?.let {
                    code ->

                    Surface(
                        modifier =
                            Modifier
                                .fillMaxWidth(),

                        shape =
                            RoundedCornerShape(
                                20.dp
                            ),

                        tonalElevation =
                            6.dp
                    ) {
                        Column(
                            modifier =
                                Modifier.padding(
                                    22.dp
                                ),

                            horizontalAlignment =
                                Alignment.CenterHorizontally
                        ) {
                            Text(
                                text =
                                    "PAIRING CODE",

                                fontWeight =
                                    FontWeight
                                        .SemiBold
                            )

                            Spacer(
                                modifier =
                                    Modifier.height(
                                        8.dp
                                    )
                            )

                            Text(
                                text =
                                    code,

                                fontSize =
                                    38.sp,

                                fontWeight =
                                    FontWeight.Bold
                            )

                            Spacer(
                                modifier =
                                    Modifier.height(
                                        6.dp
                                    )
                            )

                            Text(
                                text =
                                    "Compare this code with Windows before confirming enrollment."
                            )
                        }
                    }

                    Spacer(
                        modifier =
                            Modifier.height(
                                18.dp
                            )
                    )
                }

                result?.let {
                    value ->

                    Surface(
                        modifier =
                            Modifier
                                .fillMaxWidth(),

                        shape =
                            RoundedCornerShape(
                                18.dp
                            ),

                        tonalElevation =
                            3.dp
                    ) {
                        Column(
                            modifier =
                                Modifier.padding(
                                    18.dp
                                )
                        ) {
                            CapabilityRow(
                                "Bluetooth available",
                                value.bluetoothAvailable
                            )

                            CapabilityRow(
                                "Bluetooth enabled",
                                value.bluetoothEnabled
                            )

                            CapabilityRow(
                                "BLE advertising supported",
                                value.bleAdvertisingSupported
                            )

                            CapabilityRow(
                                "BLE advertiser available",
                                value.advertiserAvailable
                            )

                            CapabilityRow(
                                "Advertise permission granted",
                                value.advertisePermissionGranted
                            )
                        }
                    }

                    Spacer(
                        modifier =
                            Modifier.height(
                                16.dp
                            )
                    )

                    if (
                        Build.VERSION.SDK_INT >=
                        Build.VERSION_CODES.S &&
                        !value
                            .advertisePermissionGranted
                    ) {
                        Button(
                            onClick =
                                onGrantPermissions,

                            modifier =
                                Modifier
                                    .fillMaxWidth()
                                    .height(
                                        54.dp
                                    )
                        ) {
                            Text(
                                "Grant Bluetooth permissions"
                            )
                        }

                        Spacer(
                            modifier =
                                Modifier.height(
                                    10.dp
                                )
                        )
                    }
                }

                Surface(
                    modifier =
                        Modifier
                            .fillMaxWidth(),

                    shape =
                        RoundedCornerShape(
                            16.dp
                        ),

                    tonalElevation =
                        2.dp
                ) {
                    Column(
                        modifier =
                            Modifier.padding(
                                18.dp
                            )
                    ) {
                        Text(
                            text =
                                "PhoneKey status",

                            fontWeight =
                                FontWeight
                                    .SemiBold
                        )

                        Spacer(
                            modifier =
                                Modifier.height(
                                    6.dp
                                )
                        )

                        Text(
                            text =
                                serverStatus
                        )
                    }
                }

                Spacer(
                    modifier =
                        Modifier.height(
                            16.dp
                        )
                )

                Button(
                    onClick =
                        onScanQr,

                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .height(
                                56.dp
                            )
                ) {
                    Text(
                        "Scan Windows QR"
                    )
                }

                Spacer(
                    modifier =
                        Modifier.height(
                            16.dp
                        )
                )

                Button(
                    onClick =
                        onStartServer,

                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .height(
                                56.dp
                            )
                ) {
                    Text(
                        "Developer: Start BLE"
                    )
                }

                Spacer(
                    modifier =
                        Modifier.height(
                            10.dp
                        )
                )

                Button(
                    onClick =
                        onStopServer,

                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .height(
                                56.dp
                            )
                ) {
                    Text(
                        "Developer: Stop BLE"
                    )
                }

                Spacer(
                    modifier =
                        Modifier.height(
                            10.dp
                        )
                )

                Button(
                    onClick =
                        onRefresh,

                    modifier =
                        Modifier
                            .fillMaxWidth()
                            .height(
                                56.dp
                            )
                ) {
                    Text(
                        "Refresh capability check"
                    )
                }
            }
        }
    }
}

@Composable
private fun CapabilityRow(
    label: String,
    value: Boolean
) {
    Column(
        modifier =
            Modifier.padding(
                vertical =
                    3.dp
            )
    ) {
        Text(
            text =
                label,

            style =
                MaterialTheme
                    .typography
                    .labelMedium
        )

        Text(
            text =
                if (value) {
                    "YES"
                } else {
                    "NO"
                },

            fontWeight =
                FontWeight.SemiBold
        )
    }
}

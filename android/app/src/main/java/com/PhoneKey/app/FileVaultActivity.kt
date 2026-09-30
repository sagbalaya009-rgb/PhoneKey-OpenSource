package com.PhoneKey.app

import android.content.ClipData
import android.content.ClipboardManager
import android.content.pm.ApplicationInfo
import android.os.Bundle
import androidx.activity.compose.setContent
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
import androidx.compose.material3.Button
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Text
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.fragment.app.FragmentActivity
import com.PhoneKey.app.ui.theme.PhoneKeyTheme

/** Separate setup screen for the file vault. The Windows login flow stays unchanged. */
class FileVaultActivity : FragmentActivity() {
    private lateinit var identityManager: DeviceIdentityManager
    private lateinit var biometricPrompt: BiometricPrompt
    private var export by mutableStateOf<String?>(null)
    private var status by mutableStateOf("Approve with your fingerprint or phone PIN to prepare file encryption.")

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        identityManager = DeviceIdentityManager(this)
        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
            java.io.File(cacheDir, "file-binding-export.txt").delete()
        }
        biometricPrompt = BiometricPrompt(this, ContextCompat.getMainExecutor(this),
            object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    try {
                        val signed = PhoneKeyFileBinding.create(identityManager)
                        export = signed
                        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                            java.io.File(cacheDir, "file-binding-export.txt").writeText(signed)
                        }
                        status = "File-encryption key prepared. Copy its signed pairing code to Windows."
                    } catch (error: Exception) {
                        export = null
                        if (applicationInfo.flags and ApplicationInfo.FLAG_DEBUGGABLE != 0) {
                            java.io.File(cacheDir, "file-binding-export.txt").delete()
                        }
                        status = "Could not prepare the file key: ${error.message}"
                    }
                }

                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    status = "File setup was cancelled: $errString"
                }
            })

        setContent {
            PhoneKeyTheme {
                Column(
                    modifier = Modifier.fillMaxSize().padding(24.dp),
                    verticalArrangement = Arrangement.Center,
                    horizontalAlignment = Alignment.CenterHorizontally
                ) {
                    Text("PhoneKey Files", style = MaterialTheme.typography.headlineMedium)
                    Spacer(Modifier.height(16.dp))
                    Text("This creates a separate phone-held key for encrypted files. It does not change Windows sign-in.")
                    Spacer(Modifier.height(16.dp))
                    Text(status)
                    Spacer(Modifier.height(20.dp))
                    Button(onClick = { approveFileSetup() }, modifier = Modifier.fillMaxWidth()) {
                        Text("Approve file-encryption setup")
                    }
                    if (export != null) {
                        Spacer(Modifier.height(12.dp))
                        Button(onClick = { copyExport() }, modifier = Modifier.fillMaxWidth()) {
                            Text("Copy signed pairing code")
                        }
                    }
                }
            }
        }
    }

    private fun approveFileSetup() {
        biometricPrompt.authenticate(
            BiometricPrompt.PromptInfo.Builder()
                .setTitle("Enable PhoneKey file encryption")
                .setSubtitle("Approve this phone's separate file key")
                .setAllowedAuthenticators(BIOMETRIC_STRONG or DEVICE_CREDENTIAL)
                .build()
        )
    }

    private fun copyExport() {
        val value = export ?: return
        val clipboard = getSystemService(CLIPBOARD_SERVICE) as ClipboardManager
        clipboard.setPrimaryClip(ClipData.newPlainText("PhoneKey file binding", value))
        status = "Signed file-key pairing code copied. Paste it into the Windows file-vault setup."
    }
}

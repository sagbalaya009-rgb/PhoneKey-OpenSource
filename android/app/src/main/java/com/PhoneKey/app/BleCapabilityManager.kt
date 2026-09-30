package com.PhoneKey.app

import android.Manifest
import android.bluetooth.BluetoothAdapter
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import androidx.core.content.ContextCompat

class BleCapabilityManager(
    private val context: Context
) {

    data class BleCapabilityResult(
        val bluetoothAvailable: Boolean,
        val bluetoothEnabled: Boolean,
        val bleAdvertisingSupported: Boolean,
        val advertiserAvailable: Boolean,
        val advertisePermissionGranted: Boolean
    )

    fun checkCapabilities(): BleCapabilityResult {

        val bluetoothManager =
            context.getSystemService(
                BluetoothManager::class.java
            )

        val adapter: BluetoothAdapter? =
            bluetoothManager?.adapter

        val bluetoothAvailable =
            adapter != null

        val bluetoothEnabled =
            adapter?.isEnabled == true

        val advertisingSupported =
            adapter?.isMultipleAdvertisementSupported == true

        val advertiserAvailable =
            if (
                bluetoothEnabled &&
                advertisingSupported
            ) {
                adapter?.bluetoothLeAdvertiser != null
            } else {
                false
            }

        val permissionGranted =
            if (
                Build.VERSION.SDK_INT >=
                Build.VERSION_CODES.S
            ) {
                ContextCompat.checkSelfPermission(
                    context,
                    Manifest.permission.BLUETOOTH_ADVERTISE
                ) == PackageManager.PERMISSION_GRANTED
            } else {
                true
            }

        return BleCapabilityResult(
            bluetoothAvailable =
                bluetoothAvailable,

            bluetoothEnabled =
                bluetoothEnabled,

            bleAdvertisingSupported =
                advertisingSupported,

            advertiserAvailable =
                advertiserAvailable,

            advertisePermissionGranted =
                permissionGranted
        )
    }
}
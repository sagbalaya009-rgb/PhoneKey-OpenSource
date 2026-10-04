package com.PhoneKey.app

import android.Manifest
import android.annotation.SuppressLint
import android.bluetooth.BluetoothGatt
import android.bluetooth.BluetoothGattCharacteristic
import android.bluetooth.BluetoothGattDescriptor
import android.bluetooth.BluetoothGattServer
import android.bluetooth.BluetoothGattServerCallback
import android.bluetooth.BluetoothGattService
import android.bluetooth.BluetoothManager
import android.bluetooth.BluetoothProfile
import android.bluetooth.le.AdvertiseCallback
import android.bluetooth.le.AdvertiseData
import android.bluetooth.le.AdvertiseSettings
import android.content.Context
import android.content.pm.PackageManager
import android.os.Build
import android.os.Handler
import android.os.Looper
import android.os.ParcelUuid
import android.os.SystemClock
import android.util.Log
import androidx.core.content.ContextCompat
import java.util.UUID
import java.util.concurrent.atomic.AtomicLong

class PhoneKeyGattServer(
    private val context: Context,
    private val onStatusChanged: (String) -> Unit,
    private val onChallengeReceived: (ByteArray) -> Unit
) {

    companion object {
        val SERVICE_UUID: UUID =
            UUID.fromString(
                "7d2ea28a-f7bd-485a-bd9d-92ad6ecfe93e"
            )

        val CHALLENGE_UUID: UUID =
            UUID.fromString(
                "7d2ea28b-f7bd-485a-bd9d-92ad6ecfe93e"
            )

        val PROOF_UUID: UUID =
            UUID.fromString(
                "7d2ea28c-f7bd-485a-bd9d-92ad6ecfe93e"
            )

        private val CLIENT_CONFIGURATION_UUID: UUID =
            UUID.fromString(
                "00002902-0000-1000-8000-00805f9b34fb"
            )
    }

    private val bluetoothManager =
        context.getSystemService(
            BluetoothManager::class.java
        )

    private val bluetoothAdapter
        get() = bluetoothManager.adapter

    private var gattServer:
        BluetoothGattServer? = null

    // The callback is assigned before startAdvertising returns. A QR rescan
    // can therefore stop even a request whose success callback is still queued.
    private val advertiseLock = Any()
    private var activeAdvertiseCallback: AdvertiseCallback? = null
    private var advertiseGeneration = 0L
    @Volatile private var bleClientConnected = false
    private val mainHandler = Handler(Looper.getMainLooper())

    @Volatile
    private var proofPayload =
        byteArrayOf()

    private val proofReadyAtMs = AtomicLong(0)
    private val preparedFileWrite = PhoneKeyFilePreparedWrite()

    fun setProofPayload(
        payload: ByteArray
    ) {
        require(
            payload.size <=
                PhoneKeyProtocol.MAX_MESSAGE_SIZE
        )

        proofPayload =
            payload.copyOf()
        proofReadyAtMs.set(SystemClock.elapsedRealtime())

        onStatusChanged(
            "Real LoginProof ready (${payload.size} bytes)"
        )
    }

    fun clearProofPayload() {
        proofPayload =
            byteArrayOf()
        proofReadyAtMs.set(0)
    }

    @SuppressLint("MissingPermission")
    fun start() {
        if (!hasRequiredPermissions()) {
            onStatusChanged(
                "Bluetooth permission missing"
            )
            return
        }

        if (!bluetoothAdapter.isEnabled) {
            onStatusChanged(
                "Bluetooth is turned off"
            )
            return
        }

        if (
            !bluetoothAdapter
                .isMultipleAdvertisementSupported
        ) {
            onStatusChanged(
                "BLE advertising is not supported"
            )
            return
        }

        if (gattServer != null) {
            val active = synchronized(advertiseLock) { activeAdvertiseCallback != null }
            if (active) {
                // Windows begins discovery when it creates the QR. Interrupting
                // an already active advertiser when the camera opens races its
                // connection and can strand the phone before the challenge.
                val generation = synchronized(advertiseLock) { advertiseGeneration }
                mainHandler.postDelayed({
                    if (gattServer != null && !bleClientConnected &&
                        synchronized(advertiseLock) { advertiseGeneration == generation }) {
                        Log.i("PhoneKeyTiming", "ble_idle_advertiser_refresh")
                        stopAdvertising()
                        mainHandler.postDelayed({
                            if (gattServer != null && !bleClientConnected) startAdvertising()
                        }, 200)
                    }
                }, 8000)
                return
            }
            // A failed or stopped advertiser can leave the GATT server alive.
            stopAdvertising()
            onStatusChanged("Refreshing PhoneKey BLE advertising...")
            val generation = synchronized(advertiseLock) { advertiseGeneration }
            mainHandler.postDelayed({
                if (gattServer != null &&
                    synchronized(advertiseLock) { advertiseGeneration == generation }) {
                    startAdvertising()
                }
            }, 200)
            return
        }

        createGattServer()
    }

    @SuppressLint("MissingPermission")
    fun stop() {
        stopAdvertising()
        bleClientConnected = false

        gattServer?.close()
        gattServer = null

        clearProofPayload()

        onStatusChanged(
            "PhoneKey BLE server stopped"
        )
    }

    @SuppressLint("MissingPermission")
    private fun createGattServer() {
        val server =
            bluetoothManager.openGattServer(
                context,
                gattServerCallback
            )

        if (server == null) {
            onStatusChanged(
                "Unable to create BLE GATT server"
            )
            return
        }

        gattServer =
            server

        val service =
            BluetoothGattService(
                SERVICE_UUID,
                BluetoothGattService
                    .SERVICE_TYPE_PRIMARY
            )

        val challenge =
            BluetoothGattCharacteristic(
                CHALLENGE_UUID,
                BluetoothGattCharacteristic
                    .PROPERTY_WRITE,
                BluetoothGattCharacteristic
                    .PERMISSION_WRITE
            )

        val proof =
            BluetoothGattCharacteristic(
                PROOF_UUID,
                BluetoothGattCharacteristic
                    .PROPERTY_READ or
                    BluetoothGattCharacteristic
                        .PROPERTY_NOTIFY,
                BluetoothGattCharacteristic
                    .PERMISSION_READ
            )

        proof.addDescriptor(
            BluetoothGattDescriptor(
                CLIENT_CONFIGURATION_UUID,
                BluetoothGattDescriptor
                    .PERMISSION_READ or
                    BluetoothGattDescriptor
                        .PERMISSION_WRITE
            )
        )

        service.addCharacteristic(
            challenge
        )

        service.addCharacteristic(
            proof
        )

        if (!server.addService(service)) {
            onStatusChanged(
                "Unable to add PhoneKey GATT service"
            )

            stop()
            return
        }

        onStatusChanged(
            "Creating PhoneKey BLE service..."
        )
    }

    private val gattServerCallback =
        object :
            BluetoothGattServerCallback() {

            override fun onServiceAdded(
                status: Int,
                service: BluetoothGattService
            ) {
                if (
                    service.uuid !=
                    SERVICE_UUID
                ) {
                    return
                }

                if (
                    status ==
                    BluetoothGatt.GATT_SUCCESS
                ) {
                    onStatusChanged(
                        "PhoneKey GATT service ready"
                    )

                    startAdvertising()
                } else {
                    gattServer?.close()
                    gattServer = null
                    onStatusChanged(
                        "Failed to create GATT service: $status"
                    )
                }
            }

            override fun onConnectionStateChange(
                device:
                    android.bluetooth.BluetoothDevice,
                status: Int,
                newState: Int
            ) {
                if (status != BluetoothGatt.GATT_SUCCESS) {
                    onStatusChanged(
                        "BLE client connection failed: $status"
                    )
                    return
                }

                when (newState) {
                    BluetoothProfile.STATE_CONNECTED ->
                        {
                            bleClientConnected = true
                            Log.i("PhoneKeyTiming", "ble_client_connected")
                            onStatusChanged("Windows BLE client connected")
                        }

                    BluetoothProfile.STATE_DISCONNECTED ->
                        {
                            bleClientConnected = false
                            preparedFileWrite.clear()
                            Log.i("PhoneKeyTiming", "ble_client_disconnected")
                            onStatusChanged("BLE client disconnected")
                        }
                }
            }

            @SuppressLint("MissingPermission")
            override fun onCharacteristicWriteRequest(
                device:
                    android.bluetooth.BluetoothDevice,
                requestId: Int,
                characteristic:
                    BluetoothGattCharacteristic,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray
            ) {
                if (characteristic.uuid == CHALLENGE_UUID && preparedWrite) {
                    val valid = try {
                        preparedFileWrite.append(device.address, offset, value)
                        true
                    } catch (error: IllegalArgumentException) {
                        preparedFileWrite.clear()
                        false
                    }
                    if (responseNeeded) {
                        gattServer?.sendResponse(
                            device, requestId,
                            if (valid) BluetoothGatt.GATT_SUCCESS else BluetoothGatt.GATT_FAILURE,
                            offset,
                            if (valid) value else null
                        )
                    }
                    return
                }
                if (
                    characteristic.uuid ==
                    CHALLENGE_UUID &&
                    !preparedWrite &&
                    offset == 0
                ) {
                    preparedFileWrite.clear()
                    clearProofPayload()

                    if (responseNeeded) {
                        gattServer?.sendResponse(
                            device,
                            requestId,
                            BluetoothGatt.GATT_SUCCESS,
                            0,
                            null
                        )
                    }

                    Log.i("PhoneKeyTiming", "ble_challenge_received")
                    onStatusChanged(
                        "Real LoginChallenge received (${value.size} bytes)"
                    )

                    onChallengeReceived(
                        value.copyOf()
                    )

                    return
                }

                if (responseNeeded) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt
                            .GATT_REQUEST_NOT_SUPPORTED,
                        offset,
                        null
                    )
                }
            }

            @SuppressLint("MissingPermission")
            override fun onExecuteWrite(
                device: android.bluetooth.BluetoothDevice,
                requestId: Int,
                execute: Boolean
            ) {
                val payload = try {
                    preparedFileWrite.finish(device.address, execute)
                } catch (error: IllegalArgumentException) {
                    preparedFileWrite.clear()
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                    return
                }
                if (payload == null) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                    return
                }
                val validFileRequest = try {
                    PhoneKeyProtocol.decodeFileOpenChallenge(payload)
                    true
                } catch (error: Exception) {
                    false
                }
                if (!validFileRequest) {
                    gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_FAILURE, 0, null)
                    return
                }
                clearProofPayload()
                gattServer?.sendResponse(device, requestId, BluetoothGatt.GATT_SUCCESS, 0, null)
                onStatusChanged("Encrypted-file challenge received (${payload.size} bytes)")
                onChallengeReceived(payload)
            }

            @SuppressLint("MissingPermission")
            override fun onCharacteristicReadRequest(
                device:
                    android.bluetooth.BluetoothDevice,
                requestId: Int,
                offset: Int,
                characteristic:
                    BluetoothGattCharacteristic
            ) {
                if (
                    characteristic.uuid !=
                    PROOF_UUID
                ) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt
                            .GATT_REQUEST_NOT_SUPPORTED,
                        offset,
                        null
                    )

                    return
                }

                val payload =
                    proofPayload

                if (payload.isEmpty()) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt.GATT_FAILURE,
                        0,
                        null
                    )

                    return
                }

                if (
                    offset >
                    payload.size
                ) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt
                            .GATT_INVALID_OFFSET,
                        offset,
                        null
                    )

                    return
                }

                val response =
                    payload.copyOfRange(
                        offset,
                        payload.size
                    )

                val sent = gattServer?.sendResponse(
                    device,
                    requestId,
                    BluetoothGatt.GATT_SUCCESS,
                    offset,
                    response
                ) == true

                if (sent) {
                    val readyAt = proofReadyAtMs.getAndSet(0)
                    if (readyAt > 0) {
                        Log.i("PhoneKeyTiming", "proof_ready_to_ble_read_ms=${SystemClock.elapsedRealtime() - readyAt}")
                    }
                }

                onStatusChanged(if (sent)
                    "Real LoginProof sent to Windows (${payload.size} bytes)"
                else "Unable to send PhoneKey proof over BLE")
            }

            @SuppressLint("MissingPermission")
            override fun onDescriptorWriteRequest(
                device:
                    android.bluetooth.BluetoothDevice,
                requestId: Int,
                descriptor:
                    BluetoothGattDescriptor,
                preparedWrite: Boolean,
                responseNeeded: Boolean,
                offset: Int,
                value: ByteArray
            ) {
                if (
                    descriptor.uuid ==
                    CLIENT_CONFIGURATION_UUID
                ) {
                    if (responseNeeded) {
                        gattServer?.sendResponse(
                            device,
                            requestId,
                            BluetoothGatt.GATT_SUCCESS,
                            offset,
                            null
                        )
                    }

                    return
                }

                if (responseNeeded) {
                    gattServer?.sendResponse(
                        device,
                        requestId,
                        BluetoothGatt
                            .GATT_REQUEST_NOT_SUPPORTED,
                        offset,
                        null
                    )
                }
            }
        }

    @SuppressLint("MissingPermission")
    private fun startAdvertising() {
        if (!hasRequiredPermissions()) {
            return
        }

        val advertiser =
            bluetoothAdapter
                .bluetoothLeAdvertiser
                ?: run {
                    onStatusChanged(
                        "BLE advertiser unavailable"
                    )
                    return
                }

        val settings =
            AdvertiseSettings.Builder()
                .setAdvertiseMode(
                    AdvertiseSettings
                        .ADVERTISE_MODE_LOW_LATENCY
                )
                .setTxPowerLevel(
                    AdvertiseSettings
                        .ADVERTISE_TX_POWER_MEDIUM
                )
                .setConnectable(true)
                .setTimeout(0)
                .build()

        val data =
            AdvertiseData.Builder()
                .setIncludeDeviceName(false)
                .setIncludeTxPowerLevel(false)
                .addServiceUuid(
                    ParcelUuid(
                        SERVICE_UUID
                    )
                )
                .build()

        synchronized(advertiseLock) {
            if (activeAdvertiseCallback != null) return
            val callback = object : AdvertiseCallback() {
                override fun onStartSuccess(settingsInEffect: AdvertiseSettings) {
                    if (synchronized(advertiseLock) { activeAdvertiseCallback === this }) {
                        Log.i("PhoneKeyTiming", "ble_advertising_ready")
                        onStatusChanged("PhoneKey is advertising over BLE")
                    } else {
                        // A late success belongs to a canceled QR scan.
                        try { advertiser.stopAdvertising(this) } catch (_: Exception) { }
                    }
                }

                override fun onStartFailure(errorCode: Int) {
                    val current = synchronized(advertiseLock) {
                        if (activeAdvertiseCallback === this) {
                            activeAdvertiseCallback = null
                            true
                        } else false
                    }
                    if (current) {
                        Log.i("PhoneKeyTiming", "ble_advertising_failed_code=$errorCode")
                        onStatusChanged("BLE advertising failed: $errorCode")
                    }
                }
            }
            activeAdvertiseCallback = callback
            try {
                advertiser.startAdvertising(settings, data, callback)
            } catch (error: Exception) {
                activeAdvertiseCallback = null
                onStatusChanged("BLE advertising could not start: ${error.message}")
                return
            }
            Log.i("PhoneKeyTiming", "ble_advertise_requested")
        }

        onStatusChanged(
            "Starting PhoneKey BLE advertising..."
        )
    }

    @SuppressLint("MissingPermission")
    private fun stopAdvertising() {
        val callback = synchronized(advertiseLock) {
            advertiseGeneration++
            val previous = activeAdvertiseCallback
            activeAdvertiseCallback = null
            previous
        }
        if (callback != null && hasRequiredPermissions()) {
            try {
                bluetoothAdapter.bluetoothLeAdvertiser?.stopAdvertising(callback)
                Log.i("PhoneKeyTiming", "ble_advertiser_stop_requested")
            } catch (error: Exception) {
                onStatusChanged("BLE advertising stop failed: ${error.message}")
            }
        }
    }

    private fun hasRequiredPermissions():
        Boolean {
        if (
            Build.VERSION.SDK_INT <
            Build.VERSION_CODES.S
        ) {
            return true
        }

        return ContextCompat
            .checkSelfPermission(
                context,
                Manifest.permission
                    .BLUETOOTH_ADVERTISE
            ) ==
            PackageManager.PERMISSION_GRANTED &&
            ContextCompat
                .checkSelfPermission(
                    context,
                    Manifest.permission
                        .BLUETOOTH_CONNECT
                ) ==
            PackageManager.PERMISSION_GRANTED
    }
}

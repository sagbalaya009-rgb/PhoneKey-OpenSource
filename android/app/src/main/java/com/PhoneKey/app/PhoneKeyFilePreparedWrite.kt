package com.PhoneKey.app

import java.io.ByteArrayOutputStream

/** Bounded GATT long-write assembly for FILE_OPEN only. Login keeps its
 * existing single-write path. Each fragment is acknowledged before execute.
 */
class PhoneKeyFilePreparedWrite {
    private var writer: String? = null
    private val pending = ByteArrayOutputStream()

    @Synchronized
    fun append(deviceAddress: String, offset: Int, value: ByteArray) {
        require(value.isNotEmpty()) { "Empty prepared write" }
        if (offset == 0) {
            clear()
            writer = deviceAddress
        }
        require(writer == deviceAddress && offset == pending.size()) {
            "Out-of-order prepared write"
        }
        require(value.size <= PhoneKeyProtocol.MAX_MESSAGE_SIZE - pending.size()) {
            "Prepared file request is too large"
        }
        pending.write(value)
    }

    @Synchronized
    fun finish(deviceAddress: String, execute: Boolean): ByteArray? {
        if (!execute) {
            clear()
            return null
        }
        require(writer == deviceAddress && pending.size() > 0) {
            "No prepared file request"
        }
        val result = pending.toByteArray()
        clear()
        return result
    }

    @Synchronized
    fun clear() {
        pending.reset()
        writer = null
    }
}

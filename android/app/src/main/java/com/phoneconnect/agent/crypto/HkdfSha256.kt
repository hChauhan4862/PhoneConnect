package com.phoneconnect.agent.crypto

import javax.crypto.Mac
import javax.crypto.spec.SecretKeySpec

/**
 * HKDF-SHA256 (RFC 5869) as `crates/transport` uses it: extract the X25519 shared secret
 * with a salt built from the session id and the connection epoch, then expand 64 bytes into
 * one key per direction.
 */
object HkdfSha256 {
    private const val HASH_LEN = 32
    private const val ALGORITHM = "HmacSHA256"

    fun extract(salt: ByteArray, inputKeyMaterial: ByteArray): ByteArray {
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(if (salt.isEmpty()) ByteArray(HASH_LEN) else salt, ALGORITHM))
        return mac.doFinal(inputKeyMaterial)
    }

    fun expand(pseudoRandomKey: ByteArray, info: ByteArray, length: Int): ByteArray {
        require(length >= 0 && length <= 255 * HASH_LEN) { "HKDF output of $length bytes is out of range" }
        val mac = Mac.getInstance(ALGORITHM)
        mac.init(SecretKeySpec(pseudoRandomKey, ALGORITHM))

        val output = ByteArray(length)
        var previous = ByteArray(0)
        var offset = 0
        var counter = 1
        while (offset < length) {
            mac.reset()
            mac.update(previous)
            mac.update(info)
            mac.update(counter.toByte())
            previous = mac.doFinal()
            val chunk = minOf(HASH_LEN, length - offset)
            previous.copyInto(output, offset, 0, chunk)
            offset += chunk
            counter += 1
        }
        return output
    }

    fun derive(salt: ByteArray, inputKeyMaterial: ByteArray, info: ByteArray, length: Int): ByteArray =
        expand(extract(salt, inputKeyMaterial), info, length)
}

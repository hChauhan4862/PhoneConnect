package com.phoneconnect.agent.crypto

import java.security.MessageDigest

/**
 * The sealed-frame header and its derivations, byte for byte with
 * `crates/transport/src/aead.rs`.
 *
 * Layout: `version(1) | key_id(8) | direction(1) | counter(8, big endian) | stream_kind(1) |
 * sequence(4, big endian)` = 23 bytes, followed by the ChaCha20-Poly1305 ciphertext and its
 * 16-byte tag. The header is authenticated as associated data together with the session id,
 * so a changed header is a failed tag — never a different frame.
 */
object SealedFrame {
    const val VERSION: Byte = 1
    const val KEY_ID_LEN = 8
    const val TAG_LEN = 16
    const val HEADER_LEN = 23
    const val MIN_LEN = HEADER_LEN + TAG_LEN

    const val VERSION_OFFSET = 0
    const val KEY_ID_OFFSET = VERSION_OFFSET + 1
    const val DIRECTION_OFFSET = KEY_ID_OFFSET + KEY_ID_LEN
    const val COUNTER_OFFSET = DIRECTION_OFFSET + 1
    const val STREAM_KIND_OFFSET = COUNTER_OFFSET + 8
    const val SEQUENCE_OFFSET = STREAM_KIND_OFFSET + 1

    const val AEAD_LABEL = "phoneconnect-aead-v1"
    const val KEY_ID_LABEL = "phoneconnect-key-id-v1"

    /** Highest counter in flight; a frame counter of 0 is reserved. */
    const val FIRST_COUNTER = 1L

    private val aeadLabel = AEAD_LABEL.toByteArray(Charsets.UTF_8)
    private val keyIdLabel = KEY_ID_LABEL.toByteArray(Charsets.UTF_8)

    /** True when [frame] can even hold a header and a tag. */
    fun isReadable(frame: ByteArray): Boolean = frame.size >= MIN_LEN

    /** The stream kind a sealed frame declares, if its header is readable. */
    fun streamKind(frame: ByteArray): Int? =
        if (!isReadable(frame)) null else frame[STREAM_KIND_OFFSET].toInt() and 0xFF

    /** Associated data: the AEAD label, the length-prefixed session id, then the header. */
    fun associatedData(sessionId: String, header: ByteArray): ByteArray {
        require(header.size == HEADER_LEN) { "header must be $HEADER_LEN bytes" }
        val session = sessionId.toByteArray(Charsets.UTF_8)
        require(session.size <= 0xFFFF) { "session id is too long to length-prefix" }
        val aad = ByteArray(aeadLabel.size + 2 + session.size + header.size)
        var offset = 0
        aeadLabel.copyInto(aad, offset)
        offset += aeadLabel.size
        aad[offset] = (session.size ushr 8).toByte()
        aad[offset + 1] = session.size.toByte()
        offset += 2
        session.copyInto(aad, offset)
        offset += session.size
        header.copyInto(aad, offset)
        return aad
    }

    /** Nonce = `direction | counter (big endian) | 0 0 0`, 12 bytes as RFC 8439 expects. */
    fun nonce(direction: Byte, counter: Long): ByteArray {
        val nonce = ByteArray(12)
        nonce[0] = direction
        for (index in 0 until 8) {
            nonce[1 + index] = (counter ushr (56 - index * 8)).toByte()
        }
        return nonce
    }

    /** Header for one frame; [sequence] is the envelope's per-stream sequence. */
    fun header(
        keyId: ByteArray,
        direction: Byte,
        counter: Long,
        streamKind: Int,
        sequence: Int,
    ): ByteArray {
        require(keyId.size == KEY_ID_LEN) { "key id must be $KEY_ID_LEN bytes" }
        val header = ByteArray(HEADER_LEN)
        header[VERSION_OFFSET] = VERSION
        keyId.copyInto(header, KEY_ID_OFFSET)
        header[DIRECTION_OFFSET] = direction
        for (index in 0 until 8) {
            header[COUNTER_OFFSET + index] = (counter ushr (56 - index * 8)).toByte()
        }
        header[STREAM_KIND_OFFSET] = streamKind.toByte()
        for (index in 0 until 4) {
            header[SEQUENCE_OFFSET + index] = (sequence ushr (24 - index * 8)).toByte()
        }
        return header
    }

    fun readKeyId(frame: ByteArray): ByteArray =
        frame.copyOfRange(KEY_ID_OFFSET, DIRECTION_OFFSET)

    fun readDirection(frame: ByteArray): Byte = frame[DIRECTION_OFFSET]

    fun readCounter(frame: ByteArray): Long {
        var counter = 0L
        for (index in 0 until 8) {
            counter = (counter shl 8) or (frame[COUNTER_OFFSET + index].toLong() and 0xFF)
        }
        return counter
    }

    /**
     * Key id shared by both peers for one identity pair, session, and epoch:
     * `SHA256(label | u16be(len(session)) | session | min(pub) | max(pub) | salt)[0..8]`.
     *
     * Sorting the two public keys makes both directions derive the same id without knowing
     * which peer is asking.
     */
    fun keyId(
        sessionId: String,
        ownPublic: ByteArray,
        peerPublic: ByteArray,
        salt: ByteArray,
    ): ByteArray {
        require(ownPublic.size == X25519.KEY_SIZE && peerPublic.size == X25519.KEY_SIZE) {
            "identity keys must be ${X25519.KEY_SIZE} bytes"
        }
        val (first, second) = if (compare(ownPublic, peerPublic) <= 0) {
            ownPublic to peerPublic
        } else {
            peerPublic to ownPublic
        }
        val session = sessionId.toByteArray(Charsets.UTF_8)
        val digest = MessageDigest.getInstance("SHA-256")
        digest.update(keyIdLabel)
        digest.update((session.size ushr 8).toByte())
        digest.update(session.size.toByte())
        digest.update(session)
        digest.update(first)
        digest.update(second)
        digest.update(salt)
        return digest.digest().copyOf(KEY_ID_LEN)
    }

    /** Lexicographic comparison of two equal-length key arrays, unsigned. */
    fun compare(left: ByteArray, right: ByteArray): Int {
        for (index in 0 until minOf(left.size, right.size)) {
            val difference = (left[index].toInt() and 0xFF) - (right[index].toInt() and 0xFF)
            if (difference != 0) return difference
        }
        return left.size - right.size
    }

    fun hex(bytes: ByteArray): String = bytes.joinToString("") { "%02x".format(it) }
}

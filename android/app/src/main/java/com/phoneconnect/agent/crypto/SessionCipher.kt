package com.phoneconnect.agent.crypto

import com.phoneconnect.agent.EnvelopeCodec
import com.phoneconnect.agent.WireError
import com.phoneconnect.agent.wire.Envelope
import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.spec.IvParameterSpec
import javax.crypto.spec.SecretKeySpec

/** Explicit confidentiality failures; nothing degrades into plaintext or a silent retry. */
sealed class SealedError(message: String) : Exception(message) {
    data object InvalidKeyMaterial : SealedError("identity key material is invalid")
    data object WeakKey : SealedError("the agreed key is degenerate; refusing to use it")
    data object InvalidEpoch : SealedError("connection epoch is missing or empty; re-register with rendezvous")
    data object EpochReused :
        SealedError("this connection epoch was already used for this session and role; fetch a fresh ticket")

    data class Malformed(val reason: String) : SealedError("sealed frame is malformed: $reason")
    data class UnknownKeyId(val found: String, val expected: String) :
        SealedError("sealed frame carries key id $found; this session uses $expected")

    data object WrongDirection : SealedError("sealed frame was sent in the wrong direction")
    data object Authentication : SealedError("frame authentication failed: the ciphertext or its header was changed")
    data class Replayed(val counter: Long) : SealedError("frame counter $counter was already received")
    data class CounterRegression(val counter: Long, val highest: Long) :
        SealedError("frame counter $counter regressed outside the replay window (highest $highest)")

    data object CounterExhausted : SealedError("frame counter space is exhausted; the session must be re-established")
    data class InvalidEnvelope(val reason: String) : SealedError("sealed frame does not contain a valid envelope: $reason")
}

/**
 * Per-frame secrecy and authentication for one session connection, byte-compatible with
 * `crates/transport/src/aead.rs`.
 *
 * Keys: `X25519(own secret, pinned peer public)` → HKDF-SHA256 with salt
 * `session | 0 | client_nonce | 0 | device_nonce` and info `phoneconnect-aead-v1`, expanded
 * to 64 bytes, split into one key per direction. The server only holds public identity keys
 * and cannot derive a traffic key.
 *
 * Every frame has a fresh nonce (`direction | counter`) and authenticates its header plus the
 * session id as associated data, so a captured frame cannot be replayed, a lower counter is a
 * regression, a reflected frame carries the wrong direction, and a frame for another identity
 * pair carries an unknown key id.
 */
class SessionCipher private constructor(
    private val sessionId: String,
    private val role: SessionRole,
    private val keyId: ByteArray,
    private val sendKey: ByteArray,
    private val recvKey: ByteArray,
) {
    private val sendLock = Any()
    private val recvLock = Any()
    private var sendCounter: Long = SealedFrame.FIRST_COUNTER
    private val replayWindow = ReplayWindow()

    val peerDirection: Byte = role.opposite().direction
    val ownDirection: Byte = role.direction

    /** Hex key id both peers of this identity pair, session, and epoch agree on. */
    fun keyId(): String = SealedFrame.hex(keyId)

    /**
     * Seals one envelope. The caller sends the returned bytes; nothing else on the wire
     * describes the frame's contents.
     */
    fun seal(envelope: Envelope): Result<ByteArray> = runCatching {
        val streamKind = EnvelopeCodec.streamKindNumber(EnvelopeCodec.validate(envelope))
        val counter = synchronized(sendLock) {
            val current = sendCounter
            if (current == Long.MAX_VALUE) throw SealedError.CounterExhausted
            sendCounter = current + 1
            current
        }
        val header = SealedFrame.header(
            keyId = keyId,
            direction = role.direction,
            counter = counter,
            streamKind = streamKind,
            sequence = envelope.sequence,
        )
        val aad = SealedFrame.associatedData(sessionId, header)
        val body = invoiceEnvelope(envelope)
        val ciphertext = aead(encrypt = true, key = sendKey, nonce = SealedFrame.nonce(role.direction, counter), aad = aad, input = body)
        header + ciphertext
    }

    /**
     * Opens one sealed frame: authenticate first, then apply the replay window, so a forged
     * frame can never burn a counter and a reordered frame is still delivered.
     */
    fun open(frame: ByteArray): Result<Envelope> = runCatching {
        if (frame.size < SealedFrame.MIN_LEN) {
            throw SealedError.Malformed("sealed frame is ${frame.size} bytes")
        }
        if (frame[SealedFrame.VERSION_OFFSET] != SealedFrame.VERSION) {
            throw SealedError.Malformed("unsupported sealed-frame version ${frame[SealedFrame.VERSION_OFFSET]}")
        }
        val foundKeyId = SealedFrame.readKeyId(frame)
        if (!foundKeyId.contentEquals(keyId)) {
            throw SealedError.UnknownKeyId(SealedFrame.hex(foundKeyId), keyId())
        }
        val direction = SealedFrame.readDirection(frame)
        if (direction != peerDirection) {
            throw SealedError.WrongDirection
        }
        val counter = SealedFrame.readCounter(frame)
        if (counter == 0L) {
            throw SealedError.Malformed("frame counter 0 is reserved")
        }
        val header = frame.copyOfRange(0, SealedFrame.HEADER_LEN)
        val aad = SealedFrame.associatedData(sessionId, header)
        val plaintext = aead(
            encrypt = false,
            key = recvKey,
            nonce = SealedFrame.nonce(direction, counter),
            aad = aad,
            input = frame.copyOfRange(SealedFrame.HEADER_LEN, frame.size),
        )
        synchronized(recvLock) {
            replayWindow.accept(counter).getOrThrow()
        }
        val envelope = EnvelopeCodec.decodeBody(plaintext).getOrElse { error ->
            throw SealedError.InvalidEnvelope(error.message ?: "invalid envelope")
        }
        envelope
    }

    private fun invoiceEnvelope(envelope: Envelope): ByteArray = try {
        envelope.toByteArray()
    } catch (error: RuntimeException) {
        throw SealedError.InvalidEnvelope(error.message ?: "envelope could not be encoded")
    }

    private fun aead(encrypt: Boolean, key: ByteArray, nonce: ByteArray, aad: ByteArray, input: ByteArray): ByteArray {
        val cipher = Cipher.getInstance(TRANSFORMATION)
        cipher.init(
            if (encrypt) Cipher.ENCRYPT_MODE else Cipher.DECRYPT_MODE,
            SecretKeySpec(key, KEY_ALGORITHM),
            IvParameterSpec(nonce),
        )
        cipher.updateAAD(aad)
        return try {
            cipher.doFinal(input)
        } catch (error: javax.crypto.AEADBadTagException) {
            throw SealedError.Authentication
        } catch (error: GeneralSecurityException) {
            throw SealedError.Authentication
        }
    }

    override fun toString(): String = "SessionCipher(session=$sessionId, role=$role, keyId=${keyId()})"

    companion object {
        private const val TRANSFORMATION = "ChaCha20-Poly1305"
        private const val KEY_ALGORITHM = "ChaCha20"

        /**
         * Agrees on the session keys from this peer's identity key and the pinned peer
         * identity key. The server is not part of this computation.
         */
        fun agree(
            own: IdentityKey,
            peerPublic: ByteArray,
            sessionId: String,
            role: SessionRole,
            epoch: Epoch,
        ): Result<SessionCipher> = runCatching {
            if (sessionId.isEmpty()) throw SealedError.InvalidKeyMaterial
            if (peerPublic.size != X25519.KEY_SIZE) throw SealedError.InvalidKeyMaterial
            // Two paths for one session with the same epoch would reuse a ChaCha20-Poly1305
            // nonce, so the second is refused instead of silently repeating keystream.
            EpochClaims.claim(sessionId, role, epoch).getOrThrow()

            val shared = X25519.scalarMultiply(own.secretBytes(), peerPublic)
            if (X25519.isWeak(shared)) throw SealedError.WeakKey

            val salt = epoch.salt(sessionId)
            val okm = HkdfSha256.derive(
                salt = salt,
                inputKeyMaterial = shared,
                info = SealedFrame.AEAD_LABEL.toByteArray(Charsets.UTF_8),
                length = 64,
            )
            shared.fill(0)
            val clientToDevice = okm.copyOfRange(0, 32)
            val deviceToClient = okm.copyOfRange(32, 64)
            val (sendKey, recvKey) = when (role) {
                SessionRole.CLIENT -> clientToDevice to deviceToClient
                SessionRole.DEVICE -> deviceToClient to clientToDevice
            }

            // The key id must be the same for both roles, so it is derived from the sorted
            // public keys rather than from "own" and "peer".
            val ownPublic = own.publicKey()
            val keyId = SealedFrame.keyId(sessionId, ownPublic, peerPublic, salt)

            SessionCipher(sessionId, role, keyId, sendKey, recvKey)
        }
    }
}

/**
 * Epochs this process already used, per session and role. A reconnect must bring fresh
 * tickets; reusing a ticket pair would derive the same keys, which is the one thing AEAD
 * cannot survive.
 */
internal object EpochClaims {
    private const val TTL_MS = 600_000L
    private const val MAX_CLAIMS = 8_192
    private val claimed = LinkedHashMap<String, Long>()

    fun claim(sessionId: String, role: SessionRole, epoch: Epoch): Result<Unit> = runCatching {
        val key = "$sessionId|${role.direction}|${epoch.clientNonce}|${epoch.deviceNonce}"
        synchronized(claimed) {
            val now = System.currentTimeMillis()
            claimed.entries.removeIf { now - it.value >= TTL_MS }
            if (claimed.size >= MAX_CLAIMS && !claimed.containsKey(key)) {
                claimed.remove(claimed.keys.first())
            }
            if (claimed.put(key, now) != null) {
                throw SealedError.EpochReused
            }
        }
    }

    /** Test seam: forget every claim so one test cannot poison another. */
    fun clear() {
        synchronized(claimed) { claimed.clear() }
    }
}

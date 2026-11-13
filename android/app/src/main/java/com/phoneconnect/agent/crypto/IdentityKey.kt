package com.phoneconnect.agent.crypto

import java.security.SecureRandom
import java.util.Base64

/**
 * A static X25519 identity key. The private half never leaves the device; in the agent it is
 * sealed by the Android Keystore before it is stored (`KeystoreEnrollmentStore`).
 *
 * [secretBytes] hands out the live buffer so the transport boundary can use it without a
 * copy; [close] zeroes it.
 */
class IdentityKey private constructor(private val secret: ByteArray) : AutoCloseable {
    private var closed = false

    fun publicKey(): ByteArray {
        check(!closed) { "identity key is closed" }
        return X25519.publicKey(secret)
    }

    fun secretBytes(): ByteArray {
        check(!closed) { "identity key is closed" }
        return secret
    }

    /** Unpadded base64url of the private half, for the sealed enrollment record. */
    fun secretBase64Url(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(secret)

    override fun close() {
        if (closed) return
        closed = true
        secret.fill(0)
    }

    override fun toString(): String = "IdentityKey(public=${publicKeyBase64Url()}, secret=<redacted>)"

    fun publicKeyBase64Url(): String = Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey())

    companion object {
        /** Generation is only reachable from the enrollment/setup boundary. */
        fun generate(): IdentityKey {
            val secret = ByteArray(X25519.KEY_SIZE)
            SecureRandom().nextBytes(secret)
            return IdentityKey(secret)
        }

        fun fromBytes(bytes: ByteArray): Result<IdentityKey> = runCatching {
            if (bytes.size != X25519.KEY_SIZE) {
                throw SealedError.InvalidKeyMaterial
            }
            IdentityKey(bytes.copyOf())
        }

        fun fromBase64Url(value: String): Result<IdentityKey> = runCatching {
            IdentityKey(decode(value))
        }

        fun decode(value: String): ByteArray = try {
            Base64.getUrlDecoder().decode(value.trim())
        } catch (error: IllegalArgumentException) {
            throw SealedError.InvalidKeyMaterial
        }

        fun encode(bytes: ByteArray): String = Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)

        /** A peer's pinned public key from its wire form. */
        fun decodePublicKey(value: String): Result<ByteArray> = runCatching {
            decode(value).also {
                if (it.size != X25519.KEY_SIZE) throw SealedError.InvalidKeyMaterial
            }
        }
    }
}

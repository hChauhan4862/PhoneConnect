package com.phoneconnect.agent.crypto

/**
 * Per-connection key epoch: the two peers' single-use rendezvous nonces in role order.
 *
 * The identity keys are static, so without an epoch the same session id would derive the
 * same keys (and the same ChaCha20-Poly1305 nonces) on every connection. Both peers mix the
 * same pair into the HKDF salt, ordered client-first so they agree.
 */
class Epoch private constructor(
    val clientNonce: String,
    val deviceNonce: String,
) {
    /** HKDF salt: `session_id | 0x00 | client_nonce | 0x00 | device_nonce`. */
    fun salt(sessionId: String): ByteArray {
        val session = sessionId.toByteArray(Charsets.UTF_8)
        val client = clientNonce.toByteArray(Charsets.UTF_8)
        val device = deviceNonce.toByteArray(Charsets.UTF_8)
        val salt = ByteArray(session.size + client.size + device.size + 2)
        var offset = 0
        session.copyInto(salt, offset); offset += session.size
        salt[offset] = 0; offset += 1
        client.copyInto(salt, offset); offset += client.size
        salt[offset] = 0; offset += 1
        device.copyInto(salt, offset)
        return salt
    }

    override fun toString(): String = "Epoch(client=$clientNonce, device=$deviceNonce)"

    companion object {
        fun of(clientNonce: String, deviceNonce: String): Result<Epoch> = runCatching {
            if (clientNonce.isEmpty() || deviceNonce.isEmpty()) {
                throw SealedError.InvalidEpoch
            }
            Epoch(clientNonce, deviceNonce)
        }

        /**
         * Orders this peer's own nonce and the peer's nonce by role, which is what makes both
         * sides derive the same salt.
         */
        fun split(ownNonce: String, peerNonce: String, role: SessionRole): Result<Epoch> = when (role) {
            SessionRole.CLIENT -> of(ownNonce, peerNonce)
            SessionRole.DEVICE -> of(peerNonce, ownNonce)
        }
    }
}

/** Which end of a session this agent is. Direction bytes are on the wire: never change them. */
enum class SessionRole(val direction: Byte) {
    CLIENT(1),
    DEVICE(2),
    ;

    fun opposite(): SessionRole = if (this == CLIENT) DEVICE else CLIENT
}

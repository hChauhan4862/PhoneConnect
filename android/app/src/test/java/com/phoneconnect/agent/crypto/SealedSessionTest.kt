package com.phoneconnect.agent.crypto

import com.phoneconnect.agent.EnvelopeCodec
import com.phoneconnect.agent.wire.StreamKind
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test

/**
 * Cross-implementation vectors and confidentiality properties.
 *
 * The sealed-frame fixtures were produced by the Rust `crates/transport` build
 * (`SessionCipher` with `IdentityKey::from_bytes`, `Epoch::new`, `TicketRole::Client` and
 * `TicketRole::Device`). Matching them byte for byte is what proves the Kotlin port is the
 * same protocol rather than merely self-consistent.
 */
class SealedSessionTest {
    @Before
    fun resetEpochClaims() {
        EpochClaims.clear()
    }

    @Test
    fun `RFC 7748 scalar multiplication vectors`() {
        assertEquals(ALICE_PUBLIC, X25519.publicKey(ALICE_SECRET.hex()).hex())
        assertEquals(BOB_PUBLIC, X25519.publicKey(BOB_SECRET.hex()).hex())
        assertArrayEquals(
            SHARED_SECRET.hex(),
            X25519.scalarMultiply(ALICE_SECRET.hex(), BOB_PUBLIC.hex()),
        )
        assertArrayEquals(
            SHARED_SECRET.hex(),
            X25519.scalarMultiply(BOB_SECRET.hex(), ALICE_PUBLIC.hex()),
        )
    }

    @Test
    fun `public keys match the Rust identity keys used for the frame vectors`() {
        assertEquals(CLIENT_PUBLIC, IdentityKey.encode(X25519.publicKey(CLIENT_SECRET.hex())))
        assertEquals(DEVICE_PUBLIC, IdentityKey.encode(X25519.publicKey(DEVICE_SECRET.hex())))
    }

    @Test
    fun `HKDF-SHA256 matches RFC 5869 test case 1`() {
        val okm = HkdfSha256.derive(
            salt = "000102030405060708090a0b0c".hex(),
            inputKeyMaterial = "0b".repeat(22).hex(),
            info = "f0f1f2f3f4f5f6f7f8f9".hex(),
            length = 42,
        )

        assertEquals(
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865",
            okm.hex(),
        )
    }

    @Test
    fun `the key id matches the Rust implementation for both roles`() {
        val (client, device) = ciphers()

        assertEquals("504ecf1f0e255804", client.keyId())
        assertEquals("504ecf1f0e255804", device.keyId())
    }

    @Test
    fun `the client seal matches the Rust ciphertext byte for byte`() {
        val (client, _) = ciphers()

        val sealed = client.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()

        assertEquals(CLIENT_SEAL_1, sealed.hex())
    }

    @Test
    fun `the device seal matches the Rust ciphertext byte for byte`() {
        val (_, device) = ciphers()

        val sealed = device.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()

        assertEquals(DEVICE_SEAL_1, sealed.hex())
    }

    @Test
    fun `the second frame advances the counter exactly as Rust does`() {
        val (client, _) = ciphers()
        client.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()

        val sealed = client.seal(vectorEnvelope(sequence = 8, payload = "second".toByteArray())).getOrThrow()

        assertEquals(CLIENT_SEAL_2, sealed.hex())
    }

    @Test
    fun `a Rust-sealed frame opens with the same envelope`() {
        val (client, device) = ciphers()

        val openedByDevice = device.open(CLIENT_SEAL_1.hex()).getOrThrow()
        val openedByClient = client.open(DEVICE_SEAL_1.hex()).getOrThrow()

        assertEquals(vectorEnvelope(sequence = 7, payload = PAYLOAD), openedByDevice)
        assertEquals(vectorEnvelope(sequence = 7, payload = PAYLOAD), openedByClient)
    }

    @Test
    fun `the sealed frame carries no plaintext envelope`() {
        val (client, _) = ciphers()

        val sealed = client.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()

        val marker = PAYLOAD.toList()
        assertTrue(
            "the payload marker must not appear in ciphertext",
            sealed.toList().windowed(marker.size).none { it == marker },
        )
        assertNotEquals(
            EnvelopeCodec.encode(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow().hex(),
            sealed.hex(),
        )
    }

    @Test
    fun `a tampered ciphertext is rejected`() {
        val (client, device) = ciphers()
        val sealed = client.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()
        sealed[sealed.size - 1] = (sealed[sealed.size - 1].toInt() xor 0x01).toByte()

        val error = device.open(sealed).exceptionOrNull()

        assertTrue("expected Authentication, got $error", error is SealedError.Authentication)
    }

    @Test
    fun `a tampered header is rejected even though the header is not secret`() {
        val (client, device) = ciphers()
        val sealed = client.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()
        // Change the sequence the header claims; the tag covers it as associated data.
        sealed[SealedFrame.SEQUENCE_OFFSET + 3] = 0xFF.toByte()

        val error = device.open(sealed).exceptionOrNull()

        assertTrue("expected Authentication, got $error", error is SealedError.Authentication)
    }

    @Test
    fun `a replayed frame is refused`() {
        val (client, device) = ciphers()
        val sealed = client.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()

        device.open(sealed).getOrThrow()
        val error = device.open(sealed).exceptionOrNull()

        assertTrue("expected Replayed, got $error", error is SealedError.Replayed)
        assertEquals(1L, (error as SealedError.Replayed).counter)
    }

    @Test
    fun `a counter below the replay window is a regression, not a replay`() {
        val (client, device) = ciphers()
        val frames = (1..ReplayWindow.WINDOW.toInt() + 10).map { index ->
            client.seal(vectorEnvelope(sequence = index, payload = byteArrayOf(index.toByte()))).getOrThrow()
        }

        // Deliver the highest frame first, then one that is now outside the window.
        device.open(frames.last()).getOrThrow()
        val error = device.open(frames.first()).exceptionOrNull()

        assertTrue("expected CounterRegression, got $error", error is SealedError.CounterRegression)
        assertEquals(1L, (error as SealedError.CounterRegression).counter)
        assertEquals(frames.size.toLong(), error.highest)
    }

    @Test
    fun `reordering inside the window is accepted`() {
        val (client, device) = ciphers()
        val frames = (1..3).map { index ->
            client.seal(vectorEnvelope(sequence = index, payload = byteArrayOf(index.toByte()))).getOrThrow()
        }

        device.open(frames[2]).getOrThrow()
        device.open(frames[0]).getOrThrow()
        device.open(frames[1]).getOrThrow()
    }

    @Test
    fun `a reflected frame carries the wrong direction`() {
        val (client, _) = ciphers()
        val sealed = client.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()

        val error = client.open(sealed).exceptionOrNull()

        assertTrue("expected WrongDirection, got $error", error is SealedError.WrongDirection)
    }

    @Test
    fun `a frame from another epoch carries an unknown key id`() {
        val (_, device) = ciphers()
        val otherEpoch = Epoch.of("other-client", "other-device").getOrThrow()
        val other = SessionCipher.agree(
            clientIdentity(),
            devicePublic(),
            SESSION,
            SessionRole.CLIENT,
            otherEpoch,
        ).getOrThrow()
        val sealed = other.seal(vectorEnvelope(sequence = 7, payload = PAYLOAD)).getOrThrow()

        val error = device.open(sealed).exceptionOrNull()

        assertTrue("expected UnknownKeyId, got $error", error is SealedError.UnknownKeyId)
    }

    @Test
    fun `reusing an epoch for the same session and role is refused`() {
        val identity = clientIdentity()
        val epoch = epoch()

        SessionCipher.agree(identity, devicePublic(), SESSION, SessionRole.CLIENT, epoch).getOrThrow()
        val error = SessionCipher.agree(identity, devicePublic(), SESSION, SessionRole.CLIENT, epoch).exceptionOrNull()

        assertTrue("expected EpochReused, got $error", error is SealedError.EpochReused)
        // The other role is a different direction, so it is allowed.
        SessionCipher.agree(identity, devicePublic(), SESSION, SessionRole.DEVICE, epoch).getOrThrow()
    }

    @Test
    fun `a degenerate shared secret is refused`() {
        val error = SessionCipher.agree(
            clientIdentity(),
            ByteArray(X25519.KEY_SIZE),
            SESSION,
            SessionRole.CLIENT,
            epoch(),
        ).exceptionOrNull()

        assertTrue("expected WeakKey, got $error", error is SealedError.WeakKey)
    }

    private fun ciphers(): Pair<SessionCipher, SessionCipher> {
        val client = SessionCipher.agree(
            clientIdentity(),
            devicePublic(),
            SESSION,
            SessionRole.CLIENT,
            epoch(),
        ).getOrThrow()
        val device = SessionCipher.agree(
            deviceIdentity(),
            clientPublic(),
            SESSION,
            SessionRole.DEVICE,
            epoch(),
        ).getOrThrow()
        return client to device
    }

    private fun vectorEnvelope(sequence: Int, payload: ByteArray) =
        EnvelopeCodec.newEnvelope(
            streamKind = StreamKind.STREAM_KIND_CONTROL,
            deviceId = "dev_vector",
            sessionId = SESSION,
            requestId = "req-vector",
        ).toBuilder()
            .setSequence(sequence)
            .setDeadlineUnixMs(1_760_000_000_000)
            .setPayload(com.google.protobuf.ByteString.copyFrom(payload))
            .build()

    private fun epoch() = Epoch.of(CLIENT_NONCE, DEVICE_NONCE).getOrThrow()

    private fun clientIdentity() = IdentityKey.fromBytes(CLIENT_SECRET.hex()).getOrThrow()

    private fun deviceIdentity() = IdentityKey.fromBytes(DEVICE_SECRET.hex()).getOrThrow()

    private fun clientPublic() = clientIdentity().publicKey()

    private fun devicePublic() = deviceIdentity().publicKey()

    private fun String.hex(): ByteArray {
        require(length % 2 == 0) { "hex needs an even length" }
        return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private fun ByteArray.hex(): String = joinToString("") { "%02x".format(it) }

    private companion object {
        const val SESSION = "sess_aead_vector"
        const val CLIENT_NONCE = "client-nonce-vector"
        const val DEVICE_NONCE = "device-nonce-vector"
        val PAYLOAD = "PC-AEAD-VECTOR".toByteArray()

        // RFC 7748 §6.1.
        const val ALICE_SECRET = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
        const val ALICE_PUBLIC = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        const val BOB_SECRET = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
        const val BOB_PUBLIC = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
        const val SHARED_SECRET = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

        // Identity keys and sealed frames produced by crates/transport.
        const val CLIENT_SECRET = "1111111111111111111111111111111111111111111111111111111111111111"
        const val DEVICE_SECRET = "2222222222222222222222222222222222222222222222222222222222222222"
        const val CLIENT_PUBLIC = "e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM"
        const val DEVICE_PUBLIC = "D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyA"
        const val CLIENT_SEAL_1 =
            "01504ecf1f0e2558040100000000000000010100000007b59b0e9fb8996ab7f56fcc7464ccc7f7f770d9326a" +
            "c4028b1fca418387e2085c9dae59bb6a66ad9d87d7ca2c858cadbaaa9d852f7ed409c2f4440ae2886c071183" +
            "732fe62ef36e5d89567ce815d19252cfa1d56080d24f"
        const val DEVICE_SEAL_1 =
            "01504ecf1f0e2558040200000000000000010100000007b35320ed79c8000e92ecca095bc94dea457c569927" +
            "9a3c92c093cf2dde8b38c8b7167486ac4bc8a9a4a056e33b2b79c7c2e9f617cf94951f4cd0a24a66c657b224" +
            "5b189f19df2fa6149d389b76a47d525fd3d763c07e7b"
        const val CLIENT_SEAL_2 =
            "01504ecf1f0e25580401000000000000000201000000081766d373197ace7bbbcb6d38864a2bf2c4c2154a6a" +
            "1b28e27e94bc674740c80df5e2a56c7c61a9a8c27ada73343e909b3b8db62fac696aff2899cf05080f8ee5af" +
            "9878e185d324fa728142ec6c63e8"
    }
}

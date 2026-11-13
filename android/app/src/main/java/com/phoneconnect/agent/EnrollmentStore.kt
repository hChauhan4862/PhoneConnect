package com.phoneconnect.agent

/**
 * Marks the one place device secrets may be decrypted and used.
 *
 * Enrollment storage deliberately has no method that returns a credential or a private key
 * to general agent code. The methods behind this marker are usable only by a file that
 * explicitly opts in (the transport/identity boundary), so a feature adapter cannot read a
 * device credential by accident.
 */
@RequiresOptIn(
    level = RequiresOptIn.Level.ERROR,
    message = "Device secrets belong to the transport/identity boundary, never to general agent code.",
)
@Retention(AnnotationRetention.BINARY)
@Target(
    AnnotationTarget.CLASS,
    AnnotationTarget.FUNCTION,
    AnnotationTarget.PROPERTY,
    AnnotationTarget.CONSTRUCTOR,
)
annotation class IdentityBoundary

/** Lifecycle of the locally stored enrollment. */
enum class EnrollmentState {
    ENROLLED,
    REVOKED,
}

/** Non-secret enrollment description: safe for the status surface and the retry loop. */
data class EnrollmentInfo(
    val deviceId: String,
    val state: EnrollmentState,
    val enrolledAtMs: Long,
)

/**
 * What a finished enrollment hands to the store. The server issues [deviceId] and
 * [credential]; [identityPrivateKey] never leaves the device and is wrapped before it
 * touches disk.
 */
data class EnrollmentRequest(
    val deviceId: String,
    val credential: String,
    val identityPrivateKey: ByteArray,
    val identityPublicKey: ByteArray,
    val enrolledAtMs: Long,
)

/** Why an enrollment was removed; the setup UI reads this to explain recovery. */
enum class ClearReason {
    UNENROLLED,
    REVOKED,
    SERVER_REJECTED,
    UNREADABLE,
}

/** A storage failure that must not be mistaken for a healthy enrollment. */
class EnrollmentStorageException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * Enrollment state for the agent.
 *
 * Only [info], [lastClearReason], and [clear] are general-purpose: they carry no secret and
 * are what the status surface and the reconnect loop use. [enroll] and [openIdentity] sit
 * behind [IdentityBoundary], and the store decrypts inside [openIdentity], so plaintext
 * never becomes a return value of general agent code.
 */
interface EnrollmentStore {
    suspend fun info(): EnrollmentInfo?

    /** Why the last enrollment was cleared, so recovery can be explained. */
    suspend fun lastClearReason(): ClearReason?

    @IdentityBoundary
    suspend fun enroll(request: EnrollmentRequest)

    /** Decrypts this device's secrets for one transport attempt; close it when the attempt ends. */
    @IdentityBoundary
    suspend fun openIdentity(): DeviceIdentity?

    suspend fun clear(reason: ClearReason): Boolean
}

/**
 * Decrypted secrets for exactly one session attempt. [close] zeroes them, so a transport
 * cannot keep using a credential after its stream ended.
 *
 * The secret accessors hand out the live buffers rather than copies: the boundary is
 * expected to use them and let [close] wipe them, not to retain them.
 */
@IdentityBoundary
class DeviceIdentity internal constructor(
    val deviceId: String,
    private val credentialBytes: ByteArray,
    private val privateKeyBytes: ByteArray,
    val identityPublicKey: ByteArray,
) : AutoCloseable {
    private var closed = false

    /** Credential bytes for the authenticated HTTP/transport handshake. */
    fun credentialForTransport(): ByteArray {
        check(!closed) { "identity is closed" }
        return credentialBytes
    }

    /** X25519 private key for the session key agreement. */
    fun identityPrivateKeyForTransport(): ByteArray {
        check(!closed) { "identity is closed" }
        return privateKeyBytes
    }

    override fun close() {
        if (closed) return
        closed = true
        credentialBytes.fill(0)
        privateKeyBytes.fill(0)
    }

    override fun toString(): String = "DeviceIdentity(deviceId=$deviceId, secrets=<redacted>)"
}

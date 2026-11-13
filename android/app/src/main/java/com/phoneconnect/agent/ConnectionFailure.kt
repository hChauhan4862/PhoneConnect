package com.phoneconnect.agent

/** Transient reason a session ended and may be retried. */
enum class ReconnectReason {
    NETWORK_UNAVAILABLE,
    SERVER_UNREACHABLE,
    TRANSPORT_CLOSED,
    TICKET_EXPIRED,
    PROTOCOL_ERROR,

    /** The session (or the control lease behind it) ended; wait for a new one. */
    SESSION_ENDED,
}

/**
 * Why one connection attempt ended.
 *
 * Only a dead credential stops the agent: [DeviceRevoked] and [NotEnrolled]. Every
 * session-scoped failure ([SessionEnded], [RelayUnavailable], and [Retryable]) leaves the
 * enrollment usable and resumes on a fresh session, so a routine lease revocation or the
 * five-minute session expiry never takes the phone offline until reboot. [retryReason]
 * names the reason the status surface reports; `null` means terminal.
 */
sealed interface ConnectionFailure {
    /** The server revoked this device (`device_revoked`). The credential is dead. */
    data object DeviceRevoked : ConnectionFailure

    /** The server has no enrollment for this device (`device_unknown`, cleared locally). */
    data object NotEnrolled : ConnectionFailure

    /**
     * The relay lease for this session was refused with `409 relay_unavailable`. That is
     * terminal *for the session id*, not for the agent: the runner abandons the id and
     * waits for a new session. The device credential stays valid.
     */
    data object RelayUnavailable : ConnectionFailure

    /**
     * The session expired, closed, or was revoked server-side, or the control lease that
     * authorized it was revoked. The enrollment stays valid; a new session is needed.
     */
    data object SessionEnded : ConnectionFailure

    /**
     * The server keeps answering an authentication failure with a code this build cannot
     * classify. Continuing would retry forever with no operator-visible outcome, so after a
     * bounded number of consecutive refusals the agent stops — and keeps the enrollment, so
     * a server fix or a re-enrollment recovers the device.
     */
    data class CredentialRejected(val code: String) : ConnectionFailure

    data class Retryable(val reason: ReconnectReason) : ConnectionFailure
}

/**
 * The reason to retry with, or `null` when nothing can be retried because the credential is
 * gone. A session-scoped failure retries with [ReconnectReason.SESSION_ENDED] so the status
 * text says the session ended rather than claiming a protocol fault.
 */
val ConnectionFailure.retryReason: ReconnectReason?
    get() = when (this) {
        ConnectionFailure.DeviceRevoked, ConnectionFailure.NotEnrolled,
        is ConnectionFailure.CredentialRejected,
        -> null

        ConnectionFailure.RelayUnavailable, ConnectionFailure.SessionEnded ->
            ReconnectReason.SESSION_ENDED

        is ConnectionFailure.Retryable -> reason
    }

/** How much locally stored state a terminal failure invalidates. */
enum class Invalidation {
    NONE,
    SESSION,
    ENROLLMENT,
}

val ConnectionFailure.isTerminal: Boolean
    get() = retryReason == null

val ConnectionFailure.invalidation: Invalidation
    get() = when (this) {
        ConnectionFailure.DeviceRevoked, ConnectionFailure.NotEnrolled -> Invalidation.ENROLLMENT
        // The session id is not persisted, so there is nothing local to invalidate: the
        // supervisor simply awaits a new session. A rejected credential is kept on purpose:
        // the operator sees the terminal reason and can fix the server or re-enroll.
        else -> Invalidation.NONE
    }

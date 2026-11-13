package com.phoneconnect.agent

/** Transient reason a session ended and may be retried. */
enum class ReconnectReason {
    NETWORK_UNAVAILABLE,
    SERVER_UNREACHABLE,
    TRANSPORT_CLOSED,
    PROTOCOL_ERROR,
}

/**
 * Why one connection attempt ended.
 *
 * Terminal failures stop the retry loop; [invalidation] says how much state they kill. A
 * retryable failure always carries a [ReconnectReason] so the status surface can explain
 * what is being retried.
 */
sealed interface ConnectionFailure {
    /** The server revoked this device (`device_revoked`). The credential is dead. */
    data object DeviceRevoked : ConnectionFailure

    /** The server has no enrollment for this device (`device_unknown`, cleared locally). */
    data object NotEnrolled : ConnectionFailure

    /**
     * The relay lease for this session was refused with `409 relay_unavailable`. The
     * protocol makes that terminal *for the session id*: a new session is needed, and the
     * same one is never retried. The device credential stays valid.
     */
    data object RelayUnavailable : ConnectionFailure

    /** The session expired, closed, or was revoked server-side. Enroll again is not needed. */
    data object SessionEnded : ConnectionFailure

    data class Retryable(val reason: ReconnectReason) : ConnectionFailure
}

/** How much locally stored state a terminal failure invalidates. */
enum class Invalidation {
    NONE,
    SESSION,
    ENROLLMENT,
}

val ConnectionFailure.isTerminal: Boolean
    get() = when (this) {
        ConnectionFailure.DeviceRevoked,
        ConnectionFailure.NotEnrolled,
        ConnectionFailure.RelayUnavailable,
        ConnectionFailure.SessionEnded,
        -> true

        is ConnectionFailure.Retryable -> false
    }

val ConnectionFailure.invalidation: Invalidation
    get() = when (this) {
        ConnectionFailure.DeviceRevoked, ConnectionFailure.NotEnrolled -> Invalidation.ENROLLMENT
        ConnectionFailure.RelayUnavailable, ConnectionFailure.SessionEnded -> Invalidation.SESSION
        is ConnectionFailure.Retryable -> Invalidation.NONE
    }

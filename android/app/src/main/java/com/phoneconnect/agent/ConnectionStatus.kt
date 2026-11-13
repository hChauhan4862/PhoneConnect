package com.phoneconnect.agent

/** What the single connection notification says, and what the setup UI reads. */
sealed interface ConnectionStatus {
    data class Connecting(val attempt: Int) : ConnectionStatus

    data class Connected(val path: ConnectionPath, val sinceMs: Long) : ConnectionStatus

    data class Reconnecting(
        val attempt: Int,
        val retryInMs: Long,
        val reason: ReconnectReason,
    ) : ConnectionStatus

    /** Retrying has stopped; [failure] is the reason and decides what was invalidated. */
    data class Terminal(val failure: ConnectionFailure) : ConnectionStatus

    /** Nothing to connect with until the device is enrolled again. */
    data object Unenrolled : ConnectionStatus

    /** The agent is installed but something it needs is missing; the message says what. */
    data class ActionRequired(val message: String) : ConnectionStatus
}

/** Which transport path a healthy session is using. */
enum class ConnectionPath {
    DIRECT,
    RELAY,
}

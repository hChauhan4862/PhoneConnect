package com.phoneconnect.agent

/** What the single connection notification says, and what the setup UI reads. */
sealed interface ConnectionStatus {
    data class Connecting(val attempt: Int) : ConnectionStatus

    data class Connected(
        val path: ConnectionPath,
        val sinceMs: Long,
        /**
         * The management channel's state. It shares this service and this notification, but
         * a healthy sealed session does not imply the command channel is up.
         */
        val management: ManagementChannelState = ManagementChannelState.OFFLINE,
    ) : ConnectionStatus

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

/**
 * The management channel's state, reported beside the sealed session: telemetry and commands
 * travel on it, so "connected" alone would not say whether the device can be managed.
 */
enum class ManagementChannelState {
    /** Nothing is connected and nothing is retrying. */
    OFFLINE,
    CONNECTING,
    /** Commands and telemetry are flowing. */
    ONLINE,
    /** The channel dropped or was refused; it is waiting out its bounded backoff. */
    RETRYING,
}

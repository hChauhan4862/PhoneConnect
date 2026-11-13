package com.phoneconnect.agent

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.content.Context
import androidx.core.app.NotificationCompat

/**
 * The agent's one notification. Every connection, telemetry, reconnect, and session state
 * updates this notification in place: there is exactly one id, one channel, and one
 * `startForeground` call site (in `ConnectionService`), so a second status notification
 * cannot exist.
 *
 * The text states what the agent is doing and what the user can do about it. It never
 * promises that Android will keep the process alive: ordinary apps can always be stopped.
 */
class NotificationController(
    context: Context,
    private val manager: NotificationManager,
) {
    private val appContext: Context = context.applicationContext

    /** Creates the single channel idempotently; calling it again changes nothing. */
    fun ensureChannel() {
        if (manager.getNotificationChannel(CHANNEL_ID) != null) {
            return
        }
        val channel = NotificationChannel(
            CHANNEL_ID,
            appContext.getString(R.string.connection_channel_name),
            NotificationManager.IMPORTANCE_LOW,
        ).apply {
            description = appContext.getString(R.string.connection_channel_description)
            setShowBadge(false)
            enableVibration(false)
        }
        manager.createNotificationChannel(channel)
    }

    /** Updates the one notification. It can never add another one. */
    fun update(status: ConnectionStatus, ongoing: Boolean = true) {
        manager.notify(NOTIFICATION_ID, build(status, ongoing))
    }

    fun clear() {
        manager.cancel(NOTIFICATION_ID)
    }

    /**
     * The notification for [status]. [ongoing] is false for a final status the service is
     * about to detach: the reason must stay readable, and the user must be able to dismiss it.
     */
    fun build(status: ConnectionStatus, ongoing: Boolean = true): Notification {
        val text = text(status)
        return NotificationCompat.Builder(appContext, CHANNEL_ID)
            .setSmallIcon(R.drawable.ic_stat_connection)
            .setContentTitle(appContext.getString(R.string.connection_notification_title))
            .setContentText(text)
            .setStyle(NotificationCompat.BigTextStyle().bigText(text))
            .setOngoing(ongoing)
            .setSilent(true)
            .setShowWhen(false)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .build()
    }

    /** What the user reads for [status]; also what the status UI shows. */
    fun text(status: ConnectionStatus): String = when (status) {
        is ConnectionStatus.Connecting ->
            "Connecting to the PhoneConnect server (attempt ${status.attempt + 1}). " + BEST_EFFORT

        is ConnectionStatus.Connected -> when (status.path) {
            ConnectionPath.DIRECT -> "Connected over a direct path."
            ConnectionPath.RELAY -> "Connected over the server relay."
        }

        is ConnectionStatus.Reconnecting ->
            "Retrying in ${seconds(status.retryInMs)} (attempt ${status.attempt}): " +
                "${describe(status.reason)}. $BEST_EFFORT"

        is ConnectionStatus.Terminal -> terminalText(status.failure)

        ConnectionStatus.Unenrolled ->
            "Not enrolled. Open PhoneConnect to enroll this device with your server."

        is ConnectionStatus.ActionRequired -> status.message
    }

    private fun terminalText(failure: ConnectionFailure): String = when (failure) {
        ConnectionFailure.DeviceRevoked ->
            "Stopped: this device was revoked. Enroll it again from the PhoneConnect server."

        ConnectionFailure.NotEnrolled ->
            "Stopped: the server has no enrollment for this device. Enroll it again."

        ConnectionFailure.RelayUnavailable ->
            "Stopped: the relay refused this session. Start a new session from the server."

        ConnectionFailure.SessionEnded ->
            "Stopped: the session ended. A new session is needed."

        is ConnectionFailure.CredentialRejected ->
            "Stopped: the server rejected this device's credential (${failure.code}). " +
                "Check the server configuration, then enroll this device again if the credential was rotated."

        // The server's own answer for a ticket with no pinned identity is that the device must
        // be enrolled again; a new session would not fix it. Every other refusal here is a
        // scope mismatch, which a new session does fix.
        is ConnectionFailure.SessionRefused ->
            if (failure.code == "ticket_identity_missing") {
                "Stopped: the server has no identity pinned for this device's ticket. " +
                    "Enroll this device again from the PhoneConnect server."
            } else {
                "Stopped: the server refused this session (${failure.code}). The device stays " +
                    "enrolled; create a new session from the PhoneConnect server."
            }

        is ConnectionFailure.Retryable -> "Stopped: ${describe(failure.reason)}."
    }

    private fun describe(reason: ReconnectReason): String = when (reason) {
        ReconnectReason.NETWORK_UNAVAILABLE -> "no network"
        ReconnectReason.SERVER_UNREACHABLE -> "server unreachable"
        ReconnectReason.TRANSPORT_CLOSED -> "connection closed"
        ReconnectReason.TICKET_EXPIRED -> "rendezvous ticket expired"
        ReconnectReason.PROTOCOL_ERROR -> "protocol error"
        ReconnectReason.SESSION_ENDED -> "session ended; waiting for a new one"
    }

    private fun seconds(milliseconds: Long): String =
        if (milliseconds >= 1_000) "${milliseconds / 1_000}s" else "$milliseconds ms"

    companion object {
        /**
         * The only notification id the agent ever posts. Keeping it a single constant is
         * what makes "one persistent notification" checkable rather than a convention.
         */
        const val NOTIFICATION_ID: Int = 0x5043

        /** The only channel the agent creates. */
        const val CHANNEL_ID: String = "connection"

        private const val BEST_EFFORT =
            "Android can still stop background apps, so this connection is best effort."

        fun create(context: Context): NotificationController =
            NotificationController(context, context.getSystemService(NotificationManager::class.java))
    }
}

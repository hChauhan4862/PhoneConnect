package com.phoneconnect.agent

import android.app.Service
import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.IBinder
import androidx.core.content.ContextCompat
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.launch

/**
 * The agent's only foreground service and only notification.
 *
 * It owns the lifecycle (foreground start, boot/network recovery, cancellation on stop) and
 * delegates the reconnect policy to [ConnectionSupervisor] and the notification to
 * [NotificationController]. Control, telemetry, reconnect, and session state all update the
 * one notification id; nothing here can create a second one.
 *
 * This is an ordinary app: the OS may stop it at any time, and the status text says so.
 * `START_STICKY` is best effort, not a guarantee.
 */
open class ConnectionService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var notifications: NotificationController
    private var loop: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null

    override fun onCreate() {
        super.onCreate()
        notifications = NotificationController.create(this)
        notifications.ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopConnection()
            stopSelf()
            return START_NOT_STICKY
        }

        val runner = sessionRunner()

        // The only startForeground call site: the service is foreground from its first
        // moment and every later state updates this same notification.
        startForeground(NotificationController.NOTIFICATION_ID, notifications.build(initialStatus(runner)))

        if (loop?.isActive != true) {
            startLoop(runner)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        releaseNetworkRecovery()
        loop?.cancel()
        loop = null
        serviceScope.cancel()
        notifications.clear()
        super.onDestroy()
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** Composition point for the sealed session transport. */
    internal open fun sessionRunner(): SessionRunner? = null

    /** Composition point for enrollment storage. */
    internal open fun enrollmentStore(): EnrollmentStore = KeystoreEnrollmentStore(this)

    private fun initialStatus(runner: SessionRunner?): ConnectionStatus =
        if (runner == null) {
            ConnectionStatus.ActionRequired(
                "The connection transport is not installed in this build. Reinstall a complete agent.",
            )
        } else {
            ConnectionStatus.Connecting(0)
        }

    private fun startLoop(runner: SessionRunner?) {
        if (runner == null) return
        val supervisor = ConnectionSupervisor(
            store = enrollmentStore(),
            sessions = runner,
            policy = ReconnectPolicy(),
            status = notifications::update,
        )
        registerNetworkRecovery(supervisor)
        loop = serviceScope.launch { supervisor.run() }
    }

    private fun stopConnection() {
        loop?.cancel()
        loop = null
        releaseNetworkRecovery()
        notifications.clear()
    }

    /** Recovers immediately when connectivity returns instead of waiting out a backoff. */
    private fun registerNetworkRecovery(supervisor: ConnectionSupervisor) {
        releaseNetworkRecovery()
        val connectivity = getSystemService(ConnectivityManager::class.java) ?: return
        val callback = object : ConnectivityManager.NetworkCallback() {
            override fun onAvailable(network: Network) {
                supervisor.onNetworkAvailable()
            }
        }
        val request = NetworkRequest.Builder()
            .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
            .build()
        try {
            connectivity.registerNetworkCallback(request, callback)
            networkCallback = callback
        } catch (error: SecurityException) {
            // Without network permission the loop still retries, just without a wake-up.
            networkCallback = null
        }
    }

    private fun releaseNetworkRecovery() {
        val callback = networkCallback ?: return
        networkCallback = null
        try {
            getSystemService(ConnectivityManager::class.java)?.unregisterNetworkCallback(callback)
        } catch (error: IllegalArgumentException) {
            // Already unregistered.
        }
    }

    companion object {
        const val ACTION_START = "com.phoneconnect.agent.action.START"
        const val ACTION_STOP = "com.phoneconnect.agent.action.STOP"

        fun startIntent(context: Context): Intent =
            Intent(context, ConnectionService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, ConnectionService::class.java).setAction(ACTION_STOP)

        /** Asks for the one service; foreground start rules are the caller's to satisfy. */
        fun requestStart(context: Context) {
            ContextCompat.startForegroundService(context, startIntent(context))
        }
    }
}

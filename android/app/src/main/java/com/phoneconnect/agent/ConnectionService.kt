package com.phoneconnect.agent

import android.app.Activity
import android.app.ForegroundServiceStartNotAllowedException
import android.app.Service
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.os.Build
import android.os.IBinder
import androidx.annotation.RequiresApi
import androidx.core.content.ContextCompat
import androidx.core.content.IntentCompat
import com.phoneconnect.agent.control.AndroidAppPlatform
import com.phoneconnect.agent.control.AppsHandler
import com.phoneconnect.agent.control.CommandDispatcher
import com.phoneconnect.agent.control.FileHandler
import com.phoneconnect.agent.control.LogcatHandler
import com.phoneconnect.agent.control.MediaProjectionScreenCapture
import com.phoneconnect.agent.control.PathGuard
import com.phoneconnect.agent.control.ScreenCapture
import com.phoneconnect.agent.control.ScreenHandler
import com.phoneconnect.agent.control.ShellHandler
import com.phoneconnect.agent.control.SystemPropertiesHandler
import com.phoneconnect.agent.net.DeviceControlChannel
import com.phoneconnect.agent.net.HubClient
import com.phoneconnect.agent.net.TransportSessionRunner
import com.phoneconnect.agent.telemetry.TelemetrySampler
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.io.File

/** Outcome of asking the system for the foreground service. */
sealed interface StartResult {
    data object Started : StartResult

    /** The system refused the start (background-start restrictions); the reason is for the UI. */
    data class Refused(val reason: String) : StartResult
}

/** The screen-capture consent a user just granted, carried from the setup screen to the service. */
data class CaptureGrant(val resultCode: Int, val data: Intent)

/**
 * The management connection the service runs beside the sealed session.
 *
 * An implementation owns its own bounded retry loop and reports every state change through
 * `onState`. It never starts a service, posts a notification, or publishes a status: there is
 * exactly one foreground service and one notification, and [ConnectionService] owns both.
 */
fun interface ManagementChannel {
    suspend fun run(store: EnrollmentStore, onState: suspend (ManagementChannelState) -> Unit)
}

/**
 * The agent's only foreground service and only notification.
 *
 * It owns the lifecycle (foreground start, boot/network recovery, cancellation on stop) and
 * delegates the reconnect policy to [ConnectionSupervisor], the session to the configured
 * [SessionRunner], and the notification to [NotificationController]. Control, telemetry,
 * reconnect, and session state all update the one notification id; nothing here can create a
 * second one.
 *
 * The service type is `connectedDevice`: this app's job is a long-lived authenticated
 * connection, and `dataSync` would cap it at six hours a day and cannot legally be started
 * from `BOOT_COMPLETED` on Android 15.
 *
 * This is an ordinary app: the OS may stop it at any time, and the status text says so.
 * `START_STICKY` is best effort, not a guarantee.
 */
open class ConnectionService : Service() {
    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var notifications: NotificationController
    private var loop: Job? = null
    private var managementJob: Job? = null
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    private var detachedStatus = false
    private var lastStatus: ConnectionStatus? = null

    /**
     * The projection the user granted on the setup screen, held for this service's lifetime.
     * Android cannot persist the token across process death, so after a restart the command
     * answers `consent_required` until the user grants it again. Lazy: a service that never
     * captures never touches `MediaProjection`.
     */
    private val screenCapture: ScreenCapture by lazy { screenCaptureProvider() }

    /** Written and read on the main thread only. */
    private var managementState = ManagementChannelState.OFFLINE

    override fun onCreate() {
        super.onCreate()
        notifications = NotificationController.create(this)
        notifications.ensureChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            screenCapture.release()
            captureEnded()
            stopConnection()
            stopSelf()
            return START_NOT_STICKY
        }

        val runner = sessionRunner()
        val grant = captureGrant(intent)

        // The only startForeground call site. The projection type is declared *before* the
        // grant is used: from Android 14 the service must already be running with
        // `mediaProjection` when the token is acquired, and the notification stays the same
        // single id and channel.
        enterForeground(runner, projection = grant != null || screenCapture.available())

        if (intent?.action == ACTION_REVOKE_CAPTURE) {
            screenCapture.release()
            captureEnded()
            enterForeground(runner, projection = false)
        }
        if (grant != null) {
            // The system can end the projection at any time ("Stop sharing", a lock screen);
            // the screen must stop claiming capture is on when it does.
            screenCapture.accept(grant.resultCode, grant.data) {
                captureEnded()
                // The mediaProjection type must not outlive the projection. The callback can
                // arrive on the capture worker or the main looper; the service scope keeps the
                // foreground update on the main thread, and a detached (stopping) service is
                // never made foreground again.
                serviceScope.launch {
                    if (!detachedStatus) enterForeground(runner, projection = false)
                }
            }
            if (screenCapture.available()) {
                captureGranted()
            } else {
                // A refused token means the type must not claim a projection we do not hold.
                captureEnded()
                enterForeground(runner, projection = false)
            }
        }

        if (loop?.isActive != true) {
            startLoop(runner)
        }
        return START_STICKY
    }

    override fun onDestroy() {
        releaseNetworkRecovery()
        loop?.cancel()
        loop = null
        managementJob?.cancel()
        managementJob = null
        // A projection is a session, not a preference: it must not outlive the service that
        // declared the type it runs under.
        screenCapture.release()
        captureEnded()
        serviceScope.cancel()
        // A terminal status is deliberately left visible after the service stops.
        if (!detachedStatus) {
            notifications.clear()
        }
        super.onDestroy()
    }

    /**
     * The system's last-resort callback when a foreground service exceeds its time limit.
     * Nothing is left running: the loop stops and the notification goes away, so the agent
     * never becomes a zombie the user cannot see or stop.
     */
    override fun onTimeout(startId: Int, fgsType: Int) {
        AgentDiagnostics(this).recordStartRefusal(REFUSAL_FOREGROUND_TIMEOUT)
        stopConnection()
        stopSelf(startId)
    }

    override fun onBind(intent: Intent?): IBinder? = null

    /** Composition point for the sealed session transport. */
    internal open fun sessionRunner(): SessionRunner? {
        val hubUrl = AgentSettings(this).hubUrl() ?: return null
        val hub = HubClient.create(hubUrl).getOrElse { return null }
        return TransportSessionRunner(hub)
    }

    /**
     * Composition point for the management channel: the service's second connection.
     * `null` means this build cannot manage the device (no hub URL configured).
     */
    internal open fun managementChannel(): ManagementChannel? {
        val hubUrl = AgentSettings(this).hubUrl() ?: return null
        val hub = HubClient.create(hubUrl).getOrElse { return null }
        val sampler = TelemetrySampler.fromContext(this)
        return DeviceControlChannel(
            hub = hub,
            dispatcher = CommandDispatcher(
                telemetry = sampler,
                files = FileHandler(PathGuard(filesRoot())),
                apps = AppsHandler(AndroidAppPlatform(this)),
                screen = ScreenHandler(screenCapture),
                props = SystemPropertiesHandler(),
                shell = ShellHandler(),
                logcat = LogcatHandler(),
            ),
            telemetry = sampler,
        )
    }

    /**
     * Composition point for the projection. The only production implementation talks to
     * `MediaProjection`; tests inject one that records the grant lifecycle.
     */
    internal open fun screenCaptureProvider(): ScreenCapture = MediaProjectionScreenCapture(this)

    /**
     * The one directory file commands may touch: this app's own external files directory,
     * which needs no storage permission and is removed with the app. Never `/`, never shared
     * storage at large.
     */
    private fun filesRoot(): File = getExternalFilesDir(null) ?: filesDir

    /** Dispatcher for the management channel's socket work; tests override it. */
    internal open fun managementDispatcher(): CoroutineDispatcher = Dispatchers.IO

    /** Composition point for enrollment storage. */
    internal open fun enrollmentStore(): EnrollmentStore = KeystoreEnrollmentStore(this)

    /** Dispatcher for storage work; production uses IO, tests override it. */
    internal open fun storageDispatcher(): CoroutineDispatcher = Dispatchers.IO

    /**
     * The only place the service becomes foreground. [projection] adds the mediaProjection
     * type; the notification id and channel never change, so there is still exactly one
     * notification.
     */
    private fun enterForeground(runner: SessionRunner?, projection: Boolean) {
        val status = lastStatus ?: initialStatus(runner)
        val notification = notifications.build(status)
        // The typed form is API 29+; API 28 has no foreground-service types to declare.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            startForeground(
                NotificationController.NOTIFICATION_ID,
                notification,
                if (projection) {
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE or
                        ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PROJECTION
                } else {
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE
                },
            )
        } else {
            startForeground(NotificationController.NOTIFICATION_ID, notification)
        }
    }

    /** The consent result the setup screen handed over, or `null` when it did not grant one. */
    private fun captureGrant(intent: Intent?): CaptureGrant? {
        if (intent?.action != ACTION_GRANT_CAPTURE) return null
        val resultCode = intent.getIntExtra(EXTRA_CAPTURE_RESULT_CODE, Activity.RESULT_CANCELED)
        val data = IntentCompat.getParcelableExtra(intent, EXTRA_CAPTURE_RESULT_DATA, Intent::class.java)
            ?: return null
        if (resultCode != Activity.RESULT_OK) return null
        return CaptureGrant(resultCode, data)
    }

    private fun initialStatus(runner: SessionRunner?): ConnectionStatus =
        if (runner == null) {
            ConnectionStatus.ActionRequired(
                "Not set up yet. Open PhoneConnect to enter your hub URL and enroll this device.",
            )
        } else {
            ConnectionStatus.Connecting(0)
        }

    private fun startLoop(runner: SessionRunner?) {
        if (runner == null) return
        loop = serviceScope.launch {
            // SharedPreferences loads and Keystore access stay off the main thread.
            val store = withContext(storageDispatcher()) { enrollmentStore() }
            // The second connection: same service, same notification, its own retry loop.
            // It is a sibling of the session loop, not its child: a terminal session
            // outcome must be able to stop the service without waiting for it.
            managementChannel()?.let { channel ->
                managementJob = serviceScope.launch { runManagement(channel, store) }
            }
            val supervisor = ConnectionSupervisor(
                store = store,
                sessions = runner,
                policy = ReconnectPolicy(),
                status = ::publishStatus,
                management = { managementState },
            )
            registerNetworkRecovery(supervisor)
            handleOutcome(supervisor.run())
        }
    }

    private suspend fun runManagement(channel: ManagementChannel, store: EnrollmentStore) {
        withContext(managementDispatcher()) {
            channel.run(store) { state ->
                withContext(Dispatchers.Main.immediate) { publishManagementState(state) }
            }
        }
    }

    /** The one place a status reaches the bus and the notification. */
    private fun publishStatus(status: ConnectionStatus) {
        val effective = if (status is ConnectionStatus.Connected) {
            status.copy(management = managementState)
        } else {
            status
        }
        lastStatus = effective
        ConnectionStatusBus.publish(effective)
        notifications.update(effective)
    }

    /** A management state change updates the same notification, never a second one. */
    private fun publishManagementState(state: ManagementChannelState) {
        managementState = state
        val connected = lastStatus as? ConnectionStatus.Connected ?: return
        val updated = connected.copy(management = state)
        lastStatus = updated
        ConnectionStatusBus.publish(updated)
        notifications.update(updated)
    }

    /**
     * A terminal or unenrolled outcome means nothing is retrying, so the service stops being
     * foreground and ends. The status notification is detached, not cancelled: the user can
     * still read why it stopped, and a later enrollment starts a fresh service instance.
     */
    private fun handleOutcome(outcome: SupervisorOutcome) {
        when (outcome) {
            is SupervisorOutcome.Terminal, SupervisorOutcome.Unenrolled -> {
                // Leave the reason visible but dismissible: an ongoing notification would
                // stay pinned forever because nothing is left to clear it.
                lastStatus?.let { notifications.update(it, ongoing = false) }
                detachedStatus = true
                stopForeground(STOP_FOREGROUND_DETACH)
                stopSelf()
            }

            SupervisorOutcome.Cancelled -> Unit
        }
    }

    private fun stopConnection() {
        loop?.cancel()
        loop = null
        managementJob?.cancel()
        managementJob = null
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

        /** Carries a user's screen-capture consent into the service; never sent by a command. */
        const val ACTION_GRANT_CAPTURE = "com.phoneconnect.agent.action.GRANT_CAPTURE"

        /** Ends the projection the user enabled; the next snapshot is `consent_required`. */
        const val ACTION_REVOKE_CAPTURE = "com.phoneconnect.agent.action.REVOKE_CAPTURE"

        const val EXTRA_CAPTURE_RESULT_CODE = "com.phoneconnect.agent.extra.CAPTURE_RESULT_CODE"
        const val EXTRA_CAPTURE_RESULT_DATA = "com.phoneconnect.agent.extra.CAPTURE_RESULT_DATA"

        const val REFUSAL_FOREGROUND_TIMEOUT = "foreground_service_timeout"
        const val REFUSAL_BACKGROUND_START = "foreground_service_start_not_allowed"
        const val REFUSAL_OTHER = "foreground_service_start_refused"

        fun startIntent(context: Context): Intent =
            Intent(context, ConnectionService::class.java).setAction(ACTION_START)

        fun stopIntent(context: Context): Intent =
            Intent(context, ConnectionService::class.java).setAction(ACTION_STOP)

        /** Hands the system's consent result to the one service, which holds it until stopped. */
        fun captureConsentIntent(context: Context, resultCode: Int, data: Intent): Intent =
            Intent(context, ConnectionService::class.java)
                .setAction(ACTION_GRANT_CAPTURE)
                .putExtra(EXTRA_CAPTURE_RESULT_CODE, resultCode)
                .putExtra(EXTRA_CAPTURE_RESULT_DATA, data)

        fun revokeCaptureIntent(context: Context): Intent =
            Intent(context, ConnectionService::class.java).setAction(ACTION_REVOKE_CAPTURE)

        /**
         * Whether this process currently holds a projection. A UI mirror only: the service
         * updates it when a grant is accepted, revoked, the screen size changes, or the system
         * ends the session. Android cannot persist the grant, so after a restart this is false
         * and a snapshot is `consent_required` again.
         */
        private val captureEnabled = MutableStateFlow(false)

        fun screenCaptureEnabled(): Boolean = captureEnabled.value

        /** The setup screen observes this while it is visible; it never drives a command. */
        fun captureState(): StateFlow<Boolean> = captureEnabled

        /** The user granted capture; the service confirms or clears this when it installs it. */
        internal fun captureGranted() {
            captureEnabled.value = true
        }

        /** No projection is held any more: every path that ends one clears the mirror here. */
        internal fun captureEnded() {
            captureEnabled.value = false
        }

        /**
         * Asks for the one service and reports a refusal instead of crashing. Android 12+
         * throws `ForegroundServiceStartNotAllowedException` when a background start is not
         * permitted (for example from `BOOT_COMPLETED` on a `dataSync` service); the caller
         * surfaces the reason to the user.
         */
        fun requestStart(context: Context): StartResult = try {
            ContextCompat.startForegroundService(context, startIntent(context))
            StartResult.Started
        } catch (error: IllegalStateException) {
            StartResult.Refused(
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                    refusalReason(error)
                } else {
                    REFUSAL_OTHER
                },
            )
        }

        /** The specific API 31+ refusal is what the setup screen names. */
        @RequiresApi(Build.VERSION_CODES.S)
        private fun refusalReason(error: IllegalStateException): String =
            if (error is ForegroundServiceStartNotAllowedException) {
                REFUSAL_BACKGROUND_START
            } else {
                REFUSAL_OTHER
            }
    }
}

package com.phoneconnect.agent

import android.Manifest
import android.app.Activity
import android.app.NotificationManager
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.media.projection.MediaProjectionManager
import android.os.Build
import android.os.Bundle
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import androidx.core.net.toUri
import com.phoneconnect.agent.net.HubClient
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

/**
 * The minimal on-device setup: hub URL + enrollment token, then the one connection service.
 *
 * Enrollment is the only place that creates an identity key and calls
 * [EnrollmentStore.enroll]; it happens off the main thread, and the status text explains what
 * to do when a connection stops. The screen does not promise the app will survive: it states
 * that Android can stop it and what to do then.
 */
open class SetupActivity : Activity() {
    private val scope = CoroutineScope(SupervisorJob() + Dispatchers.Main.immediate)
    private lateinit var hubField: EditText
    private lateinit var tokenField: EditText
    private lateinit var statusView: TextView
    private lateinit var enrollButton: Button
    private lateinit var enableCaptureButton: Button
    private lateinit var disableCaptureButton: Button
    private lateinit var captureStatusView: TextView
    private lateinit var grantWriteSettingsButton: Button
    private lateinit var grantPolicyAccessButton: Button
    private lateinit var grantsStatusView: TextView

    /** What this screen last knew about the projection; the service is the authority. */
    private var captureOn = false

    /** Test seams: the real implementations are the Keystore store and the HTTPS client. */
    internal open fun enrollmentStore(): EnrollmentStore = KeystoreEnrollmentStore(this)

    internal open fun hubClient(hubUrl: String): Result<HubClient> = HubClient.create(hubUrl)

    /** The system's screen-capture consent dialog; a user action, never a command. */
    internal open fun screenCaptureIntent(): Intent =
        getSystemService(MediaProjectionManager::class.java).createScreenCaptureIntent()

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        hubField = findViewById(R.id.hub_url)
        tokenField = findViewById(R.id.enrollment_token)
        statusView = findViewById(R.id.status)
        enrollButton = findViewById(R.id.enroll)
        enableCaptureButton = findViewById(R.id.enable_capture)
        disableCaptureButton = findViewById(R.id.disable_capture)
        captureStatusView = findViewById(R.id.capture_status)
        grantWriteSettingsButton = findViewById(R.id.grant_write_settings)
        grantPolicyAccessButton = findViewById(R.id.grant_policy_access)
        grantsStatusView = findViewById(R.id.grants_status)

        hubField.setText(AgentSettings(this).hubUrl().orEmpty())
        enrollButton.setOnClickListener { enroll() }
        enableCaptureButton.setOnClickListener { requestScreenCapture() }
        disableCaptureButton.setOnClickListener { stopScreenCapture() }
        grantWriteSettingsButton.setOnClickListener { openWriteSettings() }
        grantPolicyAccessButton.setOnClickListener { openPolicyAccess() }

        captureOn = ConnectionService.screenCaptureEnabled()
        showCaptureState()
        showGrantState()
        requestNotificationPermission()
        showInitialState()

        scope.launch {
            ConnectionStatusBus.status.collectLatest { status ->
                if (status != null) {
                    statusView.text = describe(status)
                }
            }
        }
        // A projection can end while this screen is open (the user stops sharing from the
        // system UI, or a rotation retires the grant), so the control follows the service's
        // state instead of a value read once.
        scope.launch {
            ConnectionService.captureState().collectLatest { enabled ->
                if (enabled != captureOn) {
                    captureOn = enabled
                    showCaptureState()
                }
            }
        }
    }

    /**
     * The explicit user action screen capture needs. The result is handed to the one service;
     * no command can reach this path, which is why a snapshot without consent is a refusal
     * rather than a dialog.
     */
    private fun requestScreenCapture() {
        val intent = try {
            screenCaptureIntent()
        } catch (error: RuntimeException) {
            captureStatusView.text = getString(R.string.setup_capture_not_granted)
            return
        }
        startActivityForResult(intent, REQUEST_SCREEN_CAPTURE)
    }

    private fun stopScreenCapture() {
        try {
            ContextCompat.startForegroundService(this, ConnectionService.revokeCaptureIntent(this))
        } catch (error: IllegalStateException) {
            // The service is not startable from here; nothing is held, so nothing is leaked.
        }
        captureOn = false
        showCaptureState()
    }

    /** The consent result comes back only from the system's own dialog. */
    public override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode != REQUEST_SCREEN_CAPTURE) {
            super.onActivityResult(requestCode, resultCode, data)
            return
        }
        if (resultCode != RESULT_OK || data == null) {
            showCaptureState()
            captureStatusView.text = getString(R.string.setup_capture_not_granted)
            return
        }
        try {
            ContextCompat.startForegroundService(
                this,
                ConnectionService.captureConsentIntent(this, resultCode, data),
            )
        } catch (error: IllegalStateException) {
            captureStatusView.text = getString(R.string.setup_capture_not_granted)
            return
        }
        // Record the user's grant before onResume runs: the service accepts the intent
        // asynchronously, and the screen must not claim capture is off in that window.
        ConnectionService.captureGranted()
        captureOn = true
        showCaptureState()
    }

    private fun showCaptureState() {
        captureStatusView.text = getString(
            if (captureOn) R.string.setup_capture_on else R.string.setup_capture_off,
        )
        enableCaptureButton.isEnabled = !captureOn
        disableCaptureButton.isEnabled = captureOn
    }

    /**
     * The two grants `control.set` gates on are given in Android's own settings, never by this
     * app: the buttons open those screens, and the status line reports what Android says.
     */
    private fun openWriteSettings() {
        try {
            startActivity(
                Intent(Settings.ACTION_MANAGE_WRITE_SETTINGS, "package:$packageName".toUri()),
            )
        } catch (_: ActivityNotFoundException) {
            grantsStatusView.text = getString(R.string.setup_grants_unavailable)
        }
    }

    private fun openPolicyAccess() {
        try {
            startActivity(Intent(Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS))
        } catch (_: ActivityNotFoundException) {
            grantsStatusView.text = getString(R.string.setup_grants_unavailable)
        }
    }

    private fun showGrantState() {
        grantsStatusView.text = getString(
            R.string.setup_grants_status,
            getString(if (canWriteSettings()) R.string.setup_grant_granted else R.string.setup_grant_missing),
            getString(if (hasPolicyAccess()) R.string.setup_grant_granted else R.string.setup_grant_missing),
        )
    }

    /** Test seams: the real answers come from the settings provider and the notification service. */
    internal open fun canWriteSettings(): Boolean = Settings.System.canWrite(this)

    internal open fun hasPolicyAccess(): Boolean =
        getSystemService(NotificationManager::class.java)?.isNotificationPolicyAccessGranted == true

    public override fun onResume() {
        super.onResume()
        // A projection can end from the system UI ("Stop sharing"), which this screen cannot
        // observe directly; the service's mirror is the shared truth. The grant path records
        // itself first, so this refresh cannot race the service's start.
        val enabled = ConnectionService.screenCaptureEnabled()
        if (enabled != captureOn) {
            captureOn = enabled
            showCaptureState()
        }
        // The user may have allowed a grant in the system screen this app opened.
        showGrantState()
    }

    override fun onDestroy() {
        scope.cancel()
        super.onDestroy()
    }

    private fun showInitialState() {
        val diagnostics = AgentDiagnostics(this)
        val refusal = diagnostics.lastStartRefusal()
        scope.launch {
            val (enrollment, cleared) = withContext(Dispatchers.IO) {
                val store = enrollmentStore()
                store.info() to store.lastClearReason()
            }
            val base = when {
                enrollment != null -> getString(R.string.setup_enrolled, enrollment.deviceId)
                cleared != null -> getString(R.string.setup_enrolled_cleared, cleared.name.lowercase())
                else -> getString(R.string.setup_not_enrolled)
            }
            statusView.text = if (refusal != null) {
                getString(R.string.setup_status_with_refusal, base, refusal)
            } else {
                base
            }
        }
    }

    private fun enroll() {
        val hubUrl = hubField.text.toString().trim()
        val token = tokenField.text.toString().trim()
        if (hubUrl.isEmpty() || token.isEmpty()) {
            statusView.text = getString(R.string.setup_not_enrolled)
            return
        }
        enrollButton.isEnabled = false
        statusView.text = getString(R.string.setup_enrolling)

        scope.launch {
            try {
                val hub = hubClient(hubUrl).getOrElse { error ->
                    statusView.text = getString(R.string.setup_invalid_hub, error.message.orEmpty())
                    return@launch
                }
                val enrolled = withContext(Dispatchers.IO) {
                    EnrollmentFlow(enrollmentStore(), hub).enroll(token)
                }.getOrElse { error ->
                    statusView.text = getString(R.string.setup_enroll_failed, error.message.orEmpty())
                    return@launch
                }
                AgentSettings(this@SetupActivity).setHubUrl(hubUrl)
                AgentDiagnostics(this@SetupActivity).clearStartRefusal()
                statusView.text = getString(R.string.setup_enrolled, enrolled.deviceId)
                when (val start = ConnectionService.requestStart(this@SetupActivity)) {
                    is StartResult.Refused -> statusView.text = getString(
                        R.string.setup_enrolled_refused,
                        enrolled.deviceId,
                        start.reason,
                    )

                    StartResult.Started -> Unit
                }
            } finally {
                enrollButton.isEnabled = true
            }
        }
    }

    private fun requestNotificationPermission() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.TIRAMISU) return
        val granted = ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS) ==
            PackageManager.PERMISSION_GRANTED
        if (!granted) {
            ActivityCompat.requestPermissions(this, arrayOf(Manifest.permission.POST_NOTIFICATIONS), REQUEST_NOTIFICATIONS)
        }
    }

    private fun describe(status: ConnectionStatus): String = when (status) {
        is ConnectionStatus.Connecting -> "Connecting…"
        is ConnectionStatus.Connected ->
            if (status.path == ConnectionPath.RELAY) "Connected over the server relay." else "Connected directly."

        is ConnectionStatus.Reconnecting -> "Retrying in ${status.retryInMs / 1_000}s (${status.reason.name.lowercase()})."
        is ConnectionStatus.Terminal -> "Stopped: ${status.failure}. Enroll or start again from this screen."
        ConnectionStatus.Unenrolled -> getString(R.string.setup_not_enrolled)
        is ConnectionStatus.ActionRequired -> status.message
    }

    internal companion object {
        const val REQUEST_NOTIFICATIONS = 1001
        const val REQUEST_SCREEN_CAPTURE = 1002
    }
}

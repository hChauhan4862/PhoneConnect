package com.phoneconnect.agent

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import android.os.Bundle
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
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

    /** Test seams: the real implementations are the Keystore store and the HTTPS client. */
    internal open fun enrollmentStore(): EnrollmentStore = KeystoreEnrollmentStore(this)

    internal open fun hubClient(hubUrl: String): Result<HubClient> = HubClient.create(hubUrl)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_setup)
        hubField = findViewById(R.id.hub_url)
        tokenField = findViewById(R.id.enrollment_token)
        statusView = findViewById(R.id.status)
        enrollButton = findViewById(R.id.enroll)

        hubField.setText(AgentSettings(this).hubUrl().orEmpty())
        enrollButton.setOnClickListener { enroll() }

        requestNotificationPermission()
        showInitialState()

        scope.launch {
            ConnectionStatusBus.status.collectLatest { status ->
                if (status != null) {
                    statusView.text = describe(status)
                }
            }
        }
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

    private companion object {
        const val REQUEST_NOTIFICATIONS = 1001
    }
}

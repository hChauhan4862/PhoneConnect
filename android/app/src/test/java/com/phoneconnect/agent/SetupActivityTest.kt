package com.phoneconnect.agent

import android.app.Activity
import android.app.Application
import android.content.Context
import android.content.Intent
import android.os.Looper
import android.provider.Settings
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
import androidx.core.content.IntentCompat
import com.phoneconnect.agent.net.HubClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * The setup screen is the real entry point: it enrolls a device through the hub API and
 * starts the one connection service. Without this path the agent could never be launched or
 * enrolled.
 */
@OptIn(IdentityBoundary::class, ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SetupActivityTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private lateinit var server: MockWebServer
    private lateinit var store: KeystoreEnrollmentStore

    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        server = MockWebServer()
        server.start()
        store = KeystoreEnrollmentStore(context, FakeCipher())
        context.getSharedPreferences(AgentSettings.PREFERENCES_NAME, Context.MODE_PRIVATE).edit().clear().commit()
        context.getSharedPreferences(AgentDiagnostics.PREFERENCES_NAME, Context.MODE_PRIVATE).edit().clear().commit()
        ConnectionService.captureEnded()
        TestSetupActivity.writeSettingsGranted = false
        TestSetupActivity.policyGranted = false
        TestSetupActivity.batteryExempt = false
        TestSetupActivity.batteryScreen = SetupActivity.BatteryScreen.SCOPED_DIALOG
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        ConnectionService.captureEnded()
        runCatching { server.shutdown() }
    }

    @Test
    fun `enrolling from the setup screen stores a sealed enrollment and starts the service`() {
        server.enqueue(
            MockResponse()
                .setResponseCode(201)
                .setBody("""{"device_id":"dev_setup","credential":"pcdev_setup"}"""),
        )
        val hubUrl = server.url("/").toString().trimEnd('/')
        val activity = setupActivity()

        activity.findViewById<EditText>(R.id.hub_url).setText(hubUrl)
        activity.findViewById<EditText>(R.id.enrollment_token).setText("pcenr_setup")
        activity.findViewById<Button>(R.id.enroll).performClick()

        // The screen's own confirmation is the observable. Waiting on the store alone races the
        // coroutine that resumes on the main thread to write the status text.
        awaitUntil { statusText(activity).contains("dev_setup") }

        val info = runBlockingInfo()
        assertNotNull("the enrollment must be persisted", info)
        assertEquals("dev_setup", info!!.deviceId)
        assertEquals(EnrollmentState.ENROLLED, info.state)
        assertEquals("the hub URL must be remembered", hubUrl, AgentSettings(context).hubUrl())
        val status = activity.findViewById<TextView>(R.id.status).text.toString()
        assertTrue("the status must confirm enrollment, was '$status'", status.contains("dev_setup"))

        shadowOf(Looper.getMainLooper()).idle()
        val started = shadowOf(context as Application).nextStartedService
        assertEquals(
            "enrollment must start the one connection service",
            ConnectionService::class.java.name,
            started?.component?.className,
        )

        // The credential is sealed: the preferences never contain it in the clear.
        val raw = context.getSharedPreferences(KeystoreEnrollmentStore.PREFERENCES_NAME, Context.MODE_PRIVATE)
            .all
            .values
            .joinToString("\n")
        assertTrue("a credential must have been stored", raw.isNotEmpty())
        assertTrue("the credential must not be stored in the clear", !raw.contains("pcdev_setup"))
    }

    @Test
    fun `an invalid token is reported and nothing is stored`() {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"enrollment_token_unknown"}"""))
        val activity = setupActivity()

        activity.findViewById<EditText>(R.id.hub_url).setText(server.url("/").toString())
        activity.findViewById<EditText>(R.id.enrollment_token).setText("pcenr_wrong")
        activity.findViewById<Button>(R.id.enroll).performClick()
        awaitUntil { activity.findViewById<TextView>(R.id.status).text.contains("failed", ignoreCase = true) }

        val status = activity.findViewById<TextView>(R.id.status).text.toString()
        assertTrue("the failure must name the problem, was '$status'", status.contains("enrollment_token_unknown"))
        assertNullInfo()
    }

    @Test
    fun `the screen explains recovery and never promises the app cannot be stopped`() {
        val activity = setupActivity()

        val recovery = activity.findViewById<TextView>(R.id.recovery).text.toString().lowercase()
        assertTrue("recovery guidance must be present", recovery.contains("stop"))
        assertTrue("recovery must tell the user what to do", recovery.contains("open this screen"))
        for (claim in listOf("will not be killed", "cannot be killed", "guaranteed", "immune")) {
            assertTrue("the screen must not promise persistence, found '$claim'", !recovery.contains(claim))
        }
    }

    @Test
    fun `enabling screen capture is an explicit action that hands the grant to the service`() {
        val activity = setupActivity()

        activity.findViewById<Button>(R.id.enable_capture).performClick()
        val request = shadowOf(activity).nextStartedActivityForResult
        assertNotNull("the setup screen must ask the system for consent", request)
        assertEquals(SetupActivity.REQUEST_SCREEN_CAPTURE, request.requestCode)

        val grant = Intent("android.media.projection.test").putExtra("token", "grant")
        activity.onActivityResult(SetupActivity.REQUEST_SCREEN_CAPTURE, Activity.RESULT_OK, grant)
        shadowOf(Looper.getMainLooper()).idle()

        val started = shadowOf(context as Application).nextStartedService
        assertEquals(
            "the grant must reach the one connection service",
            ConnectionService::class.java.name,
            started?.component?.className,
        )
        assertEquals(ConnectionService.ACTION_GRANT_CAPTURE, started?.action)
        assertEquals(
            Activity.RESULT_OK,
            started?.getIntExtra(ConnectionService.EXTRA_CAPTURE_RESULT_CODE, Int.MIN_VALUE),
        )
        assertNotNull(
            "the consent token must be handed over as the system returned it",
            IntentCompat.getParcelableExtra(
                started!!,
                ConnectionService.EXTRA_CAPTURE_RESULT_DATA,
                Intent::class.java,
            ),
        )
        val status = activity.findViewById<TextView>(R.id.capture_status).text.toString()
        assertTrue("the screen must say capture is on, was '$status'", status.contains("enabled", ignoreCase = true))
        assertTrue("the screen must offer a way to stop it", activity.findViewById<Button>(R.id.disable_capture).isEnabled)
        assertTrue(
            "the grant must be visible to a later setup screen before the service confirms it",
            ConnectionService.screenCaptureEnabled(),
        )
    }

    @Test
    fun `a projection that ends while the screen is open updates the control`() {
        ConnectionService.captureGranted()
        val activity = setupActivity()
        assertFalse(activity.findViewById<Button>(R.id.enable_capture).isEnabled)

        // The system ends sharing; nothing tells the activity directly, but the service's
        // state does, so the only path back to consent reappears without a resume.
        ConnectionService.captureEnded()
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(
            "the control must follow the service's state while the screen is open",
            activity.findViewById<Button>(R.id.enable_capture).isEnabled,
        )
    }

    @Test
    fun `a system-ended projection offers Enable screen capture again`() {
        ConnectionService.captureGranted()
        val activity = setupActivity()
        assertFalse(
            "an enabled projection must not offer Enable",
            activity.findViewById<Button>(R.id.enable_capture).isEnabled,
        )

        // The user ends sharing in the system UI; the service clears the mirror.
        ConnectionService.captureEnded()
        activity.onResume()
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue(
            "the only path back to consent must be offered",
            activity.findViewById<Button>(R.id.enable_capture).isEnabled,
        )
        val status = activity.findViewById<TextView>(R.id.capture_status).text.toString()
        assertTrue("the screen must say capture is off, was '$status'", status.contains("off", ignoreCase = true))
    }

    @Test
    fun `a refused or cancelled consent request is reported and enables nothing`() {
        val activity = setupActivity()

        activity.onActivityResult(SetupActivity.REQUEST_SCREEN_CAPTURE, Activity.RESULT_CANCELED, null)
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(
            "a cancelled consent must not touch the service",
            null,
            shadowOf(context as Application).nextStartedService,
        )
        val status = activity.findViewById<TextView>(R.id.capture_status).text.toString()
        assertTrue("the screen must say consent was not granted, was '$status'", status.contains("not granted", ignoreCase = true))
    }

    @Test
    fun `stopping screen capture sends the revoke action`() {
        val activity = setupActivity()
        activity.onActivityResult(
            SetupActivity.REQUEST_SCREEN_CAPTURE,
            Activity.RESULT_OK,
            Intent("android.media.projection.test"),
        )
        shadowOf(context as Application).clearStartedServices()

        activity.findViewById<Button>(R.id.disable_capture).performClick()
        shadowOf(Looper.getMainLooper()).idle()

        val started = shadowOf(context as Application).nextStartedService
        assertEquals(ConnectionService.ACTION_REVOKE_CAPTURE, started?.action)
        val status = activity.findViewById<TextView>(R.id.capture_status).text.toString()
        assertTrue("the screen must say capture is off, was '$status'", status.contains("off", ignoreCase = true))
    }

    @Test
    fun `the brightness grant opens the system settings screen for this package`() {
        val activity = setupActivity()

        activity.findViewById<Button>(R.id.grant_write_settings).performClick()

        val started = shadowOf(activity).nextStartedActivity
        assertEquals(Settings.ACTION_MANAGE_WRITE_SETTINGS, started.action)
        assertEquals(
            "the grant must be requested for this package, not for every app",
            "package:${context.packageName}",
            started.data.toString(),
        )
    }

    @Test
    fun `the Do Not Disturb grant opens the notification policy access screen`() {
        val activity = setupActivity()

        activity.findViewById<Button>(R.id.grant_policy_access).performClick()

        val started = shadowOf(activity).nextStartedActivity
        assertEquals(Settings.ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS, started.action)
    }

    @Test
    fun `the screen reports which grants the user has given`() {
        TestSetupActivity.writeSettingsGranted = true
        val activity = setupActivity()

        val status = activity.findViewById<TextView>(R.id.grants_status).text.toString()
        assertTrue("the allowed grant must be visible, was '$status'", status.contains("Brightness changes: allowed"))
        assertTrue(
            "a missing grant must be visible, was '$status'",
            status.contains("Do Not Disturb changes: not allowed"),
        )
    }

    @Test
    fun `the battery exemption opens the scoped dialog and names only this package`() {
        val activity = setupActivity()

        activity.findViewById<Button>(R.id.grant_battery_exemption).performClick()

        val started = shadowOf(activity).nextStartedActivity
        assertEquals(SetupActivity.SETTINGS_REQUEST_EXEMPTION, started.action)
        assertEquals(
            "the dialog must be scoped to this app, never the whole device",
            "package:${activity.packageName}",
            started.data.toString(),
        )
    }

    @Test
    fun `a build without the scoped dialog falls back to the settings list`() {
        TestSetupActivity.batteryScreen = SetupActivity.BatteryScreen.SETTINGS_LIST
        val activity = setupActivity()

        activity.findViewById<Button>(R.id.grant_battery_exemption).performClick()

        val started = shadowOf(activity).nextStartedActivity
        assertEquals(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS, started.action)
    }

    @Test
    fun `a missing exemption says Android may still stop the app`() {
        TestSetupActivity.batteryExempt = false
        val activity = setupActivity()

        val status = activity.findViewById<TextView>(R.id.battery_status).text.toString()
        assertTrue("a missing exemption must warn, was '$status'", status.contains("may still stop", ignoreCase = true))
        assertFalse(
            "the screen must never promise it cannot be stopped, was '$status'",
            status.contains("cannot be stopped", ignoreCase = true),
        )
    }

    @Test
    fun `an exemption is reported without claiming immortality`() {
        TestSetupActivity.batteryExempt = true
        val activity = setupActivity()

        val status = activity.findViewById<TextView>(R.id.battery_status).text.toString()
        assertTrue("the exemption must be visible, was '$status'", status.contains("exempts this app", ignoreCase = true))
    }

    @Test
    fun `an unreadable exemption is neither optimised nor exempt`() {
        TestSetupActivity.batteryExempt = null
        val activity = setupActivity()

        val status = activity.findViewById<TextView>(R.id.battery_status).text.toString()
        assertTrue(
            "an unknown state must say so and assume the app can be stopped, was '$status'",
            status.contains("did not say", ignoreCase = true),
        )
        assertTrue("and still warn about stopping, was '$status'", status.contains("can still be stopped"))
    }

    private fun setupActivity(): SetupActivity {
        TestSetupActivity.storeOverride = store
        return Robolectric.buildActivity(
            TestSetupActivity::class.java,
            android.content.Intent(context, TestSetupActivity::class.java),
        ).setup().get()
    }

    private fun statusText(activity: SetupActivity): String =
        activity.findViewById<TextView>(R.id.status).text.toString()

    private fun runBlockingInfo(): EnrollmentInfo? = kotlinx.coroutines.runBlocking { store.info() }

    private fun assertNullInfo() {
        assertEquals(null, runBlockingInfo())
    }

    private fun awaitUntil(timeoutMs: Long = 5_000, condition: () -> Boolean) {
        val deadline = System.currentTimeMillis() + timeoutMs
        while (System.currentTimeMillis() < deadline) {
            shadowOf(Looper.getMainLooper()).idle()
            if (condition()) return
            Thread.sleep(10)
        }
        throw AssertionError("condition was not met within ${timeoutMs}ms")
    }

    private class TestSetupActivity : SetupActivity() {
        override fun enrollmentStore(): EnrollmentStore = storeOverride

        override fun hubClient(hubUrl: String): Result<HubClient> = HubClient.create(hubUrl)

        override fun screenCaptureIntent(): Intent = Intent("com.phoneconnect.test.CAPTURE_CONSENT")

        override fun canWriteSettings(): Boolean = writeSettingsGranted

        override fun hasPolicyAccess(): Boolean = policyGranted

        override fun ignoresBatteryOptimizations(): Boolean? = batteryExempt

        override fun batteryScreenToOpen(): BatteryScreen = batteryScreen

        companion object {
            lateinit var storeOverride: EnrollmentStore
            var writeSettingsGranted = false
            var policyGranted = false
            var batteryExempt: Boolean? = false
            var batteryScreen = SetupActivity.BatteryScreen.SCOPED_DIALOG
        }
    }

    private class FakeCipher : SecretCipher {
        override fun seal(plaintext: ByteArray): ByteArray = byteArrayOf(0xA5.toByte(), 0x5A.toByte()) + plaintext.reversedArray()

        override fun open(ciphertext: ByteArray): ByteArray {
            if (ciphertext.size < 2) throw EncryptionException("sealed blob too short")
            return ciphertext.copyOfRange(2, ciphertext.size).reversedArray()
        }
    }
}

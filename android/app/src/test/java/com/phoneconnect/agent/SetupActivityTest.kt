package com.phoneconnect.agent

import android.app.Application
import android.content.Context
import android.os.Looper
import android.widget.Button
import android.widget.EditText
import android.widget.TextView
import androidx.test.core.app.ApplicationProvider
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
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
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

        awaitUntil { runBlockingInfo() != null }

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

    private fun setupActivity(): SetupActivity {
        TestSetupActivity.storeOverride = store
        return Robolectric.buildActivity(
            TestSetupActivity::class.java,
            android.content.Intent(context, TestSetupActivity::class.java),
        ).setup().get()
    }

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

        companion object {
            lateinit var storeOverride: EnrollmentStore
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

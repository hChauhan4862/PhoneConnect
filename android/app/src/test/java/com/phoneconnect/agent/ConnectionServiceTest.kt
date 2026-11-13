package com.phoneconnect.agent

import android.app.Application
import android.app.Notification
import android.app.NotificationManager
import android.content.ComponentName
import android.content.Context
import android.content.ContextWrapper
import android.content.Intent
import android.content.pm.ServiceInfo
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.Robolectric
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import java.io.File

@OptIn(IdentityBoundary::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ConnectionServiceTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val manager = context.getSystemService(NotificationManager::class.java)
    private lateinit var runner: RecordingRunner

    @Before
    fun setUp() {
        Dispatchers.setMain(UnconfinedTestDispatcher())
        runner = RecordingRunner()
        TestConnectionService.install { runner }
        TestConnectionService.store = FakeStore(enrolled = true)
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        TestConnectionService.clear()
        context.getSharedPreferences(AgentDiagnostics.PREFERENCES_NAME, Context.MODE_PRIVATE)
            .edit().clear().commit()
    }

    @Test
    fun `repeated starts keep one service loop and one notification`() {
        val controller = Robolectric.buildService(
            TestConnectionService::class.java,
            ConnectionService.startIntent(context),
        )
        controller.create()

        controller.startCommand(0, 1)
        controller.startCommand(0, 2)
        shadowOf(Looper.getMainLooper()).idle()

        val shadow = shadowOf(manager)
        assertEquals("a second start must not add a notification", 1, shadow.size())
        assertNotNull(shadow.getNotification(NotificationController.NOTIFICATION_ID))
        assertEquals("a second start must not open a second connection", 1, runner.starts)
    }

    @Test
    fun `destroy cancels the loop and removes the notification`() {
        val controller = Robolectric.buildService(
            TestConnectionService::class.java,
            ConnectionService.startIntent(context),
        )
        controller.create().startCommand(0, 1)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals(1, runner.starts)

        controller.destroy()
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue("the session must observe cancellation", runner.cancelled)
        assertEquals("a stopped service must not leave a stale status", 0, shadowOf(manager).size())
    }

    @Test
    fun `a start without a configured hub reports an actionable status instead of looping`() {
        TestConnectionService.install { null }
        val controller = Robolectric.buildService(
            TestConnectionService::class.java,
            ConnectionService.startIntent(context),
        )
        controller.create().startCommand(0, 1)
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(0, runner.starts)
        val text = notificationText() ?: ""
        assertTrue("expected an actionable status, got '$text'", text.contains("not set up", ignoreCase = true))
        assertTrue("the status must say what to do, got '$text'", text.contains("PhoneConnect", ignoreCase = true))
    }

    @Test
    fun `stop removes the notification and cancels the loop`() {
        val controller = Robolectric.buildService(
            TestConnectionService::class.java,
            ConnectionService.startIntent(context),
        )
        controller.create().startCommand(0, 1)
        shadowOf(Looper.getMainLooper()).idle()

        controller.get().onStartCommand(ConnectionService.stopIntent(context), 0, 2)
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(0, shadowOf(manager).size())
        assertTrue(runner.cancelled)
    }

    @Test
    fun `a terminal outcome stops the service but leaves the reason visible`() {
        val terminal = RecordingRunner(terminal = ConnectionFailure.DeviceRevoked)
        TestConnectionService.install { terminal }
        val controller = Robolectric.buildService(
            TestConnectionService::class.java,
            ConnectionService.startIntent(context),
        )
        controller.create().startCommand(0, 1)
        shadowOf(Looper.getMainLooper()).idle()

        val service = controller.get()
        assertTrue("a terminal outcome must stop the service", shadowOf(service).isStoppedBySelf())
        assertTrue("neither must it keep a foreground service alive", shadowOf(service).isForegroundStopped())
        assertEquals("the revoked device credential must be cleared", listOf(ClearReason.REVOKED), TestConnectionService.store.clears)
        val text = notificationText() ?: ""
        assertTrue("the reason must stay readable, got '$text'", text.contains("revoked", ignoreCase = true))

        // A later enrollment (which restores the credential) starts a fresh service instance.
        TestConnectionService.store.enrolled = true
        Robolectric.buildService(TestConnectionService::class.java, ConnectionService.startIntent(context))
            .create()
            .startCommand(0, 1)
        shadowOf(Looper.getMainLooper()).idle()
        assertEquals("a re-enrolled device must be startable again", 2, terminal.starts)
    }

    @Test
    fun `the platform timeout stops the loop, clears the notification, and records why`() {
        val controller = Robolectric.buildService(
            TestConnectionService::class.java,
            ConnectionService.startIntent(context),
        )
        controller.create().startCommand(0, 1)
        shadowOf(Looper.getMainLooper()).idle()

        controller.get().onTimeout(1, ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE)
        shadowOf(Looper.getMainLooper()).idle()

        assertTrue("the loop must stop on timeout", runner.cancelled)
        assertEquals(0, shadowOf(manager).size())
        assertTrue(shadowOf(controller.get()).isStoppedBySelf())
        assertEquals(
            ConnectionService.REFUSAL_FOREGROUND_TIMEOUT,
            AgentDiagnostics(context).lastStartRefusal(),
        )
    }

    @Test
    fun `boot recovery starts the service only when an enrollment exists`() {
        val unenrolled = TestRecoveryReceiver()
        unenrolled.store = FakeStore(enrolled = false)
        unenrolled.onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
        assertNull("an unenrolled device must not start the service", eligibleStart())

        val enrolled = TestRecoveryReceiver()
        enrolled.store = FakeStore(enrolled = true)
        enrolled.onReceive(context, Intent(Intent.ACTION_BOOT_COMPLETED))
        val started = eligibleStart()
        assertNotNull("boot must ask for the one service", started)
        assertEquals(ConnectionService::class.java.name, started?.className)
    }

    @Test
    fun `a package replacement restarts the service like a boot`() {
        val receiver = TestRecoveryReceiver()
        receiver.store = FakeStore(enrolled = true)
        receiver.onReceive(context, Intent(Intent.ACTION_MY_PACKAGE_REPLACED))
        assertNotNull(eligibleStart())
    }

    @Test
    fun `a refused background start is recorded instead of crashing the receiver`() {
        val receiver = TestRecoveryReceiver()
        receiver.store = FakeStore(enrolled = true)
        val refusing = RefusingContext(context)

        receiver.onReceive(refusing, Intent(Intent.ACTION_BOOT_COMPLETED))

        assertEquals(
            ConnectionService.REFUSAL_OTHER,
            AgentDiagnostics(context).lastStartRefusal(),
        )
    }

    @Test
    fun `the manifest pairs connectedDevice with its permissions and one launcher`() {
        val manifest = File("src/main/AndroidManifest.xml").readText()
        val build = File("app/build.gradle.kts").let { if (it.isFile) it else File("build.gradle.kts") }.readText()

        assertEquals("exactly one service declaration", 1, Regex("<service\\b").findAll(manifest).count())
        assertTrue(
            "the service must be a connectedDevice foreground service",
            manifest.contains("android:foregroundServiceType=\"connectedDevice\""),
        )
        assertFalse(
            "dataSync would be capped at six hours",
            manifest.contains("foregroundServiceType=\"dataSync\""),
        )
        for (permission in listOf(
            "android.permission.FOREGROUND_SERVICE",
            "android.permission.FOREGROUND_SERVICE_CONNECTED_DEVICE",
            "android.permission.CHANGE_NETWORK_STATE",
            "android.permission.POST_NOTIFICATIONS",
            "android.permission.RECEIVE_BOOT_COMPLETED",
        )) {
            assertTrue("manifest must declare $permission", manifest.contains(permission))
        }
        assertTrue("targetSdk must be at least 34 for the foreground-service rules", build.contains("targetSdk = 35"))
        assertTrue(
            "the setup screen is the single launcher entry",
            manifest.contains("android.intent.action.MAIN") && manifest.contains("android.intent.category.LAUNCHER"),
        )
    }

    private fun notificationText(): String? = shadowOf(manager)
        .getNotification(NotificationController.NOTIFICATION_ID)
        ?.extras
        ?.getCharSequence(Notification.EXTRA_TEXT)
        ?.toString()

    private fun eligibleStart(): ComponentName? =
        shadowOf(context as Application).nextStartedService?.component

    private class RecordingRunner(
        private val terminal: ConnectionFailure? = null,
    ) : SessionRunner {
        var starts = 0
            private set
        var cancelled = false
            private set

        override suspend fun run(
            store: EnrollmentStore,
            onConnected: (ConnectionPath) -> Unit,
        ): SessionEnd {
            starts += 1
            terminal?.let { return SessionEnd.Failed(it) }
            try {
                awaitCancellation()
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                this.cancelled = true
                throw cancelled
            }
        }
    }

    private class FakeStore(var enrolled: Boolean) : EnrollmentStore {
        val clears = mutableListOf<ClearReason>()

        override suspend fun info(): EnrollmentInfo? =
            if (enrolled) EnrollmentInfo("dev_1", EnrollmentState.ENROLLED, 0) else null

        override suspend fun lastClearReason(): ClearReason? = clears.lastOrNull()

        override suspend fun enroll(request: EnrollmentRequest) {
            enrolled = true
        }

        override suspend fun openIdentity(): DeviceIdentity? = null

        override suspend fun clear(reason: ClearReason): Boolean {
            clears += reason
            enrolled = false
            return true
        }
    }

    /** Replaces the transport composition point so the service lifecycle is testable on the JVM. */
    private class TestConnectionService : ConnectionService() {
        override fun sessionRunner(): SessionRunner? = installed?.invoke()

        override fun enrollmentStore(): EnrollmentStore = store

        override fun storageDispatcher() = Dispatchers.Unconfined

        companion object {
            private var installed: (() -> SessionRunner?)? = null
            var store: FakeStore = FakeStore(enrolled = true)

            fun install(provider: () -> SessionRunner?) {
                installed = provider
            }

            fun clear() {
                installed = null
            }
        }
    }

    private class TestRecoveryReceiver : RecoveryReceiver() {
        var store: EnrollmentStore? = null

        override fun enrollmentStore(context: Context): EnrollmentStore =
            store ?: super.enrollmentStore(context)

        /** Run the post-boot work on the calling thread so the test can assert it. */
        override fun backgroundScope() = kotlinx.coroutines.CoroutineScope(
            kotlinx.coroutines.SupervisorJob() + Dispatchers.Unconfined,
        )
    }

    private class RefusingContext(base: Context) : ContextWrapper(base) {
        override fun getApplicationContext(): Context = this

        override fun startForegroundService(service: Intent): ComponentName {
            throw IllegalStateException("background start not allowed")
        }
    }
}

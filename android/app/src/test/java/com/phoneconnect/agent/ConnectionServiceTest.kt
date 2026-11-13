package com.phoneconnect.agent

import android.app.NotificationManager
import android.content.Context
import android.os.Looper
import androidx.test.core.app.ApplicationProvider
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.test.UnconfinedTestDispatcher
import kotlinx.coroutines.test.resetMain
import kotlinx.coroutines.test.setMain
import org.junit.After
import org.junit.Assert.assertEquals
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
    }

    @After
    fun tearDown() {
        Dispatchers.resetMain()
        TestConnectionService.clear()
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
    fun `a start without an installed transport reports an actionable status instead of looping`() {
        TestConnectionService.install { null }
        val controller = Robolectric.buildService(
            TestConnectionService::class.java,
            ConnectionService.startIntent(context),
        )
        controller.create().startCommand(0, 1)
        shadowOf(Looper.getMainLooper()).idle()

        assertEquals(0, runner.starts)
        val text = shadowOf(manager).getNotification(NotificationController.NOTIFICATION_ID)
            ?.extras
            ?.getCharSequence(android.app.Notification.EXTRA_TEXT)
            ?.toString()
            .orEmpty()
        assertTrue("expected an actionable status, got '$text'", text.contains("not installed"))
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
    fun `boot recovery starts the service only when an enrollment exists`() {
        val unenrolled = TestRecoveryReceiver()
        unenrolled.store = FakeStore(enrolled = false)
        unenrolled.onReceive(context, android.content.Intent(android.content.Intent.ACTION_BOOT_COMPLETED))
        assertNull("an unenrolled device must not start the service", eligibleStart())

        val enrolled = TestRecoveryReceiver()
        enrolled.store = FakeStore(enrolled = true)
        enrolled.onReceive(context, android.content.Intent(android.content.Intent.ACTION_BOOT_COMPLETED))
        assertNotNull("boot must ask for the one service", eligibleStart())
    }

    @Test
    fun `a package replacement restarts the service like a boot`() {
        val receiver = TestRecoveryReceiver()
        receiver.store = FakeStore(enrolled = true)
        receiver.onReceive(context, android.content.Intent(android.content.Intent.ACTION_MY_PACKAGE_REPLACED))
        assertNotNull(eligibleStart())
    }

    private fun eligibleStart(): android.content.ComponentName? =
        shadowOf(context as android.app.Application).nextStartedService?.component

    private class RecordingRunner : SessionRunner {
        var starts = 0
            private set
        var cancelled = false
            private set

        override suspend fun run(
            store: EnrollmentStore,
            onConnected: (ConnectionPath) -> Unit,
        ): SessionEnd {
            starts += 1
            try {
                awaitCancellation()
            } catch (cancelled: kotlinx.coroutines.CancellationException) {
                this.cancelled = true
                throw cancelled
            }
        }
    }

    private class FakeStore(private val enrolled: Boolean) : EnrollmentStore {
        override suspend fun info(): EnrollmentInfo? =
            if (enrolled) EnrollmentInfo("dev_1", EnrollmentState.ENROLLED, 0) else null

        override suspend fun lastClearReason(): ClearReason? = null

        override suspend fun enroll(request: EnrollmentRequest) = Unit

        override suspend fun openIdentity(): DeviceIdentity? = null

        override suspend fun clear(reason: ClearReason): Boolean = true
    }

    /** Replaces the transport composition point so the service lifecycle is testable on the JVM. */
    private class TestConnectionService : ConnectionService() {
        override fun sessionRunner(): SessionRunner? = installed?.invoke()

        override fun enrollmentStore(): EnrollmentStore = store

        companion object {
            private var installed: (() -> SessionRunner?)? = null
            private val store = FakeStore(enrolled = true)

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
    }
}

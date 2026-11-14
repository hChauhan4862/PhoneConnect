package com.phoneconnect.agent

import com.phoneconnect.agent.control.AppPlatform
import com.phoneconnect.agent.control.AppsHandler
import com.phoneconnect.agent.control.CapturedFrame
import com.phoneconnect.agent.control.CommandDispatcher
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.DeviceDescription
import com.phoneconnect.agent.control.DeviceInfoHandler
import com.phoneconnect.agent.control.FileHandler
import com.phoneconnect.agent.control.InstalledApp
import com.phoneconnect.agent.control.LogcatHandler
import com.phoneconnect.agent.control.PathGuard
import com.phoneconnect.agent.control.ScreenCapture
import com.phoneconnect.agent.control.ScreenHandler
import com.phoneconnect.agent.control.ShellHandler
import com.phoneconnect.agent.control.SystemPropertiesHandler
import com.phoneconnect.agent.control.SystemPropertySource
import com.phoneconnect.agent.net.DeviceControlChannel
import com.phoneconnect.agent.telemetry.BatteryReading
import com.phoneconnect.agent.telemetry.MemoryReading
import com.phoneconnect.agent.telemetry.TelemetrySampler
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.Runnable
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.coroutines.CoroutineContext

/**
 * The command vocabulary of this build: three names, a device-owned `unknown_command`, and a
 * bounded reconnect backoff for the channel that delivers them.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class CommandDispatcherTest {
    @get:Rule
    val temp = TemporaryFolder()

    private val telemetry = TelemetrySampler(
        battery = { BatteryReading(percent = 55, charging = true) },
        memory = { MemoryReading(usedBytes = 2_097_152, totalBytes = 8_388_608) },
        connectivity = { "wifi" },
        clock = { 1_760_000_000_000 },
    )

    private val dispatcher = CommandDispatcher(
        telemetry = telemetry,
        deviceInfo = DeviceInfoHandler { DeviceDescription("Pixel 8", "Google", "15", 35) },
        clock = { 1_760_000_000_000 },
    )

    @Test
    fun `device info reports the platform description`() = runBlocking {
        val output = dispatcher.dispatch(CommandDispatcher.DEVICE_INFO).getOrThrow()

        assertEquals("Pixel 8", output.getString("model"))
        assertEquals("Google", output.getString("manufacturer"))
        assertEquals("15", output.getString("android_version"))
        assertEquals(35, output.getInt("sdk"))
    }

    @Test
    fun `device ping answers with a timestamp`() = runBlocking {
        val output = dispatcher.dispatch(CommandDispatcher.DEVICE_PING).getOrThrow()

        assertEquals(true, output.getBoolean("pong"))
        assertEquals(1_760_000_000_000, output.getLong("at_ms"))
    }

    @Test
    fun `telemetry now returns the current sample`() = runBlocking {
        val output = dispatcher.dispatch(CommandDispatcher.TELEMETRY_NOW).getOrThrow()

        assertEquals(1_760_000_000_000, output.getLong("sampled_at_ms"))
        assertEquals(55, output.getInt("battery_percent"))
        assertEquals(true, output.getBoolean("battery_charging"))
        assertEquals("wifi", output.getString("connectivity"))
        assertEquals(2_097_152L, output.getLong("memory_used_bytes"))
        assertTrue("an ordinary app cannot read CPU percent", !output.has("cpu_percent"))
    }

    @Test
    fun `an unknown command name is unknown_command`() = runBlocking {
        val failure = dispatcher.dispatch("no.such_command").exceptionOrNull()

        assertTrue("expected a CommandFailure, got $failure", failure is CommandFailure)
        assertEquals("unknown_command", (failure as CommandFailure).code)
    }

    @Test
    fun `file commands run on the injected background dispatcher`() = runBlocking {
        val root = temp.newFolder("shared")
        val recording = RecordingDispatcher(Dispatchers.IO)
        val withFiles = CommandDispatcher(
            telemetry = telemetry,
            files = FileHandler(PathGuard(root)),
            ioDispatcher = recording,
        )

        val output = withFiles.dispatch(CommandDispatcher.FILES_LIST, JSONObject().put("path", "")).getOrThrow()

        assertEquals(0, output.getJSONArray("entries").length())
        assertTrue("file I/O must not run on the command receive loop", recording.used.get())
    }

    @Test
    fun `app commands run on the injected background dispatcher`() = runBlocking {
        val recording = RecordingDispatcher(Dispatchers.IO)
        val withApps = CommandDispatcher(
            telemetry = telemetry,
            apps = AppsHandler(
                object : AppPlatform {
                    override fun installed() = listOf(
                        InstalledApp("com.example.zeta", "Zeta", "1.0", 1, false, true, 1),
                    )

                    override fun launchIntent(packageName: String) = null

                    override fun startActivity(intent: android.content.Intent) = Unit

                    override fun killBackgroundProcesses(packageName: String) = Unit

                    override fun mayStartActivityFromBackground() = true
                },
            ),
            ioDispatcher = recording,
        )

        val output = withApps.dispatch(CommandDispatcher.APPS_LIST, JSONObject()).getOrThrow()

        assertEquals(1, output.getJSONArray("apps").length())
        assertTrue("app listing must not run on the command receive loop", recording.used.get())
    }

    @Test
    fun `an app command without a configured handler is still answered by name`() = runBlocking {
        val failure = dispatcher.dispatch(CommandDispatcher.APPS_LAUNCH).exceptionOrNull()

        assertTrue("expected a CommandFailure, got $failure", failure is CommandFailure)
        assertEquals("unknown_command", (failure as CommandFailure).code)
    }

    @Test
    fun `a file command without a configured root is still answered by name`() = runBlocking {
        val failure = dispatcher.dispatch(CommandDispatcher.FILES_LIST).exceptionOrNull()

        assertTrue("expected a CommandFailure, got $failure", failure is CommandFailure)
        assertEquals("unknown_command", (failure as CommandFailure).code)
    }

    @Test
    fun `a refused file path is the handler's machine code`() = runBlocking {
        val root = temp.newFolder("shared")
        val withFiles = CommandDispatcher(telemetry = telemetry, files = FileHandler(PathGuard(root)))

        val failure = withFiles
            .dispatch(CommandDispatcher.FILES_READ, JSONObject().put("path", "../secret"))
            .exceptionOrNull()

        assertEquals("path_outside_root", (failure as CommandFailure).code)
    }

    @Test
    fun `the management channel backoff is bounded and monotonic`() {
        val delays = (0..100).map { DeviceControlChannel.backoffMs(it) }

        assertEquals("a nonsense attempt still waits the base delay", 1_000L, delays.first())
        assertEquals(delays.sorted(), delays)
        assertTrue(
            "every delay is positive and capped: $delays",
            delays.all { it in 1..DeviceControlChannel.MAX_BACKOFF_MS },
        )
        assertEquals(DeviceControlChannel.MAX_BACKOFF_MS, delays.last())
        assertEquals(
            "an absurd attempt cannot overflow the cap",
            DeviceControlChannel.MAX_BACKOFF_MS,
            DeviceControlChannel.backoffMs(Int.MAX_VALUE),
        )
    }

    @Test
    fun `the screen snapshot runs off the receive loop and honours the command budget`() = runBlocking {
        val recording = RecordingDispatcher(Dispatchers.IO)
        var seenTimeout = 0L
        val capture = object : ScreenCapture {
            override fun available() = true

            override fun accept(resultCode: Int, data: android.content.Intent?, onEnded: () -> Unit) = Unit

            override fun capture(maxEncodedBytes: Int, timeoutMs: Long): CapturedFrame {
                seenTimeout = timeoutMs
                return CapturedFrame(byteArrayOf(1, 2, 3), width = 10, height = 20, capturedAtMs = 5)
            }

            override fun release() = Unit
        }
        val withScreen = CommandDispatcher(
            telemetry = telemetry,
            screen = ScreenHandler(capture),
            ioDispatcher = recording,
        )

        val output = withScreen
            .dispatch(CommandDispatcher.SCREEN_SNAPSHOT, JSONObject(), budgetMs = 750)
            .getOrThrow()

        assertEquals(750L, seenTimeout)
        assertEquals(10, output.getInt("width"))
        assertTrue("a capture must not run on the command receive loop", recording.used.get())
    }

    @Test
    fun `a screen snapshot without a configured projection is still answered by name`() = runBlocking {
        val failure = dispatcher.dispatch(CommandDispatcher.SCREEN_SNAPSHOT).exceptionOrNull()

        assertEquals("unknown_command", (failure as CommandFailure).code)
    }

    @Test
    fun `system props report the documented allowlist through the handler`() = runBlocking {
        val withProps = CommandDispatcher(
            telemetry = telemetry,
            props = SystemPropertiesHandler(
                SystemPropertySource { name -> if (name == "ro.build.version.sdk") "35" else null },
            ),
        )

        val selected = withProps.dispatch(CommandDispatcher.SYSTEM_PROPS).getOrThrow().getJSONObject("selected")

        assertEquals("35", selected.getString("sdk"))
        assertTrue("a property the platform did not report is null", selected.isNull("model"))
    }

    @Test
    fun `shell exec and logcat tail are refusals the dispatcher owns`() = runBlocking {
        val withConsole = CommandDispatcher(
            telemetry = telemetry,
            shell = ShellHandler(),
            logcat = LogcatHandler(),
        )

        for (name in listOf(CommandDispatcher.SHELL_EXEC, CommandDispatcher.LOGCAT_TAIL)) {
            val failure = withConsole.dispatch(name).exceptionOrNull()
            assertTrue("$name must not be unknown", failure is CommandFailure)
            assertEquals("not_permitted", (failure as CommandFailure).code)
        }
    }

    @Test
    fun `a console refusal without a configured handler is still answered by name`() = runBlocking {
        val failure = dispatcher.dispatch(CommandDispatcher.SHELL_EXEC).exceptionOrNull()

        assertEquals("unknown_command", (failure as CommandFailure).code)
    }

    /** Records that work was dispatched instead of run inline, then delegates to a real pool. */
    private class RecordingDispatcher(
        private val delegate: CoroutineDispatcher,
    ) : CoroutineDispatcher() {
        val used = AtomicBoolean(false)

        override fun dispatch(context: CoroutineContext, block: Runnable) {
            used.set(true)
            delegate.dispatch(context, block)
        }
    }
}

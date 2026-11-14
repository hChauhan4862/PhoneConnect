package com.phoneconnect.agent

import androidx.test.core.app.ApplicationProvider
import com.phoneconnect.agent.control.AndroidControlPlatform
import com.phoneconnect.agent.control.AppPlatform
import com.phoneconnect.agent.control.AppsHandler
import com.phoneconnect.agent.control.CapturedFrame
import com.phoneconnect.agent.control.CommandDispatcher
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.ControlHandler
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
import com.phoneconnect.agent.telemetry.BatteryReading
import com.phoneconnect.agent.telemetry.MemoryReading
import com.phoneconnect.agent.telemetry.TelemetrySampler
import kotlinx.coroutines.runBlocking
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * `docs/capabilities.md` is the one place a reader learns what each command can do, so it must
 * agree with the dispatcher in both directions: a command the code registers but the document
 * omits is invisible drift, and a row the code does not implement is a fabricated capability.
 *
 * The three inputs are the registered list, the command constants in the dispatcher, and the
 * document itself. The document is read relative to this module (`android/app`), which is the
 * Gradle test working directory, so the same path resolves locally and in CI.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class CapabilityMatrixTest {
    @get:Rule
    val temp = TemporaryFolder()

    private val document = File("../..", "docs/capabilities.md")
    private val dispatcherSource =
        File("src/main/java/com/phoneconnect/agent/control/CommandDispatcher.kt")

    /** The first cell of a table row that names one command, e.g. ``| `device.info` | … |``. */
    private val commandRow = Regex("""^\|\s*`([a-z][a-z_]*\.[a-z][a-z_]*)`\s*\|""")

    private val constant = Regex("""const val [A-Z_]+ = "([^"]+)"""")

    @Test
    fun `the capability document lists exactly the commands this build registers`() {
        assertTrue(
            "the capability document must exist at ${document.absolutePath}",
            document.isFile,
        )
        val documented = documentedCommands()

        assertEquals(
            "docs/capabilities.md and CommandDispatcher.COMMANDS must name the same commands",
            CommandDispatcher.COMMANDS.sorted(),
            documented.sorted(),
        )
        assertEquals(
            "a command appears in more than one row: $documented",
            documented.size,
            documented.toSet().size,
        )
    }

    @Test
    fun `every command constant is on the registered list`() {
        val declared = constant.findAll(dispatcherSource.readText())
            .map { match -> match.groupValues[1] }
            .toSet()

        assertEquals(
            "a command constant outside CommandDispatcher.COMMANDS would escape the matrix",
            declared,
            CommandDispatcher.COMMANDS.toSet(),
        )
    }

    @Test
    fun `every registered command reaches a handler instead of unknown_command`() = runBlocking {
        val dispatcher = fullDispatcher()

        for (name in CommandDispatcher.COMMANDS) {
            val failure = dispatcher.dispatch(name, JSONObject()).exceptionOrNull() as? CommandFailure
            assertNotEquals(
                "$name is listed but the dispatcher does not route it",
                "unknown_command",
                failure?.code,
            )
        }
    }

    /** Every command name in a table row, in document order. */
    private fun documentedCommands(): List<String> = document.readText()
        .lineSequence()
        .mapNotNull { line -> commandRow.find(line)?.groupValues?.get(1) }
        .toList()

    /**
     * A dispatcher with every handler configured, so a registered name cannot answer
     * `unknown_command` merely because this test left a handler out. The commands are dispatched
     * with empty arguments; whatever a handler answers about those arguments is not the point.
     */
    private fun fullDispatcher(): CommandDispatcher {
        val capture = object : ScreenCapture {
            override fun available() = true

            override fun accept(
                resultCode: Int,
                data: android.content.Intent?,
                onEnded: () -> Unit,
            ) = Unit

            override fun capture(maxEncodedBytes: Int, timeoutMs: Long) =
                CapturedFrame(byteArrayOf(1, 2, 3), width = 1, height = 1, capturedAtMs = 0)

            override fun release() = Unit
        }
        val apps = object : AppPlatform {
            override fun installed() = listOf(
                InstalledApp("com.example.app", "Example", "1.0", 1, false, true, 0),
            )

            override fun launchIntent(packageName: String) = null

            override fun startActivity(intent: android.content.Intent) = Unit

            override fun killBackgroundProcesses(packageName: String) = Unit

            override fun mayStartActivityFromBackground() = true
        }
        return CommandDispatcher(
            telemetry = TelemetrySampler(
                battery = { BatteryReading(percent = 50, charging = false) },
                memory = { MemoryReading(usedBytes = 1, totalBytes = 2) },
                connectivity = { "wifi" },
            ),
            deviceInfo = DeviceInfoHandler { DeviceDescription("Model", "Maker", "15", 35) },
            files = FileHandler(PathGuard(temp.newFolder("root"))),
            apps = AppsHandler(apps),
            screen = ScreenHandler(capture),
            props = SystemPropertiesHandler(SystemPropertySource { "value" }),
            shell = ShellHandler(),
            logcat = LogcatHandler(),
            control = ControlHandler(
                AndroidControlPlatform(ApplicationProvider.getApplicationContext()),
            ),
        )
    }
}

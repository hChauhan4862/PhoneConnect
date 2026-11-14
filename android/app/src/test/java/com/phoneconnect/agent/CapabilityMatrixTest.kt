package com.phoneconnect.agent

import androidx.test.core.app.ApplicationProvider
import com.phoneconnect.agent.control.AndroidControlPlatform
import com.phoneconnect.agent.control.AppPlatform
import com.phoneconnect.agent.control.AppsHandler
import com.phoneconnect.agent.control.CapturedFrame
import com.phoneconnect.agent.control.CommandDispatcher
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.CommandReasons
import com.phoneconnect.agent.control.ControlHandler
import com.phoneconnect.agent.control.ControlKey
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
 * omits is invisible drift, a row the code does not implement is a fabricated capability, and a
 * refusal token the handlers can answer with but the document never names is a refusal a reader
 * cannot look up.
 *
 * The inputs are the registered command list, the command constants in the dispatcher, the token
 * constants `CommandReasons.kt` declares, every token-shaped constant in the agent sources, every
 * token-shaped literal under the control package, and the document itself. A literal is matched
 * wherever it appears — a failure code, a factory's message, a helper's `when` branch, a `Reading`
 * reason — so a new shape does not need a new pattern. The document is read relative to this
 * module (`android/app`), which is the Gradle test working directory, so the same path resolves
 * locally and in CI.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class CapabilityMatrixTest {
    @get:Rule
    val temp = TemporaryFolder()

    private val document = File("../..", "docs/capabilities.md")
    private val dispatcherSource =
        File("src/main/java/com/phoneconnect/agent/control/CommandDispatcher.kt")
    private val reasonsSource =
        File("src/main/java/com/phoneconnect/agent/control/CommandReasons.kt")
    private val agentSources = File("src/main/java/com/phoneconnect/agent")
    private val controlSources = File("src/main/java/com/phoneconnect/agent/control")

    /**
     * Strings that look like a token but are not one: answer field names, control keys, file
     * operation labels, the envelope type, a file mode, and the keys the agent persists.
     *
     * Everything else that looks like a token must be in [CommandReasons.tokens]. This list is
     * checked against the token set too, because an entry that collided with a real token would
     * be skipped by the literal scan instead of failing it.
     */
    private val nonTokenStrings = setOf(
        // Answer field names: device.info, telemetry, files, apps, screen, properties, control.
        "at_ms", "pong", "model", "manufacturer", "android_version", "sdk", "release",
        "build_id", "security_patch", "selected", "keys", "entries", "name", "path", "is_dir",
        "size_bytes", "modified_ms", "data_base64", "truncated", "offset", "length", "append",
        "bytes_written", "apps", "package", "label", "version_name", "version_code", "system",
        "enabled", "updated_ms", "launched", "kill_requested", "png_base64", "width", "height",
        "captured_at_ms", "key", "value", "applied", "mode_changed", "unavailable",
        // Control keys: the readings control.get reports and the changes control.set names.
        ControlKey.BRIGHTNESS,
        ControlKey.BRIGHTNESS_MODE,
        ControlKey.VOLUME_MUSIC,
        ControlKey.VOLUME_MAX,
        ControlKey.ROTATION,
        ControlKey.DND_FILTER,
        ControlKey.NIGHT_MODE,
        ControlKey.WIFI_ENABLED,
        ControlKey.BLUETOOTH_ENABLED,
        ControlKey.MOBILE_DATA_ENABLED,
        ControlKey.BATTERY_SAVER,
        ControlKey.BATTERY_PERCENT,
        ControlKey.WIFI,
        ControlKey.BLUETOOTH,
        ControlKey.MOBILE_DATA,
        ControlKey.REBOOT,
        // File operation labels used in an io_error message, and the mode a file is opened in.
        "read", "write", "list", "mkdir", "delete", "rename", "from", "to", "get", "r",
        // The envelope type the management channel recognises.
        "type", "hello",
        // Persistence keys and the refusal labels the agent stores for the setup screen.
        "hub_url", "record", "last_clear_reason", "version", "device_id", "state",
        "enrolled_at_ms", "credential", "identity_private_key", "identity_public_key",
        "last_start_refusal", "connection", "foreground_service_timeout",
        "foreground_service_start_not_allowed", "foreground_service_start_refused",
    )

    /** The first cell of a table row that names one command, e.g. ``| `device.info` | … |``. */
    private val commandRow = Regex("""^\|\s*`([a-z][a-z_]*\.[a-z][a-z_]*)`\s*\|""")

    /** Any backticked machine token, e.g. `` `write_settings_required` ``. */
    private val backtickedToken = Regex("""`([a-z][a-z0-9_]*)`""")

    private val commandConstant =
        Regex("""const val [A-Z_0-9]+\s*(?::\s*String\s*)?=\s*"([^"]+)"""")

    /**
     * A token-shaped `const val` in any declaration shape this package uses: untyped, typed
     * (`: String`), and with the value on the next line.
     */
    private val tokenConstant =
        Regex("""const val [A-Za-z_0-9]+\s*(?::\s*String\s*)?=\s*"([a-z][a-z0-9_]*)"""")

    /** A string literal a token can be written as: lowercase, underscores, no spaces. */
    private val tokenShapedLiteral = Regex("\"([a-z][a-z0-9_]*)\"")

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
    fun `every device token the handlers answer with appears in the capability document`() {
        assertTrue(
            "the capability document must exist at ${document.absolutePath}",
            document.isFile,
        )
        val tokens = CommandReasons.tokens
        assertEquals(
            "CommandReasons.tokens must not repeat a token",
            tokens.size,
            tokens.toSet().size,
        )

        val documented = backtickedToken.findAll(document.readText())
            .map { match -> match.groupValues[1] }
            .toSet()
        val missing = tokens.filterNot { token -> token in documented }

        assertTrue(
            "docs/capabilities.md must name every device token; missing: $missing",
            missing.isEmpty(),
        )
    }

    @Test
    fun `the token list is exactly the constants CommandReasons declares`() {
        val declared = tokenConstant.findAll(reasonsSource.readText())
            .map { match -> match.groupValues[1] }
            .toSet()

        assertEquals(
            "a constant missing from CommandReasons.tokens would escape the matrix",
            declared.sorted(),
            CommandReasons.tokens.sorted(),
        )
    }

    @Test
    fun `the token list and the non-token allowlist are disjoint`() {
        val collisions = CommandReasons.tokens.filter { token -> token in nonTokenStrings }

        assertTrue(
            "a string cannot be both a device token and an allowlisted non-token: $collisions",
            collisions.isEmpty(),
        )
    }

    @Test
    fun `no constant outside CommandReasons declares a token outside the list`() {
        assertTrue(
            "the agent source root must exist at ${agentSources.absolutePath}",
            agentSources.isDirectory,
        )
        val files = agentSources.walkTopDown()
            .filter { file ->
                file.isFile && file.extension == "kt" && file.name != "CommandReasons.kt"
            }
            .toList()
        assertTrue("no Kotlin sources under ${agentSources.absolutePath}", files.isNotEmpty())

        var declarations = 0
        val outside = files.flatMap { file ->
            tokenConstant.findAll(file.readText()).mapNotNull { match ->
                declarations++
                entryOutsideAllowlist(file, match.groupValues[1])
            }.toList()
        }
        assertTrue(
            "no token-shaped constant found under ${agentSources.absolutePath}: the scan would " +
                "pass vacuously",
            declarations > 0,
        )

        assertTrue(
            "a token-shaped constant must be in CommandReasons.tokens (and in " +
                "docs/capabilities.md) or an allowlisted non-token; outside: $outside",
            outside.isEmpty(),
        )
    }

    @Test
    fun `no token-shaped literal under control escapes the token list`() {
        assertTrue(
            "the control source root must exist at ${controlSources.absolutePath}",
            controlSources.isDirectory,
        )
        val files = controlSources.walkTopDown()
            .filter { file ->
                file.isFile && file.extension == "kt" && file.name != "CommandReasons.kt"
            }
            .toList()
        assertTrue("no Kotlin sources under ${controlSources.absolutePath}", files.isNotEmpty())

        var literals = 0
        val outside = files.flatMap { file ->
            tokenShapedLiteral.findAll(file.readText()).mapNotNull { match ->
                literals++
                entryOutsideAllowlist(file, match.groupValues[1])
            }.toList()
        }
        assertTrue(
            "no token-shaped literal found under ${controlSources.absolutePath}: the scan would " +
                "pass vacuously",
            literals > 0,
        )

        assertTrue(
            "a token-shaped literal must be in CommandReasons.tokens (and in " +
                "docs/capabilities.md) or an allowlisted non-token; outside: $outside",
            outside.isEmpty(),
        )
    }

    /** `null` when [value] is a token or an allowlisted non-token; otherwise the offending entry. */
    private fun entryOutsideAllowlist(file: File, value: String): String? = when {
        value in CommandReasons.tokens || value in nonTokenStrings -> null
        else -> "${file.name}: $value"
    }

    @Test
    fun `every command constant is on the registered list`() {
        val declared = commandConstant.findAll(dispatcherSource.readText())
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

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
 * constants `CommandReasons.kt` declares, the token literals written in a failure, reason, or
 * `unavailable` position anywhere in the main sources, and the document itself. The document is
 * read relative to this module (`android/app`), which is the Gradle test working directory, so
 * the same path resolves locally and in CI.
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
    private val mainSources = File("src/main/java")
    private val controlSources = File("src/main/java/com/phoneconnect/agent/control")

    /**
     * `const val`s under `control/` that are control keys or answer field names, not tokens.
     * A new key or field name must be added here, which is the point: it cannot slip in as a
     * token that the document does not name.
     */
    private val controlFieldNames = setOf(
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
        ControlHandler.MODE_CHANGED,
        ControlHandler.UNAVAILABLE,
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

    /**
     * A call the vocabulary says carries a stable token: a failure's code or message, a
     * `Reading.unavailable` reason, or a reason placed in the `unavailable` map.
     */
    private val tokenCall = Regex("""\b(?:unavailable\.put|CommandFailure|unavailable)\(""")

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
    fun `no control constant declares a token outside the list`() {
        assertTrue(
            "the control source root must exist at ${controlSources.absolutePath}",
            controlSources.isDirectory,
        )
        val declared = controlSources.walkTopDown()
            .filter { file ->
                file.isFile && file.extension == "kt" && file.name != "CommandReasons.kt"
            }
            .flatMap { file ->
                tokenConstant.findAll(file.readText())
                    .map { match -> "${file.name}: ${match.groupValues[1]}" }
                    .toList()
            }
            .filter { entry -> entry.substringAfter(": ") !in controlFieldNames }
            .toList()

        val outside = declared.filter { entry ->
            entry.substringAfter(": ") !in CommandReasons.tokens
        }

        assertTrue(
            "a token constant outside CommandReasons (and outside the field-name allowlist) " +
                "would escape the matrix; outside: $outside",
            outside.isEmpty(),
        )
    }

    @Test
    fun `no handler writes a token literal outside the token list`() {
        assertTrue(
            "the main source root must exist at ${mainSources.absolutePath}",
            mainSources.isDirectory,
        )
        val files = mainSources.walkTopDown()
            .filter { file -> file.isFile && file.extension == "kt" }
            .toList()
        assertTrue("no Kotlin sources under ${mainSources.absolutePath}", files.isNotEmpty())

        var calls = 0
        val literals = files.flatMap { file ->
            val text = file.readText()
            tokenCall.findAll(text).flatMap { match ->
                calls++
                tokenShapedLiteral.findAll(callArguments(text, match.range.last))
                    .map { literal -> "${file.name}: ${literal.groupValues[1]}" }
                    .toList()
            }
        }
        assertTrue(
            "no token-carrying call found under ${mainSources.absolutePath}: the scan would pass " +
                "vacuously",
            calls > 0,
        )

        val outside = literals.filter { entry ->
            entry.substringAfter(": ") !in CommandReasons.tokens
        }

        assertTrue(
            "a token literal in a failure, reason, or unavailable position must come from " +
                "CommandReasons.tokens (and be named in docs/capabilities.md); outside: $outside",
            outside.isEmpty(),
        )
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
     * The arguments of the call whose `(` is at [openParen], up to its matching `)`.
     *
     * Parens inside string literals are not counted, and a raw string is skipped whole, so a
     * message such as `"(limit 2 000 apps)"` cannot cut the call short.
     */
    private fun callArguments(text: String, openParen: Int): String {
        var depth = 0
        var index = openParen
        while (index < text.length) {
            val char = text[index]
            if (char == '"') {
                if (text.startsWith("\"\"\"", index)) {
                    val end = text.indexOf("\"\"\"", index + 3)
                    if (end < 0) return text.substring(openParen + 1)
                    index = end + 3
                    continue
                }
                index++
                while (index < text.length && text[index] != '"') {
                    if (text[index] == '\\') index++
                    index++
                }
            } else if (char == '(') {
                depth++
            } else if (char == ')') {
                depth--
                if (depth == 0) return text.substring(openParen + 1, index)
            }
            index++
        }
        return text.substring(openParen + 1)
    }

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

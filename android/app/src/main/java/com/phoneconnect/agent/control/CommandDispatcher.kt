package com.phoneconnect.agent.control

import com.phoneconnect.agent.telemetry.TelemetrySampler
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject

/**
 * A device-side command failure. [code] is the stable machine code the caller reads; the
 * server stores it verbatim, so nothing is translated into a success-shaped answer.
 */
class CommandFailure(val code: String, message: String? = null) : Exception(message ?: code) {
    companion object {
        fun unknown(name: String): CommandFailure =
            CommandFailure(CommandReasons.UNKNOWN_COMMAND, "this agent does not implement '$name'")

        fun invalid(message: String): CommandFailure =
            CommandFailure(CommandReasons.INVALID_ARGS, message)

        fun internal(reason: String): CommandFailure =
            CommandFailure(CommandReasons.INTERNAL_ERROR, reason)
    }
}

/**
 * Routes the command names this build implements to their handlers.
 *
 * The vocabulary belongs to the device: the server forwards whatever name it is given, and
 * a name this build does not implement is an explicit `unknown_command`. Adding a feature
 * means adding a branch here plus a handler file — no existing handler changes.
 *
 * Handlers are `suspend` so a deadline can stop them cooperatively; a handler that blocks a
 * thread cannot be interrupted, which is why the channel also refuses to *start* a command
 * whose absolute server deadline has already passed. File and app work is I/O, so it runs on
 * [ioDispatcher] and never on the command receive loop.
 */
open class CommandDispatcher(
    private val telemetry: TelemetrySampler,
    private val deviceInfo: DeviceInfoHandler = DeviceInfoHandler(),
    private val files: FileHandler? = null,
    private val apps: AppsHandler? = null,
    private val screen: ScreenHandler? = null,
    private val props: SystemPropertiesHandler? = null,
    private val shell: ShellHandler? = null,
    private val logcat: LogcatHandler? = null,
    private val control: ControlHandler? = null,
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    /**
     * Routes one command. [budgetMs] is what is left of the server's deadline; a handler that
     * blocks a thread (a frame capture) uses it to bound its own wait, because a coroutine
     * timeout cannot interrupt a blocking platform call.
     */
    open suspend fun dispatch(
        name: String,
        args: JSONObject? = null,
        budgetMs: Long = DEFAULT_BUDGET_MS,
    ): Result<JSONObject> = when (name) {
        DEVICE_INFO -> runCatching { deviceInfo.describe() }
        DEVICE_PING -> runCatching {
            JSONObject()
                .put("pong", true)
                .put("at_ms", clock())
        }
        TELEMETRY_NOW -> runCatching { telemetry.sample().toJson() }
        FILES_LIST, FILES_READ, FILES_WRITE, FILES_MKDIR, FILES_DELETE, FILES_RENAME ->
            withContext(ioDispatcher) {
                val handler = files
                    ?: return@withContext Result.failure(CommandFailure.unknown(name))
                runCatching { handler.handle(name, args) }
            }
        APPS_LIST, APPS_LAUNCH, APPS_STOP, APPS_CLEAR, APPS_SET_ENABLED ->
            withContext(ioDispatcher) {
                val handler = apps
                    ?: return@withContext Result.failure(CommandFailure.unknown(name))
                runCatching { handler.handle(name, args) }
            }
        SCREEN_SNAPSHOT ->
            withContext(ioDispatcher) {
                val handler = screen
                    ?: return@withContext Result.failure(CommandFailure.unknown(name))
                runCatching { handler.snapshot(budgetMs) }
            }
        SYSTEM_PROPS -> withContext(ioDispatcher) {
            val handler = props ?: return@withContext Result.failure(CommandFailure.unknown(name))
            runCatching { handler.select(args) }
        }
        // These two can never succeed for this app; they are here so a caller gets
        // `not_permitted` with a reason rather than `unknown_command`.
        SHELL_EXEC -> runCatching {
            (shell ?: throw CommandFailure.unknown(name)).exec()
        }
        LOGCAT_TAIL -> runCatching {
            (logcat ?: throw CommandFailure.unknown(name)).tail()
        }
        // Device control reads and writes framework services, so it runs off the command
        // receive loop; the reboot refusal never touches the platform.
        CONTROL_GET, CONTROL_SET -> withContext(ioDispatcher) {
            val handler = control ?: return@withContext Result.failure(CommandFailure.unknown(name))
            runCatching { handler.handle(name, args) }
        }
        CONTROL_REBOOT -> runCatching {
            (control ?: throw CommandFailure.unknown(name)).handle(name, args)
        }
        else -> Result.failure(CommandFailure.unknown(name))
    }

    companion object {
        const val DEVICE_INFO = "device.info"
        const val DEVICE_PING = "device.ping"
        const val TELEMETRY_NOW = "telemetry.now"

        const val FILES_LIST = "files.list"
        const val FILES_READ = "files.read"
        const val FILES_WRITE = "files.write"
        const val FILES_MKDIR = "files.mkdir"
        const val FILES_DELETE = "files.delete"
        const val FILES_RENAME = "files.rename"

        const val APPS_LIST = "apps.list"
        const val APPS_LAUNCH = "apps.launch"
        const val APPS_STOP = "apps.stop"
        const val APPS_CLEAR = "apps.clear"
        const val APPS_SET_ENABLED = "apps.set_enabled"

        const val SCREEN_SNAPSHOT = "screen.snapshot"
        const val SYSTEM_PROPS = "system.props"
        const val SHELL_EXEC = "shell.exec"
        const val LOGCAT_TAIL = "logcat.tail"

        const val CONTROL_GET = "control.get"
        const val CONTROL_SET = "control.set"
        const val CONTROL_REBOOT = "control.reboot"

        /**
         * Every command name this build registers, in family order.
         *
         * These are the same constants the [dispatch] branches use, so a command cannot be
         * routed without appearing here. `CapabilityMatrixTest` reads this list, the
         * constants in this file, and `docs/capabilities.md`, and fails when the three
         * disagree in either direction.
         */
        val COMMANDS: List<String> = listOf(
            DEVICE_INFO,
            DEVICE_PING,
            TELEMETRY_NOW,
            FILES_LIST,
            FILES_READ,
            FILES_WRITE,
            FILES_MKDIR,
            FILES_DELETE,
            FILES_RENAME,
            APPS_LIST,
            APPS_LAUNCH,
            APPS_STOP,
            APPS_CLEAR,
            APPS_SET_ENABLED,
            SCREEN_SNAPSHOT,
            SYSTEM_PROPS,
            SHELL_EXEC,
            LOGCAT_TAIL,
            CONTROL_GET,
            CONTROL_SET,
            CONTROL_REBOOT,
        )

        /** The server's default deadline, used when a caller does not supply a budget. */
        const val DEFAULT_BUDGET_MS: Long = 10_000
    }
}

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
            CommandFailure("unknown_command", "this agent does not implement '$name'")

        fun invalid(message: String): CommandFailure = CommandFailure("invalid_args", message)

        fun internal(reason: String): CommandFailure = CommandFailure("internal_error", reason)
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
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    open suspend fun dispatch(name: String, args: JSONObject? = null): Result<JSONObject> = when (name) {
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
    }
}

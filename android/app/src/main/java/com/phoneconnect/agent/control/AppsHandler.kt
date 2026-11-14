package com.phoneconnect.agent.control

import android.content.Intent
import org.json.JSONArray
import org.json.JSONObject

/** One installed application, exactly as the platform reported it. */
data class InstalledApp(
    val packageName: String,
    val label: String,
    val versionName: String?,
    val versionCode: Long,
    val system: Boolean,
    val enabled: Boolean,
    val updatedMs: Long,
)

/**
 * What the `apps.*` commands need from Android.
 *
 * The interface exists so the handler's decisions — what is refused before any platform call,
 * and what a platform refusal becomes — are testable without a package database. The only
 * production implementation is [AndroidAppPlatform].
 */
interface AppPlatform {
    /** Every package visible to this app's UID. */
    fun installed(): List<InstalledApp>

    /** The package's launcher intent, or `null` when it has no launchable activity. */
    fun launchIntent(packageName: String): Intent?

    /** Starts [intent]; the platform may throw a `SecurityException` instead. */
    fun startActivity(intent: Intent)

    /** Asks Android to kill the package's background processes; throws when not permitted. */
    fun killBackgroundProcesses(packageName: String)

    /**
     * Whether Android currently permits this process to start an activity. From Android 10 a
     * background start is blocked *without* an exception, so a handler that skips this check
     * would report a launch that never happened.
     */
    fun mayStartActivityFromBackground(): Boolean
}

/**
 * The five `apps.*` commands.
 *
 * An ordinary installed app cannot do everything an ADB shell can, and these handlers say so
 * instead of pretending: `apps.clear` and `apps.set_enabled` need signature-level permissions
 * and are constant `not_permitted` refusals that point at the ADB path, while `apps.stop`
 * reports the kill it requested rather than a stop it cannot observe. Every acting command
 * resolves `package` against the device's own list first, so an unknown name is
 * `unknown_package` and never a platform exception string.
 */
class AppsHandler(private val platform: AppPlatform) {
    /** Routes one command name this handler owns. */
    fun handle(name: String, args: JSONObject?): JSONObject = when (name) {
        CommandDispatcher.APPS_LIST -> list()
        CommandDispatcher.APPS_LAUNCH -> launch(args)
        CommandDispatcher.APPS_STOP -> stop(args)
        CommandDispatcher.APPS_CLEAR -> clear(args)
        CommandDispatcher.APPS_SET_ENABLED -> setEnabled(args)
        else -> throw CommandFailure.unknown(name)
    }

    fun list(): JSONObject {
        val apps = platform.installed().sortedWith(
            compareBy(String.CASE_INSENSITIVE_ORDER) { app: InstalledApp -> app.label }
                .thenBy(InstalledApp::packageName),
        )
        val entries = ArrayList<JSONObject>(apps.size)
        var encodedBytes = 0
        for (app in apps) {
            val entry = describe(app)
            val encoded = entry.toString().toByteArray(Charsets.UTF_8).size + 1
            // One listing is one command result and the server refuses anything over 2 MiB.
            // Measure UTF-8 bytes and stop before materializing an oversized answer, exactly
            // as `files.list` does; a silently truncated listing would be a fabricated one.
            if (entries.size >= MAX_LIST_APPS || encodedBytes + encoded > MAX_LIST_BYTES) {
                throw CommandFailure(
                    CommandReasons.LISTING_TOO_LARGE,
                    "the device has more apps than one listing may carry " +
                        "(limit $MAX_LIST_APPS apps or $MAX_LIST_BYTES bytes)",
                )
            }
            encodedBytes += encoded
            entries.add(entry)
        }
        return JSONObject().put("apps", JSONArray(entries))
    }

    fun launch(args: JSONObject?): JSONObject {
        val packageName = requireInstalled(args)
        val intent = platform.launchIntent(packageName)
            ?: throw CommandFailure(
                CommandReasons.NO_LAUNCH_ACTIVITY,
                "the package has no launchable activity",
            )
        if (!platform.mayStartActivityFromBackground()) {
            throw CommandFailure(
                CommandReasons.LAUNCH_BLOCKED,
                CommandReasons.BACKGROUND_ACTIVITY_START_RESTRICTED,
            )
        }
        try {
            platform.startActivity(intent)
        } catch (_: RuntimeException) {
            // The platform's message can name absolute paths; the caller gets a code and a
            // short reason instead.
            throw CommandFailure(CommandReasons.LAUNCH_BLOCKED, CommandReasons.PLATFORM_REFUSED)
        }
        // Success means the platform accepted the start. Android offers no callback proving
        // the activity became visible, and this response does not claim it did.
        return JSONObject()
            .put("package", packageName)
            .put("launched", true)
    }

    fun stop(args: JSONObject?): JSONObject {
        val packageName = requireInstalled(args)
        try {
            platform.killBackgroundProcesses(packageName)
        } catch (_: RuntimeException) {
            throw CommandFailure(CommandReasons.NOT_PERMITTED, KILL_REFUSED_MESSAGE)
        }
        // A background kill is a request: Android never confirms that a process died, so the
        // answer says what was asked for and nothing more.
        return JSONObject()
            .put("package", packageName)
            .put("kill_requested", true)
    }

    fun clear(args: JSONObject?): JSONObject {
        requireInstalled(args)
        throw CommandFailure(CommandReasons.NOT_PERMITTED, CLEAR_MESSAGE)
    }

    fun setEnabled(args: JSONObject?): JSONObject {
        requireInstalled(args)
        requireBoolean(args, "enabled")
        throw CommandFailure(CommandReasons.NOT_PERMITTED, SET_ENABLED_MESSAGE)
    }

    private fun describe(app: InstalledApp): JSONObject = JSONObject()
        .put("package", app.packageName)
        // A label the platform could not resolve falls back to the package name: the one name
        // Android itself would show. Nothing is invented.
        .put("label", app.label.ifBlank { app.packageName })
        .put("version_name", app.versionName ?: JSONObject.NULL)
        .put("version_code", app.versionCode)
        .put("system", app.system)
        .put("enabled", app.enabled)
        .put("updated_ms", app.updatedMs)

    /** The requested package, provided the device's own list actually contains it. */
    private fun requireInstalled(args: JSONObject?): String {
        val requested = requiredPackage(args)
        if (platform.installed().none { it.packageName == requested }) {
            throw CommandFailure(CommandReasons.UNKNOWN_PACKAGE, "the package is not installed on this device")
        }
        return requested
    }

    private fun requiredPackage(args: JSONObject?): String {
        val value = args?.opt("package") ?: throw CommandFailure.invalid("package is required")
        if (value == JSONObject.NULL) throw CommandFailure.invalid("package is required")
        if (value !is String) throw CommandFailure.invalid("package must be a string")
        val packageName = value.trim()
        if (packageName.isEmpty()) throw CommandFailure.invalid("package must not be empty")
        return packageName
    }

    private fun requireBoolean(args: JSONObject?, key: String) {
        val value = args?.opt(key) ?: throw CommandFailure.invalid("$key is required")
        if (value == JSONObject.NULL) throw CommandFailure.invalid("$key is required")
        if (value !is Boolean) throw CommandFailure.invalid("$key must be a boolean")
    }

    companion object {
        /** Apps one listing may carry before it is refused as `listing_too_large`. */
        const val MAX_LIST_APPS: Int = 2_000

        /**
         * UTF-8 bytes of the serialized entries one listing may carry. The server refuses a
         * result above 2 MiB, so staying under one mebibyte leaves room for the envelope and
         * makes the refusal the device's own rather than a dropped channel.
         */
        private const val MAX_LIST_BYTES: Int = 1_000_000

        const val KILL_REFUSED_MESSAGE =
            "Android refused to kill background processes; " +
                "the KILL_BACKGROUND_PROCESSES permission is not granted"

        /**
         * `pm clear` needs `android.permission.DELETE_PACKAGES`-class authority that only a
         * signature/privileged app or a device owner holds. The ADB path is the honest one.
         */
        const val CLEAR_MESSAGE =
            "clearing app data needs a signature-level permission an installed app cannot " +
                "hold; use the ADB path: adb shell pm clear <package>"

        /**
         * `PackageManager.setApplicationEnabledSetting` needs `CHANGE_COMPONENT_ENABLED_STATE`,
         * a signature-level permission. The ADB path is the honest one.
         */
        const val SET_ENABLED_MESSAGE =
            "enabling or disabling a package needs a signature-level permission an installed " +
                "app cannot hold; use the ADB path: adb shell pm disable-user --user 0 <package>"
    }
}

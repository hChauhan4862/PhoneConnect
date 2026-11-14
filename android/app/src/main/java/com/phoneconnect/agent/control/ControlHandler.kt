package com.phoneconnect.agent.control

import org.json.JSONObject

/** One reading: a value the platform produced, or the constant reason it produced none. */
data class Reading<out T>(val value: T?, val reason: String?) {
    companion object {
        fun <T : Any> of(value: T): Reading<T> = Reading(value, null)

        fun unavailable(reason: String): Reading<Nothing> = Reading(null, reason)
    }
}

/**
 * What the `control.*` commands need from Android.
 *
 * The interface exists so the handler's decisions — what is refused before any platform call,
 * what a grant gates, and what an unreadable value becomes — are testable without a device.
 * The only production implementation is [AndroidControlPlatform].
 */
interface ControlPlatform {
    fun brightness(): Reading<Int>

    fun brightnessMode(): Reading<Int>

    fun volumeMusic(): Reading<Int>

    fun volumeMax(): Reading<Int>

    fun rotation(): Reading<Int>

    fun dndFilter(): Reading<Int>

    fun nightMode(): Reading<Int>

    fun wifiEnabled(): Reading<Boolean>

    fun bluetoothEnabled(): Reading<Boolean>

    fun mobileDataEnabled(): Reading<Boolean>

    fun batterySaver(): Reading<Boolean>

    fun batteryPercent(): Reading<Int>

    /** Whether the user has allowed this package to modify system settings. */
    fun canWriteSettings(): Boolean

    /**
     * Writes `Settings.System.SCREEN_BRIGHTNESS`; `false` when the provider refused the write.
     * Throws `SecurityException` when the grant vanished between the check and the write.
     */
    fun writeBrightness(value: Int): Boolean

    /**
     * Writes `Settings.System.SCREEN_BRIGHTNESS_MODE`; `false` when the provider refused the
     * write. Throws `SecurityException` when the grant vanished before the write.
     */
    fun writeBrightnessMode(mode: Int): Boolean

    /** Whether the user has granted notification-policy (Do Not Disturb) access. */
    fun hasPolicyAccess(): Boolean

    /** Applies a music-stream volume; `false` when the device has no audio service. */
    fun writeVolumeMusic(value: Int): Boolean

    /** Applies an interruption filter; `false` when the device has no notification service. */
    fun writeDndFilter(value: Int): Boolean
}

/** The keys `control.get` reports and `control.set` names. */
object ControlKey {
    const val BRIGHTNESS = "brightness"
    const val BRIGHTNESS_MODE = "brightness_mode"
    const val VOLUME_MUSIC = "volume_music"
    const val VOLUME_MAX = "volume_max"
    const val ROTATION = "rotation"
    const val DND_FILTER = "dnd_filter"
    const val NIGHT_MODE = "night_mode"
    const val WIFI_ENABLED = "wifi_enabled"
    const val BLUETOOTH_ENABLED = "bluetooth_enabled"
    const val MOBILE_DATA_ENABLED = "mobile_data_enabled"
    const val BATTERY_SAVER = "battery_saver"
    const val BATTERY_PERCENT = "battery_percent"

    /**
     * The changes `control.set` names. The radios lose the `_enabled` suffix because the
     * command names the radio, not the reading.
     */
    const val WIFI = "wifi"
    const val BLUETOOTH = "bluetooth"
    const val MOBILE_DATA = "mobile_data"

    /**
     * Not a reading: `control.reboot` is named in `unavailable` too, so the UI renders its
     * reason from the device's own answer instead of hardcoding one.
     */
    const val REBOOT = "reboot"
}

/**
 * The constant reasons a control is unavailable. Each one is a stable machine token the caller
 * and the UI render; a reason never carries platform text or a device path.
 */
object ControlReason {
    /** The user has not allowed this package to modify system settings (`WRITE_SETTINGS`). */
    const val WRITE_SETTINGS_REQUIRED = "write_settings_required"

    /** The user has not granted notification-policy (Do Not Disturb) access. */
    const val POLICY_ACCESS_REQUIRED = "policy_access_required"

    /** `REBOOT` is signature-level; only a system or device-owner build could reboot. */
    const val REBOOT_REQUIRES_PRIVILEGE = "reboot_requires_privilege"

    /** `WifiManager.setWifiEnabled` returns false for an app targeting Android 10+. */
    const val WIFI_SETTER_REMOVED = "wifi_setter_removed"

    /** `BluetoothAdapter.enable` is a no-op for an app targeting Android 13+. */
    const val BLUETOOTH_SETTER_REMOVED = "bluetooth_setter_removed"

    /** `TelephonyManager.setDataEnabled` needs the signature-level `MODIFY_PHONE_STATE`. */
    const val MOBILE_DATA_SETTER_SIGNATURE_GATED = "mobile_data_setter_signature_gated"

    /** `UiModeManager.setNightMode` needs the signature-level `MODIFY_DAY_NIGHT_MODE`. */
    const val NIGHT_MODE_SETTER_SIGNATURE_GATED = "night_mode_setter_signature_gated"

    /** The rotation lock belongs to the system UI; an installed app has no setter for it. */
    const val ROTATION_REQUIRES_SYSTEM_UI = "rotation_requires_system_ui"

    /** The platform threw, or does not keep the setting this key names. */
    const val PLATFORM_READ_FAILED = "platform_read_failed"

    /** The device reports no Bluetooth adapter. */
    const val NO_BLUETOOTH_ADAPTER = "no_bluetooth_adapter"

    /** The device has no mobile-data radio. */
    const val NO_TELEPHONY_DATA = "no_telephony_data"

    /** `BatteryManager` does not report a capacity for this device. */
    const val BATTERY_NOT_REPORTED = "battery_not_reported"

    /** The settings provider accepted the brightness write but the value did not stick. */
    const val BRIGHTNESS_NOT_APPLIED = "brightness_not_applied"

    /**
     * Automatic brightness governs the display from ambient light, so a stored value would not
     * hold; the mode could not be turned off.
     */
    const val BRIGHTNESS_MODE_AUTOMATIC = "brightness_mode_automatic"

    /**
     * The platform accepted a write but would not report the value back, so nothing confirms
     * that the change took.
     */
    const val READ_BACK_UNAVAILABLE = "read_back_unavailable"

    /** The audio service accepted the volume change but the stream reports another index. */
    const val VOLUME_NOT_APPLIED = "volume_not_applied"

    /** The interruption filter did not become the requested one. */
    const val DND_NOT_APPLIED = "dnd_not_applied"

    /** The stream max cannot be read, so no volume in range can be validated. */
    const val VOLUME_MAX_UNREADABLE = "volume_max_unreadable"
}

/**
 * `control.get`, `control.set`, and `control.reboot`.
 *
 * An ordinary installed app can read most of these values and change three of them — and the
 * three only with a grant the user gives on the setup screen. Everything else is a constant,
 * documented refusal: the setters Android removed or made signature-level, and a reboot that
 * needs `REBOOT`. Nothing here is a silent no-op:
 *
 * - `control.get` reports a value or `null`, and names the constant reason in `unavailable`.
 *   A platform exception becomes `null` with a reason, never an `internal_error` (a read can
 *   never throw) and never a fabricated zero.
 * - `control.set` validates the value before any write, refuses a missing grant with the
 *   machine reason the UI shows, and confirms an accepted write by reading the value back.
 *   Brightness turns automatic mode off first and reports that side effect, because a value
 *   written under an ambient-light strategy would never reach the display. A write the
 *   platform accepted but did not apply is `not_applied`, and a write it would not let the app
 *   confirm is `unconfirmed`: neither is ever `ok`.
 * - `control.reboot` exists so a caller gets `reboot_requires_privilege` rather than
 *   `unknown_command`; there is no reboot path that cannot work.
 */
class ControlHandler(private val platform: ControlPlatform) {
    fun handle(name: String, args: JSONObject?): JSONObject = when (name) {
        CommandDispatcher.CONTROL_GET -> read()
        CommandDispatcher.CONTROL_SET -> set(args)
        CommandDispatcher.CONTROL_REBOOT -> throw CommandFailure(
            NOT_PERMITTED,
            ControlReason.REBOOT_REQUIRES_PRIVILEGE,
        )

        else -> throw CommandFailure.unknown(name)
    }

    /**
     * Every reading, plus the keys the platform refuses, with their constant reasons.
     *
     * A key in `unavailable` is unavailable for some purpose: when the reading is also present
     * it is the *change* that is refused (brightness without `WRITE_SETTINGS`, night mode). A
     * read that fails writes its own reason over a setter reason, because the missing value is
     * what the caller sees first.
     */
    fun read(): JSONObject {
        val unavailable = JSONObject()
        // The five changes Android has no app-facing setter for, and the reboot that needs a
        // signature-level permission. They are named here so the UI can render a disabled
        // control with the reason instead of a button that would fail.
        unavailable.put(ControlKey.WIFI, ControlReason.WIFI_SETTER_REMOVED)
        unavailable.put(ControlKey.BLUETOOTH, ControlReason.BLUETOOTH_SETTER_REMOVED)
        unavailable.put(ControlKey.MOBILE_DATA, ControlReason.MOBILE_DATA_SETTER_SIGNATURE_GATED)
        unavailable.put(ControlKey.NIGHT_MODE, ControlReason.NIGHT_MODE_SETTER_SIGNATURE_GATED)
        unavailable.put(ControlKey.ROTATION, ControlReason.ROTATION_REQUIRES_SYSTEM_UI)
        unavailable.put(ControlKey.REBOOT, ControlReason.REBOOT_REQUIRES_PRIVILEGE)
        if (!writeSettingsGranted()) {
            unavailable.put(ControlKey.BRIGHTNESS, ControlReason.WRITE_SETTINGS_REQUIRED)
        }
        if (!policyAccessGranted()) {
            unavailable.put(ControlKey.DND_FILTER, ControlReason.POLICY_ACCESS_REQUIRED)
        }

        val readings = JSONObject()
        record(readings, unavailable, ControlKey.BRIGHTNESS, platform::brightness)
        record(readings, unavailable, ControlKey.BRIGHTNESS_MODE, platform::brightnessMode)
        record(readings, unavailable, ControlKey.VOLUME_MUSIC, platform::volumeMusic)
        record(readings, unavailable, ControlKey.VOLUME_MAX, platform::volumeMax)
        record(readings, unavailable, ControlKey.ROTATION, platform::rotation)
        record(readings, unavailable, ControlKey.DND_FILTER, platform::dndFilter)
        record(readings, unavailable, ControlKey.NIGHT_MODE, platform::nightMode)
        record(readings, unavailable, ControlKey.WIFI_ENABLED, platform::wifiEnabled)
        record(readings, unavailable, ControlKey.BLUETOOTH_ENABLED, platform::bluetoothEnabled)
        record(readings, unavailable, ControlKey.MOBILE_DATA_ENABLED, platform::mobileDataEnabled)
        record(readings, unavailable, ControlKey.BATTERY_SAVER, platform::batterySaver)
        record(readings, unavailable, ControlKey.BATTERY_PERCENT, platform::batteryPercent)
        return readings.put(UNAVAILABLE, unavailable)
    }

    /** Applies one change, or refuses it with the reason the platform gives. */
    fun set(args: JSONObject?): JSONObject {
        val key = requiredKey(args)
        val value = requiredValue(args)
        return when (key) {
            ControlKey.BRIGHTNESS -> setBrightness(
                requireRange(value, key, 0, MAX_BRIGHTNESS),
            )

            ControlKey.VOLUME_MUSIC -> setVolume(requireInteger(value, key))
            ControlKey.DND_FILTER -> setDnd(
                requireRange(value, key, MIN_INTERRUPTION_FILTER, MAX_INTERRUPTION_FILTER),
            )

            ControlKey.WIFI, ControlKey.BLUETOOTH, ControlKey.MOBILE_DATA,
            ControlKey.NIGHT_MODE, ControlKey.ROTATION,
            // No value can make these work, so no value is validated: the caller gets the
            // platform restriction instead of a complaint about the value's type.
            -> throw CommandFailure(NOT_PERMITTED, refusedReason(key))

            else -> throw CommandFailure.invalid("key is not a control this build implements")
        }
    }

    private fun setBrightness(value: Int): JSONObject {
        if (!writeSettingsGranted()) {
            throw CommandFailure(NOT_PERMITTED, ControlReason.WRITE_SETTINGS_REQUIRED)
        }
        // Under automatic brightness the display is governed by the ambient-light strategy, so
        // a value written to the setting would never reach it: the mode is turned off first and
        // that side effect is reported in the answer. An unreadable mode is treated as
        // automatic, because writing a value the display might ignore is the failure this
        // guards against.
        val mode = observed(platform::brightnessMode)
        val modeChanged = mode != BRIGHTNESS_MODE_MANUAL
        if (modeChanged) {
            writeMode(BRIGHTNESS_MODE_MANUAL)
        }
        val accepted = try {
            platform.writeBrightness(value)
        } catch (_: SecurityException) {
            // The user turned the grant off between the check and the write.
            throw CommandFailure(NOT_PERMITTED, ControlReason.WRITE_SETTINGS_REQUIRED)
        }
        if (!accepted) {
            throw CommandFailure(NOT_APPLIED, ControlReason.BRIGHTNESS_NOT_APPLIED)
        }
        // The value itself is read back from the store that was written: a provider that
        // accepted the write but kept another value did not apply the change.
        val current = observed(platform::brightness)
            ?: throw CommandFailure(UNCONFIRMED, ControlReason.READ_BACK_UNAVAILABLE)
        if (current != value) {
            throw CommandFailure(NOT_APPLIED, ControlReason.BRIGHTNESS_NOT_APPLIED)
        }
        // A device that turned automatic back on between the two writes did not keep the value.
        val finalMode = observed(platform::brightnessMode)
        if (finalMode != null && finalMode != BRIGHTNESS_MODE_MANUAL) {
            throw CommandFailure(NOT_APPLIED, ControlReason.BRIGHTNESS_MODE_AUTOMATIC)
        }
        return applied(ControlKey.BRIGHTNESS, value)
            .put(ControlKey.BRIGHTNESS_MODE, finalMode ?: BRIGHTNESS_MODE_MANUAL)
            .put(MODE_CHANGED, modeChanged)
    }

    /** Turns automatic brightness off, or refuses rather than leaving a value that cannot hold. */
    private fun writeMode(mode: Int) {
        val accepted = try {
            platform.writeBrightnessMode(mode)
        } catch (_: SecurityException) {
            throw CommandFailure(NOT_PERMITTED, ControlReason.WRITE_SETTINGS_REQUIRED)
        }
        if (!accepted) {
            throw CommandFailure(NOT_APPLIED, ControlReason.BRIGHTNESS_MODE_AUTOMATIC)
        }
    }

    private fun setVolume(value: Int): JSONObject {
        if (value < 0) throw CommandFailure.invalid("value for volume_music must not be negative")
        val max = try {
            platform.volumeMax()
        } catch (_: Exception) {
            Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)
        }
        val limit = max.value
            ?: throw CommandFailure(
                ControlReason.PLATFORM_READ_FAILED,
                ControlReason.VOLUME_MAX_UNREADABLE,
            )
        if (value > limit) {
            throw CommandFailure.invalid("value for volume_music must be at most $limit")
        }
        val accepted = try {
            platform.writeVolumeMusic(value)
        } catch (_: SecurityException) {
            // From Android N, a volume change that would toggle Do Not Disturb needs policy
            // access, and the platform throws instead of refusing quietly.
            throw CommandFailure(NOT_PERMITTED, ControlReason.POLICY_ACCESS_REQUIRED)
        }
        if (!accepted) {
            throw CommandFailure(NOT_APPLIED, ControlReason.VOLUME_NOT_APPLIED)
        }
        val current = observed(platform::volumeMusic)
            ?: throw CommandFailure(UNCONFIRMED, ControlReason.READ_BACK_UNAVAILABLE)
        if (current != value) {
            throw CommandFailure(NOT_APPLIED, ControlReason.VOLUME_NOT_APPLIED)
        }
        return applied(ControlKey.VOLUME_MUSIC, value)
    }

    private fun setDnd(value: Int): JSONObject {
        if (!policyAccessGranted()) {
            throw CommandFailure(NOT_PERMITTED, ControlReason.POLICY_ACCESS_REQUIRED)
        }
        val accepted = try {
            platform.writeDndFilter(value)
        } catch (_: SecurityException) {
            throw CommandFailure(NOT_PERMITTED, ControlReason.POLICY_ACCESS_REQUIRED)
        }
        if (!accepted) {
            throw CommandFailure(NOT_APPLIED, ControlReason.DND_NOT_APPLIED)
        }
        val current = observed(platform::dndFilter)
            ?: throw CommandFailure(UNCONFIRMED, ControlReason.READ_BACK_UNAVAILABLE)
        if (current != value) {
            throw CommandFailure(NOT_APPLIED, ControlReason.DND_NOT_APPLIED)
        }
        return applied(ControlKey.DND_FILTER, value)
    }

    /** One reading; a platform exception is `null` plus the constant reason, never a throw. */
    private fun record(
        readings: JSONObject,
        unavailable: JSONObject,
        key: String,
        read: () -> Reading<Any>,
    ) {
        val reading = try {
            read()
        } catch (_: Exception) {
            Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)
        }
        val value = reading.value
        if (value == null) {
            readings.put(key, JSONObject.NULL)
            unavailable.put(key, reading.reason ?: ControlReason.PLATFORM_READ_FAILED)
        } else {
            readings.put(key, value)
        }
    }

    private fun applied(key: String, value: Any): JSONObject = JSONObject()
        .put("key", key)
        .put("value", value)
        .put("applied", true)

    /** The read-back of a write, or `null` when the platform will not report it. */
    private fun observed(read: () -> Reading<Int>): Int? = try {
        read().value
    } catch (_: Exception) {
        null
    }

    private fun writeSettingsGranted(): Boolean = try {
        platform.canWriteSettings()
    } catch (_: Exception) {
        false
    }

    private fun policyAccessGranted(): Boolean = try {
        platform.hasPolicyAccess()
    } catch (_: Exception) {
        false
    }

    private fun refusedReason(key: String): String = when (key) {
        ControlKey.WIFI -> ControlReason.WIFI_SETTER_REMOVED
        ControlKey.BLUETOOTH -> ControlReason.BLUETOOTH_SETTER_REMOVED
        ControlKey.MOBILE_DATA -> ControlReason.MOBILE_DATA_SETTER_SIGNATURE_GATED
        ControlKey.NIGHT_MODE -> ControlReason.NIGHT_MODE_SETTER_SIGNATURE_GATED
        ControlKey.ROTATION -> ControlReason.ROTATION_REQUIRES_SYSTEM_UI
        else -> ControlReason.PLATFORM_READ_FAILED
    }

    private fun requiredKey(args: JSONObject?): String {
        val value = args?.opt("key") ?: throw CommandFailure.invalid("key is required")
        if (value == JSONObject.NULL) throw CommandFailure.invalid("key is required")
        if (value !is String) throw CommandFailure.invalid("key must be a string")
        val key = value.trim()
        if (key.isEmpty()) throw CommandFailure.invalid("key must not be empty")
        return key
    }

    private fun requiredValue(args: JSONObject?): Any {
        val value = args?.opt("value") ?: throw CommandFailure.invalid("value is required")
        if (value == JSONObject.NULL) throw CommandFailure.invalid("value is required")
        return value
    }

    private fun requireInteger(value: Any, key: String): Int {
        val number = value as? Number
            ?: throw CommandFailure.invalid("value for $key must be an integer")
        val asDouble = number.toDouble()
        if (asDouble % 1.0 != 0.0) {
            throw CommandFailure.invalid("value for $key must be an integer")
        }
        return asDouble.toInt()
    }

    private fun requireRange(value: Any, key: String, min: Int, max: Int): Int {
        val number = requireInteger(value, key)
        if (number < min || number > max) {
            throw CommandFailure.invalid("value for $key must be in $min..$max")
        }
        return number
    }

    companion object {
        const val NOT_PERMITTED = "not_permitted"

        /** The platform accepted a call but the value did not take, so the answer is not `ok`. */
        const val NOT_APPLIED = "not_applied"

        /**
         * The platform accepted a call but would not report the value back, so the change is
         * not confirmed either way and the answer is not `ok`.
         */
        const val UNCONFIRMED = "unconfirmed"

        /** The answer's field naming the brightness mode the device now runs under. */
        const val MODE_CHANGED = "mode_changed"

        /** `Settings.System.SCREEN_BRIGHTNESS_MODE_MANUAL` and `_AUTOMATIC`. */
        const val BRIGHTNESS_MODE_MANUAL = 0
        const val BRIGHTNESS_MODE_AUTOMATIC = 1

        /** The map of keys the platform refuses, keyed by the control's own name. */
        const val UNAVAILABLE = "unavailable"

        /** Android stores screen brightness as 0–255. */
        const val MAX_BRIGHTNESS = 255

        /** `NotificationManager.INTERRUPTION_FILTER_ALL` … `INTERRUPTION_FILTER_ALARMS`. */
        const val MIN_INTERRUPTION_FILTER = 1
        const val MAX_INTERRUPTION_FILTER = 4
    }
}

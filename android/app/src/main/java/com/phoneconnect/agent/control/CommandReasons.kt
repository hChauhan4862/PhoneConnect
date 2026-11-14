package com.phoneconnect.agent.control

/**
 * Every stable machine token this agent can answer with: a failure code, a reason in
 * `unavailable`, or a message that is itself a token.
 *
 * This is the one list `CapabilityMatrixTest` enforces against `docs/capabilities.md`, and the
 * handlers take their tokens from here rather than carrying their own literals, so a new
 * refusal cannot exist only in code. The document says which command produces each token.
 */
internal object CommandReasons {
    // Answers the dispatcher and the channel give for any command.
    const val UNKNOWN_COMMAND = "unknown_command"
    const val INVALID_ARGS = "invalid_args"
    const val INTERNAL_ERROR = "internal_error"
    const val TIMEOUT = "timeout"

    /** A command, key, or operation an ordinary installed app has no authority to perform. */
    const val NOT_PERMITTED = "not_permitted"

    // The shared file root and the commands that act inside it.
    const val NOT_FOUND = "not_found"
    const val NOT_A_DIRECTORY = "not_a_directory"
    const val NOT_A_FILE = "not_a_file"
    const val TOO_LARGE = "too_large"
    const val IS_DIRECTORY = "is_directory"
    const val ALREADY_EXISTS = "already_exists"
    const val DIR_NOT_EMPTY = "dir_not_empty"
    const val IO_ERROR = "io_error"
    const val LISTING_TOO_LARGE = "listing_too_large"
    const val INVALID_PATH = "invalid_path"
    const val PATH_OUTSIDE_ROOT = "path_outside_root"

    // The app inventory and the commands that act on a package.
    const val NO_LAUNCH_ACTIVITY = "no_launch_activity"
    const val LAUNCH_BLOCKED = "launch_blocked"
    const val UNKNOWN_PACKAGE = "unknown_package"

    /** Why a launch was blocked: Android restricts a background start, or refused this one. */
    const val BACKGROUND_ACTIVITY_START_RESTRICTED = "background_activity_start_restricted"
    const val PLATFORM_REFUSED = "platform_refused"

    // Screen capture.
    const val CONSENT_REQUIRED = "consent_required"
    const val CAPTURE_FAILED = "capture_failed"
    const val CAPTURE_TIMEOUT = "capture_timeout"
    const val RESULT_TOO_LARGE = "result_too_large"

    // System properties.
    const val PROPS_UNAVAILABLE = "props_unavailable"

    // Control writes: the answer is not `ok`, and these are the two ways it can fall short.
    const val NOT_APPLIED = "not_applied"
    const val UNCONFIRMED = "unconfirmed"

    // Control readings and changes: one constant reason per platform restriction or fault.
    const val WRITE_SETTINGS_REQUIRED = "write_settings_required"
    const val POLICY_ACCESS_REQUIRED = "policy_access_required"
    const val REBOOT_REQUIRES_PRIVILEGE = "reboot_requires_privilege"
    const val WIFI_SETTER_REMOVED = "wifi_setter_removed"
    const val BLUETOOTH_SETTER_REMOVED = "bluetooth_setter_removed"
    const val MOBILE_DATA_SETTER_SIGNATURE_GATED = "mobile_data_setter_signature_gated"
    const val NIGHT_MODE_SETTER_SIGNATURE_GATED = "night_mode_setter_signature_gated"
    const val ROTATION_REQUIRES_SYSTEM_UI = "rotation_requires_system_ui"
    const val PLATFORM_READ_FAILED = "platform_read_failed"
    const val NO_BLUETOOTH_ADAPTER = "no_bluetooth_adapter"
    const val NO_TELEPHONY_DATA = "no_telephony_data"
    const val BATTERY_NOT_REPORTED = "battery_not_reported"
    const val BRIGHTNESS_NOT_APPLIED = "brightness_not_applied"
    const val BRIGHTNESS_MODE_AUTOMATIC = "brightness_mode_automatic"
    const val READ_BACK_UNAVAILABLE = "read_back_unavailable"
    const val BRIGHTNESS_NOT_APPLIED_MODE_LEFT_MANUAL = "brightness_not_applied_mode_left_manual"
    const val READ_BACK_UNAVAILABLE_MODE_LEFT_MANUAL = "read_back_unavailable_mode_left_manual"
    const val WRITE_SETTINGS_REQUIRED_MODE_LEFT_MANUAL = "write_settings_required_mode_left_manual"
    const val VOLUME_NOT_APPLIED = "volume_not_applied"
    const val DND_NOT_APPLIED = "dnd_not_applied"
    const val VOLUME_MAX_UNREADABLE = "volume_max_unreadable"

    /** Every token a device answer may carry, in the order the families appear in the document. */
    val tokens: List<String> = listOf(
        UNKNOWN_COMMAND,
        INVALID_ARGS,
        INTERNAL_ERROR,
        TIMEOUT,
        NOT_PERMITTED,
        NOT_FOUND,
        NOT_A_DIRECTORY,
        NOT_A_FILE,
        TOO_LARGE,
        IS_DIRECTORY,
        ALREADY_EXISTS,
        DIR_NOT_EMPTY,
        IO_ERROR,
        LISTING_TOO_LARGE,
        INVALID_PATH,
        PATH_OUTSIDE_ROOT,
        NO_LAUNCH_ACTIVITY,
        LAUNCH_BLOCKED,
        UNKNOWN_PACKAGE,
        BACKGROUND_ACTIVITY_START_RESTRICTED,
        PLATFORM_REFUSED,
        CONSENT_REQUIRED,
        CAPTURE_FAILED,
        CAPTURE_TIMEOUT,
        RESULT_TOO_LARGE,
        PROPS_UNAVAILABLE,
        NOT_APPLIED,
        UNCONFIRMED,
        WRITE_SETTINGS_REQUIRED,
        POLICY_ACCESS_REQUIRED,
        REBOOT_REQUIRES_PRIVILEGE,
        WIFI_SETTER_REMOVED,
        BLUETOOTH_SETTER_REMOVED,
        MOBILE_DATA_SETTER_SIGNATURE_GATED,
        NIGHT_MODE_SETTER_SIGNATURE_GATED,
        ROTATION_REQUIRES_SYSTEM_UI,
        PLATFORM_READ_FAILED,
        NO_BLUETOOTH_ADAPTER,
        NO_TELEPHONY_DATA,
        BATTERY_NOT_REPORTED,
        BRIGHTNESS_NOT_APPLIED,
        BRIGHTNESS_MODE_AUTOMATIC,
        READ_BACK_UNAVAILABLE,
        BRIGHTNESS_NOT_APPLIED_MODE_LEFT_MANUAL,
        READ_BACK_UNAVAILABLE_MODE_LEFT_MANUAL,
        WRITE_SETTINGS_REQUIRED_MODE_LEFT_MANUAL,
        VOLUME_NOT_APPLIED,
        DND_NOT_APPLIED,
        VOLUME_MAX_UNREADABLE,
    )
}

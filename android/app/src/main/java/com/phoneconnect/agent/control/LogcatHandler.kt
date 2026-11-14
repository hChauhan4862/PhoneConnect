package com.phoneconnect.agent.control

import org.json.JSONObject

/**
 * `logcat.tail`: always a refusal, and the same refusal every time.
 *
 * The system log is protected by `READ_LOGS`, a signature-level permission only a system or
 * privileged app can hold. The command exists so a caller receives `not_permitted` with the
 * platform reason instead of `unknown_command`, and it never returns a fabricated log.
 */
class LogcatHandler {
    fun tail(): JSONObject = throw CommandFailure(NOT_PERMITTED, MESSAGE)

    companion object {
        const val NOT_PERMITTED: String = CommandReasons.NOT_PERMITTED

        const val MESSAGE =
            "an ordinary installed app cannot read the system log: READ_LOGS is a " +
                "signature-level permission, so only a system or privileged app can read logcat"
    }
}

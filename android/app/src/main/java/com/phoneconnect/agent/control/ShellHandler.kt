package com.phoneconnect.agent.control

import org.json.JSONObject

/**
 * `shell.exec`: always a refusal, and the same refusal every time.
 *
 * Android gives command execution to the ADB shell UID (or root); a user-installed app has
 * neither. The command exists so a caller receives `not_permitted` with a reason instead of
 * `unknown_command`, and it never pretends to have run anything.
 */
class ShellHandler {
    fun exec(): JSONObject = throw CommandFailure(NOT_PERMITTED, MESSAGE)

    companion object {
        const val NOT_PERMITTED = "not_permitted"

        const val MESSAGE =
            "an ordinary installed app cannot run a shell: executing commands on the device " +
                "needs the privileged shell (ADB) or root user, which this app is not"
    }
}

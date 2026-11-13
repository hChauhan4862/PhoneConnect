package com.phoneconnect.agent

import android.content.Context
import androidx.core.content.edit

/**
 * Persistent, non-secret diagnostics the setup screen shows: why a background start was
 * refused, so a user can act on it instead of seeing a service that silently never ran.
 */
class AgentDiagnostics(context: Context) {
    private val preferences = context.applicationContext
        .getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun lastStartRefusal(): String? = preferences.getString(KEY_START_REFUSAL, null)

    fun recordStartRefusal(reason: String) {
        preferences.edit(commit = true) { putString(KEY_START_REFUSAL, reason) }
    }

    fun clearStartRefusal() {
        preferences.edit(commit = true) { remove(KEY_START_REFUSAL) }
    }

    companion object {
        const val PREFERENCES_NAME = "phoneconnect.diagnostics"
        private const val KEY_START_REFUSAL = "last_start_refusal"
    }
}

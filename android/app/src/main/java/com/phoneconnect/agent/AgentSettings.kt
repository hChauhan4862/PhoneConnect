package com.phoneconnect.agent

import android.content.Context
import androidx.core.content.edit

/**
 * Non-secret agent settings the setup screen writes and the service reads: the hub URL.
 * Kept apart from [EnrollmentStore] because it must be readable before any enrollment
 * exists, and it holds nothing that needs the Keystore.
 */
class AgentSettings(context: Context) {
    private val preferences = context.applicationContext
        .getSharedPreferences(PREFERENCES_NAME, Context.MODE_PRIVATE)

    fun hubUrl(): String? = preferences.getString(KEY_HUB_URL, null)?.takeIf { it.isNotBlank() }

    fun setHubUrl(url: String) {
        preferences.edit(commit = true) { putString(KEY_HUB_URL, url.trim()) }
    }

    companion object {
        const val PREFERENCES_NAME = "phoneconnect.settings"
        private const val KEY_HUB_URL = "hub_url"
    }
}

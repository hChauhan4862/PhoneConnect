package com.phoneconnect.agent.system

import android.content.Context
import android.content.Intent
import android.net.Uri
import android.os.PowerManager
import android.provider.Settings
import android.util.Log

/**
 * The battery-optimisation exemption, asked for honestly.
 *
 * Android (and every OEM battery manager) may stop a foreground service. The documented
 * mitigation is an exemption the user grants in Android's own settings; this app can only
 * open that screen and report what Android says afterwards. It is a request, not a right: when
 * it is refused the agent keeps working, less reliably, and the setup screen says so instead of
 * pretending the app cannot be stopped.
 */
object BatteryExemption {
    private const val TAG = "BatteryExemption"

    /** The system dialog, scoped to this package. */
    const val ACTION_REQUEST_IGNORE = "android.settings.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS"

    fun isIgnoring(context: Context): Boolean = runCatching {
        context.getSystemService(PowerManager::class.java)
            ?.isIgnoringBatteryOptimizations(context.packageName) == true
    }.getOrElse { error ->
        Log.w(TAG, "could not read the battery-optimisation state: ${error.javaClass.simpleName}")
        false
    }

    /** The scoped request dialog. Some builds do not answer it; callers handle that. */
    fun request(packageName: String): Intent =
        Intent(ACTION_REQUEST_IGNORE)
            .setData(Uri.parse("package:$packageName"))

    /** The settings list, for a build that refuses the scoped dialog. */
    fun settings(): Intent =
        Intent(Settings.ACTION_IGNORE_BATTERY_OPTIMIZATION_SETTINGS)
}

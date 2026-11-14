package com.phoneconnect.agent.control

import android.app.ActivityManager
import android.content.Context
import android.content.Intent
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.content.pm.PackageManager
import android.os.Build
import android.os.Process

/**
 * The production [AppPlatform]: `PackageManager` for the inventory and the launch intent,
 * `ActivityManager` for the background kill and for whether an activity start is allowed.
 *
 * Every platform call is wrapped, because its exception message can name absolute device
 * paths; a failure becomes a [CommandFailure] carrying a code and the exception's class name.
 */
class AndroidAppPlatform(private val context: Context) : AppPlatform {
    private val packageManager: PackageManager = context.packageManager
    private val activityManager: ActivityManager =
        context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager

    override fun installed(): List<InstalledApp> {
        val packages = try {
            installedPackages()
        } catch (error: RuntimeException) {
            throw CommandFailure(
                "io_error",
                "reading the installed apps failed (${error.javaClass.simpleName})",
            )
        }
        return packages.mapNotNull(::toInstalledApp)
    }

    override fun launchIntent(packageName: String): Intent? =
        runCatching { packageManager.getLaunchIntentForPackage(packageName) }.getOrNull()

    override fun startActivity(intent: Intent) {
        // A service context is not an activity: without NEW_TASK the platform refuses this.
        context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
    }

    override fun killBackgroundProcesses(packageName: String) {
        activityManager.killBackgroundProcesses(packageName)
    }

    override fun mayStartActivityFromBackground(): Boolean {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) return true
        // Android 10+ blocks a background activity start without throwing. Only a foreground
        // *activity* is exempt; a foreground service is not, so this agent normally cannot
        // launch and must say so. When the platform will not report our importance, refuse
        // rather than guess that a launch would work.
        val self = runCatching {
            activityManager.getRunningAppProcesses()?.firstOrNull { it.pid == Process.myPid() }
        }.getOrNull() ?: return false
        return self.importance <= ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND
    }

    private fun installedPackages(): List<PackageInfo> =
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
            packageManager.getInstalledPackages(PackageManager.PackageInfoFlags.of(0))
        } else {
            @Suppress("DEPRECATION")
            packageManager.getInstalledPackages(0)
        }

    private fun toInstalledApp(info: PackageInfo): InstalledApp? {
        val application = info.applicationInfo ?: return null
        return InstalledApp(
            packageName = info.packageName,
            // Empty when the platform cannot resolve a label; the handler then falls back to
            // the package name rather than inventing one.
            label = labelOf(application),
            versionName = info.versionName,
            versionCode = info.longVersionCode,
            system = (application.flags and ApplicationInfo.FLAG_SYSTEM) != 0,
            enabled = application.enabled,
            updatedMs = info.lastUpdateTime,
        )
    }

    private fun labelOf(application: ApplicationInfo): String =
        runCatching { packageManager.getApplicationLabel(application)?.toString() }
            .getOrNull()
            ?.takeIf { it.isNotBlank() }
            ?: ""
}

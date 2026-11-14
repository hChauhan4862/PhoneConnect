package com.phoneconnect.agent

import android.app.ActivityManager
import android.content.ComponentName
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.content.pm.ApplicationInfo
import android.content.pm.PackageInfo
import android.os.Process
import androidx.test.core.app.ApplicationProvider
import com.phoneconnect.agent.control.AndroidAppPlatform
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * The production adapter, against Robolectric's package and activity managers: the inventory
 * comes from `PackageManager`, and a background-activity decision comes from the platform
 * rather than from an assumption.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AndroidAppPlatformTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val packageManager = context.packageManager
    private val activityManager =
        context.getSystemService(Context.ACTIVITY_SERVICE) as ActivityManager
    private val platform = AndroidAppPlatform(context)

    @Test
    fun `installed reports what the package manager holds`() {
        install("com.example.zeta", label = "Zeta", system = true, enabled = false)

        val app = platform.installed().single { it.packageName == "com.example.zeta" }

        assertEquals("Zeta", app.label)
        assertEquals("1.2.3", app.versionName)
        assertEquals(42L, app.versionCode)
        assertTrue(app.system)
        assertFalse(app.enabled)
        assertEquals(1_760_000_000_000L, app.updatedMs)
    }

    @Test
    fun `an unresolvable label is empty, not invented`() {
        install("com.example.silent", label = "", system = false, enabled = true)

        val app = platform.installed().single { it.packageName == "com.example.silent" }

        assertEquals("", app.label)
    }

    @Test
    fun `a launch intent exists only for a package with a launcher activity`() {
        install("com.example.zeta", label = "Zeta", system = false, enabled = true)
        install("com.example.serviceonly", label = "Service only", system = false, enabled = true)
        val component = ComponentName("com.example.zeta", "com.example.zeta.MainActivity")
        shadowOf(packageManager).addActivityIfNotPresent(component)
        shadowOf(packageManager).addIntentFilterForActivity(
            component,
            IntentFilter(Intent.ACTION_MAIN).apply { addCategory(Intent.CATEGORY_LAUNCHER) },
        )

        assertNotNull(platform.launchIntent("com.example.zeta"))
        assertNull(platform.launchIntent("com.example.serviceonly"))
    }

    @Test
    fun `a foreground service alone is not permission to start an activity`() {
        shadowOf(activityManager).setProcesses(listOf(process(ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND_SERVICE)))

        assertFalse(platform.mayStartActivityFromBackground())
    }

    @Test
    fun `a foreground activity permits an activity start`() {
        shadowOf(activityManager).setProcesses(listOf(process(ActivityManager.RunningAppProcessInfo.IMPORTANCE_FOREGROUND)))

        assertTrue(platform.mayStartActivityFromBackground())
    }

    @Test
    fun `an unknown process importance refuses rather than guesses`() {
        shadowOf(activityManager).setProcesses(emptyList())

        assertFalse(
            "without the platform's own answer the agent must not assume a launch would work",
            platform.mayStartActivityFromBackground(),
        )
    }

    @Test
    fun `the background kill reaches ActivityManager`() {
        install("com.example.zeta", label = "Zeta", system = false, enabled = true)

        platform.killBackgroundProcesses("com.example.zeta")

        assertEquals("com.example.zeta", shadowOf(activityManager).backgroundPackage)
    }

    private fun process(importance: Int) = ActivityManager.RunningAppProcessInfo().apply {
        pid = Process.myPid()
        this.importance = importance
    }

    private fun install(
        name: String,
        label: String,
        system: Boolean,
        enabled: Boolean,
    ) {
        val info = PackageInfo().apply {
            packageName = name
            versionName = "1.2.3"
            longVersionCode = 42L
            lastUpdateTime = 1_760_000_000_000L
            applicationInfo = ApplicationInfo().apply {
                packageName = name
                nonLocalizedLabel = label
                flags = if (system) ApplicationInfo.FLAG_SYSTEM else 0
                this.enabled = enabled
            }
        }
        shadowOf(packageManager).installPackage(info)
    }
}

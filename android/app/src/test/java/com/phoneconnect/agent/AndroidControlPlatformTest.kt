package com.phoneconnect.agent

import android.app.AppOpsManager
import android.app.NotificationManager
import android.app.UiModeManager
import android.bluetooth.BluetoothAdapter
import android.content.Context
import android.media.AudioManager
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.PowerManager
import android.provider.Settings
import androidx.test.core.app.ApplicationProvider
import com.phoneconnect.agent.control.AndroidControlPlatform
import com.phoneconnect.agent.control.ControlReason
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config
import org.robolectric.shadows.ShadowBluetoothAdapter

/**
 * The production adapter against Robolectric's own framework services: what the platform really
 * reads, what it really writes, and the constant reason it reports when it can read nothing.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AndroidControlPlatformTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()
    private val platform = AndroidControlPlatform(context)
    private val resolver = context.contentResolver
    private val audioManager = context.getSystemService(AudioManager::class.java)
    private val notificationManager = context.getSystemService(NotificationManager::class.java)

    @Test
    fun `brightness and its mode are read from the settings provider`() {
        Settings.System.putInt(resolver, Settings.System.SCREEN_BRIGHTNESS, 102)
        Settings.System.putInt(
            resolver,
            Settings.System.SCREEN_BRIGHTNESS_MODE,
            Settings.System.SCREEN_BRIGHTNESS_MODE_MANUAL,
        )

        assertEquals(102, platform.brightness().value)
        assertEquals(
            Settings.System.SCREEN_BRIGHTNESS_MODE_MANUAL,
            platform.brightnessMode().value,
        )
    }

    @Test
    fun `a missing setting is a constant reason, never a zero`() {
        // Robolectric's provider has no auto-rotate setting until one is written.
        Settings.System.putInt(resolver, Settings.System.SCREEN_BRIGHTNESS, 102)

        val rotation = platform.rotation()

        assertNull("a setting the platform does not hold must not read as 0", rotation.value)
        assertEquals(ControlReason.PLATFORM_READ_FAILED, rotation.reason)
    }

    @Test
    fun `writing brightness is read back, so a write the provider drops cannot look applied`() {
        Settings.System.putInt(resolver, Settings.System.SCREEN_BRIGHTNESS, 10)

        assertTrue(platform.writeBrightness(200))
        assertEquals(200, platform.brightness().value)
    }

    @Test
    fun `writing the brightness mode is read back`() {
        Settings.System.putInt(
            resolver,
            Settings.System.SCREEN_BRIGHTNESS_MODE,
            Settings.System.SCREEN_BRIGHTNESS_MODE_AUTOMATIC,
        )

        assertTrue(
            platform.writeBrightnessMode(Settings.System.SCREEN_BRIGHTNESS_MODE_MANUAL),
        )
        assertEquals(
            Settings.System.SCREEN_BRIGHTNESS_MODE_MANUAL,
            platform.brightnessMode().value,
        )
    }

    @Test
    fun `write settings is granted through the app op the user allows`() {
        val appOps = context.getSystemService(AppOpsManager::class.java)
        shadowOf(appOps).setMode(
            AppOpsManager.OPSTR_WRITE_SETTINGS,
            android.os.Process.myUid(),
            context.packageName,
            AppOpsManager.MODE_ERRORED,
        )
        assertFalse(
            "the user has not allowed system settings to be modified",
            platform.canWriteSettings(),
        )

        shadowOf(appOps).setMode(
            AppOpsManager.OPSTR_WRITE_SETTINGS,
            android.os.Process.myUid(),
            context.packageName,
            AppOpsManager.MODE_ALLOWED,
        )
        assertTrue(platform.canWriteSettings())
    }

    @Test
    fun `music volume is read and written through the audio service`() {
        shadowOf(audioManager).setStreamVolume(5)

        assertEquals(5, platform.volumeMusic().value)
        assertTrue("the stream max is a positive number", (platform.volumeMax().value ?: 0) > 0)

        platform.writeVolumeMusic(9)

        assertEquals(9, platform.volumeMusic().value)
    }

    @Test
    fun `the interruption filter is read and only writable with policy access`() {
        assertFalse("notification policy access is the user's to grant", platform.hasPolicyAccess())
        // The filter is readable without the grant; only changing it needs access.
        assertEquals(
            NotificationManager.INTERRUPTION_FILTER_ALL,
            platform.dndFilter().value,
        )

        shadowOf(notificationManager).setNotificationPolicyAccessGranted(true)
        assertTrue(platform.hasPolicyAccess())

        platform.writeDndFilter(NotificationManager.INTERRUPTION_FILTER_ALARMS)

        assertEquals(
            NotificationManager.INTERRUPTION_FILTER_ALARMS,
            platform.dndFilter().value,
        )
    }

    @Test
    fun `wi-fi and battery saver are read from their services`() {
        val wifi = context.getSystemService(WifiManager::class.java)
        shadowOf(wifi).setWifiState(WifiManager.WIFI_STATE_ENABLED)
        assertEquals(true, platform.wifiEnabled().value)

        shadowOf(wifi).setWifiState(WifiManager.WIFI_STATE_DISABLED)
        assertEquals(false, platform.wifiEnabled().value)

        val power = context.getSystemService(PowerManager::class.java)
        shadowOf(power).setIsPowerSaveMode(true)
        assertEquals(true, platform.batterySaver().value)
    }

    @Test
    fun `bluetooth reports its adapter state, and no adapter is a reason`() {
        val adapter = context.getSystemService(android.bluetooth.BluetoothManager::class.java).adapter
        shadowOf(adapter).setEnabled(true)
        assertEquals(true, platform.bluetoothEnabled().value)

        ShadowBluetoothAdapter.setIsBluetoothSupported(false)
        try {
            val absent = platform.bluetoothEnabled()
            assertNull(absent.value)
            assertEquals(ControlReason.NO_BLUETOOTH_ADAPTER, absent.reason)
        } finally {
            ShadowBluetoothAdapter.setIsBluetoothSupported(true)
            shadowOf(BluetoothAdapter.getDefaultAdapter()).setEnabled(false)
        }
    }

    @Test
    fun `night mode is read from the UiModeManager`() {
        val uiMode = context.getSystemService(UiModeManager::class.java)
        shadowOf(uiMode).currentNightMode = UiModeManager.MODE_NIGHT_YES

        assertEquals(UiModeManager.MODE_NIGHT_YES, platform.nightMode().value)
    }

    @Test
    fun `battery percent is the platform's own capacity, and an unsupported reading is a reason`() {
        val battery = context.getSystemService(BatteryManager::class.java)
        shadowOf(battery).setIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY, 42)
        assertEquals(42, platform.batteryPercent().value)

        // BatteryManager reports Int.MIN_VALUE for a property it does not support.
        shadowOf(battery).setIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY, Int.MIN_VALUE)
        val unsupported = platform.batteryPercent()
        assertNull(unsupported.value)
        assertEquals(ControlReason.BATTERY_NOT_REPORTED, unsupported.reason)
    }

    @Test
    fun `mobile data reports the platform's answer or why there is none`() {
        shadowOf(context.packageManager)
            .setSystemFeature(android.content.pm.PackageManager.FEATURE_TELEPHONY_DATA, true)
        val telephony = context.getSystemService(android.telephony.TelephonyManager::class.java)
        shadowOf(telephony).setDataEnabled(true)
        assertEquals(true, platform.mobileDataEnabled().value)

        shadowOf(telephony).setDataEnabled(false)
        assertEquals(false, platform.mobileDataEnabled().value)
    }

    @Test
    fun `a device with no mobile-data radio says so instead of reporting it off`() {
        shadowOf(context.packageManager)
            .setSystemFeature(android.content.pm.PackageManager.FEATURE_TELEPHONY_DATA, false)

        val mobile = platform.mobileDataEnabled()

        assertNull(mobile.value)
        assertEquals(ControlReason.NO_TELEPHONY_DATA, mobile.reason)
    }
}

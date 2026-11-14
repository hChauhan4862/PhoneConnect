package com.phoneconnect.agent.control

import android.app.NotificationManager
import android.app.UiModeManager
import android.bluetooth.BluetoothManager
import android.content.Context
import android.content.pm.PackageManager
import android.media.AudioManager
import android.net.wifi.WifiManager
import android.os.BatteryManager
import android.os.PowerManager
import android.provider.Settings
import android.telephony.TelephonyManager

/**
 * The only production [ControlPlatform]: framework services, and the platform's own answer.
 *
 * Nothing here decides what is allowed; it reports what Android reports. A service this device
 * does not have, a setting it does not keep, and a call it refuses all become a [Reading] with
 * a constant reason, so the handler never has to catch a platform exception itself.
 */
class AndroidControlPlatform(private val context: Context) : ControlPlatform {
    private val app = context.applicationContext
    private val resolver = app.contentResolver

    override fun brightness(): Reading<Int> = systemSetting(Settings.System.SCREEN_BRIGHTNESS)

    override fun brightnessMode(): Reading<Int> = systemSetting(Settings.System.SCREEN_BRIGHTNESS_MODE)

    override fun rotation(): Reading<Int> = systemSetting(Settings.System.ACCELEROMETER_ROTATION)

    override fun volumeMusic(): Reading<Int> = audio()?.let { manager ->
        guarded { Reading.of(manager.getStreamVolume(AudioManager.STREAM_MUSIC)) }
    } ?: Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

    override fun volumeMax(): Reading<Int> = audio()?.let { manager ->
        guarded { Reading.of(manager.getStreamMaxVolume(AudioManager.STREAM_MUSIC)) }
    } ?: Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

    override fun dndFilter(): Reading<Int> = notifications()?.let { manager ->
        guarded { Reading.of(manager.currentInterruptionFilter) }
    } ?: Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

    override fun nightMode(): Reading<Int> = uiMode()?.let { manager ->
        guarded { Reading.of(manager.nightMode) }
    } ?: Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

    override fun wifiEnabled(): Reading<Boolean> = wifi()?.let { manager ->
        guarded { Reading.of(manager.isWifiEnabled) }
    } ?: Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

    override fun bluetoothEnabled(): Reading<Boolean> {
        val adapter = bluetooth()?.adapter
            ?: return Reading.unavailable(ControlReason.NO_BLUETOOTH_ADAPTER)
        return guarded { Reading.of(adapter.isEnabled) }
    }

    override fun mobileDataEnabled(): Reading<Boolean> {
        // A device without a mobile-data radio has no answer; reporting `false` would read as
        // "mobile data is off".
        if (!app.packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_DATA)) {
            return Reading.unavailable(ControlReason.NO_TELEPHONY_DATA)
        }
        val telephony = app.getSystemService(TelephonyManager::class.java)
            ?: return Reading.unavailable(ControlReason.NO_TELEPHONY_DATA)
        // `ACCESS_NETWORK_STATE` (declared) covers this read, but a telephony service that is
        // present without a data radio still throws, and a read must never throw.
        return try {
            Reading.of(telephony.isDataEnabled)
        } catch (_: SecurityException) {
            Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)
        } catch (_: Exception) {
            Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)
        }
    }

    override fun batterySaver(): Reading<Boolean> = power()?.let { manager ->
        guarded { Reading.of(manager.isPowerSaveMode) }
    } ?: Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

    override fun batteryPercent(): Reading<Int> {
        val manager = app.getSystemService(BatteryManager::class.java)
            ?: return Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)
        return try {
            // BatteryManager reports Int.MIN_VALUE for a property it does not support.
            val percent = manager.getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            if (percent in 0..100) {
                Reading.of(percent)
            } else {
                Reading.unavailable(ControlReason.BATTERY_NOT_REPORTED)
            }
        } catch (_: Exception) {
            Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)
        }
    }

    override fun canWriteSettings(): Boolean = try {
        Settings.System.canWrite(app)
    } catch (_: Exception) {
        false
    }

    override fun writeBrightness(value: Int): Boolean = try {
        Settings.System.putInt(resolver, Settings.System.SCREEN_BRIGHTNESS, value) &&
            systemSetting(Settings.System.SCREEN_BRIGHTNESS).value == value
    } catch (_: SecurityException) {
        false
    }

    override fun writeBrightnessMode(mode: Int): Boolean = try {
        Settings.System.putInt(resolver, Settings.System.SCREEN_BRIGHTNESS_MODE, mode) &&
            systemSetting(Settings.System.SCREEN_BRIGHTNESS_MODE).value == mode
    } catch (_: SecurityException) {
        false
    }

    override fun hasPolicyAccess(): Boolean = try {
        notifications()?.isNotificationPolicyAccessGranted == true
    } catch (_: Exception) {
        false
    }

    override fun writeVolumeMusic(value: Int): Boolean {
        val manager = audio() ?: return false
        manager.setStreamVolume(AudioManager.STREAM_MUSIC, value, 0)
        return true
    }

    override fun writeDndFilter(value: Int): Boolean {
        val manager = notifications() ?: return false
        manager.setInterruptionFilter(value)
        return true
    }

    private fun systemSetting(name: String): Reading<Int> = guarded {
        Reading.of(Settings.System.getInt(resolver, name))
    }

    private fun audio(): AudioManager? = app.getSystemService(AudioManager::class.java)

    private fun notifications(): NotificationManager? =
        app.getSystemService(NotificationManager::class.java)

    private fun uiMode(): UiModeManager? = app.getSystemService(UiModeManager::class.java)

    private fun wifi(): WifiManager? = app.getSystemService(WifiManager::class.java)

    private fun bluetooth(): BluetoothManager? = app.getSystemService(BluetoothManager::class.java)

    private fun power(): PowerManager? = app.getSystemService(PowerManager::class.java)

    /** A platform call that throws is a read the platform refused, never an exception uphill. */
    private fun <T> guarded(read: () -> Reading<T>): Reading<T> = try {
        read()
    } catch (_: Exception) {
        Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)
    }
}

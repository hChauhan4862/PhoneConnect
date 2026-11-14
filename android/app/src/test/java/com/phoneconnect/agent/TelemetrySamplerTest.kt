package com.phoneconnect.agent

import android.app.ActivityManager
import android.content.Context
import android.net.NetworkCapabilities
import android.os.BatteryManager
import androidx.test.core.app.ApplicationProvider
import com.phoneconnect.agent.telemetry.BatteryReading
import com.phoneconnect.agent.telemetry.MemoryReading
import com.phoneconnect.agent.telemetry.TelemetrySampler
import com.phoneconnect.agent.telemetry.connectivityName
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.Shadows.shadowOf
import org.robolectric.annotation.Config

/**
 * Telemetry is reported, not invented: the framework's values are mapped as they are, and a
 * metric this platform does not expose stays null instead of becoming a healthy-looking 0.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class TelemetrySamplerTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun `BatteryManager and ActivityManager values are mapped`() {
        val battery = context.getSystemService(BatteryManager::class.java)
        shadowOf(battery).setIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY, 64)
        shadowOf(battery).setIntProperty(
            BatteryManager.BATTERY_PROPERTY_STATUS,
            BatteryManager.BATTERY_STATUS_CHARGING,
        )
        val activity = context.getSystemService(ActivityManager::class.java)
        shadowOf(activity).setMemoryInfo(
            ActivityManager.MemoryInfo().apply {
                totalMem = 8_388_608
                availMem = 2_097_152
            },
        )

        val sample = TelemetrySampler.fromContext(context) { 1_760_000_000_000 }.sample()

        assertEquals(1_760_000_000_000, sample.sampledAtMs)
        assertEquals("battery percent comes from BatteryManager", 64, sample.batteryPercent)
        assertEquals(true, sample.batteryCharging)
        assertEquals("memory total comes from ActivityManager", 8_388_608L, sample.memoryTotalBytes)
        assertEquals(
            "used memory is total minus available",
            6_291_456L,
            sample.memoryUsedBytes,
        )
        assertNull("an ordinary app cannot read CPU percent", sample.cpuPercent)
    }

    @Test
    fun `a discharging battery is reported as not charging`() {
        val battery = context.getSystemService(BatteryManager::class.java)
        shadowOf(battery).setIntProperty(
            BatteryManager.BATTERY_PROPERTY_STATUS,
            BatteryManager.BATTERY_STATUS_DISCHARGING,
        )

        val sample = TelemetrySampler.fromContext(context) { 1 }.sample()

        assertEquals(false, sample.batteryCharging)
    }

    @Test
    fun `unsupported metrics are null and are omitted from the wire frame`() {
        val sampler = TelemetrySampler(
            battery = { BatteryReading(percent = null, charging = null) },
            memory = { MemoryReading(usedBytes = null, totalBytes = null) },
            connectivity = { null },
            clock = { 42 },
        )

        val sample = sampler.sample()

        assertEquals(42, sample.sampledAtMs)
        assertNull("an unreported percentage is not 0", sample.batteryPercent)
        assertNull(sample.batteryCharging)
        assertNull(sample.memoryUsedBytes)
        assertNull(sample.memoryTotalBytes)
        assertNull(sample.connectivity)
        assertNull(sample.cpuPercent)

        val json = sample.toJson()
        assertEquals(42, json.getLong("sampled_at_ms"))
        for (absent in listOf(
            "cpu_percent",
            "memory_used_bytes",
            "memory_total_bytes",
            "battery_percent",
            "battery_charging",
            "connectivity",
        )) {
            assertFalse("$absent must be absent, not null or zero", json.has(absent))
        }
    }

    @Test
    fun `connectivity names the active transport and nothing when there is none`() {
        assertEquals("wifi", connectivityName { it == NetworkCapabilities.TRANSPORT_WIFI })
        assertEquals("cellular", connectivityName { it == NetworkCapabilities.TRANSPORT_CELLULAR })
        assertEquals("ethernet", connectivityName { it == NetworkCapabilities.TRANSPORT_ETHERNET })
        assertEquals("vpn", connectivityName { it == NetworkCapabilities.TRANSPORT_VPN })
        assertNull("no transport is not a network", connectivityName { false })
    }

    @Test
    fun `a device without a battery or memory service reports nothing rather than zero`() {
        val sampler = TelemetrySampler.fromContext(context) { 1 }

        val sample = sampler.sample()

        assertNull("an unset battery property reads as unknown, never 0%", sample.batteryPercent)
        assertNull(sample.batteryCharging)
        assertNull(sample.memoryTotalBytes)
        assertNull(sample.memoryUsedBytes)
    }
}

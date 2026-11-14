package com.phoneconnect.agent.telemetry

import android.app.ActivityManager
import android.content.Context
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.os.BatteryManager
import org.json.JSONObject

/**
 * One device report, in the shape the server's `TelemetrySample` accepts.
 *
 * Every metric is optional because the platform exposes what it exposes: a reading the app
 * cannot obtain is `null`, never a fabricated zero. An absent metric must stay visibly
 * absent on the status surface rather than look like a healthy 0%.
 */
data class TelemetrySample(
    val sampledAtMs: Long,
    val cpuPercent: Double? = null,
    val memoryUsedBytes: Long? = null,
    val memoryTotalBytes: Long? = null,
    val batteryPercent: Int? = null,
    val batteryCharging: Boolean? = null,
    val connectivity: String? = null,
) {
    /** The wire form for `{"type":"telemetry","sample":...}`; absent metrics are omitted. */
    fun toJson(): JSONObject = JSONObject().apply {
        put("sampled_at_ms", sampledAtMs)
        cpuPercent?.let { put("cpu_percent", it) }
        memoryUsedBytes?.let { put("memory_used_bytes", it) }
        memoryTotalBytes?.let { put("memory_total_bytes", it) }
        batteryPercent?.let { put("battery_percent", it) }
        batteryCharging?.let { put("battery_charging", it) }
        connectivity?.let { put("connectivity", it) }
    }
}

/** Battery percentage and charging state, either of which the platform may not report. */
data class BatteryReading(val percent: Int?, val charging: Boolean?)

/** Memory in bytes: total as the system reports it and used as total minus available. */
data class MemoryReading(val usedBytes: Long?, val totalBytes: Long?)

fun interface BatteryReader {
    fun read(): BatteryReading
}

fun interface MemoryReader {
    fun read(): MemoryReading
}

fun interface ConnectivityReader {
    fun read(): String?
}

/**
 * Reads the metrics this platform lets an ordinary app read.
 *
 * CPU percentage is deliberately absent: Android does not expose per-app CPU counters to a
 * normal app (`/proc` is restricted), so [TelemetrySample.cpuPercent] is always `null`
 * rather than an invented number.
 */
class TelemetrySampler(
    private val battery: BatteryReader,
    private val memory: MemoryReader,
    private val connectivity: ConnectivityReader,
    private val clock: () -> Long = System::currentTimeMillis,
) {
    fun sample(): TelemetrySample {
        val batteryReading = battery.read()
        val memoryReading = memory.read()
        return TelemetrySample(
            sampledAtMs = clock(),
            cpuPercent = null,
            memoryUsedBytes = memoryReading.usedBytes,
            memoryTotalBytes = memoryReading.totalBytes,
            batteryPercent = batteryReading.percent,
            batteryCharging = batteryReading.charging,
            connectivity = connectivity.read(),
        )
    }

    companion object {
        /** The production sampler, reading the framework services for this context. */
        fun fromContext(
            context: Context,
            clock: () -> Long = System::currentTimeMillis,
        ): TelemetrySampler {
            val app = context.applicationContext
            return TelemetrySampler(
                battery = AndroidBatteryReader(app.getSystemService(BatteryManager::class.java)),
                memory = AndroidMemoryReader(app.getSystemService(ActivityManager::class.java)),
                connectivity = AndroidConnectivityReader(
                    app.getSystemService(ConnectivityManager::class.java),
                ),
                clock = clock,
            )
        }
    }
}

/**
 * `BatteryManager` reports `Int.MIN_VALUE` for a property it does not support; anything
 * outside 0–100 is treated as unreported, so a device without a battery reads as unknown.
 */
internal class AndroidBatteryReader(private val battery: BatteryManager?) : BatteryReader {
    override fun read(): BatteryReading {
        val manager = battery ?: return BatteryReading(null, null)
        val percent = manager
            .getIntProperty(BatteryManager.BATTERY_PROPERTY_CAPACITY)
            .takeIf { it in 0..100 }
        val charging = when (manager.getIntProperty(BatteryManager.BATTERY_PROPERTY_STATUS)) {
            BatteryManager.BATTERY_STATUS_CHARGING,
            BatteryManager.BATTERY_STATUS_FULL,
            -> true

            BatteryManager.BATTERY_STATUS_DISCHARGING,
            BatteryManager.BATTERY_STATUS_NOT_CHARGING,
            -> false

            else -> null
        }
        return BatteryReading(percent, charging)
    }
}

/** `ActivityManager.MemoryInfo`: used is total minus available, bounded to the total. */
internal class AndroidMemoryReader(private val activityManager: ActivityManager?) : MemoryReader {
    override fun read(): MemoryReading {
        val manager = activityManager ?: return MemoryReading(null, null)
        val info = ActivityManager.MemoryInfo()
        manager.getMemoryInfo(info)
        if (info.totalMem <= 0) return MemoryReading(null, null)
        val used = (info.totalMem - info.availMem).coerceIn(0, info.totalMem)
        return MemoryReading(usedBytes = used, totalBytes = info.totalMem)
    }
}

/**
 * The active network's transport, named the way the status surface renders it. No active
 * network is `null`: "offline" is a fact, not a default string.
 */
internal class AndroidConnectivityReader(
    private val connectivity: ConnectivityManager?,
) : ConnectivityReader {
    override fun read(): String? {
        val manager = connectivity ?: return null
        val network = manager.activeNetwork ?: return null
        val capabilities = manager.getNetworkCapabilities(network) ?: return null
        return connectivityName(capabilities::hasTransport)
    }
}

internal fun connectivityName(hasTransport: (Int) -> Boolean): String? = when {
    hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "wifi"
    hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "cellular"
    hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ethernet"
    hasTransport(NetworkCapabilities.TRANSPORT_VPN) -> "vpn"
    hasTransport(NetworkCapabilities.TRANSPORT_BLUETOOTH) -> "bluetooth"
    else -> null
}

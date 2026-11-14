package com.phoneconnect.agent.control

import android.os.Build
import org.json.JSONObject

/** Non-secret description of the device. Nothing here identifies the operator or the hub. */
data class DeviceDescription(
    val model: String,
    val manufacturer: String,
    val androidVersion: String,
    val sdk: Int,
) {
    /** The `hello` frame: exactly the fields the server records. */
    fun helloJson(): JSONObject = JSONObject()
        .put("type", "hello")
        .put("model", model)
        .put("android_version", androidVersion)
        .put("sdk", sdk)

    /** What `device.info` reports. */
    fun toJson(): JSONObject = JSONObject()
        .put("model", model)
        .put("manufacturer", manufacturer)
        .put("android_version", androidVersion)
        .put("sdk", sdk)

    companion object {
        /** The platform's own values. A missing string is empty, never invented. */
        fun current(): DeviceDescription = DeviceDescription(
            model = Build.MODEL.orEmpty(),
            manufacturer = Build.MANUFACTURER.orEmpty(),
            androidVersion = Build.VERSION.RELEASE.orEmpty(),
            sdk = Build.VERSION.SDK_INT,
        )
    }
}

/** `device.info`: what the device is, using only values the platform provides. */
class DeviceInfoHandler(
    private val description: () -> DeviceDescription = DeviceDescription::current,
) {
    fun describe(): JSONObject = description().toJson()

    fun hello(): JSONObject = description().helloJson()
}

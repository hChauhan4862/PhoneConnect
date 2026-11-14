package com.phoneconnect.agent

import com.phoneconnect.agent.control.CommandDispatcher
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.ControlHandler
import com.phoneconnect.agent.control.ControlKey
import com.phoneconnect.agent.control.ControlPlatform
import com.phoneconnect.agent.control.ControlReason
import com.phoneconnect.agent.control.Reading
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * `control.get`, `control.set`, and `control.reboot`: what the platform actually reports, and a
 * machine reason — never a fabricated value or a silent no-op — for everything it refuses.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ControlHandlerTest {
    private val platform = FakeControlPlatform()
    private val handler = ControlHandler(platform)

    @Test
    fun `get reports every reading the platform produced`() {
        val output = handler.handle(CommandDispatcher.CONTROL_GET, JSONObject())

        assertEquals(102, output.getInt(ControlKey.BRIGHTNESS))
        assertEquals(1, output.getInt(ControlKey.BRIGHTNESS_MODE))
        assertEquals(7, output.getInt(ControlKey.VOLUME_MUSIC))
        assertEquals(15, output.getInt(ControlKey.VOLUME_MAX))
        assertEquals(1, output.getInt(ControlKey.ROTATION))
        assertEquals(2, output.getInt(ControlKey.DND_FILTER))
        assertEquals(1, output.getInt(ControlKey.NIGHT_MODE))
        assertEquals(true, output.getBoolean(ControlKey.WIFI_ENABLED))
        assertEquals(false, output.getBoolean(ControlKey.BLUETOOTH_ENABLED))
        assertEquals(true, output.getBoolean(ControlKey.MOBILE_DATA_ENABLED))
        assertEquals(false, output.getBoolean(ControlKey.BATTERY_SAVER))
        assertEquals(88, output.getInt(ControlKey.BATTERY_PERCENT))
    }

    @Test
    fun `a reading the platform refuses is null with its reason, never zero`() {
        platform.bluetoothEnabled = Reading.unavailable(ControlReason.NO_BLUETOOTH_ADAPTER)

        val output = handler.handle(CommandDispatcher.CONTROL_GET, JSONObject())

        assertTrue("an unreadable value must be null, never a number", output.isNull(ControlKey.BLUETOOTH_ENABLED))
        assertEquals(
            ControlReason.NO_BLUETOOTH_ADAPTER,
            output.getJSONObject(UNAVAILABLE).getString(ControlKey.BLUETOOTH_ENABLED),
        )
    }

    @Test
    fun `a platform exception becomes null and a constant reason, never internal_error`() {
        platform.brightnessRead = { throw SecurityException("platform says /data/system/secret") }

        val output = handler.handle(CommandDispatcher.CONTROL_GET, JSONObject())

        assertTrue("a throwing read must be null", output.isNull(ControlKey.BRIGHTNESS))
        assertEquals(
            ControlReason.PLATFORM_READ_FAILED,
            output.getJSONObject(UNAVAILABLE).getString(ControlKey.BRIGHTNESS),
        )
        assertFalse(
            "a platform message must never reach the caller",
            output.getJSONObject(UNAVAILABLE).getString(ControlKey.BRIGHTNESS).contains("/"),
        )
        // One throwing read must not cost the other readings.
        assertEquals(88, output.getInt(ControlKey.BATTERY_PERCENT))
    }

    @Test
    fun `every key whose change the platform refuses is named in unavailable`() {
        val unavailable = handler.handle(CommandDispatcher.CONTROL_GET, JSONObject())
            .getJSONObject(UNAVAILABLE)

        assertEquals(ControlReason.WIFI_SETTER_REMOVED, unavailable.getString(ControlKey.WIFI))
        assertEquals(ControlReason.BLUETOOTH_SETTER_REMOVED, unavailable.getString(ControlKey.BLUETOOTH))
        assertEquals(
            ControlReason.MOBILE_DATA_SETTER_SIGNATURE_GATED,
            unavailable.getString(ControlKey.MOBILE_DATA),
        )
        assertEquals(
            ControlReason.NIGHT_MODE_SETTER_SIGNATURE_GATED,
            unavailable.getString(ControlKey.NIGHT_MODE),
        )
        assertEquals(
            ControlReason.ROTATION_REQUIRES_SYSTEM_UI,
            unavailable.getString(ControlKey.ROTATION),
        )
        assertEquals(
            ControlReason.REBOOT_REQUIRES_PRIVILEGE,
            unavailable.getString(ControlKey.REBOOT),
        )
        // The two grant-gated changes are unavailable until the user grants them.
        assertEquals(ControlReason.WRITE_SETTINGS_REQUIRED, unavailable.getString(ControlKey.BRIGHTNESS))
        assertEquals(ControlReason.POLICY_ACCESS_REQUIRED, unavailable.getString(ControlKey.DND_FILTER))
    }

    @Test
    fun `a granted capability stops being listed as unavailable`() {
        platform.writeSettings = true
        platform.policyAccess = true

        val unavailable = handler.handle(CommandDispatcher.CONTROL_GET, JSONObject())
            .getJSONObject(UNAVAILABLE)

        assertFalse(unavailable.has(ControlKey.BRIGHTNESS))
        assertFalse(unavailable.has(ControlKey.DND_FILTER))
    }

    @Test
    fun `set refuses a key this build does not implement as invalid_args`() {
        val failure = setFails(JSONObject().put("key", "battery_percent").put("value", 50))

        assertEquals("invalid_args", failure.code)
        assertTrue("the platform must not be touched", platform.writes.isEmpty())
    }

    @Test
    fun `set requires a key and a value`() {
        assertEquals("invalid_args", setFails(JSONObject().put("value", 1)).code)
        assertEquals("invalid_args", setFails(JSONObject().put("key", ControlKey.BRIGHTNESS)).code)
        assertEquals(
            "invalid_args",
            setFails(JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", JSONObject.NULL)).code,
        )
        assertEquals(
            "invalid_args",
            setFails(JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", "bright")).code,
        )
    }

    @Test
    fun `brightness is validated before the platform is touched`() {
        platform.writeSettings = true

        for (value in listOf(-1, 256)) {
            val failure = setFails(JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", value))
            assertEquals("invalid_args", failure.code)
        }

        assertTrue("an out-of-range value must never reach the platform", platform.writes.isEmpty())
        assertEquals("permission must not be consulted for an invalid value", 0, platform.writeSettingsChecks)
    }

    @Test
    fun `brightness without write settings is not_permitted with the machine reason`() {
        val failure = setFails(JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", 120))

        assertEquals("not_permitted", failure.code)
        assertEquals(ControlReason.WRITE_SETTINGS_REQUIRED, failure.message)
        assertTrue("nothing may be written without the grant", platform.writes.isEmpty())
    }

    @Test
    fun `brightness in manual mode is written once and confirmed`() {
        platform.writeSettings = true
        platform.brightnessMode = Reading.of(ControlHandler.BRIGHTNESS_MODE_MANUAL)

        val output = handler.handle(
            CommandDispatcher.CONTROL_SET,
            JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", 120),
        )

        assertEquals(
            "manual mode needs no mode change",
            listOf("brightness" to 120),
            platform.writes,
        )
        assertEquals(ControlKey.BRIGHTNESS, output.getString("key"))
        assertEquals(120, output.getInt("value"))
        assertEquals(true, output.getBoolean("applied"))
        assertEquals(ControlHandler.BRIGHTNESS_MODE_MANUAL, output.getInt(ControlKey.BRIGHTNESS_MODE))
        assertEquals(false, output.getBoolean(MODE_CHANGED))
    }

    @Test
    fun `an automatic display is switched to manual and the answer reports it`() {
        platform.writeSettings = true
        platform.brightnessMode = Reading.of(ControlHandler.BRIGHTNESS_MODE_AUTOMATIC)

        val output = handler.handle(
            CommandDispatcher.CONTROL_SET,
            JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", 120),
        )

        // A stored value under automatic brightness is a no-op for the display, so the mode is
        // turned off first and the side effect is in the answer.
        assertEquals(
            listOf("brightness_mode" to ControlHandler.BRIGHTNESS_MODE_MANUAL, "brightness" to 120),
            platform.writes,
        )
        assertEquals(true, output.getBoolean("applied"))
        assertEquals(ControlHandler.BRIGHTNESS_MODE_MANUAL, output.getInt(ControlKey.BRIGHTNESS_MODE))
        assertEquals(true, output.getBoolean(MODE_CHANGED))
        assertEquals(ControlHandler.BRIGHTNESS_MODE_MANUAL, platform.brightnessMode.value)
    }

    @Test
    fun `an automatic mode that will not turn off is not_applied and nothing is written`() {
        platform.writeSettings = true
        platform.brightnessMode = Reading.of(ControlHandler.BRIGHTNESS_MODE_AUTOMATIC)
        platform.brightnessModeWriteAccepted = false

        val failure = setFails(JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", 120))

        assertEquals("not_applied", failure.code)
        assertEquals(ControlReason.BRIGHTNESS_MODE_AUTOMATIC, failure.message)
        assertTrue(
            "the brightness must not be written when the display would ignore it: ${platform.writes}",
            platform.writes.none { it.first == "brightness" },
        )
    }

    @Test
    fun `an unreadable brightness mode is still turned to manual before the write`() {
        platform.writeSettings = true
        platform.brightnessMode = Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

        val output = handler.handle(
            CommandDispatcher.CONTROL_SET,
            JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", 120),
        )

        assertEquals(true, output.getBoolean("applied"))
        assertTrue(
            "an unknown mode must be made manual defensively: ${platform.writes}",
            platform.writes.contains("brightness_mode" to ControlHandler.BRIGHTNESS_MODE_MANUAL),
        )
    }

    @Test
    fun `a brightness write the setting does not keep is not_applied, never ok`() {
        platform.writeSettings = true
        platform.brightnessMode = Reading.of(ControlHandler.BRIGHTNESS_MODE_MANUAL)
        platform.brightnessAfterWrite = { Reading.of(255) }

        val failure = setFails(JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", 120))

        assertEquals("not_applied", failure.code)
        assertEquals(ControlReason.BRIGHTNESS_NOT_APPLIED, failure.message)
    }

    @Test
    fun `a brightness read-back that cannot be read is unconfirmed, never ok`() {
        platform.writeSettings = true
        platform.brightnessMode = Reading.of(ControlHandler.BRIGHTNESS_MODE_MANUAL)
        platform.brightnessAfterWrite = { Reading.unavailable(ControlReason.PLATFORM_READ_FAILED) }

        val failure = setFails(JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", 120))

        assertEquals("unconfirmed", failure.code)
        assertEquals(ControlReason.READ_BACK_UNAVAILABLE, failure.message)
    }

    @Test
    fun `a write settings grant revoked mid-call is still write_settings_required`() {
        platform.writeSettings = true
        platform.writeBrightnessError = SecurityException("caller is not allowed")

        val failure = setFails(JSONObject().put("key", ControlKey.BRIGHTNESS).put("value", 10))

        assertEquals("not_permitted", failure.code)
        assertEquals(ControlReason.WRITE_SETTINGS_REQUIRED, failure.message)
    }

    @Test
    fun `volume is validated against the platform max before the write`() {
        for (value in listOf(-1, 16)) {
            val failure = setFails(JSONObject().put("key", ControlKey.VOLUME_MUSIC).put("value", value))
            assertEquals("invalid_args", failure.code)
        }

        assertTrue("an out-of-range volume must never reach the platform", platform.writes.isEmpty())
    }

    @Test
    fun `volume in range is written and confirmed`() {
        val output = handler.handle(
            CommandDispatcher.CONTROL_SET,
            JSONObject().put("key", ControlKey.VOLUME_MUSIC).put("value", 15),
        )

        assertEquals(listOf("volume" to 15), platform.writes)
        assertEquals(15, output.getInt("value"))
        assertEquals(true, output.getBoolean("applied"))
    }

    @Test
    fun `a volume the platform does not apply is not_applied`() {
        platform.volumeAfterWrite = Reading.of(3)

        val failure = setFails(JSONObject().put("key", ControlKey.VOLUME_MUSIC).put("value", 15))

        assertEquals("not_applied", failure.code)
        assertEquals(ControlReason.VOLUME_NOT_APPLIED, failure.message)
    }

    @Test
    fun `a volume read-back that cannot be read is unconfirmed, never ok`() {
        platform.volumeAfterWrite = Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

        val failure = setFails(JSONObject().put("key", ControlKey.VOLUME_MUSIC).put("value", 15))

        assertEquals("unconfirmed", failure.code)
        assertEquals(ControlReason.READ_BACK_UNAVAILABLE, failure.message)
    }

    @Test
    fun `a volume change the DND guard refuses is not_permitted with the policy reason`() {
        platform.volumeWriteError = SecurityException("DND change needs policy access")

        val failure = setFails(JSONObject().put("key", ControlKey.VOLUME_MUSIC).put("value", 0))

        assertEquals("not_permitted", failure.code)
        assertEquals(ControlReason.POLICY_ACCESS_REQUIRED, failure.message)
    }

    @Test
    fun `dnd without policy access is not_permitted with the machine reason`() {
        val failure = setFails(JSONObject().put("key", ControlKey.DND_FILTER).put("value", 3))

        assertEquals("not_permitted", failure.code)
        assertEquals(ControlReason.POLICY_ACCESS_REQUIRED, failure.message)
        assertTrue("nothing may be written without the grant", platform.writes.isEmpty())
    }

    @Test
    fun `a dnd read-back that cannot be read is unconfirmed, never ok`() {
        platform.policyAccess = true
        platform.dndAfterWrite = Reading.unavailable(ControlReason.PLATFORM_READ_FAILED)

        val failure = setFails(JSONObject().put("key", ControlKey.DND_FILTER).put("value", 3))

        assertEquals("unconfirmed", failure.code)
        assertEquals(ControlReason.READ_BACK_UNAVAILABLE, failure.message)
    }

    @Test
    fun `dnd with policy access is applied and confirmed`() {
        platform.policyAccess = true

        val output = handler.handle(
            CommandDispatcher.CONTROL_SET,
            JSONObject().put("key", ControlKey.DND_FILTER).put("value", 3),
        )

        assertEquals(listOf("dnd" to 3), platform.writes)
        assertEquals(3, output.getInt("value"))
        assertEquals(true, output.getBoolean("applied"))
    }

    @Test
    fun `a dnd filter outside the platform's range is invalid_args`() {
        platform.policyAccess = true

        for (value in listOf(0, 5)) {
            assertEquals(
                "invalid_args",
                setFails(JSONObject().put("key", ControlKey.DND_FILTER).put("value", value)).code,
            )
        }
        assertTrue(platform.writes.isEmpty())
    }

    @Test
    fun `the constant setters refuse with their own reason and never touch the platform`() {
        val expected = mapOf(
            ControlKey.WIFI to ControlReason.WIFI_SETTER_REMOVED,
            ControlKey.BLUETOOTH to ControlReason.BLUETOOTH_SETTER_REMOVED,
            ControlKey.MOBILE_DATA to ControlReason.MOBILE_DATA_SETTER_SIGNATURE_GATED,
            ControlKey.NIGHT_MODE to ControlReason.NIGHT_MODE_SETTER_SIGNATURE_GATED,
            ControlKey.ROTATION to ControlReason.ROTATION_REQUIRES_SYSTEM_UI,
        )

        for ((key, reason) in expected) {
            val failure = setFails(JSONObject().put("key", key).put("value", true))
            assertEquals("$key must be not_permitted", "not_permitted", failure.code)
            assertEquals(reason, failure.message)
        }
        assertTrue("a refused setter must never reach the platform", platform.writes.isEmpty())
    }

    @Test
    fun `a refused key is not_permitted for any value, never a complaint about the value`() {
        // Rotation and night mode are integers in `control.get`; a caller who sends one must
        // learn that the platform has no setter, not that the value's type was wrong.
        for ((key, value) in listOf(
            ControlKey.ROTATION to 0,
            ControlKey.NIGHT_MODE to UiModeInteger.NIGHT_YES,
            ControlKey.WIFI to 1,
        )) {
            val failure = setFails(JSONObject().put("key", key).put("value", value))
            assertEquals("$key must be not_permitted, was ${failure.code}", "not_permitted", failure.code)
            assertEquals(refusedReasonFor(key), failure.message)
        }
        assertTrue("a refused setter must never reach the platform", platform.writes.isEmpty())
    }

    private fun refusedReasonFor(key: String): String = when (key) {
        ControlKey.WIFI -> ControlReason.WIFI_SETTER_REMOVED
        ControlKey.NIGHT_MODE -> ControlReason.NIGHT_MODE_SETTER_SIGNATURE_GATED
        else -> ControlReason.ROTATION_REQUIRES_SYSTEM_UI
    }

    private object UiModeInteger {
        const val NIGHT_YES = 2
    }

    @Test
    fun `reboot is always not_permitted with the privilege reason`() {
        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.CONTROL_REBOOT, JSONObject())
        }

        assertEquals("not_permitted", failure.code)
        assertEquals(ControlReason.REBOOT_REQUIRES_PRIVILEGE, failure.message)
    }

    @Test
    fun `no refusal carries platform text or an absolute path`() {
        val messages = mutableListOf<String>()
        val refusals: List<Pair<String, Any>> = listOf(
            ControlKey.WIFI to true,
            ControlKey.BLUETOOTH to true,
            ControlKey.MOBILE_DATA to true,
            ControlKey.NIGHT_MODE to true,
            ControlKey.ROTATION to true,
            ControlKey.BRIGHTNESS to 0,
            ControlKey.DND_FILTER to 3,
        )
        for ((key, value) in refusals) {
            messages += setFails(JSONObject().put("key", key).put("value", value)).message.orEmpty()
        }
        messages += assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.CONTROL_REBOOT, JSONObject())
        }.message.orEmpty()

        for (message in messages) {
            assertFalse("a refusal must not name a device path: $message", message.contains("/"))
            assertFalse("a refusal must not carry exception text: $message", message.contains("Exception"))
            assertTrue("a refusal must be a machine reason: $message", message.matches(Regex("[a-z0-9_]+")))
        }
    }

    private fun setFails(args: JSONObject): CommandFailure =
        assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.CONTROL_SET, args)
        }

    /**
     * The platform the handler talks to. Writes are recorded, so a test can prove a refusal
     * happened before the platform was touched; each read can be replaced, including with one
     * that throws.
     */
    private class FakeControlPlatform : ControlPlatform {
        var brightnessRead: () -> Reading<Int> = { Reading.of(102) }
        var brightnessAfterWrite: (() -> Reading<Int>)? = null
        var brightnessMode: Reading<Int> = Reading.of(1)
        var volumeRead: Reading<Int> = Reading.of(7)
        var volumeAfterWrite: Reading<Int>? = null
        var volumeMax: Reading<Int> = Reading.of(15)
        var rotation: Reading<Int> = Reading.of(1)
        var dndRead: Reading<Int> = Reading.of(2)
        var dndAfterWrite: Reading<Int>? = null
        var nightMode: Reading<Int> = Reading.of(1)
        var wifiEnabled: Reading<Boolean> = Reading.of(true)
        var bluetoothEnabled: Reading<Boolean> = Reading.of(false)
        var mobileDataEnabled: Reading<Boolean> = Reading.of(true)
        var batterySaver: Reading<Boolean> = Reading.of(false)
        var batteryPercent: Reading<Int> = Reading.of(88)

        var writeSettings = false
        var policyAccess = false
        var writeSettingsChecks = 0
        var brightnessModeWriteAccepted = true
        var writeBrightnessError: RuntimeException? = null
        var volumeWriteError: RuntimeException? = null
        var dndWriteError: RuntimeException? = null

        /** Every write the handler asked for, in order. A refusal must leave this empty. */
        val writes = mutableListOf<Pair<String, Int>>()

        override fun brightness(): Reading<Int> = brightnessAfterWrite?.invoke() ?: brightnessRead()

        override fun brightnessMode(): Reading<Int> = brightnessMode

        override fun volumeMusic(): Reading<Int> = volumeAfterWrite ?: volumeRead

        override fun volumeMax(): Reading<Int> = volumeMax

        override fun rotation(): Reading<Int> = rotation

        override fun dndFilter(): Reading<Int> = dndAfterWrite ?: dndRead

        override fun nightMode(): Reading<Int> = nightMode

        override fun wifiEnabled(): Reading<Boolean> = wifiEnabled

        override fun bluetoothEnabled(): Reading<Boolean> = bluetoothEnabled

        override fun mobileDataEnabled(): Reading<Boolean> = mobileDataEnabled

        override fun batterySaver(): Reading<Boolean> = batterySaver

        override fun batteryPercent(): Reading<Int> = batteryPercent

        override fun canWriteSettings(): Boolean {
            writeSettingsChecks += 1
            return writeSettings
        }

        override fun writeBrightness(value: Int): Boolean {
            writeBrightnessError?.let { throw it }
            writes += "brightness" to value
            if (brightnessAfterWrite == null) brightnessRead = { Reading.of(value) }
            return true
        }

        override fun writeBrightnessMode(mode: Int): Boolean {
            if (!brightnessModeWriteAccepted) return false
            writes += "brightness_mode" to mode
            brightnessMode = Reading.of(mode)
            return true
        }

        override fun hasPolicyAccess(): Boolean = policyAccess

        override fun writeVolumeMusic(value: Int): Boolean {
            volumeWriteError?.let { throw it }
            writes += "volume" to value
            if (volumeAfterWrite == null) volumeRead = Reading.of(value)
            return true
        }

        override fun writeDndFilter(value: Int): Boolean {
            dndWriteError?.let { throw it }
            writes += "dnd" to value
            if (dndAfterWrite == null) dndRead = Reading.of(value)
            return true
        }
    }

    private companion object {
        const val UNAVAILABLE = "unavailable"
        const val MODE_CHANGED = "mode_changed"
    }
}

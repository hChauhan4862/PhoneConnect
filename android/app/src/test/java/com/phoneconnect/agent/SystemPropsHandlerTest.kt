package com.phoneconnect.agent

import com.phoneconnect.agent.control.AndroidSystemProperties
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.SystemPropertiesHandler
import com.phoneconnect.agent.control.SystemPropertyAllowlist
import com.phoneconnect.agent.control.SystemPropertySource
import org.json.JSONArray
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
 * `system.props`: the documented allowlist, read the only way an ordinary app can read system
 * properties, and an explicit `not_permitted` for anything outside it.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class SystemPropsHandlerTest {
    private class FakeSource(
        private val values: Map<String, String> = emptyMap(),
        private val failure: CommandFailure? = null,
    ) : SystemPropertySource {
        val reads = mutableListOf<String>()

        override fun read(name: String): String? {
            reads += name
            failure?.let { throw it }
            return values[name]
        }
    }

    @Test
    fun `no arguments reports the whole documented allowlist`() {
        val source = FakeSource(
            mapOf(
                "ro.build.version.sdk" to "35",
                "ro.build.version.release" to "15",
                "ro.product.model" to "Pixel 8",
                "ro.product.manufacturer" to "Google",
                "ro.build.id" to "AP4A.250105.002",
                "ro.build.version.security_patch" to "2025-01-05",
            ),
        )

        val selected = SystemPropertiesHandler(source).select(JSONObject()).getJSONObject("selected")

        assertEquals(
            setOf("sdk", "release", "model", "manufacturer", "build_id", "security_patch"),
            selected.keys().asSequence().toSet(),
        )
        assertEquals("35", selected.getString("sdk"))
        assertEquals("15", selected.getString("release"))
        assertEquals("Pixel 8", selected.getString("model"))
        assertEquals("Google", selected.getString("manufacturer"))
        assertEquals("AP4A.250105.002", selected.getString("build_id"))
        assertEquals("2025-01-05", selected.getString("security_patch"))
        assertEquals(
            "every allowlisted property is read",
            SystemPropertyAllowlist.READABLE.values.toList(),
            source.reads,
        )
    }

    @Test
    fun `a named key selects only that property`() {
        val source = FakeSource(mapOf("ro.build.version.sdk" to "35"))

        val output = SystemPropertiesHandler(source)
            .select(JSONObject().put("keys", JSONArray().put("sdk")))

        val selected = output.getJSONObject("selected")
        assertEquals(setOf("sdk"), selected.keys().asSequence().toSet())
        assertEquals("35", selected.getString("sdk"))
        assertEquals(listOf("ro.build.version.sdk"), source.reads)
    }

    @Test
    fun `a property outside the allowlist is not_permitted and is never read`() {
        val source = FakeSource(mapOf("ro.serialno" to "should-never-be-read"))

        val failure = assertThrows(CommandFailure::class.java) {
            SystemPropertiesHandler(source)
                .select(JSONObject().put("keys", JSONArray().put("sdk").put("serialno")))
        }

        assertEquals("not_permitted", failure.code)
        val message = failure.message.orEmpty()
        assertTrue("the refusal must name the allowlist: $message", message.contains("sdk"))
        assertFalse("a message must not name a device path: $message", message.contains("/"))
        assertTrue("nothing outside the allowlist may be read", source.reads.isEmpty())
    }

    @Test
    fun `a malformed key list is invalid_args`() {
        val handler = SystemPropertiesHandler(FakeSource())

        for (body in listOf(
            JSONObject().put("keys", "sdk"),
            JSONObject().put("keys", JSONArray().put(" ")),
            JSONObject().put("keys", JSONArray().put(7)),
            JSONObject().put("keys", JSONArray()),
        )) {
            val failure = assertThrows("body $body", CommandFailure::class.java) { handler.select(body) }
            assertEquals("invalid_args", failure.code)
        }
    }

    @Test
    fun `a property the platform does not report is null, never invented`() {
        val source = FakeSource(emptyMap())

        val selected = SystemPropertiesHandler(source).select(null).getJSONObject("selected")

        assertTrue("a missing value must be null", selected.isNull("model"))
    }

    @Test
    fun `a reflection failure is props_unavailable`() {
        val source = FakeSource(failure = CommandFailure("props_unavailable", "unavailable"))

        val failure = assertThrows(CommandFailure::class.java) { SystemPropertiesHandler(source).select(null) }

        assertEquals("props_unavailable", failure.code)
    }

    @Test
    fun `the reflective reader either reads a value or refuses with props_unavailable`() {
        // Robolectric exposes the framework class, so the default reader must work here; on a
        // build without it the same call must be a machine code rather than a crash.
        val reader = AndroidSystemProperties()
        val value = try {
            reader.read("ro.build.version.sdk")
        } catch (failure: CommandFailure) {
            assertEquals("props_unavailable", failure.code)
            null
        }
        assertTrue("a readable sdk must be a number, got $value", value == null || value.toIntOrNull() != null)
    }

    @Test
    fun `a class loader without SystemProperties refuses with props_unavailable`() {
        val missing = AndroidSystemProperties { throw ClassNotFoundException("android.os.SystemProperties") }

        val failure = assertThrows(CommandFailure::class.java) { missing.read("ro.build.version.sdk") }

        assertEquals("props_unavailable", failure.code)
        assertFalse("a message must not carry exception text: ${failure.message}", failure.message.orEmpty().contains("ClassNotFound"))
    }
}

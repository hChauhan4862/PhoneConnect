package com.phoneconnect.agent

import android.content.Intent
import com.phoneconnect.agent.control.AppPlatform
import com.phoneconnect.agent.control.CommandDispatcher
import com.phoneconnect.agent.control.AppsHandler
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.InstalledApp
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.io.File

/**
 * The five `apps.*` commands: a listing that reports only what the platform says, and launches
 * and stops that answer with the platform's decision instead of an assumed success.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class AppsHandlerTest {
    private val platform = FakePlatform()
    private val handler = AppsHandler(platform)

    @Test
    fun `listing sorts by label case-insensitively and reports every field`() {
        platform.apps += listOf(
            app("com.example.zeta", "beta", versionName = "2.0", versionCode = 20, updatedMs = 7),
            app("com.example.alpha", "Alpha"),
            app("com.example.middle", "Charlie", system = true, enabled = false),
        )

        val apps = handler.handle(CommandDispatcher.APPS_LIST, JSONObject()).getJSONArray("apps")

        assertEquals(3, apps.length())
        assertEquals("Alpha", apps.getJSONObject(0).getString("label"))
        assertEquals("beta", apps.getJSONObject(1).getString("label"))
        assertEquals("Charlie", apps.getJSONObject(2).getString("label"))

        val zeta = apps.getJSONObject(1)
        assertEquals("com.example.zeta", zeta.getString("package"))
        assertEquals("2.0", zeta.getString("version_name"))
        assertEquals(20L, zeta.getLong("version_code"))
        assertEquals(false, zeta.getBoolean("system"))
        assertEquals(true, zeta.getBoolean("enabled"))
        assertEquals(7L, zeta.getLong("updated_ms"))

        val middle = apps.getJSONObject(2)
        assertEquals(true, middle.getBoolean("system"))
        assertEquals(false, middle.getBoolean("enabled"))
    }

    @Test
    fun `an app without a version name reports null rather than an invented one`() {
        platform.apps += app("com.example.plain", "Plain", versionName = null)

        val entry = handler.handle(CommandDispatcher.APPS_LIST, null).getJSONArray("apps").getJSONObject(0)

        assertEquals(true, entry.isNull("version_name"))
    }

    @Test
    fun `a missing label falls back to the package name, never to an invented one`() {
        platform.apps += app("com.example.silent", "   ")

        val entry = handler.handle(CommandDispatcher.APPS_LIST, null).getJSONArray("apps").getJSONObject(0)

        assertEquals("com.example.silent", entry.getString("label"))
    }

    @Test
    fun `a listing past the app cap is refused, never truncated`() {
        platform.apps += (1..AppsHandler.MAX_LIST_APPS + 1).map { app("com.example.app$it", "App $it") }

        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.APPS_LIST, null)
        }

        assertEquals("listing_too_large", failure.code)
        assertTrue(
            "the message names the limit, not a device path: ${failure.message}",
            failure.message!!.contains(AppsHandler.MAX_LIST_APPS.toString()),
        )
    }

    @Test
    fun `a listing past the encoded byte cap is refused even under the app count`() {
        // 60 entries x ~20 KB each is over one mebibyte while well under 2 000 apps.
        platform.apps += (1..60).map { app("com.example.big$it", "x".repeat(20_000)) }

        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.APPS_LIST, null)
        }

        assertEquals("listing_too_large", failure.code)
    }

    @Test
    fun `launch starts the app's own launch intent`() {
        platform.apps += app("com.example.zeta", "Zeta")
        platform.intents["com.example.zeta"] = Intent(Intent.ACTION_MAIN).setPackage("com.example.zeta")

        val output = handler.handle(CommandDispatcher.APPS_LAUNCH, args("package" to "com.example.zeta"))

        assertEquals("com.example.zeta", output.getString("package"))
        assertEquals(true, output.getBoolean("launched"))
        assertEquals("com.example.zeta", platform.started?.`package`)
    }

    @Test
    fun `launch of a package with no launch activity is no_launch_activity`() {
        platform.apps += app("com.example.serviceonly", "Service only")

        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.APPS_LAUNCH, args("package" to "com.example.serviceonly"))
        }

        assertEquals("no_launch_activity", failure.code)
        assertNull("nothing may be started for a package with no launcher", platform.started)
    }

    @Test
    fun `launch while Android blocks background starts is launch_blocked with a reason`() {
        platform.apps += app("com.example.zeta", "Zeta")
        platform.intents["com.example.zeta"] = Intent(Intent.ACTION_MAIN)
        platform.mayStartFromBackground = false

        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.APPS_LAUNCH, args("package" to "com.example.zeta"))
        }

        assertEquals("launch_blocked", failure.code)
        assertEquals("background_activity_start_restricted", failure.message)
        assertNull("a blocked launch must not even attempt the start", platform.started)
    }

    @Test
    fun `a refused startActivity is launch_blocked and never a raw platform message`() {
        platform.apps += app("com.example.zeta", "Zeta")
        platform.intents["com.example.zeta"] = Intent(Intent.ACTION_MAIN)
        platform.startFailure = SecurityException("Permission Denial: starting Intent at /data/app/x")

        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.APPS_LAUNCH, args("package" to "com.example.zeta"))
        }

        assertEquals("launch_blocked", failure.code)
        assertEquals("platform_refused", failure.message)
        assertTrue(
            "a message must never carry a device path: ${failure.message}",
            !failure.message!!.contains("/data"),
        )
    }

    @Test
    fun `stop asks the platform to kill the package and says only what it asked`() {
        platform.apps += app("com.example.zeta", "Zeta")

        val output = handler.handle(CommandDispatcher.APPS_STOP, args("package" to "com.example.zeta"))

        assertEquals("com.example.zeta", output.getString("package"))
        assertEquals(true, output.getBoolean("kill_requested"))
        assertEquals("com.example.zeta", platform.killed)
        assertEquals(
            "a background kill is a request, not a confirmed stop",
            false,
            output.has("stopped"),
        )
    }

    @Test
    fun `stop the platform refuses is not_permitted`() {
        platform.apps += app("com.example.zeta", "Zeta")
        platform.killFailure = SecurityException("Permission Denial: /data/app/x")

        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.APPS_STOP, args("package" to "com.example.zeta"))
        }

        assertEquals("not_permitted", failure.code)
        assertTrue(
            "the message names the missing permission: ${failure.message}",
            failure.message!!.contains("KILL_BACKGROUND_PROCESSES"),
        )
        assertTrue("never a device path: ${failure.message}", !failure.message!!.contains("/data"))
        assertNull(platform.killed)
    }

    @Test
    fun `clear is not_permitted with the ADB path, after the package is validated`() {
        platform.apps += app("com.example.zeta", "Zeta")

        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.APPS_CLEAR, args("package" to "com.example.zeta"))
        }

        assertEquals("not_permitted", failure.code)
        assertTrue(
            "the message points at the ADB path: ${failure.message}",
            failure.message!!.contains("adb shell pm clear"),
        )
        assertNull(platform.started)
        assertNull(platform.killed)
    }

    @Test
    fun `set_enabled is not_permitted with the ADB path, after the package is validated`() {
        platform.apps += app("com.example.zeta", "Zeta")

        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle(
                CommandDispatcher.APPS_SET_ENABLED,
                args("package" to "com.example.zeta", "enabled" to true),
            )
        }

        assertEquals("not_permitted", failure.code)
        assertTrue(
            "the message points at the ADB path: ${failure.message}",
            failure.message!!.contains("adb shell pm disable-user"),
        )
        assertNull(platform.started)
        assertNull(platform.killed)
    }

    @Test
    fun `set_enabled without a boolean is invalid_args before any refusal`() {
        platform.apps += app("com.example.zeta", "Zeta")

        val missing = assertThrows(CommandFailure::class.java) {
            handler.handle(CommandDispatcher.APPS_SET_ENABLED, args("package" to "com.example.zeta"))
        }
        assertEquals("invalid_args", missing.code)

        val wrong = assertThrows(CommandFailure::class.java) {
            handler.handle(
                CommandDispatcher.APPS_SET_ENABLED,
                args("package" to "com.example.zeta", "enabled" to "yes"),
            )
        }
        assertEquals("invalid_args", wrong.code)
    }

    @Test
    fun `every acting command refuses a package the device does not list`() {
        platform.apps += app("com.example.known", "Known")

        val cases = listOf(
            CommandDispatcher.APPS_LAUNCH to args("package" to "com.example.uninstalled"),
            CommandDispatcher.APPS_STOP to args("package" to "com.example.uninstalled"),
            CommandDispatcher.APPS_CLEAR to args("package" to "com.example.uninstalled"),
            CommandDispatcher.APPS_SET_ENABLED to args("package" to "com.example.uninstalled", "enabled" to false),
        )

        for ((name, arguments) in cases) {
            val failure = assertThrows("$name must refuse an unknown package", CommandFailure::class.java) {
                handler.handle(name, arguments)
            }
            assertEquals("unknown_package", failure.code)
        }
        assertNull(platform.started)
        assertNull(platform.killed)
    }

    @Test
    fun `a package argument is required, a string, and not blank`() {
        val cases = listOf(
            null,
            args("package" to JSONObject.NULL),
            args("package" to 7),
            args("package" to "   "),
        )

        for (arguments in cases) {
            val failure = assertThrows(CommandFailure::class.java) {
                handler.handle(CommandDispatcher.APPS_LAUNCH, arguments)
            }
            assertEquals("invalid_args", failure.code)
        }
    }

    @Test
    fun `a command this handler does not own is unknown_command`() {
        val failure = assertThrows(CommandFailure::class.java) {
            handler.handle("apps.no_such", JSONObject())
        }

        assertEquals("unknown_command", failure.code)
    }

    @Test
    fun `the manifest declares the package visibility and background kill permissions`() {
        val manifest = File("src/main/AndroidManifest.xml").readText()

        assertTrue(
            "Android 11+ hides other apps unless QUERY_ALL_PACKAGES is declared",
            manifest.contains("android.permission.QUERY_ALL_PACKAGES"),
        )
        assertTrue(
            "apps.stop needs KILL_BACKGROUND_PROCESSES",
            manifest.contains("android.permission.KILL_BACKGROUND_PROCESSES"),
        )
        assertTrue(
            "the package visibility permission carries its Play policy justification",
            manifest.contains("Play policy"),
        )
        assertEquals("still exactly one service", 1, Regex("<service\\b").findAll(manifest).count())
    }

    private fun app(
        name: String,
        label: String,
        versionName: String? = "1.0",
        versionCode: Long = 1,
        system: Boolean = false,
        enabled: Boolean = true,
        updatedMs: Long = 1_760_000_000_000,
    ) = InstalledApp(
        packageName = name,
        label = label,
        versionName = versionName,
        versionCode = versionCode,
        system = system,
        enabled = enabled,
        updatedMs = updatedMs,
    )

    private fun args(vararg pairs: Pair<String, Any?>): JSONObject {
        val json = JSONObject()
        for ((key, value) in pairs) json.put(key, value)
        return json
    }

    private class FakePlatform(
        val apps: MutableList<InstalledApp> = mutableListOf(),
    ) : AppPlatform {
        val intents = mutableMapOf<String, Intent>()
        var mayStartFromBackground = true
        var started: Intent? = null
        var startFailure: RuntimeException? = null
        var killed: String? = null
        var killFailure: RuntimeException? = null

        override fun installed(): List<InstalledApp> = apps.toList()

        override fun launchIntent(packageName: String): Intent? = intents[packageName]

        override fun startActivity(intent: Intent) {
            startFailure?.let { throw it }
            started = intent
        }

        override fun killBackgroundProcesses(packageName: String) {
            killFailure?.let { throw it }
            killed = packageName
        }

        override fun mayStartActivityFromBackground(): Boolean = mayStartFromBackground
    }
}

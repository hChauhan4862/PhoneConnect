package com.phoneconnect.agent.control

import android.annotation.SuppressLint
import org.json.JSONArray
import org.json.JSONObject

/**
 * The properties this agent may report, and the platform property each one reads. Anything
 * outside this map is refused: reading an arbitrary system property is not a capability an
 * ordinary app has, and pretending otherwise would be a fabricated answer.
 */
object SystemPropertyAllowlist {
    val READABLE: Map<String, String> = linkedMapOf(
        "sdk" to "ro.build.version.sdk",
        "release" to "ro.build.version.release",
        "model" to "ro.product.model",
        "manufacturer" to "ro.product.manufacturer",
        "build_id" to "ro.build.id",
        "security_patch" to "ro.build.version.security_patch",
    )
}

/** One property as the platform reports it; `null` when the platform has no value. */
fun interface SystemPropertySource {
    /** Throws [CommandFailure] `props_unavailable` when the platform reader cannot be used. */
    fun read(name: String): String?
}

/**
 * Reads properties through `android.os.SystemProperties`, the only route an ordinary app has.
 *
 * The class is hidden, so it is reached by reflection: a build where that fails is
 * `props_unavailable`, never a guessed value and never a raw reflection message. Lint's
 * `PrivateApi` warning is the point of this class — there is no public property API — and the
 * failure is already turned into a machine code rather than a crash.
 */
@SuppressLint("PrivateApi")
class AndroidSystemProperties(
    private val systemProperties: () -> Class<*> = { Class.forName(SYSTEM_PROPERTIES_CLASS) },
) : SystemPropertySource {
    override fun read(name: String): String? = try {
        val method = systemProperties().getMethod("get", String::class.java)
        (method.invoke(null, name) as? String)?.ifBlank { null }
    } catch (_: ReflectiveOperationException) {
        throw unavailable()
    } catch (_: SecurityException) {
        throw unavailable()
    } catch (_: LinkageError) {
        throw unavailable()
    }

    private fun unavailable() =
        CommandFailure(SystemPropertiesHandler.PROPS_UNAVAILABLE, SystemPropertiesHandler.PROPS_UNAVAILABLE_MESSAGE)

    private companion object {
        const val SYSTEM_PROPERTIES_CLASS = "android.os.SystemProperties"
    }
}

/**
 * `system.props`: the documented allowlist, and nothing else.
 *
 * `{}` reports every allowlisted property; `{keys:[...]}` selects a subset and answers
 * `not_permitted` for a name outside the allowlist before anything is read. This is the honest
 * replacement for `shell.exec getprop`, which an installed app cannot run at all.
 */
class SystemPropertiesHandler(
    private val source: SystemPropertySource = AndroidSystemProperties(),
) {
    fun select(args: JSONObject?): JSONObject {
        val requested = requestedKeys(args)
        val selected = JSONObject()
        for ((key, property) in SystemPropertyAllowlist.READABLE) {
            if (requested != null && key !in requested) continue
            // A property the platform does not report is null, never an empty string.
            selected.put(key, source.read(property) ?: JSONObject.NULL)
        }
        return JSONObject().put("selected", selected)
    }

    /** `null` means "the whole allowlist". */
    private fun requestedKeys(args: JSONObject?): Set<String>? {
        val raw = args?.opt("keys") ?: return null
        if (raw == JSONObject.NULL) return null
        if (raw !is JSONArray) throw CommandFailure.invalid("keys must be an array of allowlisted names")
        if (raw.length() == 0) throw CommandFailure.invalid("keys must name at least one property")
        val keys = LinkedHashSet<String>(raw.length())
        for (index in 0 until raw.length()) {
            val value = raw.opt(index)
            if (value !is String || value.isBlank()) {
                throw CommandFailure.invalid("keys must contain non-empty strings")
            }
            val key = value.trim()
            if (!SystemPropertyAllowlist.READABLE.containsKey(key)) {
                throw CommandFailure("not_permitted", OUTSIDE_ALLOWLIST_MESSAGE)
            }
            keys += key
        }
        return keys
    }

    companion object {
        const val PROPS_UNAVAILABLE = "props_unavailable"

        const val PROPS_UNAVAILABLE_MESSAGE =
            "this build's platform does not expose its system-property reader through " +
                "reflection, so no property can be reported"

        const val OUTSIDE_ALLOWLIST_MESSAGE =
            "only the documented system properties may be read: " +
                "sdk, release, model, manufacturer, build_id, security_patch"
    }
}

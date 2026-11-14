package com.phoneconnect.agent.control

import android.content.Intent
import android.util.Base64
import org.json.JSONObject

/** One frame the platform produced, PNG-encoded at [width] x [height]. */
class CapturedFrame(
    val png: ByteArray,
    val width: Int,
    val height: Int,
    val capturedAtMs: Long,
)

/**
 * The one thing `screen.snapshot` can do with the platform: a single frame from a projection
 * the user granted from the setup screen.
 *
 * [accept] is called only from a user action (the setup screen's consent result reaching
 * [com.phoneconnect.agent.ConnectionService]); [capture] never asks for consent, so a command
 * can never raise a system dialog. The projection is held for the service lifetime because
 * Android cannot persist the grant across process death — after a restart the command answers
 * `consent_required` again instead of reusing a token that no longer exists.
 */
interface ScreenCapture {
    /** True while a projection the user granted is held. */
    fun available(): Boolean

    /**
     * Installs a grant the user just made; a non-`RESULT_OK` result installs nothing.
     *
     * [onEnded] runs when the projection ends without the app asking (the user stopped
     * sharing, the screen was locked, or the system ended the session), so the owner can stop
     * showing capture as enabled.
     */
    fun accept(resultCode: Int, data: Intent?, onEnded: () -> Unit)

    /**
     * One frame, PNG-encoded to at most [maxEncodedBytes] of base64, within [timeoutMs].
     *
     * Throws [CommandFailure] (`consent_required`, `capture_timeout`, `capture_failed`, or
     * `result_too_large`) instead of returning a frame that is not there.
     */
    fun capture(maxEncodedBytes: Int, timeoutMs: Long): CapturedFrame

    /** Ends the projection. Safe to call when nothing is held. */
    fun release()
}

/**
 * `screen.snapshot`: one real frame, or an explicit `consent_required`.
 *
 * An ordinary installed app cannot read the screen without a `MediaProjection` the user
 * granted; there is no silent capture. The handler therefore refuses before touching the
 * platform when no grant is held, and bounds what it returns so the server never has to drop
 * an oversized frame.
 */
class ScreenHandler(private val capture: ScreenCapture) {
    fun snapshot(budgetMs: Long): JSONObject {
        if (!capture.available()) {
            throw CommandFailure(CONSENT_REQUIRED, CONSENT_MESSAGE)
        }
        val frame = capture.capture(MAX_ENCODED_BYTES, budgetMs.coerceIn(1L, CAPTURE_TIMEOUT_MS))
        if (frame.png.isEmpty() || frame.width <= 0 || frame.height <= 0) {
            throw CommandFailure("capture_failed", "the platform produced no usable frame")
        }
        val encoded = Base64.encodeToString(frame.png, Base64.NO_WRAP)
        // The capture downscales until the encoded frame fits; this is the last check, and it
        // refuses rather than handing the server something it must drop.
        if (encoded.length > MAX_ENCODED_BYTES) {
            throw CommandFailure(
                "result_too_large",
                "the encoded frame exceeds the ${MAX_ENCODED_BYTES}-byte base64 result budget",
            )
        }
        return JSONObject()
            .put("png_base64", encoded)
            .put("width", frame.width)
            .put("height", frame.height)
            .put("captured_at_ms", frame.capturedAtMs)
    }

    companion object {
        const val CONSENT_REQUIRED = "consent_required"

        const val CONSENT_MESSAGE =
            "screen capture needs the user's consent, granted from the PhoneConnect setup " +
                "screen on the device; no projection is held"

        /**
         * Base64 bytes one result may carry. The server refuses a result above 2 MiB, and the
         * envelope has to fit beside the payload, so the budget stops short of the cap.
         */
        const val MAX_ENCODED_BYTES: Int = 2 * 1024 * 1024 - 64 * 1024

        /** The longest one frame may take to arrive, independent of the command deadline. */
        const val CAPTURE_TIMEOUT_MS: Long = 5_000
    }
}

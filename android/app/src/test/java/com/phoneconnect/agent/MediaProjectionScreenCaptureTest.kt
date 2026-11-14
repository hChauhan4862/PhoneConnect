package com.phoneconnect.agent

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.test.core.app.ApplicationProvider
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.MediaProjectionScreenCapture
import com.phoneconnect.agent.control.base64Length
import com.phoneconnect.agent.control.encodeWithinLimit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * The platform side of screen capture: nothing is captured without a grant the user made, and
 * the encoded frame is downscaled until it fits the result cap instead of being dropped.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class MediaProjectionScreenCaptureTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    @Test
    fun `without a grant there is nothing to capture and the answer is consent_required`() {
        val capture = MediaProjectionScreenCapture(context)

        assertFalse(capture.available())
        val failure = assertThrows(CommandFailure::class.java) { capture.capture(1_000_000, 100) }
        assertEquals("consent_required", failure.code)
    }

    @Test
    fun `a cancelled or empty consent result installs no projection`() {
        val capture = MediaProjectionScreenCapture(context)

        capture.accept(Activity.RESULT_CANCELED, Intent("capture"))
        capture.accept(Activity.RESULT_OK, null)

        assertFalse(capture.available())
        // Releasing twice must not throw: the service releases on both stop and destroy.
        capture.release()
        capture.release()
    }

    @Test
    fun `a frame that fits is encoded at its natural size`() {
        val encoded = encodeWithinLimit(1080, 1920, maxEncodedBytes = 1_000_000) { width, height ->
            ByteArray(width * height / 1000)
        }

        assertEquals(1080, encoded.width)
        assertEquals(1920, encoded.height)
        assertTrue(base64Length(encoded.png.size) <= 1_000_000)
    }

    @Test
    fun `an oversized frame is downscaled by whole factors until it fits`() {
        val encoded = encodeWithinLimit(1000, 2000, maxEncodedBytes = 700) { width, height ->
            // 1 byte of PNG per 1 000 pixels, so only a real downscale makes it fit.
            ByteArray(((width.toLong() * height) / 1000).toInt())
        }

        assertEquals("a factor of 2 must halve both dimensions", 500, encoded.width)
        assertEquals(1000, encoded.height)
        assertTrue(
            "the reported size must be the size actually encoded",
            base64Length(encoded.png.size) <= 700,
        )
    }

    @Test
    fun `a frame that cannot be downscaled small enough is result_too_large`() {
        val failure = assertThrows(CommandFailure::class.java) {
            encodeWithinLimit(4000, 4000, maxEncodedBytes = 8) { _, _ -> ByteArray(64) }
        }

        assertEquals("result_too_large", failure.code)
        assertFalse("a message must not name a device path", failure.message.orEmpty().contains("/"))
    }

    @Test
    fun `a 2 MiB base64 cap is not exceeded by the base64 of the returned png`() {
        val cap = 2 * 1024 * 1024 - 64 * 1024
        val encoded = encodeWithinLimit(3840, 2160, cap) { width, height ->
            ByteArray(width * height)
        }

        assertTrue(base64Length(encoded.png.size) <= cap)
        assertTrue("the frame must really have been downscaled", encoded.width < 3840)
    }
}

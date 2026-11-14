package com.phoneconnect.agent

import android.content.Intent
import android.util.Base64
import com.phoneconnect.agent.control.CapturedFrame
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.ScreenCapture
import com.phoneconnect.agent.control.ScreenHandler
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

/**
 * `screen.snapshot`: refused as `consent_required` until the user granted projection from the
 * setup screen, one frame when they did, and never a result the server would have to drop.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class ScreenHandlerTest {
    private val frameBytes = byteArrayOf(0x89.toByte(), 0x50, 0x4E, 0x47, 1, 2, 3)

    private class FakeCapture(
        var granted: Boolean = true,
        private val frame: () -> CapturedFrame = {
            CapturedFrame(byteArrayOf(1, 2, 3), width = 1080, height = 1920, capturedAtMs = 1_760_000_000_000)
        },
    ) : ScreenCapture {
        var captures = 0
            private set
        var releases = 0
            private set
        var lastMaxEncodedBytes = 0
            private set
        var lastTimeoutMs = 0L
            private set

        override fun available(): Boolean = granted

        override fun accept(resultCode: Int, data: Intent?) = Unit

        override fun capture(maxEncodedBytes: Int, timeoutMs: Long): CapturedFrame {
            captures += 1
            lastMaxEncodedBytes = maxEncodedBytes
            lastTimeoutMs = timeoutMs
            return frame()
        }

        override fun release() {
            releases += 1
            granted = false
        }
    }

    @Test
    fun `a command never captures without consent and answers consent_required`() {
        val capture = FakeCapture(granted = false)
        val handler = ScreenHandler(capture)

        val failure = assertThrows(CommandFailure::class.java) { handler.snapshot(10_000) }

        assertEquals("consent_required", failure.code)
        assertEquals("a command must never prompt for consent", 0, capture.captures)
        val message = failure.message.orEmpty()
        assertTrue("the refusal must say consent is required: $message", message.contains("consent"))
        assertFalse("a message must not name a device path: $message", message.contains("/"))
    }

    @Test
    fun `a granted projection returns one frame with the size and time actually captured`() {
        val capture = FakeCapture()
        val handler = ScreenHandler(capture)

        val output = handler.snapshot(10_000)

        assertEquals(1, capture.captures)
        assertTrue(
            "the frame bytes must survive base64 unchanged",
            Base64.decode(output.getString("png_base64"), Base64.NO_WRAP).contentEquals(byteArrayOf(1, 2, 3)),
        )
        assertEquals(1080, output.getInt("width"))
        assertEquals(1920, output.getInt("height"))
        assertEquals(1_760_000_000_000L, output.getLong("captured_at_ms"))
    }

    @Test
    fun `a second capture reuses the same consent instead of asking again`() {
        val capture = FakeCapture()
        val handler = ScreenHandler(capture)

        handler.snapshot(10_000)
        handler.snapshot(10_000)

        assertEquals("one grant must serve every later command", 2, capture.captures)
    }

    @Test
    fun `the capture timeout is bounded by the command budget`() {
        val capture = FakeCapture()
        val handler = ScreenHandler(capture)

        handler.snapshot(250)
        assertEquals("a short command budget bounds the capture", 250L, capture.lastTimeoutMs)

        handler.snapshot(60_000)
        assertEquals(ScreenHandler.CAPTURE_TIMEOUT_MS, capture.lastTimeoutMs)
    }

    @Test
    fun `the encoded frame is held under the server's result cap`() {
        val capture = FakeCapture()
        val handler = ScreenHandler(capture)

        handler.snapshot(10_000)

        assertTrue(
            "the capture budget must leave the result envelope room under 2 MiB",
            capture.lastMaxEncodedBytes <= 2 * 1024 * 1024,
        )
        assertTrue(
            "the capture budget must not be needlessly small",
            capture.lastMaxEncodedBytes > 1024 * 1024,
        )
    }

    @Test
    fun `an encoded frame over the cap is result_too_large, never truncated`() {
        // Base64 of this frame is longer than the cap even though the raw PNG is not.
        val oversized = ByteArray(ScreenHandler.MAX_ENCODED_BYTES * 3 / 4 + 3)
        val capture = FakeCapture(frame = { CapturedFrame(oversized, 10, 10, 1) })
        val handler = ScreenHandler(capture)

        val failure = assertThrows(CommandFailure::class.java) { handler.snapshot(10_000) }

        assertEquals("result_too_large", failure.code)
    }

    @Test
    fun `a frame the platform did not really produce is capture_failed`() {
        val capture = FakeCapture(frame = { CapturedFrame(ByteArray(0), 0, 0, 1) })
        val handler = ScreenHandler(capture)

        val failure = assertThrows(CommandFailure::class.java) { handler.snapshot(10_000) }

        assertEquals("capture_failed", failure.code)
    }

    @Test
    fun `releasing the consent makes the next command consent_required again`() {
        val capture = FakeCapture()
        val handler = ScreenHandler(capture)

        capture.release()

        val failure = assertThrows(CommandFailure::class.java) { handler.snapshot(10_000) }
        assertEquals("consent_required", failure.code)
        assertEquals(1, capture.releases)
    }
}

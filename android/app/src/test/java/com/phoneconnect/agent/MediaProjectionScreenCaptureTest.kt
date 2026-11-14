package com.phoneconnect.agent

import android.app.Activity
import android.content.Context
import android.content.Intent
import androidx.core.graphics.createBitmap
import androidx.test.core.app.ApplicationProvider
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.MediaProjectionScreenCapture
import com.phoneconnect.agent.control.MirrorFrame
import com.phoneconnect.agent.control.MirrorSource
import com.phoneconnect.agent.control.ScreenMetrics
import com.phoneconnect.agent.control.ScreenMirror
import com.phoneconnect.agent.control.base64Length
import com.phoneconnect.agent.control.encodeWithinLimit
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.ArrayDeque
import java.util.concurrent.Executor

/**
 * The platform side of screen capture: no grant means no capture, a size change resizes the
 * display the grant already owns, nothing blocks the caller while a stop is cleaned up, a stale
 * callback cannot retire a newer grant, and every stop path releases the mirror.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class MediaProjectionScreenCaptureTest {
    private val context = ApplicationProvider.getApplicationContext<Context>()

    /** A mirror with no framework behind it: the size and the frame are exactly what it says. */
    private class FakeMirror(
        override var width: Int,
        override var height: Int,
        var frame: MirrorFrame? = null,
    ) : ScreenMirror {
        @Volatile
        override var open: Boolean = true
            private set
        var closed = false
            private set
        var resizeSucceeds = true
        var resizes = 0
            private set

        override fun newestFrame(): MirrorFrame? = if (open) frame else null

        override fun resize(screen: ScreenMetrics): Boolean {
            resizes += 1
            if (!resizeSucceeds) return false
            width = screen.widthPixels
            height = screen.heightPixels
            frame = MirrorFrame(createBitmap(width, height), capturedAtMs = NOW + 1)
            return true
        }

        override fun close() {
            open = false
            closed = true
        }
    }

    private class FakeSource(private val frameSize: Pair<Int, Int>? = null) : MirrorSource {
        var opened = 0
            private set
        var stopped = false
            private set
        var lastScreen: ScreenMetrics? = null
        var mirror: FakeMirror? = null
            private set
        private var ended: (() -> Unit)? = null
        private var resized: ((Int, Int) -> Unit)? = null

        override fun open(screen: ScreenMetrics): ScreenMirror {
            opened += 1
            lastScreen = screen
            val (width, height) = frameSize ?: (screen.widthPixels to screen.heightPixels)
            val created = FakeMirror(
                width = width,
                height = height,
                frame = MirrorFrame(createBitmap(width, height), capturedAtMs = NOW),
            )
            mirror = created
            return created
        }

        override fun stop() {
            stopped = true
        }

        override fun onEnded(listener: () -> Unit) {
            ended = listener
        }

        override fun onContentResized(listener: (width: Int, height: Int) -> Unit) {
            resized = listener
        }

        /** What the platform does on "Stop sharing": the registered callback fires. */
        fun end() {
            ended?.invoke()
        }

        /** What Android 14+ does on rotation: `onCapturedContentResize` fires. */
        fun reportContentSize(width: Int, height: Int) {
            resized?.invoke(width, height)
        }
    }

    /** Runs teardown work when the test says so, so "not on the caller's thread" is visible. */
    private class DeferredExecutor : Executor {
        private val queued = ArrayDeque<Runnable>()

        override fun execute(command: Runnable) {
            queued.add(command)
        }

        fun runQueued() {
            while (queued.isNotEmpty()) queued.poll()?.run()
        }
    }

    private fun captureWith(
        source: FakeSource = FakeSource(),
        metrics: ScreenMetrics = DEFAULT_METRICS,
        teardown: Executor = Executor(Runnable::run),
    ): MediaProjectionScreenCapture = MediaProjectionScreenCapture(
        context = context,
        metrics = { metrics },
        clock = { NOW },
        teardown = teardown,
        openSource = { _, _ -> source },
    )

    @Test
    fun `without a grant there is nothing to capture and the answer is consent_required`() {
        val capture = captureWith()

        assertFalse(capture.available())
        val failure = assertThrows(CommandFailure::class.java) { capture.capture(1_000_000, 100) }
        assertEquals("consent_required", failure.code)
    }

    @Test
    fun `a cancelled or empty consent result installs no projection`() {
        val source = FakeSource()
        val capture = captureWith(source)

        capture.accept(Activity.RESULT_CANCELED, Intent("capture")) { }
        capture.accept(Activity.RESULT_OK, null) { }

        assertFalse(capture.available())
        assertEquals(0, source.opened)
        // Releasing twice must not throw: the service releases on both stop and destroy.
        capture.release()
        capture.release()
    }

    @Test
    fun `a capture reports the size the mirror produced, not the current metrics`() {
        // A 100x200 frame with 1080x2400 metrics: copying with the metrics would be the bug.
        val capture = captureWith(FakeSource(frameSize = 100 to 200))
        capture.accept(Activity.RESULT_OK, Intent("capture")) { }

        val frame = capture.capture(Int.MAX_VALUE, 100)

        assertEquals(100, frame.width)
        assertEquals(200, frame.height)
    }

    @Test
    fun `a size change resizes the mirror and keeps the grant`() {
        var metrics = DEFAULT_METRICS
        val source = FakeSource()
        var ended = 0
        val capture = MediaProjectionScreenCapture(
            context = context,
            metrics = { metrics },
            clock = { NOW },
            teardown = Executor(Runnable::run),
            openSource = { _, _ -> source },
        )
        capture.accept(Activity.RESULT_OK, Intent("capture")) { ended += 1 }
        assertEquals(1080, capture.capture(Int.MAX_VALUE, 100).width)
        val mirror = source.mirror!!

        // Rotation: the same display is resized, so the user does not grant again.
        metrics = ScreenMetrics(2400, 1080, 420)
        val frame = capture.capture(Int.MAX_VALUE, 100)

        assertEquals(1, mirror.resizes)
        assertEquals(2400, frame.width)
        assertEquals(1080, frame.height)
        assertTrue("the grant must survive a resize", capture.available())
        assertFalse("the projection must not be stopped", source.stopped)
        assertEquals("the owner must not be told capture ended", 0, ended)
    }

    @Test
    fun `a resize failure retires the grant with the size-changed message`() {
        var metrics = DEFAULT_METRICS
        val source = FakeSource()
        var ended = 0
        val capture = MediaProjectionScreenCapture(
            context = context,
            metrics = { metrics },
            clock = { NOW },
            teardown = Executor(Runnable::run),
            openSource = { _, _ -> source },
        )
        capture.accept(Activity.RESULT_OK, Intent("capture")) { ended += 1 }
        capture.capture(Int.MAX_VALUE, 100)
        source.mirror!!.resizeSucceeds = false

        metrics = ScreenMetrics(2400, 1080, 420)
        val failure = assertThrows(CommandFailure::class.java) {
            capture.capture(Int.MAX_VALUE, 100)
        }

        assertEquals("consent_required", failure.code)
        assertEquals(MediaProjectionScreenCapture.SIZE_CHANGED_MESSAGE, failure.message)
        assertFalse("the unusable grant must be dropped", capture.available())
        assertTrue("the projection must be stopped", source.stopped)
        assertTrue(source.mirror!!.closed)
        assertEquals("the owner must learn capture is off", 1, ended)
    }

    @Test
    fun `the content resize callback resizes on the teardown worker`() {
        var metrics = DEFAULT_METRICS
        val teardown = DeferredExecutor()
        val source = FakeSource()
        val capture = MediaProjectionScreenCapture(
            context = context,
            metrics = { metrics },
            clock = { NOW },
            teardown = teardown,
            openSource = { _, _ -> source },
        )
        capture.accept(Activity.RESULT_OK, Intent("capture")) { }
        capture.capture(Int.MAX_VALUE, 100)
        val mirror = source.mirror!!

        // Android 14+ reports the new captured-content size before the next command arrives.
        metrics = ScreenMetrics(2400, 1080, 420)
        source.reportContentSize(2400, 1080)
        assertEquals("the platform callback must not block", 0, mirror.resizes)

        teardown.runQueued()

        assertEquals(1, mirror.resizes)
        assertEquals(2400, mirror.width)
        assertEquals(1080, mirror.height)
        assertTrue("a resize keeps the grant", capture.available())
        assertFalse(source.stopped)
        assertEquals(2400, capture.capture(Int.MAX_VALUE, 100).width)
        assertEquals("a resized mirror is not resized again", 1, mirror.resizes)
    }

    @Test
    fun `a stale end from an old grant does not retire the new one`() {
        val first = FakeSource()
        val second = FakeSource()
        var next: FakeSource = first
        var ended = 0
        val capture = MediaProjectionScreenCapture(
            context = context,
            metrics = { DEFAULT_METRICS },
            clock = { NOW },
            teardown = Executor(Runnable::run),
            openSource = { _, _ -> next },
        )
        capture.accept(Activity.RESULT_OK, Intent("capture")) { ended += 1 }
        capture.capture(Int.MAX_VALUE, 100)

        next = second
        capture.accept(Activity.RESULT_OK, Intent("capture")) { ended += 1 }

        // The platform's onStop for the first grant arrives only now.
        first.end()

        assertTrue("the newer grant must survive a stale end", capture.available())
        assertEquals("the newer grant's owner must not be told capture ended", 0, ended)
        assertTrue("the replaced projection must be stopped", first.stopped)

        val frame = capture.capture(Int.MAX_VALUE, 100)
        assertEquals("the newer grant must be the one used", 1, second.opened)
        assertEquals(1080, frame.width)
    }

    @Test
    fun `a resize queued before a re-grant cannot retire the newer grant`() {
        val teardown = DeferredExecutor()
        val first = FakeSource()
        val second = FakeSource()
        var next: FakeSource = first
        var ended = 0
        val capture = MediaProjectionScreenCapture(
            context = context,
            metrics = { DEFAULT_METRICS },
            clock = { NOW },
            teardown = teardown,
            openSource = { _, _ -> next },
        )
        capture.accept(Activity.RESULT_OK, Intent("capture")) { ended += 1 }
        capture.capture(Int.MAX_VALUE, 100)
        val firstMirror = first.mirror!!

        // A rotation queues a resize; the user grants again before it runs.
        first.reportContentSize(1200, 2400)
        next = second
        capture.accept(Activity.RESULT_OK, Intent("capture")) { ended += 1 }
        firstMirror.resizeSucceeds = false

        teardown.runQueued()

        assertTrue("the newer grant must survive a stale resize", capture.available())
        assertEquals("the newer grant must not be told capture ended", 0, ended)
        assertEquals("the stale resize must not touch the older mirror", 0, firstMirror.resizes)
        assertTrue("the replaced projection must be stopped", first.stopped)
        assertEquals("the replaced mirror must be closed", true, firstMirror.closed)

        val frame = capture.capture(Int.MAX_VALUE, 100)
        assertEquals("the newer grant must be the one used", 1, second.opened)
        assertEquals(1080, frame.width)
    }

    @Test
    fun `a new grant after a release opens a mirror at the new size`() {
        var metrics = DEFAULT_METRICS
        val first = FakeSource()
        val second = FakeSource()
        var next: FakeSource = first
        val capture = MediaProjectionScreenCapture(
            context = context,
            metrics = { metrics },
            clock = { NOW },
            teardown = Executor(Runnable::run),
            openSource = { _, _ -> next },
        )

        capture.accept(Activity.RESULT_OK, Intent("capture")) { }
        assertEquals(1080, capture.capture(Int.MAX_VALUE, 100).width)

        capture.release()
        metrics = ScreenMetrics(2400, 1080, 420)
        next = second
        capture.accept(Activity.RESULT_OK, Intent("capture")) { }

        val frame = capture.capture(Int.MAX_VALUE, 100)

        assertEquals("the new grant must open its own mirror", 1, second.opened)
        assertEquals(ScreenMetrics(2400, 1080, 420), second.lastScreen)
        assertEquals(2400, frame.width)
        assertEquals(1080, frame.height)
    }

    @Test
    fun `a frame that is already available is returned without waiting`() {
        val capture = captureWith()
        capture.accept(Activity.RESULT_OK, Intent("capture")) { }

        val startedAt = System.nanoTime()
        val frame = capture.capture(Int.MAX_VALUE, 5_000)
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000

        assertNotNull(frame)
        assertTrue("a buffered frame must not wait, took ${elapsedMs}ms", elapsedMs < 500)
    }

    @Test
    fun `a closed mirror refuses immediately instead of waiting out the timeout`() {
        val source = FakeSource()
        val capture = captureWith(source)
        capture.accept(Activity.RESULT_OK, Intent("capture")) { }
        capture.capture(Int.MAX_VALUE, 100)
        source.mirror!!.frame = null
        source.mirror!!.close()

        val startedAt = System.nanoTime()
        val failure = assertThrows(CommandFailure::class.java) {
            capture.capture(1_000_000, 5_000)
        }
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000

        // A mirror that is gone means the projection is gone: the answer is consent again, and
        // the caller is not made to wait for a frame that can never arrive.
        assertEquals("consent_required", failure.code)
        assertTrue("the wait must end at once, took ${elapsedMs}ms", elapsedMs < 500)
    }

    @Test
    fun `a stop during a capture is cleaned up off the calling thread and still releases`() {
        val teardown = DeferredExecutor()
        val source = FakeSource()
        val capture = captureWith(source, teardown = teardown)
        capture.accept(Activity.RESULT_OK, Intent("capture")) { }
        capture.capture(Int.MAX_VALUE, 100)

        capture.release()

        assertFalse("the caller must not wait for the mirror to close", source.mirror!!.closed)
        assertFalse(source.stopped)

        teardown.runQueued()

        assertTrue("the display and reader must be released", source.mirror!!.closed)
        assertTrue("the projection must be stopped", source.stopped)
    }

    @Test
    fun `a stop during an in-flight capture returns at once and still releases`() {
        val teardown = java.util.concurrent.Executors.newSingleThreadExecutor()
        try {
            val source = FakeSource()
            val capture = captureWith(source, teardown = teardown)
            capture.accept(Activity.RESULT_OK, Intent("capture")) { }
            capture.capture(Int.MAX_VALUE, 100)
            // The next capture has nothing to return, so it sits in the wait.
            source.mirror!!.frame = null

            val waiting = Thread {
                assertThrows(CommandFailure::class.java) {
                    capture.capture(Int.MAX_VALUE, 5_000)
                }
            }
            waiting.start()
            Thread.sleep(150)

            val startedAt = System.nanoTime()
            capture.release()
            val releaseMs = (System.nanoTime() - startedAt) / 1_000_000

            assertTrue("release must not wait for the capture, took ${releaseMs}ms", releaseMs < 500)
            waiting.join(2_000)
            assertFalse("the capture must end once the mirror closes", waiting.isAlive)
            assertTrue("the display and reader must be released", source.mirror!!.closed)
            assertTrue("the projection must be stopped", source.stopped)
        } finally {
            teardown.shutdownNow()
        }
    }

    @Test
    fun `a system stop clears the grant, releases the mirror, and tells the owner`() {
        val teardown = DeferredExecutor()
        val source = FakeSource()
        var ownerEnded = 0
        val capture = MediaProjectionScreenCapture(
            context = context,
            metrics = { DEFAULT_METRICS },
            clock = { NOW },
            teardown = teardown,
            openSource = { _, _ -> source },
        )
        capture.accept(Activity.RESULT_OK, Intent("capture")) { ownerEnded += 1 }
        capture.capture(Int.MAX_VALUE, 100)

        source.end()

        assertFalse(capture.available())
        assertEquals("the owner must learn capture is off", 1, ownerEnded)
        assertFalse("onStop must not block the main thread", source.mirror!!.closed)
        teardown.runQueued()
        assertTrue(source.mirror!!.closed)

        val failure = assertThrows(CommandFailure::class.java) { capture.capture(Int.MAX_VALUE, 100) }
        assertEquals("consent_required", failure.code)
    }

    @Test
    fun `re-granting does not keep the previous mirror or its frozen frame`() {
        val teardown = DeferredExecutor()
        val first = FakeSource()
        val second = FakeSource()
        var next: FakeSource = first
        val capture = MediaProjectionScreenCapture(
            context = context,
            metrics = { DEFAULT_METRICS },
            clock = { NOW },
            teardown = teardown,
            openSource = { _, _ -> next },
        )
        capture.accept(Activity.RESULT_OK, Intent("capture")) { }
        capture.capture(Int.MAX_VALUE, 100)

        next = second
        capture.accept(Activity.RESULT_OK, Intent("capture")) { }
        teardown.runQueued()

        assertTrue("the previous mirror must be closed", first.mirror!!.closed)
        assertTrue("the previous projection must be stopped", first.stopped)

        val frame = capture.capture(Int.MAX_VALUE, 100)
        assertEquals("the new grant must open its own mirror", 1, second.opened)
        assertEquals(1080, frame.width)
        assertNull("the old frame must not be reused", first.mirror?.newestFrame())
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

    private companion object {
        const val NOW = 1_760_000_000_000L
        val DEFAULT_METRICS = ScreenMetrics(1080, 2400, 420)
    }
}

package com.phoneconnect.agent.control

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.media.projection.MediaProjectionManager
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import android.os.SystemClock
import androidx.core.graphics.createBitmap
import androidx.core.graphics.scale
import java.io.ByteArrayOutputStream

/** The display a projection mirrors: the surface size and density it must be created with. */
data class ScreenMetrics(val widthPixels: Int, val heightPixels: Int, val densityDpi: Int) {
    companion object {
        fun from(context: Context): ScreenMetrics {
            val metrics = context.resources.displayMetrics
            return ScreenMetrics(metrics.widthPixels, metrics.heightPixels, metrics.densityDpi)
        }
    }
}

/** The PNG actually returned, at the size it was encoded. */
class EncodedFrame(val png: ByteArray, val width: Int, val height: Int)

/**
 * The base64 length of [rawBytes] without materializing the encoding.
 *
 * Base64 is `4 * ceil(n / 3)`; measuring the raw PNG keeps a multi-megabyte frame from being
 * encoded twice just to find out it does not fit.
 */
internal fun base64Length(rawBytes: Int): Long = 4L * ((rawBytes + 2) / 3)

/**
 * Encodes at factor 1, then at each successive whole downscale, until the base64 PNG fits
 * [maxEncodedBytes]. Never crops and never truncates: a frame that still does not fit at
 * [MAX_DOWNSCALE_FACTOR] is `result_too_large`.
 */
internal fun encodeWithinLimit(
    width: Int,
    height: Int,
    maxEncodedBytes: Int,
    encode: (width: Int, height: Int) -> ByteArray,
): EncodedFrame {
    var factor = 1
    while (factor <= MAX_DOWNSCALE_FACTOR) {
        val targetWidth = (width / factor).coerceAtLeast(1)
        val targetHeight = (height / factor).coerceAtLeast(1)
        val png = encode(targetWidth, targetHeight)
        if (base64Length(png.size) <= maxEncodedBytes) {
            return EncodedFrame(png, targetWidth, targetHeight)
        }
        if (targetWidth == 1 && targetHeight == 1) break
        factor += 1
    }
    throw CommandFailure(
        "result_too_large",
        "the frame could not be downscaled under the ${maxEncodedBytes}-byte base64 budget",
    )
}

/**
 * `screen.snapshot`'s platform half: one frame through `MediaProjection` + `VirtualDisplay` +
 * `ImageReader`, PNG-encoded and downscaled to fit the result budget.
 *
 * The projection is acquired only from a grant the user made on the setup screen. It is held
 * for the service lifetime: Android cannot persist a projection token across process death, and
 * a new grant would need another user action.
 *
 * One `VirtualDisplay` + `ImageReader` pair serves the whole grant. That is a platform
 * requirement, not a shortcut: from Android 14 a token may create one virtual display, and
 * calling `createVirtualDisplay` again after the display was released logs `Reusing token:
 * Throw exception due to invalid projection` and stops the projection, so a per-frame release
 * would make every capture after the first fail. The reader's listener keeps the newest frame,
 * so a capture of an unchanged screen does not wait for a change that will never come. The
 * display, the reader, the cached frame, and the projection are all released when the user
 * stops capture, the service ends, or the system ends the session — nothing outlives the grant.
 */
class MediaProjectionScreenCapture(
    private val context: Context,
    private val metrics: () -> ScreenMetrics = { ScreenMetrics.from(context) },
    private val clock: () -> Long = System::currentTimeMillis,
) : ScreenCapture {
    private val lock = Any()

    /** Serializes captures: one frame at a time, so the display and reader cannot be raced. */
    private val captureLock = Any()

    private var projection: MediaProjection? = null
    private var callback: MediaProjection.Callback? = null
    private var display: VirtualDisplay? = null
    private var reader: ImageReader? = null
    private var frameThread: HandlerThread? = null

    /** The most recent frame the mirror produced, and when it was produced. */
    private var latest: Image? = null
    private var latestAtMs: Long = 0L

    override fun available(): Boolean = synchronized(lock) { projection != null }

    override fun accept(resultCode: Int, data: Intent?) {
        if (resultCode != Activity.RESULT_OK || data == null) return
        val manager = context.getSystemService(MediaProjectionManager::class.java) ?: return
        val acquired = try {
            manager.getMediaProjection(resultCode, data)
        } catch (_: RuntimeException) {
            // A refused or already-consumed token installs nothing; the command says so.
            null
        } ?: return
        val registered = object : MediaProjection.Callback() {
            override fun onStop() {
                // The user or the system ended the session. Forget the grant so the next
                // command answers consent_required instead of reusing a dead projection.
                synchronized(lock) {
                    if (projection !== acquired) return
                    projection = null
                    callback = null
                }
                // Cleanup waits for an in-flight capture, which is itself bounded by the
                // command budget, so nothing is left holding a dead projection.
                releaseTransient()
            }
        }
        try {
            acquired.registerCallback(registered, Handler(Looper.getMainLooper()))
        } catch (_: RuntimeException) {
            // Older platforms do not require a callback; a capture still works without it.
        }
        val previous = synchronized(lock) {
            val old = projection
            projection = acquired
            callback = registered
            old
        }
        stopQuietly(previous)
    }

    override fun capture(maxEncodedBytes: Int, timeoutMs: Long): CapturedFrame =
        synchronized(captureLock) {
            val active = synchronized(lock) { projection }
                ?: throw CommandFailure(ScreenHandler.CONSENT_REQUIRED, ScreenHandler.CONSENT_MESSAGE)
            val screen = metrics()
            if (screen.widthPixels <= 0 || screen.heightPixels <= 0 || screen.densityDpi <= 0) {
                throw CommandFailure("capture_failed", "the display size is not available")
            }
            framesFor(active, screen)
            awaitFirstFrame(timeoutMs)

            try {
                // Copy under the lock so the listener cannot close the image mid-copy;
                // encoding (the expensive part) happens outside it.
                val (bitmap, capturedAtMs) = synchronized(lock) {
                    val image = latest ?: throw CommandFailure(
                        "capture_timeout",
                        "no frame arrived within ${timeoutMs.coerceAtLeast(1)} ms",
                    )
                    image.toBitmap(screen.widthPixels, screen.heightPixels) to latestAtMs
                }
                val encoded = encodeWithinLimit(
                    screen.widthPixels,
                    screen.heightPixels,
                    maxEncodedBytes,
                ) { width, height ->
                    val scaled = if (width == bitmap.width && height == bitmap.height) {
                        bitmap
                    } else {
                        bitmap.scale(width, height)
                    }
                    scaled.toPng()
                }
                CapturedFrame(encoded.png, encoded.width, encoded.height, capturedAtMs)
            } catch (failure: CommandFailure) {
                throw failure
            } catch (_: RuntimeException) {
                throw CommandFailure("capture_failed", "the platform could not produce a frame")
            }
        }

    override fun release() {
        releaseTransient()
        val held = synchronized(lock) {
            val held = projection to callback
            projection = null
            callback = null
            held
        }
        val (projection, callback) = held
        if (callback != null && projection != null) {
            try {
                projection.unregisterCallback(callback)
            } catch (_: RuntimeException) {
                // Already unregistered.
            }
        }
        stopQuietly(projection)
    }

    /**
     * The one `VirtualDisplay` and `ImageReader` this grant may create, made on the first
     * capture and reused afterwards (Android 14 refuses a second display for the same token).
     * The listener keeps the newest frame so a later capture has one to return.
     */
    private fun framesFor(active: MediaProjection, screen: ScreenMetrics): ImageReader {
        reader?.let { return it }
        val frames = ImageReader.newInstance(
            screen.widthPixels,
            screen.heightPixels,
            PixelFormat.RGBA_8888,
            2,
        )
        val thread = HandlerThread(FRAME_THREAD_NAME).also { it.start() }
        frames.setOnImageAvailableListener(frameListener, Handler(thread.looper))
        val created = try {
            active.createVirtualDisplay(
                VIRTUAL_DISPLAY_NAME,
                screen.widthPixels,
                screen.heightPixels,
                screen.densityDpi,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                frames.surface,
                null,
                null,
            )
        } catch (_: SecurityException) {
            discard(frames, thread)
            // The grant ended between the command and the display: say so, do not pretend.
            synchronized(lock) {
                projection = null
                callback = null
            }
            throw CommandFailure(ScreenHandler.CONSENT_REQUIRED, ScreenHandler.CONSENT_MESSAGE)
        } catch (_: RuntimeException) {
            discard(frames, thread)
            throw CommandFailure("capture_failed", "the platform refused a virtual display")
        }
        if (created == null) {
            discard(frames, thread)
            throw CommandFailure("capture_failed", "the platform refused a virtual display")
        }
        reader = frames
        display = created
        frameThread = thread
        return frames
    }

    private val frameListener = ImageReader.OnImageAvailableListener { frames ->
        val next = try {
            frames.acquireLatestImage()
        } catch (_: RuntimeException) {
            null
        } ?: return@OnImageAvailableListener
        var previous: Image? = null
        val stale = synchronized(lock) {
            if (reader !== frames) {
                true
            } else {
                previous = latest
                latest = next
                latestAtMs = clock()
                false
            }
        }
        if (stale) {
            next.close()
        } else {
            previous?.close()
        }
    }

    /** Waits, bounded by [timeoutMs], for the mirror's first frame. */
    private fun awaitFirstFrame(timeoutMs: Long) {
        val bounded = timeoutMs.coerceAtLeast(1)
        val deadline = SystemClock.elapsedRealtime() + bounded
        while (true) {
            if (synchronized(lock) { latest != null }) return
            if (SystemClock.elapsedRealtime() >= deadline) {
                throw CommandFailure("capture_timeout", "no frame arrived within $bounded ms")
            }
            Thread.sleep(FRAME_POLL_MS)
        }
    }

    /** Releases the display, reader, frame thread, and cached frame; safe when nothing is held. */
    private fun releaseTransient() {
        val frames = synchronized(captureLock) {
            val held = reader
            reader = null
            held
        }
        frames?.setOnImageAvailableListener(null, null)
        val cached = synchronized(lock) {
            val held = latest
            latest = null
            held
        }
        cached?.close()
        val surface = synchronized(captureLock) {
            val held = display
            display = null
            held
        }
        if (surface != null) {
            try {
                surface.release()
            } catch (_: RuntimeException) {
                // Already released.
            }
        }
        if (frames != null) {
            try {
                frames.close()
            } catch (_: RuntimeException) {
                // Already closed.
            }
        }
        val thread = synchronized(captureLock) {
            val held = frameThread
            frameThread = null
            held
        }
        thread?.quitSafely()
    }

    private fun discard(frames: ImageReader, thread: HandlerThread) {
        frames.setOnImageAvailableListener(null, null)
        try {
            frames.close()
        } catch (_: RuntimeException) {
            // Already closed.
        }
        thread.quitSafely()
    }

    private fun stopQuietly(target: MediaProjection?) {
        if (target == null) return
        try {
            target.stop()
        } catch (_: RuntimeException) {
            // Already stopped.
        }
    }

    private fun Image.toBitmap(width: Int, height: Int): Bitmap {
        val plane = planes[0]
        val rowPadding = plane.rowStride - plane.pixelStride * width
        val paddedWidth = width + rowPadding / plane.pixelStride
        val padded = createBitmap(paddedWidth, height)
        // The cached image is read more than once, so its buffer is rewound first; a second
        // copy from a consumed buffer fails with "Buffer not large enough for pixels".
        val buffer = plane.buffer
        buffer.rewind()
        padded.copyPixelsFromBuffer(buffer)
        return if (paddedWidth == width) padded else Bitmap.createBitmap(padded, 0, 0, width, height)
    }

    private fun Bitmap.toPng(): ByteArray {
        val out = ByteArrayOutputStream()
        return try {
            compress(Bitmap.CompressFormat.PNG, 100, out)
            out.toByteArray()
        } finally {
            out.close()
        }
    }

    private companion object {
        const val VIRTUAL_DISPLAY_NAME = "PhoneConnect screen snapshot"
        const val FRAME_THREAD_NAME = "pc-screen-frames"
        const val FRAME_POLL_MS = 20L
    }
}

/** How far a frame may be downscaled by whole factors before the answer is `result_too_large`. */
internal const val MAX_DOWNSCALE_FACTOR: Int = 16

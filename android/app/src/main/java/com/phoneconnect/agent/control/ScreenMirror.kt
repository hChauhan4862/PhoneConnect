package com.phoneconnect.agent.control

import android.graphics.Bitmap
import android.graphics.PixelFormat
import android.hardware.display.DisplayManager
import android.hardware.display.VirtualDisplay
import android.media.Image
import android.media.ImageReader
import android.media.projection.MediaProjection
import android.os.Handler
import android.os.HandlerThread
import android.os.Looper
import androidx.core.graphics.createBitmap

/** One mirrored frame as pixels, and when the mirror produced it. */
internal class MirrorFrame(val bitmap: Bitmap, val capturedAtMs: Long)

/**
 * A mirrored surface for one projection: the virtual display plus the newest frame it produced.
 *
 * A capture copies [newestFrame] on demand, so a screen that has not changed still yields its
 * last frame instead of a timeout, and the size it reports is the size the platform really
 * produced — never a size assumed from the current display metrics.
 */
internal interface ScreenMirror {
    /** The surface size this mirror was created with. */
    val width: Int
    val height: Int

    /** False once [close] ran; a capture waiting for a frame must stop instead of waiting on. */
    val open: Boolean

    /** A copy of the newest frame, or `null` while none has arrived. */
    fun newestFrame(): MirrorFrame?

    /** Releases the display, the reader, the frame thread, and the cached frame. */
    fun close()
}

/**
 * The projection a capture draws from, so the lifecycle is testable without a real
 * `MediaProjection`.
 *
 * [onEnded] is invoked when the projection ends without the app asking (the user stopped
 * sharing, the screen was locked, or the system ended the session).
 */
internal interface MirrorSource {
    fun open(screen: ScreenMetrics): ScreenMirror

    /** Ends the projection, if it is still alive. Idempotent. */
    fun stop()
}

/**
 * The production mirror: `MediaProjection` + `VirtualDisplay` + `ImageReader`.
 *
 * The reader, its frame thread, and its listener exist before the display is created, so a
 * frame the platform delivers while `createVirtualDisplay` is still running is kept rather than
 * being treated as stale. The copy uses the image's own dimensions, so a display at a previous
 * size or orientation can never produce a negative row padding or a silently cropped frame.
 */
internal class MediaProjectionMirror(
    private val projection: MediaProjection,
    override val width: Int,
    override val height: Int,
    private val densityDpi: Int,
    private val clock: () -> Long = System::currentTimeMillis,
) : ScreenMirror {
    private val lock = Any()
    private val frames: ImageReader =
        ImageReader.newInstance(width, height, PixelFormat.RGBA_8888, MAX_IMAGES)
    private val thread = HandlerThread(FRAME_THREAD_NAME).also { it.start() }

    private var display: VirtualDisplay? = null
    private var latest: Image? = null
    private var latestAtMs: Long = 0L

    @Volatile
    override var open: Boolean = true
        private set

    /** Creates the display. Called once, right after construction; throws when refused. */
    fun start(): ScreenMirror {
        // The listener exists before the display does, so a frame delivered while
        // `createVirtualDisplay` is still running is cached rather than treated as stale.
        frames.setOnImageAvailableListener(frameListener, Handler(thread.looper))
        val created = try {
            projection.createVirtualDisplay(
                VIRTUAL_DISPLAY_NAME,
                width,
                height,
                densityDpi,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                frames.surface,
                null,
                null,
            )
        } catch (failure: RuntimeException) {
            close()
            throw failure
        }
        if (created == null) {
            close()
            throw IllegalStateException("the platform refused a virtual display")
        }
        synchronized(lock) { display = created }
        return this
    }

    override fun newestFrame(): MirrorFrame? = synchronized(lock) {
        val image = latest ?: return null
        MirrorFrame(image.toBitmap(), latestAtMs)
    }

    override fun close() {
        open = false
        frames.setOnImageAvailableListener(null, null)
        val cached = synchronized(lock) {
            val held = latest
            latest = null
            held
        }
        cached?.close()
        val surface = synchronized(lock) {
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
        try {
            frames.close()
        } catch (_: RuntimeException) {
            // Already closed.
        }
        thread.quitSafely()
    }

    private val frameListener = ImageReader.OnImageAvailableListener { reader ->
        val next = try {
            reader.acquireLatestImage()
        } catch (_: RuntimeException) {
            null
        } ?: return@OnImageAvailableListener
        var previous: Image? = null
        val stale = synchronized(lock) {
            if (open) {
                previous = latest
                latest = next
                latestAtMs = clock()
                false
            } else {
                true
            }
        }
        if (stale) {
            next.close()
        } else {
            previous?.close()
        }
    }

    /** The image's own size is the frame's size; nothing is assumed from current metrics. */
    private fun Image.toBitmap(): Bitmap {
        val plane = planes[0]
        val imageWidth = this.width
        val imageHeight = this.height
        val rowPadding = plane.rowStride - plane.pixelStride * imageWidth
        val paddedWidth = imageWidth + rowPadding / plane.pixelStride
        val padded = createBitmap(paddedWidth, imageHeight)
        // The cached image is read more than once, so its buffer is rewound first; a second
        // copy from a consumed buffer fails with "Buffer not large enough for pixels".
        val buffer = plane.buffer
        buffer.rewind()
        padded.copyPixelsFromBuffer(buffer)
        return if (paddedWidth == imageWidth) {
            padded
        } else {
            Bitmap.createBitmap(padded, 0, 0, imageWidth, imageHeight)
        }
    }

    private companion object {
        const val VIRTUAL_DISPLAY_NAME = "PhoneConnect screen snapshot"
        const val FRAME_THREAD_NAME = "pc-screen-frames"
        const val MAX_IMAGES = 2
    }
}

/**
 * The projection behind a mirror: registered with an end callback before any display is
 * created (required from Android 14), and stopped exactly once when the grant is released.
 */
internal class MediaProjectionMirrorSource(
    private val projection: MediaProjection,
    private val clock: () -> Long,
    private val onEnded: () -> Unit,
) : MirrorSource {
    private val callback = object : MediaProjection.Callback() {
        override fun onStop() = onEnded()
    }
    private var stopped = false

    init {
        try {
            projection.registerCallback(callback, Handler(Looper.getMainLooper()))
        } catch (_: RuntimeException) {
            // Older platforms do not require a callback; a capture still works without it.
        }
    }

    override fun open(screen: ScreenMetrics): ScreenMirror =
        MediaProjectionMirror(
            projection = projection,
            width = screen.widthPixels,
            height = screen.heightPixels,
            densityDpi = screen.densityDpi,
            clock = clock,
        ).start()

    override fun stop() {
        if (stopped) return
        stopped = true
        try {
            projection.unregisterCallback(callback)
        } catch (_: RuntimeException) {
            // Already unregistered.
        }
        try {
            projection.stop()
        } catch (_: RuntimeException) {
            // Already stopped.
        }
    }
}

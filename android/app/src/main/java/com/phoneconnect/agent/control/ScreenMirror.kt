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
    /** The surface size the mirror is currently capturing. */
    val width: Int
    val height: Int

    /** False once [close] ran; a capture waiting for a frame must stop instead of waiting on. */
    val open: Boolean

    /** A copy of the newest frame, or `null` while none has arrived. */
    fun newestFrame(): MirrorFrame?

    /**
     * Captures [screen] instead of the current size: a new reader at that size becomes the
     * display's surface and the existing display is resized. False when the platform refuses,
     * in which case the mirror is unusable and the caller retires the grant.
     */
    fun resize(screen: ScreenMetrics): Boolean

    /** Releases the display, the reader, the frame thread, and the cached frame. */
    fun close()
}

/**
 * The projection a capture draws from, so the lifecycle is testable without a real
 * `MediaProjection`.
 */
internal interface MirrorSource {
    fun open(screen: ScreenMetrics): ScreenMirror

    /** Ends the projection, if it is still alive. Idempotent. */
    fun stop()

    /** Called when the projection ends without the app asking (the user stopped sharing, …). */
    fun onEnded(listener: () -> Unit)

    /** Called when the captured content changes size (Android 14+, `onCapturedContentResize`). */
    fun onContentResized(listener: (width: Int, height: Int) -> Unit)
}

/**
 * The production mirror: `MediaProjection` + `VirtualDisplay` + `ImageReader`.
 *
 * The reader, its frame thread, and its listener exist before the display is created, so a
 * frame the platform delivers while `createVirtualDisplay` is still running is kept rather than
 * being treated as stale. The copy uses the image's own dimensions, so a display at a previous
 * size or orientation can never produce a negative row padding or a silently cropped frame.
 *
 * A size change keeps the grant: a token cannot create a second display, but the one it already
 * owns can be resized ([VirtualDisplay.resize]) and pointed at a new surface
 * ([VirtualDisplay.setSurface]). That is what [resize] does.
 */
internal class MediaProjectionMirror(
    private val projection: MediaProjection,
    initial: ScreenMetrics,
    private val clock: () -> Long = System::currentTimeMillis,
) : ScreenMirror {
    private val lock = Any()
    private val thread = HandlerThread(FRAME_THREAD_NAME).also { it.start() }

    @Volatile
    override var width: Int = initial.widthPixels
        private set

    @Volatile
    override var height: Int = initial.heightPixels
        private set

    @Volatile
    private var densityDpi: Int = initial.densityDpi

    private val frameListener = ImageReader.OnImageAvailableListener { reader ->
        val next = try {
            reader.acquireLatestImage()
        } catch (_: RuntimeException) {
            null
        } ?: return@OnImageAvailableListener
        var previous: Image? = null
        val stale = synchronized(lock) {
            if (!open || frames !== reader) {
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

    private var frames: ImageReader = newReader(initial)
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

    override fun resize(screen: ScreenMetrics): Boolean {
        if (screen.widthPixels == width &&
            screen.heightPixels == height &&
            screen.densityDpi == densityDpi
        ) {
            return true
        }
        val surface = synchronized(lock) { if (open) display else null } ?: return false
        val replacement = try {
            newReader(screen)
        } catch (_: RuntimeException) {
            return false
        }
        // The new reader becomes the one whose frames are kept before the display is pointed at
        // it: a frame arriving right after `setSurface` must not be dropped as stale.
        val previous = synchronized(lock) {
            val held = frames
            frames = replacement
            held
        }
        try {
            surface.setSurface(replacement.surface)
            surface.resize(screen.widthPixels, screen.heightPixels, screen.densityDpi)
        } catch (_: RuntimeException) {
            // The display may already point at the replacement surface, so this mirror cannot be
            // trusted; the caller retires the grant and closes everything.
            synchronized(lock) { if (frames === replacement) frames = previous }
            replacement.setOnImageAvailableListener(null, null)
            replacement.close()
            return false
        }
        val cached = synchronized(lock) {
            width = screen.widthPixels
            height = screen.heightPixels
            densityDpi = screen.densityDpi
            val held = latest
            latest = null
            latestAtMs = 0
            held
        }
        cached?.close()
        previous.setOnImageAvailableListener(null, null)
        previous.close()
        return true
    }

    override fun newestFrame(): MirrorFrame? = synchronized(lock) {
        if (!open) return null
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

    private fun newReader(screen: ScreenMetrics): ImageReader =
        ImageReader.newInstance(
            screen.widthPixels,
            screen.heightPixels,
            PixelFormat.RGBA_8888,
            MAX_IMAGES,
        ).also { reader ->
            reader.setOnImageAvailableListener(frameListener, Handler(thread.looper))
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
 * The projection behind a mirror: registered with its end and size callbacks before any display
 * is created (the callback is required from Android 14), and stopped exactly once when the grant
 * is released.
 */
internal class MediaProjectionMirrorSource(
    private val projection: MediaProjection,
    private val clock: () -> Long,
) : MirrorSource {
    @Volatile
    private var ended: (() -> Unit)? = null

    @Volatile
    private var resized: ((width: Int, height: Int) -> Unit)? = null

    @Volatile
    private var stopped = false

    private val callback = object : MediaProjection.Callback() {
        override fun onStop() {
            ended?.invoke()
        }

        // Android 14+: the captured content changed size (rotation, fold, resolution change).
        override fun onCapturedContentResize(width: Int, height: Int) {
            resized?.invoke(width, height)
        }
    }

    init {
        try {
            projection.registerCallback(callback, Handler(Looper.getMainLooper()))
        } catch (_: RuntimeException) {
            // Older platforms do not require a callback; a capture still works without it.
        }
    }

    override fun open(screen: ScreenMetrics): ScreenMirror =
        MediaProjectionMirror(projection = projection, initial = screen, clock = clock).start()

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

    override fun onEnded(listener: () -> Unit) {
        ended = listener
    }

    override fun onContentResized(listener: (width: Int, height: Int) -> Unit) {
        resized = listener
    }
}

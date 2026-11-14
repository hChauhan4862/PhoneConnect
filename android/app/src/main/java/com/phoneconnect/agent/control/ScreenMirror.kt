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
 * Which frame reader is installed, and whether the mirror can still capture.
 *
 * Swapping a reader, closing the mirror, and the "the mirror closed while a resize was still
 * talking to the platform" race are decided here, on plain values, so the caller always knows
 * exactly which reader it still owns and which one it must close. A reader that is returned by
 * [install] was never installed and must be closed by the caller; one returned by [detach] was
 * installed and must be closed by the caller. Nothing here closes anything itself, so a test can
 * count how many times each reader is released.
 */
internal class ReaderSlot<R : Any>(initial: R) {
    private var current: R? = initial

    var open: Boolean = true
        private set

    /** The installed reader, or `null` once the slot is closed. */
    fun installed(): R? = current

    /**
     * Installs [replacement]. Returns the reader the caller must close: the previous one when the
     * swap happened, or [replacement] itself when the slot is already closed (it stays
     * uninstalled, so closing it is the caller's only duty).
     */
    fun install(replacement: R): R {
        if (!open) return replacement
        val previous = current ?: return replacement
        current = replacement
        return previous
    }

    /** Closes the slot and returns the installed reader, once. */
    fun detach(): R? {
        open = false
        val held = current
        current = null
        return held
    }
}

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
            if (!slot.open || slot.installed() !== reader) {
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

    private val slot: ReaderSlot<ImageReader> = ReaderSlot(newReader(initial))
    private var display: VirtualDisplay? = null
    private var latest: Image? = null
    private var latestAtMs: Long = 0L

    /** True while the reader slot is live; [ReaderSlot.detach] is the single place it ends. */
    override val open: Boolean
        get() = slot.open

    /** Creates the display. Called once, right after construction; throws when refused. */
    fun start(): ScreenMirror {
        // The listener exists before the display does, so a frame delivered while
        // `createVirtualDisplay` is still running is cached rather than treated as stale.
        val initialFrames = slot.installed()
            ?: throw IllegalStateException("the mirror was closed before its display was created")
        val created = try {
            projection.createVirtualDisplay(
                VIRTUAL_DISPLAY_NAME,
                width,
                height,
                densityDpi,
                DisplayManager.VIRTUAL_DISPLAY_FLAG_AUTO_MIRROR,
                initialFrames.surface,
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
        val surface = synchronized(lock) { if (slot.open) display else null } ?: return false
        val replacement = try {
            newReader(screen)
        } catch (_: RuntimeException) {
            return false
        }
        // The replacement is published only after the platform accepted both calls. A reader
        // that was never installed is closed here, so a close() racing this resize can never
        // orphan the reader that was installed before it.
        try {
            surface.setSurface(replacement.surface)
            surface.resize(screen.widthPixels, screen.heightPixels, screen.densityDpi)
        } catch (_: RuntimeException) {
            replacement.detachAndClose()
            return false
        }
        var previous: ImageReader? = null
        var cached: Image? = null
        val published = synchronized(lock) {
            if (!slot.open) {
                false
            } else {
                width = screen.widthPixels
                height = screen.heightPixels
                densityDpi = screen.densityDpi
                previous = slot.install(replacement)
                cached = latest
                latest = null
                latestAtMs = 0
                true
            }
        }
        if (!published) {
            // The mirror closed while the platform was being resized: the replacement was never
            // installed, and close() already released whatever had been.
            replacement.detachAndClose()
            return false
        }
        if (previous !== replacement) {
            previous?.detachAndClose()
        }
        cached?.close()
        return true
    }

    override fun newestFrame(): MirrorFrame? = synchronized(lock) {
        if (!slot.open) return null
        val image = latest ?: return null
        MirrorFrame(image.toBitmap(), latestAtMs)
    }

    override fun close() {
        val (readers, frame, surface) = synchronized(lock) {
            val heldReaders = slot.detach()
            val heldFrame = latest
            latest = null
            val heldSurface = display
            display = null
            Triple(heldReaders, heldFrame, heldSurface)
        }
        readers?.detachAndClose()
        frame?.close()
        if (surface != null) {
            try {
                surface.release()
            } catch (_: RuntimeException) {
                // Already released.
            }
        }
        thread.quitSafely()
    }

    private fun ImageReader.detachAndClose() {
        setOnImageAvailableListener(null, null)
        try {
            close()
        } catch (_: RuntimeException) {
            // Already closed.
        }
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

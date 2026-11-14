package com.phoneconnect.agent.control

import android.app.Activity
import android.content.Context
import android.content.Intent
import android.graphics.Bitmap
import android.media.projection.MediaProjectionManager
import android.os.SystemClock
import androidx.core.graphics.scale
import java.io.ByteArrayOutputStream
import java.util.concurrent.Executor
import java.util.concurrent.Executors

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
 * `screen.snapshot`'s platform half: one frame through `MediaProjection` + a mirrored surface,
 * PNG-encoded and downscaled to fit the result budget.
 *
 * The projection is acquired only from a grant the user made on the setup screen. It is held
 * for the service lifetime: Android cannot persist a projection token across process death, and
 * a new grant would need another user action.
 *
 * One mirror serves the whole grant. That is a platform requirement, not a shortcut: from
 * Android 14 a token may create one virtual display, and calling `createVirtualDisplay` again
 * after the display was released logs `Reusing token: Throw exception due to invalid
 * projection` and stops the projection. A size change (rotation, fold, resolution change) keeps
 * the grant: the display the token already owns is resized and pointed at a `ImageReader` of the
 * new size, which is exactly what `VirtualDisplay.resize`/`setSurface` are for. The platform's
 * `onCapturedContentResize` callback triggers the same path, and the next capture compares the
 * mirror against the current metrics as a fallback. The grant is retired only if the resize
 * genuinely fails. Everything is released on every stop path — user stop, service stop, system
 * stop — on one process-wide teardown worker, never on the caller's thread.
 */
internal class MediaProjectionScreenCapture(
    private val context: Context,
    private val metrics: () -> ScreenMetrics = { ScreenMetrics.from(context) },
    private val clock: () -> Long = System::currentTimeMillis,
    private val teardown: Executor = defaultTeardown(),
    private val openSource: ((resultCode: Int, data: Intent) -> MirrorSource?)? = null,
) : ScreenCapture {
    private val lock = Any()

    /** Serializes captures: one frame at a time, so a mirror cannot be raced. */
    private val captureLock = Any()

    private var source: MirrorSource? = null
    private var mirror: ScreenMirror? = null
    private var endedCallback: (() -> Unit)? = null

    /**
     * Identifies the grant the callbacks belong to. A platform end or resize from a grant that
     * has since been replaced must not touch the newer grant.
     */
    private var generation: Long = 0

    override fun available(): Boolean = synchronized(lock) { source != null }

    override fun accept(resultCode: Int, data: Intent?, onEnded: () -> Unit) {
        if (resultCode != Activity.RESULT_OK || data == null) return
        val opened = try {
            (openSource ?: ::openProductionSource)(resultCode, data)
        } catch (_: RuntimeException) {
            // A refused or already-consumed token installs nothing; the command says so.
            null
        } ?: return
        // A new grant replaces the old one completely: its mirror and cached frame must not
        // survive, or the new grant would return frozen frames.
        val grant: Long
        val previous: Pair<MirrorSource?, ScreenMirror?>
        synchronized(lock) {
            generation += 1
            grant = generation
            previous = source to mirror
            source = opened
            mirror = null
            endedCallback = onEnded
        }
        opened.onEnded { handleEnded(grant) }
        opened.onContentResized { width, height -> handleContentResized(grant, width, height) }
        releaseLater(previous.first, previous.second)
    }

    override fun capture(maxEncodedBytes: Int, timeoutMs: Long): CapturedFrame =
        synchronized(captureLock) {
            val active = synchronized(lock) { source }
                ?: throw CommandFailure(ScreenHandler.CONSENT_REQUIRED, ScreenHandler.CONSENT_MESSAGE)
            val screen = metrics()
            if (screen.widthPixels <= 0 || screen.heightPixels <= 0 || screen.densityDpi <= 0) {
                throw CommandFailure("capture_failed", "the display size is not available")
            }
            val frames = mirrorFor(active, screen)
            val frame = awaitFrame(frames, timeoutMs)
            try {
                val bitmap = frame.bitmap
                val encoded = encodeWithinLimit(bitmap.width, bitmap.height, maxEncodedBytes) { width, height ->
                    val scaled = if (width == bitmap.width && height == bitmap.height) {
                        bitmap
                    } else {
                        bitmap.scale(width, height)
                    }
                    scaled.toPng()
                }
                CapturedFrame(encoded.png, encoded.width, encoded.height, frame.capturedAtMs)
            } catch (failure: CommandFailure) {
                throw failure
            } catch (_: RuntimeException) {
                throw CommandFailure("capture_failed", "the platform could not produce a frame")
            }
        }

    override fun release() {
        // An explicit release is not a system stop: every caller already reports the new state
        // (`ConnectionService` clears the mirror on stop, revoke, and destroy), so only the
        // resources are released here.
        val (previousSource, previousMirror) = detach()
        releaseLater(previousSource, previousMirror)
    }

    /**
     * The mirror for this grant, created once. A token cannot create a second display, but the
     * one it owns can be resized, so a size change keeps the grant; only a refused resize ends
     * it rather than returning a frame at the wrong size.
     */
    private fun mirrorFor(active: MirrorSource, screen: ScreenMetrics): ScreenMirror {
        val existing = synchronized(lock) { mirror }
        if (existing != null) {
            if (!existing.open) {
                // The mirror was closed under us: the projection is over, not a size problem.
                discardGrant()
                throw CommandFailure(ScreenHandler.CONSENT_REQUIRED, ScreenHandler.CONSENT_MESSAGE)
            }
            if (existing.width == screen.widthPixels && existing.height == screen.heightPixels) {
                return existing
            }
            // The token cannot create a second display, but the one it owns can be resized: a
            // rotation must not cost the user another system consent dialog.
            if (existing.resize(screen)) {
                return existing
            }
            discardGrant()
            throw CommandFailure(ScreenHandler.CONSENT_REQUIRED, SIZE_CHANGED_MESSAGE)
        }
        val created = try {
            active.open(screen)
        } catch (_: SecurityException) {
            discardGrant()
            throw CommandFailure(ScreenHandler.CONSENT_REQUIRED, ScreenHandler.CONSENT_MESSAGE)
        } catch (_: RuntimeException) {
            throw CommandFailure("capture_failed", "the platform refused a virtual display")
        }
        val raced = synchronized(lock) {
            // `handleEnded` may have cleared the source while the display was being created.
            if (source === active) {
                mirror = created
                null
            } else {
                created
            }
        }
        if (raced != null) {
            raced.close()
            throw CommandFailure(ScreenHandler.CONSENT_REQUIRED, ScreenHandler.CONSENT_MESSAGE)
        }
        return created
    }

    /** Waits, bounded by [timeoutMs], for a frame; a closed mirror stops the wait immediately. */
    private fun awaitFrame(frames: ScreenMirror, timeoutMs: Long): MirrorFrame {
        val bounded = timeoutMs.coerceAtLeast(1)
        val deadline = SystemClock.elapsedRealtime() + bounded
        while (true) {
            frames.newestFrame()?.let { return it }
            if (!frames.open) {
                throw CommandFailure("capture_failed", "the projection ended before a frame arrived")
            }
            if (SystemClock.elapsedRealtime() >= deadline) {
                throw CommandFailure("capture_timeout", "no frame arrived within $bounded ms")
            }
            Thread.sleep(FRAME_POLL_MS)
        }
    }

    /** The projection ended without the app asking: forget the grant and tell the owner. */
    private fun handleEnded(grant: Long) {
        var endedSource: MirrorSource? = null
        var held: ScreenMirror? = null
        var ended: (() -> Unit)? = null
        synchronized(lock) {
            // A late end from a grant that has already been replaced must not retire the new
            // one — the new grant is still live, and the old source was stopped when replaced.
            if (generation != grant) return
            generation += 1
            endedSource = source
            held = mirror
            ended = endedCallback
            source = null
            mirror = null
            endedCallback = null
        }
        // Not the caller's thread: `onStop` arrives on the main looper, and closing a mirror can
        // wait on a capture that is already running. Stopping is idempotent, so a projection the
        // system already ended is unregistered and stopped again without effect.
        releaseLater(endedSource, held)
        ended?.invoke()
    }

    /**
     * The platform reported the captured content's new size. Resizing happens on the teardown
     * worker so the platform callback thread is never blocked, and a capture in flight finishes
     * before the surface is swapped.
     */
    private fun handleContentResized(grant: Long, width: Int, height: Int) {
        if (width <= 0 || height <= 0) return
        val current = synchronized(lock) {
            if (generation != grant) return
            mirror
        } ?: return
        if (current.width == width && current.height == height) return
        teardown.execute {
            synchronized(captureLock) {
                if (!current.open) return@synchronized
                if (!current.resize(ScreenMetrics(width, height, metrics().densityDpi))) {
                    discardGrant()
                    return@synchronized
                }
            }
        }
    }

    /** Drops the current grant because its mirror can no longer answer for this screen. */
    private fun discardGrant() {
        var previousSource: MirrorSource? = null
        var previousMirror: ScreenMirror? = null
        var ended: (() -> Unit)? = null
        synchronized(lock) {
            // Any callback still in flight from this grant is now stale.
            generation += 1
            previousSource = source
            previousMirror = mirror
            ended = endedCallback
            source = null
            mirror = null
            endedCallback = null
        }
        releaseLater(previousSource, previousMirror)
        ended?.invoke()
    }

    private fun detach(): Pair<MirrorSource?, ScreenMirror?> =
        synchronized(lock) {
            val held = source to mirror
            source = null
            mirror = null
            endedCallback = null
            held
        }

    private fun releaseLater(source: MirrorSource?, mirror: ScreenMirror?) {
        if (source == null && mirror == null) return
        teardown.execute {
            mirror?.close()
            source?.stop()
        }
    }

    private fun openProductionSource(resultCode: Int, data: Intent): MirrorSource? {
        val manager = context.getSystemService(MediaProjectionManager::class.java) ?: return null
        val projection = try {
            manager.getMediaProjection(resultCode, data)
        } catch (_: RuntimeException) {
            null
        } ?: return null
        return MediaProjectionMirrorSource(projection = projection, clock = clock)
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

    companion object {
        /** A screen size change cannot reuse the grant's one virtual display. */
        const val SIZE_CHANGED_MESSAGE =
            "the screen size changed since capture was enabled, so the projection cannot mirror " +
                "it; enable screen capture again on the device"

        /** How long a capture waits between checks for the first frame. */
        const val FRAME_POLL_MS: Long = 20

        private fun defaultTeardown(): Executor = ScreenTeardown
    }
}

/** How far a frame may be downscaled by whole factors before the answer is `result_too_large`. */
internal const val MAX_DOWNSCALE_FACTOR: Int = 16

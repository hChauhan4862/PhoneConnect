package com.phoneconnect.agent.crypto

/**
 * Bounded replay window for authenticated frames.
 *
 * A strict high-water mark would turn a legitimate UDP reorder into a fatal regression, so a
 * counter is accepted when it has not been seen and is within [WINDOW] of the highest frame.
 * A repeat is reported as [Replayed]; a counter below the window as [CounterRegression], so
 * a caller can tell a reorder from a fatal regression. Same arithmetic as
 * `crates/transport/src/aead.rs`.
 */
class ReplayWindow {
    private var highest: Long? = null
    private var seen: Long = 0

    /** Highest counter accepted so far, for callers that need to report a regression. */
    fun highestSeen(): Long? = highest

    fun accept(counter: Long): Result<Unit> = runCatching {
        val highest = highest
        when {
            highest == null -> {
                this.highest = counter
                seen = 1
            }

            counter > highest -> {
                val shift = counter - highest
                seen = if (shift >= WINDOW) 1L else (seen shl shift.toInt()) or 1L
                this.highest = counter
            }

            else -> {
                val offset = highest - counter
                if (offset >= WINDOW) {
                    throw SealedError.CounterRegression(counter, highest)
                }
                val bit = 1L shl offset.toInt()
                if (seen and bit != 0L) {
                    throw SealedError.Replayed(counter)
                }
                seen = seen or bit
            }
        }
    }

    /** True when a frame at [counter] would still be acceptable; never records it. */
    fun wouldAccept(counter: Long): Boolean {
        val highest = highest ?: return true
        return counter > highest || highest - counter < WINDOW
    }

    companion object {
        const val WINDOW: Long = 64
    }
}

package com.phoneconnect.agent

import kotlin.random.Random

/**
 * Bounded exponential backoff with symmetric jitter.
 *
 * Delay for attempt `n` is `base * 2^(n-1)`, capped at [maxDelayMs], then jittered by
 * ±[jitterRatio] so a fleet that lost the same server does not reconnect in lockstep. The
 * jittered value is clamped into `1..maxDelayMs`, so a delay is always positive and never
 * exceeds the cap.
 */
class ReconnectPolicy(
    private val baseDelayMs: Long = DEFAULT_BASE_DELAY_MS,
    private val maxDelayMs: Long = DEFAULT_MAX_DELAY_MS,
    private val jitterRatio: Double = DEFAULT_JITTER_RATIO,
    private val random: () -> Double = { Random.nextDouble() },
) {
    init {
        require(baseDelayMs >= 1) { "base delay must be positive, was $baseDelayMs" }
        require(maxDelayMs >= baseDelayMs) { "cap $maxDelayMs must be at least the base $baseDelayMs" }
        require(jitterRatio in 0.0..1.0) { "jitter must be a fraction, was $jitterRatio" }
    }

    /**
     * Delay before retry number [attempt] (1-based) for [reason]; the reason is part of the
     * contract so callers cannot forget which failure they are backing off from. A non-positive attempt is
     * treated as the first retry: a caller that lost its counter still waits the base delay
     * instead of hammering the server.
     */
    fun nextDelay(attempt: Int, reason: ReconnectReason): Long {
        val exponent = (attempt.coerceAtLeast(1) - 1).coerceAtMost(MAX_EXPONENT)
        val raw = if (baseDelayMs > (Long.MAX_VALUE shr exponent)) {
            maxDelayMs
        } else {
            (baseDelayMs shl exponent).coerceAtMost(maxDelayMs)
        }
        // Every retryable reason shares this bound: the reason travels separately to the
        // status surface, and one policy is easier to reason about than four.
        val jitter = jitterRatio * (random().coerceIn(0.0, 1.0) * 2.0 - 1.0)
        return (raw * (1.0 + jitter)).toLong().coerceIn(1L, maxDelayMs)
    }

    companion object {
        const val DEFAULT_BASE_DELAY_MS: Long = 1_000
        const val DEFAULT_MAX_DELAY_MS: Long = 60_000
        const val DEFAULT_JITTER_RATIO: Double = 0.2

        /** Shifting a `Long` past this is already far above any sane cap. */
        private const val MAX_EXPONENT = 40
    }
}

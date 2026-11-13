package com.phoneconnect.agent

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class ReconnectPolicyTest {
    private val policy = ReconnectPolicy(random = { 0.5 })

    @Test
    fun `the first retry waits the base delay`() {
        assertEquals(
            ReconnectPolicy.DEFAULT_BASE_DELAY_MS,
            policy.nextDelay(1, ReconnectReason.TRANSPORT_CLOSED),
        )
    }

    @Test
    fun `each attempt doubles the delay`() {
        val delays = (1..4).map { policy.nextDelay(it, ReconnectReason.SERVER_UNREACHABLE) }

        assertEquals(listOf(1_000L, 2_000L, 4_000L, 8_000L), delays)
    }

    @Test
    fun `the delay is capped no matter how many attempts failed`() {
        for (attempt in 7..10_000 step 97) {
            assertEquals(
                "attempt $attempt must stay at the cap",
                ReconnectPolicy.DEFAULT_MAX_DELAY_MS,
                policy.nextDelay(attempt, ReconnectReason.NETWORK_UNAVAILABLE),
            )
        }
    }

    @Test
    fun `jitter is symmetric and never escapes the band or the cap`() {
        val lowest = ReconnectPolicy(random = { 0.0 })
        val highest = ReconnectPolicy(random = { 1.0 })
        val base = ReconnectPolicy.DEFAULT_BASE_DELAY_MS

        assertEquals(800L, lowest.nextDelay(1, ReconnectReason.TRANSPORT_CLOSED))
        assertEquals(1_200L, highest.nextDelay(1, ReconnectReason.TRANSPORT_CLOSED))

        for (attempt in 1..80) {
            val low = lowest.nextDelay(attempt, ReconnectReason.TRANSPORT_CLOSED)
            val high = highest.nextDelay(attempt, ReconnectReason.TRANSPORT_CLOSED)

            assertTrue("a delay must always be positive, got $low", low >= 1)
            assertTrue("a delay must never exceed the cap, got $high", high <= ReconnectPolicy.DEFAULT_MAX_DELAY_MS)
            assertTrue("jitter must not invert the ordering at attempt $attempt", low <= high)
        }
    }

    @Test
    fun `a missing attempt count still waits the base delay instead of skipping it`() {
        assertEquals(
            ReconnectPolicy.DEFAULT_BASE_DELAY_MS,
            policy.nextDelay(0, ReconnectReason.TRANSPORT_CLOSED),
        )
        assertEquals(
            ReconnectPolicy.DEFAULT_BASE_DELAY_MS,
            policy.nextDelay(-3, ReconnectReason.TRANSPORT_CLOSED),
        )
    }

    @Test
    fun `only a dead credential stops the agent while a dead session retries`() {
        // Terminal means the agent stops. Only the two credential failures qualify: every
        // other failure leaves the enrollment usable and must resume on a new session, or a
        // routine lease revocation would take the phone offline until reboot.
        assertTrue(ConnectionFailure.DeviceRevoked.isTerminal)
        assertTrue(ConnectionFailure.NotEnrolled.isTerminal)
        assertFalse(ConnectionFailure.RelayUnavailable.isTerminal)
        assertFalse(ConnectionFailure.SessionEnded.isTerminal)
        assertFalse(ConnectionFailure.Retryable(ReconnectReason.TRANSPORT_CLOSED).isTerminal)

        assertEquals(Invalidation.ENROLLMENT, ConnectionFailure.DeviceRevoked.invalidation)
        assertEquals(Invalidation.ENROLLMENT, ConnectionFailure.NotEnrolled.invalidation)
        // The session id is not persisted, so ending the loop is the whole invalidation.
        assertEquals(Invalidation.NONE, ConnectionFailure.RelayUnavailable.invalidation)
        assertEquals(Invalidation.NONE, ConnectionFailure.SessionEnded.invalidation)

        // A session-end retries with its own reason so the status surface can say why.
        assertEquals(ReconnectReason.SESSION_ENDED, ConnectionFailure.SessionEnded.retryReason)
        assertEquals(ReconnectReason.SESSION_ENDED, ConnectionFailure.RelayUnavailable.retryReason)
        assertEquals(
            ReconnectReason.TICKET_EXPIRED,
            ConnectionFailure.Retryable(ReconnectReason.TICKET_EXPIRED).retryReason,
        )
        assertEquals(null, ConnectionFailure.DeviceRevoked.retryReason)
        assertEquals(null, ConnectionFailure.NotEnrolled.retryReason)
    }
}

package com.phoneconnect.agent

import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.isActive
import kotlinx.coroutines.withTimeoutOrNull

/** How one session attempt ended. */
sealed interface SessionEnd {
    /** The attempt was cancelled (the service stopped); nothing to retry. */
    data object Cancelled : SessionEnd

    data class Failed(val failure: ConnectionFailure) : SessionEnd
}

/**
 * Runs one session attempt end to end: opens the enrollment's identity, establishes the
 * authenticated channel, reports the selected path through [onConnected] once the session
 * is healthy, and returns when the attempt ends.
 *
 * Implementations are the transport/identity boundary: they are the only production code
 * that opens a [DeviceIdentity].
 */
fun interface SessionRunner {
    suspend fun run(store: EnrollmentStore, onConnected: (ConnectionPath) -> Unit): SessionEnd
}

/** Why the connection loop stopped. */
sealed interface SupervisorOutcome {
    data object Unenrolled : SupervisorOutcome

    data object Cancelled : SupervisorOutcome

    data class Terminal(val failure: ConnectionFailure) : SupervisorOutcome
}

/**
 * Owns the reconnect loop: one session at a time, bounded exponential backoff with jitter,
 * a reset after a healthy connection, and an explicit terminal class that stops retrying
 * and applies the failure's [Invalidation]. A session that ended (expiry, close, revoked
 * lease, relay 409) is not terminal: the loop waits out its backoff and awaits a new
 * session, so a routine revocation never stops the agent.
 *
 * A network-available callback wakes the backoff wait, so recovery does not have to sit
 * out a delay that was chosen before the network returned.
 */
class ConnectionSupervisor(
    private val store: EnrollmentStore,
    private val sessions: SessionRunner,
    private val policy: ReconnectPolicy,
    private val status: (ConnectionStatus) -> Unit,
    private val clock: () -> Long = { System.currentTimeMillis() },
) {
    private val networkRestored = Channel<Unit>(Channel.CONFLATED)

    /** Called when the OS reports usable connectivity; interrupts the current backoff. */
    fun onNetworkAvailable() {
        networkRestored.trySend(Unit)
    }

    suspend fun run(): SupervisorOutcome {
        var attempt = 0
        while (currentCoroutineContext().isActive) {
            val enrollment = store.info()
            if (enrollment == null || enrollment.state != EnrollmentState.ENROLLED) {
                status(ConnectionStatus.Unenrolled)
                return SupervisorOutcome.Unenrolled
            }
            status(ConnectionStatus.Connecting(attempt))

            var healthy = false
            val end = try {
                sessions.run(store) { path ->
                    healthy = true
                    attempt = 0
                    status(ConnectionStatus.Connected(path, clock()))
                }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (unexpected: Exception) {
                // A transport that throws instead of returning a failure is still a
                // contract violation; retry it, do not crash the service.
                SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR))
            }

            if (!currentCoroutineContext().isActive) {
                return SupervisorOutcome.Cancelled
            }
            when (end) {
                SessionEnd.Cancelled -> return SupervisorOutcome.Cancelled
                is SessionEnd.Failed -> {
                    val failure = end.failure
                    val reason = failure.retryReason
                    if (reason == null) {
                        stop(failure)
                        return SupervisorOutcome.Terminal(failure)
                    }
                    // A healthy connection in between resets the backoff to the base delay.
                    if (healthy) {
                        attempt = 0
                    }
                    attempt += 1
                    val delayMs = policy.nextDelay(attempt, reason)
                    status(ConnectionStatus.Reconnecting(attempt, delayMs, reason))
                    withTimeoutOrNull(delayMs) { networkRestored.receive() }
                }
            }
        }
        return SupervisorOutcome.Cancelled
    }

    private suspend fun stop(failure: ConnectionFailure) {
        when (failure.invalidation) {
            Invalidation.ENROLLMENT -> store.clear(
                if (failure == ConnectionFailure.DeviceRevoked) ClearReason.REVOKED else ClearReason.SERVER_REJECTED,
            )

            // The session id is not persisted; ending the loop is the whole invalidation.
            Invalidation.SESSION, Invalidation.NONE -> Unit
        }
        status(ConnectionStatus.Terminal(failure))
    }
}

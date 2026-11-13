package com.phoneconnect.agent.net

import com.phoneconnect.agent.AgentTransport
import com.phoneconnect.agent.ConnectionFailure
import com.phoneconnect.agent.ConnectionPath
import com.phoneconnect.agent.EnrollmentStore
import com.phoneconnect.agent.FrameChannel
import com.phoneconnect.agent.IdentityBoundary
import com.phoneconnect.agent.Inbound
import com.phoneconnect.agent.ReconnectReason
import com.phoneconnect.agent.SessionEnd
import com.phoneconnect.agent.SessionRunner
import com.phoneconnect.agent.crypto.Epoch
import com.phoneconnect.agent.crypto.IdentityKey
import com.phoneconnect.agent.crypto.SessionCipher
import com.phoneconnect.agent.crypto.SessionRole
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.ensureActive
import java.io.IOException

// Hub operations whose unknown authentication refusals are counted separately.
private const val OP_DISCOVERY = "session.discovery"
private const val OP_TICKET = "session.ticket"
private const val OP_NONCE = "session.nonce"
private const val OP_CANDIDATES = "session.candidates"
private const val OP_RELAY = "session.relay"

/**
 * Establishes and runs one real session against the hub.
 *
 * Flow: open the device identity → wait for a session a client authorized for this device →
 * fetch a fresh device ticket → read candidates until the peer's redemption nonce exists →
 * derive the session keys from both nonces → attach to the relay → exchange sealed frames.
 *
 * Direct (hole-punched) candidates are not implemented in this build; the relay is always
 * available and every session reports [ConnectionPath.RELAY]. That is a documented gap, not a
 * silent fallback.
 *
 * A relay `409 relay_unavailable` is terminal for that session id: this runner abandons the
 * id and waits for a different one, while the supervisor retries with
 * [ConnectionFailure.RelayUnavailable] so the agent stays online.
 */
@OptIn(IdentityBoundary::class)
class TransportSessionRunner(
    private val hub: HubClient,
    private val pollIntervalMs: Long = DEFAULT_POLL_INTERVAL_MS,
    private val maxPollIntervalMs: Long = DEFAULT_MAX_POLL_INTERVAL_MS,
    private val openChannel: suspend (url: String, credential: String) -> Result<FrameChannel> =
        { url, credential -> RelayFrameChannel.connect(url, credential) },
) : SessionRunner {
    /** A session id whose relay was refused; polling skips it until a new session appears. */
    private var abandonedSessionId: String? = null

    /**
     * Consecutive authentication refusals this build cannot classify, counted per hub
     * operation. A success on one endpoint must not mask repeated refusals on another: a proxy
     * that only 403s `/ticket` still has to become visible.
     */
    private val unknownAuthRefusals = mutableMapOf<String, Int>()

    override suspend fun run(store: EnrollmentStore, onConnected: (ConnectionPath) -> Unit): SessionEnd {
        val identity = store.openIdentity() ?: return SessionEnd.Failed(ConnectionFailure.NotEnrolled)
        try {
            return runSession(identity) { path ->
                // A session that became healthy proves every call works.
                unknownAuthRefusals.clear()
                onConnected(path)
            }
        } finally {
            identity.close()
        }
    }

    private suspend fun runSession(
        identity: com.phoneconnect.agent.DeviceIdentity,
        onConnected: (ConnectionPath) -> Unit,
    ): SessionEnd {
        val credential = String(identity.credentialForTransport(), Charsets.UTF_8)
        val deviceId = identity.deviceId
        currentCoroutineContext().ensureActive()

        val waitForSession = awaitAssignedSession(credential, deviceId)
        val session = when (waitForSession) {
            is SessionWait.Assigned -> waitForSession.session
            is SessionWait.Ended -> return waitForSession.end
        }

        val ticketResult = hub.ticket(credential, session.sessionId).acceptedByHub(OP_TICKET)
        val (ticket, _) = ticketResult.getOrElse { error ->
            return SessionEnd.Failed(error.toFailure(OP_TICKET))
        }
        if (ticket.sessionId != session.sessionId || ticket.deviceId != deviceId) {
            return SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR))
        }
        // The two ticket nonces are the per-connection epoch. This device has no direct path,
        // so it publishes its nonce exactly once without an endpoint, then reads the opposite
        // peer's nonce. Polling never redeems a ticket: a nonce is single-use, and a device
        // that is up before the client must not burn it and stop for good.
        val registered = hub.registerNonce(credential, session.sessionId, ticket).acceptedByHub(OP_NONCE)
            .getOrElse { error -> return SessionEnd.Failed(error.toFailure(OP_NONCE)) }
        val candidates = if (registered.peerNonce != null) {
            registered
        } else {
            when (val rendezvous = awaitPeerNonce(credential, session.sessionId)) {
                is RendezvousWait.Rendezvous -> rendezvous.candidates
                is RendezvousWait.Ended -> return rendezvous.end
            }
        }
        return connectOverRelay(identity, credential, deviceId, session, ticket, candidates, onConnected)
    }

    /**
     * Attaches to the relay and runs the sealed frame loop.
     *
     * The rendezvous endpoint registered above is a nonce carrier, not a direct path: this
     * build does not probe direct candidates, so the relay is the only transport it uses.
     */
    private suspend fun connectOverRelay(
        identity: com.phoneconnect.agent.DeviceIdentity,
        credential: String,
        deviceId: String,
        session: AssignedSession,
        ticket: RendezvousTicket,
        candidates: SessionCandidates,
        onConnected: (ConnectionPath) -> Unit,
    ): SessionEnd {
        val peerNonce = candidates.peerNonce
            ?: return SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR))

        val epoch = Epoch.split(ticket.nonce, peerNonce, SessionRole.DEVICE)
            .getOrElse { return SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)) }
        val peerKey = IdentityKey.decodePublicKey(ticket.peerIdentityKey)
            .getOrElse { return SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)) }
        val localKey = IdentityKey.fromBytes(identity.identityPrivateKeyForTransport())
            .getOrElse { return SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)) }
        try {
            val cipher = SessionCipher.agree(localKey, peerKey, session.sessionId, SessionRole.DEVICE, epoch)
                .getOrElse { return SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)) }

            val url = try {
                hub.relayUrl(session.sessionId, candidates)
            } catch (error: HubFailure) {
                return SessionEnd.Failed(error.toFailure(OP_RELAY))
            }
            val channel = openChannel(url, credential)
                .getOrElse { error ->
                    val failure = error.toFailure(OP_RELAY)
                    if (failure == ConnectionFailure.RelayUnavailable) {
                        abandonedSessionId = session.sessionId
                    }
                    return SessionEnd.Failed(failure)
                }
            val transport = AgentTransport(
                channel,
                deviceId,
                session.sessionId,
                cipher,
                controlAllowed = session.control,
            )
            try {
                onConnected(ConnectionPath.RELAY)
                while (true) {
                    currentCoroutineContext().ensureActive()
                    when (val inbound = transport.receive()) {
                        is Inbound.End -> {
                            // The device itself declared this session over (expired, closed,
                            // revoked, or a peer violating a read-only session); polling must
                            // not offer the same id again.
                            if (inbound.failure == ConnectionFailure.SessionEnded) {
                                abandonedSessionId = session.sessionId
                            }
                            return SessionEnd.Failed(inbound.failure)
                        }
                        // Command and telemetry adapters are a follow-up task; the connection
                        // service's job is to keep this stream authenticated and alive.
                        is Inbound.Frame -> Unit
                    }
                }
            } finally {
                transport.close()
            }
        } finally {
            localKey.close()
        }
    }

    private suspend fun awaitAssignedSession(credential: String, deviceId: String): SessionWait {
        var pause = pollIntervalMs
        while (true) {
            currentCoroutineContext().ensureActive()
            // Any accepted response proves the credential works: only consecutive refusals
            // may reach the terminal.
            val result = hub.assignedSession(credential, deviceId).acceptedByHub(OP_DISCOVERY)
            val session = result.getOrElse { error ->
                return SessionWait.Ended(SessionEnd.Failed(error.toFailure(OP_DISCOVERY)))
            }
            // A session whose relay was refused stays "active" until it expires. Waiting for
            // a different id honors "never retry the same session" without stopping the agent.
            if (session != null && session.sessionId != abandonedSessionId) {
                return SessionWait.Assigned(session)
            }
            if (pause > 0) delay(pause)
            pause = (pause * 2).coerceAtMost(maxPollIntervalMs)
        }
    }

    private suspend fun awaitPeerNonce(credential: String, sessionId: String): RendezvousWait {
        var pause = pollIntervalMs
        while (true) {
            currentCoroutineContext().ensureActive()
            val result = hub.candidates(credential, sessionId).acceptedByHub(OP_CANDIDATES)
            val candidates = result.getOrElse { error ->
                return RendezvousWait.Ended(SessionEnd.Failed(error.toFailure(OP_CANDIDATES)))
            }
            if (candidates.peerNonce != null) {
                return RendezvousWait.Rendezvous(candidates)
            }
            if (pause > 0) delay(pause)
            pause = (pause * 2).coerceAtMost(maxPollIntervalMs)
        }
    }

    /**
     * Classifies a hub answer by its machine-readable code first, then by status.
     *
     * Status alone is not enough: the hub answers `401`/`403` for expired tickets and
     * revoked sessions as well as for bad credentials. Treating those as "not enrolled"
     * would delete a perfectly good credential when a 30-second ticket expires, and the user
     * cannot mint a new one-time enrollment token from the device.
     */
    private fun Throwable.toFailure(operation: String): ConnectionFailure = when (this) {
        is HubFailure.Rejected -> when (code) {
            // Only these two mean the stored device credential is unusable.
            "invalid_credential", "device_unknown" -> ConnectionFailure.NotEnrolled
            "device_revoked" -> ConnectionFailure.DeviceRevoked

            // The session is over; the enrollment is not. The supervisor starts a new session.
            "session_expired", "session_revoked", "session_unknown" ->
                ConnectionFailure.SessionEnded

            // Deterministic scope or identity refusals: a new session cannot fix them, so
            // retrying forever would hide the condition from the operator.
            "session_scope_mismatch", "device_scope_mismatch", "ticket_scope_mismatch",
            "ticket_identity_missing",
            -> ConnectionFailure.SessionRefused(code)

            // A stale ticket is worth one more try with a fresh one; nothing is invalidated.
            "ticket_expired", "ticket_replayed" ->
                ConnectionFailure.Retryable(ReconnectReason.TICKET_EXPIRED)

            "relay_unavailable" -> ConnectionFailure.RelayUnavailable

            else -> when {
                status == 404 || status == 410 -> ConnectionFailure.SessionEnded
                status >= 500 -> ConnectionFailure.Retryable(ReconnectReason.SERVER_UNREACHABLE)
                // An auth failure with an unknown code must never wipe the credential, but it
                // must not retry forever with no operator-visible outcome either.
                status == 401 || status == 403 -> {
                    val count = (unknownAuthRefusals[operation] ?: 0) + 1
                    unknownAuthRefusals[operation] = count
                    if (count >= MAX_UNKNOWN_AUTH_REFUSALS) {
                        ConnectionFailure.CredentialRejected(code)
                    } else {
                        ConnectionFailure.SessionEnded
                    }
                }
                else -> ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)
            }
        }

        is HubFailure.Unreachable, is IOException ->
            ConnectionFailure.Retryable(ReconnectReason.SERVER_UNREACHABLE)

        is HubFailure.Malformed -> ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)

        else -> ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)
    }

    /**
     * Records that the hub accepted this credential for one operation. Only consecutive
     * refusals on the same call reach the terminal, and a success elsewhere cannot reset them.
     */
    private fun <T> Result<T>.acceptedByHub(operation: String): Result<T> =
        onSuccess { unknownAuthRefusals.remove(operation) }

    private sealed interface SessionWait {
        data class Assigned(val session: AssignedSession) : SessionWait

        data class Ended(val end: SessionEnd) : SessionWait
    }

    private sealed interface RendezvousWait {
        data class Rendezvous(val candidates: SessionCandidates) : RendezvousWait

        data class Ended(val end: SessionEnd) : RendezvousWait
    }

    companion object {
        const val DEFAULT_POLL_INTERVAL_MS: Long = 2_000
        const val DEFAULT_MAX_POLL_INTERVAL_MS: Long = 10_000

        /** Unknown authentication refusals tolerated before the agent stops with a reason. */
        const val MAX_UNKNOWN_AUTH_REFUSALS: Int = 5
    }
}

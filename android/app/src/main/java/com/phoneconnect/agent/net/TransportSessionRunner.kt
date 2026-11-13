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
import java.net.DatagramSocket
import java.net.SocketException

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
 * A relay `409 relay_unavailable` is terminal for that session id: this runner never retries
 * the same id, which the supervisor turns into [ConnectionFailure.RelayUnavailable].
 */
@OptIn(IdentityBoundary::class)
class TransportSessionRunner(
    private val hub: HubClient,
    private val pollIntervalMs: Long = DEFAULT_POLL_INTERVAL_MS,
    private val maxPollIntervalMs: Long = DEFAULT_MAX_POLL_INTERVAL_MS,
    private val openChannel: suspend (url: String, credential: String) -> Result<FrameChannel> =
        { url, credential -> RelayFrameChannel.connect(url, credential) },
) : SessionRunner {
    override suspend fun run(store: EnrollmentStore, onConnected: (ConnectionPath) -> Unit): SessionEnd {
        val identity = store.openIdentity() ?: return SessionEnd.Failed(ConnectionFailure.NotEnrolled)
        try {
            return runSession(identity, onConnected)
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

        val ticketResult = hub.ticket(credential, session.sessionId)
        val (ticket, _) = ticketResult.getOrElse { error -> return SessionEnd.Failed(error.toFailure()) }
        if (ticket.sessionId != session.sessionId || ticket.deviceId != deviceId) {
            return SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR))
        }
        // The two ticket nonces are the per-connection epoch, and each peer publishes its
        // nonce by redeeming its ticket. Without the peer's nonce there is no key to derive,
        // so waiting is the only correct behaviour.
        val rendezvousSocket = try {
            DatagramSocket(0)
        } catch (error: SocketException) {
            return SessionEnd.Failed(ConnectionFailure.Retryable(ReconnectReason.NETWORK_UNAVAILABLE))
        }
        try {
            val endpoint = "0.0.0.0:${rendezvousSocket.localPort}"
            val candidates = when (
                val rendezvous = awaitPeerNonce(credential, session.sessionId, ticket, endpoint)
            ) {
                is RendezvousWait.Rendezvous -> rendezvous.candidates
                is RendezvousWait.Ended -> return rendezvous.end
            }
            return connectOverRelay(identity, credential, deviceId, session, ticket, candidates, onConnected)
        } finally {
            rendezvousSocket.close()
        }
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
                return SessionEnd.Failed(error.toFailure())
            }
            val channel = openChannel(url, credential)
                .getOrElse { error -> return SessionEnd.Failed(error.toFailure()) }
            val transport = AgentTransport(channel, deviceId, session.sessionId, cipher)
            try {
                onConnected(ConnectionPath.RELAY)
                while (true) {
                    currentCoroutineContext().ensureActive()
                    when (val inbound = transport.receive()) {
                        is Inbound.End -> return SessionEnd.Failed(inbound.failure)
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
            val result = hub.assignedSession(credential, deviceId)
            val session = result.getOrElse { error -> return SessionWait.Ended(SessionEnd.Failed(error.toFailure())) }
            if (session != null) {
                return SessionWait.Assigned(session)
            }
            if (pause > 0) delay(pause)
            pause = (pause * 2).coerceAtMost(maxPollIntervalMs)
        }
    }

    private suspend fun awaitPeerNonce(
        credential: String,
        sessionId: String,
        ticket: RendezvousTicket,
        endpoint: String,
    ): RendezvousWait {
        var pause = pollIntervalMs
        while (true) {
            currentCoroutineContext().ensureActive()
            val result = hub.registerCandidate(credential, sessionId, ticket, endpoint)
            val candidates = result.getOrElse { error -> return RendezvousWait.Ended(SessionEnd.Failed(error.toFailure())) }
            if (candidates.peerNonce != null) {
                return RendezvousWait.Rendezvous(candidates)
            }
            if (pause > 0) delay(pause)
            pause = (pause * 2).coerceAtMost(maxPollIntervalMs)
        }
    }

    private fun Throwable.toFailure(): ConnectionFailure = when (this) {
        is HubFailure.Rejected -> when {
            code == "device_revoked" -> ConnectionFailure.DeviceRevoked
            code == "relay_unavailable" || status == 409 -> ConnectionFailure.RelayUnavailable
            status == 404 || status == 410 -> ConnectionFailure.SessionEnded
            status == 401 || status == 403 -> ConnectionFailure.NotEnrolled
            status >= 500 -> ConnectionFailure.Retryable(ReconnectReason.SERVER_UNREACHABLE)
            else -> ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)
        }

        is HubFailure.Unreachable, is IOException ->
            ConnectionFailure.Retryable(ReconnectReason.SERVER_UNREACHABLE)

        is HubFailure.Malformed -> ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)

        else -> ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)
    }

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
    }
}

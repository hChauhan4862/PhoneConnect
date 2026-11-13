package com.phoneconnect.agent.net

import com.phoneconnect.agent.ClearReason
import com.phoneconnect.agent.ConnectionFailure
import com.phoneconnect.agent.ConnectionPath
import com.phoneconnect.agent.DeviceIdentity
import com.phoneconnect.agent.EnrollmentInfo
import com.phoneconnect.agent.EnrollmentRequest
import com.phoneconnect.agent.EnrollmentState
import com.phoneconnect.agent.EnrollmentStore
import com.phoneconnect.agent.IdentityBoundary
import com.phoneconnect.agent.Invalidation
import com.phoneconnect.agent.SessionEnd
import com.phoneconnect.agent.invalidation
import com.phoneconnect.agent.isTerminal
import com.phoneconnect.agent.crypto.Epoch
import com.phoneconnect.agent.crypto.EpochClaims
import com.phoneconnect.agent.crypto.IdentityKey
import com.phoneconnect.agent.crypto.SessionCipher
import com.phoneconnect.agent.crypto.SessionRole
import com.phoneconnect.agent.EnvelopeCodec
import com.phoneconnect.agent.wire.StreamKind
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.HttpUrl.Companion.toHttpUrl
import okhttp3.OkHttpClient
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import okio.ByteString
import okio.ByteString.Companion.toByteString
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.Base64
import java.util.concurrent.TimeUnit

/**
 * The hub flow end to end against a real HTTP/WebSocket server (MockWebServer): enroll,
 * session discovery, ticket, candidates with the peer nonce, relay attach, and sealed frames.
 *
 * These are the tests the previous round lacked: the agent really reaches the relay, really
 * derives the session keys, and really reports the path.
 */
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class HubSessionTest {
    private lateinit var server: MockWebServer
    private lateinit var hub: HubClient
    private lateinit var store: FakeStore
    private val deviceSecret = ByteArray(32) { 0x33 }
    private val clientSecret = ByteArray(32) { 0x44 }

    @Before
    fun setUp() {
        EpochClaims.clear()
        server = MockWebServer()
        server.start()
        hub = HubClient.create(server.url("/").toString()).getOrThrow()
        store = FakeStore(deviceSecret)
    }

    @After
    fun tearDown() {
        runCatching { server.shutdown() }
    }

    @Test
    fun `a session is discovered, keyed, relayed, and its frames opened`() = runBlocking {
        enqueueDiscovery()
        val peer = clientCipher()
        var relayOpened = false
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        relayOpened = true
                        // A routing frame the device must unwrap and open, then a terminal close.
                        webSocket.send(routingFrame(peer.seal(controlEnvelope()).getOrThrow()).toByteString())
                        webSocket.close(1008, "device_revoked")
                    }
                },
            ),
        )
        val paths = mutableListOf<ConnectionPath>()

        val end = withTimeout(20_000) {
            TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { paths += it }
        }

        assertEquals(SessionEnd.Failed(ConnectionFailure.DeviceRevoked), end)
        assertEquals(listOf(ConnectionPath.RELAY), paths)
        assertTrue("the relay socket must have been opened", relayOpened)
        val discovery = server.takeRequest()
        assertEquals("/api/devices/dev_1/sessions/next", discovery.path)
        assertEquals("Bearer pcdev_test", discovery.headers["Authorization"])
        assertEquals("/api/sessions/sess_1/ticket", server.takeRequest().path)
        val rendezvous = server.takeRequest()
        assertEquals("/api/sessions/sess_1/candidates", rendezvous.path)
        assertEquals("the nonce is published exactly once per attempt", "POST", rendezvous.method)
        val publishBody = JSONObject(rendezvous.body.readUtf8())
        assertEquals(
            "redeeming the attempt's ticket publishes its nonce",
            DEVICE_NONCE,
            publishBody.getJSONObject("ticket").getString("nonce"),
        )
        assertTrue(
            "a relay-only device must not advertise an endpoint",
            !publishBody.has("endpoint"),
        )
        val relayRequest = server.takeRequest()
        assertEquals("/api/sessions/sess_1/relay", relayRequest.path)
        assertEquals("Bearer pcdev_test", relayRequest.headers["Authorization"])
    }

    @Test
    fun `an unopened inbound frame ends the session instead of being trusted`() = runBlocking {
        enqueueDiscovery()
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        // Random bytes are not a frame this session sealed.
                        webSocket.send(ByteString.of(*ByteArray(48) { 0x7F }))
                        webSocket.close(1000, null)
                    }
                },
            ),
        )

        val end = withTimeout(20_000) {
            TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
        }

        assertEquals(
            SessionEnd.Failed(ConnectionFailure.Retryable(com.phoneconnect.agent.ReconnectReason.PROTOCOL_ERROR)),
            end,
        )
    }

    @Test
    fun `a relay 409 is terminal for the session and never retried`() = runBlocking {
        enqueueDiscovery()
        server.enqueue(MockResponse().setResponseCode(409).setBody("""{"error":"relay_unavailable"}"""))
        val relayAttempts = mutableListOf<String>()

        val end = withTimeout(20_000) {
            TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
        }

        assertEquals(SessionEnd.Failed(ConnectionFailure.RelayUnavailable), end)
        while (true) {
            val request = server.takeRequest(50, TimeUnit.MILLISECONDS) ?: break
            relayAttempts += request.path.orEmpty()
        }
        assertEquals(
            "exactly one relay attempt, on one session id",
            1,
            relayAttempts.count { it.endsWith("/relay") },
        )
    }

    @Test
    fun `a read-only session refuses a control frame from the peer`() = runBlocking {
        enqueueDiscovery(control = false)
        val peer = clientCipher()
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        // The client tries to command a device that holds no lease.
                        webSocket.send(routingFrame(peer.seal(controlEnvelope()).getOrThrow()).toByteString())
                    }
                },
            ),
        )

        val runner = TransportSessionRunner(hub, pollIntervalMs = 0)
        val end = withTimeout(20_000) { runner.run(store) { } }

        assertEquals(
            "a read-only session must not dispatch a control frame",
            SessionEnd.Failed(ConnectionFailure.SessionEnded),
            end,
        )

        // The device declared this session over, so the next attempt waits for a different
        // one instead of polling the same id into the same refusal.
        drainRequests()
        server.enqueue(MockResponse().setResponseCode(204))
        val second = withTimeoutOrNull(2_000) { runner.run(store) { } }
        assertNull("the runner must wait for a new session", second)
        val paths = drainRequests()
        assertEquals(
            "the refused session is never ticketed again: $paths",
            0,
            paths.count { it.endsWith("/ticket") },
        )
    }

    @Test
    fun `a path-scoped auth refusal still terminates after consecutive failures`() = runBlocking {
        // Discovery succeeds every attempt, so a count that reset on *any* success would let a
        // proxy that only 403s /ticket retry forever. Counting per call site keeps it terminal.
        val runner = TransportSessionRunner(hub, pollIntervalMs = 0)
        val attempts = TransportSessionRunner.MAX_UNKNOWN_AUTH_REFUSALS
        val ends = mutableListOf<SessionEnd>()
        for (attempt in 1..attempts) {
            server.enqueue(MockResponse().setBody("""{"session_id":"sess_1","expires_at":1760000000000,"control":true}"""))
            server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"proxy_denied"}"""))
            ends += withTimeout(20_000) { runner.run(store) { } }
        }

        for (attempt in 1 until attempts) {
            assertEquals(
                "attempt $attempt is still retried",
                SessionEnd.Failed(ConnectionFailure.SessionEnded),
                ends[attempt - 1],
            )
        }
        assertEquals(
            "a refusal isolated to one endpoint must still become terminal",
            SessionEnd.Failed(ConnectionFailure.CredentialRejected("proxy_denied")),
            ends.last(),
        )
        assertEquals("stopping never deletes the credential", null, store.cleared)
    }

    @Test
    fun `a successful poll between refusals resets the unknown-auth count`() = runBlocking {
        // A 204 proves the credential is accepted. Without this reset, MAX-1 sporadic
        // unknown-code refusals spread over hours would let one more stop an idle agent
        // permanently, although no two were consecutive.
        val runner = TransportSessionRunner(hub, pollIntervalMs = 0)
        for (attempt in 1 until TransportSessionRunner.MAX_UNKNOWN_AUTH_REFUSALS) {
            server.enqueue(
                MockResponse().setResponseCode(401).setBody("""{"error":"unknown_auth_code_$attempt"}"""),
            )
            val end = withTimeout(20_000) { runner.run(store) { } }
            assertEquals(SessionEnd.Failed(ConnectionFailure.SessionEnded), end)
        }

        // A 204 with nothing to join proves the credential is accepted and resets the run;
        // the refusal in the same attempt is then the first of a new run, not the fifth.
        server.enqueue(MockResponse().setResponseCode(204))
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"unknown_auth_code_after_reset"}"""))
        val afterReset = withTimeout(20_000) { runner.run(store) { } }
        assertEquals(SessionEnd.Failed(ConnectionFailure.SessionEnded), afterReset)
        assertTrue(
            "the count restarted, so nothing reached the terminal",
            !(afterReset as SessionEnd.Failed).failure.isTerminal,
        )
        assertEquals("the credential survives", null, store.cleared)
    }

    @Test
    fun `an unrecognised auth refusal stops after a bounded number of attempts`() = runBlocking {
        // A code this build cannot classify on 401 is a credential the server rejects; it is
        // retried a few times in case the server is mid-configuration, then stopped with the
        // enrollment intact so the operator sees a terminal reason instead of a silent loop.
        val runner = TransportSessionRunner(hub, pollIntervalMs = 0)
        val attempts = TransportSessionRunner.MAX_UNKNOWN_AUTH_REFUSALS
        val ends = mutableListOf<SessionEnd>()
        for (attempt in 1..attempts) {
            server.enqueue(
                MockResponse().setResponseCode(401).setBody("""{"error":"unknown_auth_code_$attempt"}"""),
            )
            ends += withTimeout(20_000) { runner.run(store) { } }
        }

        for (attempt in 1 until attempts) {
            assertEquals(
                "attempt $attempt is still retried",
                SessionEnd.Failed(ConnectionFailure.SessionEnded),
                ends[attempt - 1],
            )
        }
        assertEquals(
            "the last attempt stops with a clear reason",
            SessionEnd.Failed(ConnectionFailure.CredentialRejected("unknown_auth_code_$attempts")),
            ends.last(),
        )
        assertEquals("stopping never deletes the credential", null, store.cleared)
    }

    @Test
    fun `an abandoned session id is skipped until a different one is offered`() = runBlocking {
        enqueueDiscovery()
        server.enqueue(MockResponse().setResponseCode(409).setBody("""{"error":"relay_unavailable"}"""))
        val runner = TransportSessionRunner(hub, pollIntervalMs = 0)

        val first = withTimeout(20_000) { runner.run(store) { } }
        assertEquals(SessionEnd.Failed(ConnectionFailure.RelayUnavailable), first)
        drainRequests()

        // The refused session is still the newest; the server then reports none at all.
        server.enqueue(MockResponse().setBody("""{"session_id":"sess_1","expires_at":1760000000000}"""))
        server.enqueue(MockResponse().setResponseCode(204))
        val second = withTimeoutOrNull(2_000) { runner.run(store) { } }

        assertNull("the runner must wait for a new session instead of retiring", second)
        val paths = drainRequests()
        assertEquals(
            "the abandoned id is polled past, never ticketed again: $paths",
            0,
            paths.count { it.endsWith("/ticket") },
        )
        assertTrue(
            "the runner keeps asking for a session: $paths",
            paths.count { it.endsWith("/sessions/next") } >= 2,
        )
    }

    @Test
    fun `a rejected credential is terminal and clearable`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"device_revoked"}"""))

        val end = withTimeout(20_000) {
            TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
        }

        assertEquals(SessionEnd.Failed(ConnectionFailure.DeviceRevoked), end)
    }

    @Test
    fun `no authorized session yet is polled, not failed`() = runBlocking {
        server.enqueue(MockResponse().setResponseCode(204))
        enqueueDiscovery()
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        webSocket.close(1008, "session_closed")
                    }
                },
            ),
        )

        val end = withTimeout(20_000) {
            TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
        }

        assertEquals(SessionEnd.Failed(ConnectionFailure.SessionEnded), end)
        assertEquals("/api/devices/dev_1/sessions/next", server.takeRequest().path)
        assertEquals("/api/devices/dev_1/sessions/next", server.takeRequest().path)
    }

    @Test
    fun `the epoch waits for the peer nonce instead of deriving early keys`() = runBlocking {
        server.enqueue(
            MockResponse().setBody(
                """{"session_id":"sess_1","expires_at":1760000000000}""",
            ),
        )
        server.enqueue(
            MockResponse().setBody(
                """{"ticket":${ticketJson()},"verification_key":"vk"}""",
            ),
        )
        // First rendezvous has no peer nonce: the peer has not registered.
        server.enqueue(MockResponse().setBody(candidatesJson(peerNonce = null)))
        server.enqueue(MockResponse().setBody(candidatesJson(peerNonce = PEER_NONCE)))
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        webSocket.close(1008, "peer_closed")
                    }
                },
            ),
        )

        val end = withTimeout(20_000) {
            TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
        }

        assertEquals(
            SessionEnd.Failed(ConnectionFailure.Retryable(com.phoneconnect.agent.ReconnectReason.TRANSPORT_CLOSED)),
            end,
        )
        assertEquals("/api/devices/dev_1/sessions/next", server.takeRequest().path)
        assertEquals("/api/sessions/sess_1/ticket", server.takeRequest().path)
        val publish = server.takeRequest()
        assertEquals("/api/sessions/sess_1/candidates", publish.path)
        assertEquals("one ticket redemption per attempt", "POST", publish.method)
        val poll = server.takeRequest()
        assertEquals("/api/sessions/sess_1/candidates", poll.path)
        assertEquals("polling is read-only", "GET", poll.method)
    }

    @Test
    fun `enrollment sends the token and identity key and returns the credential`() = runBlocking {
        server.enqueue(enrollResponse())

        val enrolled = hub.enroll("pcenr_token", devicePublicBase64()).getOrThrow()

        assertEquals("dev_1", enrolled.deviceId)
        assertEquals("pcdev_test", enrolled.credential)
        val request = server.takeRequest()
        assertEquals("/api/devices/enroll", request.path)
        val body = JSONObject(request.body.readUtf8())
        assertEquals("pcenr_token", body.getString("token"))
        assertEquals(devicePublicBase64(), body.getString("identity_key"))
    }

    @Test
    fun `only https or loopback http hubs are accepted`() {
        assertTrue(HubClient.create("https://hub.example.com").isSuccess)
        assertTrue(HubClient.create("http://127.0.0.1:8080").isSuccess)
        assertTrue(HubClient.create("http://localhost:8080").isSuccess)
        assertTrue(HubClient.create("http://hub.example.com").isFailure)
        assertTrue(HubClient.create("ftp://hub.example.com").isFailure)
        assertTrue(HubClient.create("not a url").isFailure)
    }

    @Test
    fun `relay endpoints are normalized to websocket urls`() {
        assertEquals(
            "wss://hub.example.com/api/sessions/sess_1/relay",
            HubClient.toWebSocketUrl("https://hub.example.com/api/sessions/sess_1/relay"),
        )
        assertEquals(
            "ws://127.0.0.1:8080/api/sessions/sess_1/relay",
            HubClient.toWebSocketUrl("http://127.0.0.1:8080/api/sessions/sess_1/relay"),
        )
        assertEquals("wss://already.example/relay", HubClient.toWebSocketUrl("wss://already.example/relay"))
        assertTrue(runCatching { HubClient.toWebSocketUrl("ftp://nope") }.isFailure)
    }

    @Test
    fun `a relay handshake refusal maps to a terminal relay error`() {
        val refused = RelayFrameChannel.handshakeFailure(
            response = Response.Builder()
                .request(okhttp3.Request.Builder().url("http://localhost/relay").build())
                .protocol(okhttp3.Protocol.HTTP_1_1)
                .code(409)
                .message("Conflict")
                .build(),
            error = IllegalStateException("handshake refused"),
        )

        assertEquals(HubFailure.Rejected(409, "relay_unavailable"), refused)
    }

    @Test
    fun `relay clients ping on the Rust keepalive interval`() {
        val client = RelayFrameChannel.client(OkHttpClient())

        assertEquals(
            10_000,
            client.pingIntervalMillis,
        )
        assertEquals(10L, RelayFrameChannel.KEEPALIVE_INTERVAL_SECONDS)
    }

    @Test
    fun `the device-first ordering completes without redeeming a ticket twice`() = runBlocking {
        val dispatcher = OneShotNonceDispatcher(server.url("/api/sessions/sess_1/relay").toString())
        server.dispatcher = dispatcher

        val end = withTimeout(20_000) {
            TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
        }

        assertEquals(
            SessionEnd.Failed(ConnectionFailure.Retryable(com.phoneconnect.agent.ReconnectReason.TRANSPORT_CLOSED)),
            end,
        )
        assertEquals(
            "the attempt's ticket is redeemed exactly once",
            1,
            dispatcher.candidatePosts.get(),
        )
        assertTrue("the device must poll until the peer registers", dispatcher.candidatePolls.get() >= 3)
    }

    @Test
    fun `an expired ticket is retried with a fresh one and keeps the enrollment`() = runBlocking {
        server.enqueue(MockResponse().setBody("""{"session_id":"sess_1","expires_at":1760000000000}"""))
        server.enqueue(MockResponse().setResponseCode(401).setBody("""{"error":"ticket_expired"}"""))

        val end = withTimeout(20_000) {
            TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
        }

        val failure = (end as SessionEnd.Failed).failure
        assertEquals(
            ConnectionFailure.Retryable(com.phoneconnect.agent.ReconnectReason.TICKET_EXPIRED),
            failure,
        )
        assertEquals(
            "a stale ticket must not invalidate the credential",
            Invalidation.NONE,
            failure.invalidation,
        )
    }

    @Test
    fun `session codes end the session, never the enrollment`() = runBlocking {
        val cases = listOf(
            401 to "session_expired",
            401 to "session_revoked",
            404 to "session_unknown",
        )
        for ((status, code) in cases) {
            server.enqueue(MockResponse().setBody("""{"session_id":"sess_1","expires_at":1760000000000}"""))
            server.enqueue(MockResponse().setBody("""{"ticket":${ticketJson()},"verification_key":"vk"}"""))
            server.enqueue(MockResponse().setResponseCode(status).setBody("""{"error":"$code"}"""))

            val end = withTimeout(20_000) {
                TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
            }

            assertEquals("$code must end the session", SessionEnd.Failed(ConnectionFailure.SessionEnded), end)
            assertEquals(
                "$code must not delete the credential",
                Invalidation.NONE,
                (end as SessionEnd.Failed).failure.invalidation,
            )
        }
    }

    @Test
    fun `a scope or identity refusal is terminal and keeps the enrollment`() = runBlocking {
        // A new session cannot fix a credential that is scoped elsewhere or a ticket with no
        // pinned identity, so retrying forever would only hide the condition from the operator.
        val cases = listOf(
            403 to "session_scope_mismatch",
            401 to "ticket_scope_mismatch",
            409 to "device_scope_mismatch",
            401 to "ticket_identity_missing",
        )
        for ((status, code) in cases) {
            server.enqueue(MockResponse().setBody("""{"session_id":"sess_1","expires_at":1760000000000}"""))
            server.enqueue(MockResponse().setBody("""{"ticket":${ticketJson()},"verification_key":"vk"}"""))
            server.enqueue(MockResponse().setResponseCode(status).setBody("""{"error":"$code"}"""))

            val end = withTimeout(20_000) {
                TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
            }

            val failure = (end as SessionEnd.Failed).failure
            assertEquals("$code must stop with its own reason", ConnectionFailure.SessionRefused(code), failure)
            assertTrue("$code must be terminal", failure.isTerminal)
            assertEquals("$code must keep the credential", Invalidation.NONE, failure.invalidation)
            assertEquals("$code must not clear the enrollment", null, store.cleared)
        }
    }

    @Test
    fun `only credential codes invalidate the enrollment`() = runBlocking {
        val cases = listOf(
            Triple(401, "invalid_credential", ConnectionFailure.NotEnrolled),
            Triple(404, "device_unknown", ConnectionFailure.NotEnrolled),
            Triple(401, "device_revoked", ConnectionFailure.DeviceRevoked),
        )
        for ((status, code, expected) in cases) {
            server.enqueue(MockResponse().setResponseCode(status).setBody("""{"error":"$code"}"""))

            val end = withTimeout(20_000) {
                TransportSessionRunner(hub, pollIntervalMs = 0).run(store) { }
            }

            assertEquals("$code must be classified", SessionEnd.Failed(expected), end)
            assertEquals(
                "$code must invalidate the enrollment",
                Invalidation.ENROLLMENT,
                expected.invalidation,
            )
        }
    }

    /** Paths of every request the server has received since the last drain. */
    private fun drainRequests(): List<String> {
        val paths = mutableListOf<String>()
        while (true) {
            val request = server.takeRequest(50, TimeUnit.MILLISECONDS) ?: break
            paths += request.path.orEmpty()
        }
        return paths
    }

    private fun enqueueDiscovery(control: Boolean = true) {
        server.enqueue(MockResponse().setBody("""{"session_id":"sess_1","expires_at":1760000000000,"control":$control}"""))
        server.enqueue(MockResponse().setBody("""{"ticket":${ticketJson()},"verification_key":"vk"}"""))
        server.enqueue(MockResponse().setBody(candidatesJson(PEER_NONCE)))
    }

    private fun enrollResponse() = MockResponse()
        .setResponseCode(201)
        .setBody("""{"device_id":"dev_1","credential":"pcdev_test"}""")

    private fun ticketJson(): String {
        val devicePublic = IdentityKey.fromBytes(deviceSecret).getOrThrow().publicKeyBase64Url()
        val clientPublic = IdentityKey.fromBytes(clientSecret).getOrThrow().publicKeyBase64Url()
        return JSONObject()
            .put("session_id", "sess_1")
            .put("device_id", "dev_1")
            .put("role", "device")
            .put("nonce", DEVICE_NONCE)
            .put("probe_key", "probe")
            .put("own_identity_key", devicePublic)
            .put("peer_identity_key", clientPublic)
            .put("expires_at", 1_760_000_000_000L)
            .put("signature", "sig")
            .toString()
    }

    private fun candidatesJson(peerNonce: String?): String {
        val relay = server.url("/api/sessions/sess_1/relay").toString().trimEnd('/')
        val candidates = org.json.JSONArray()
            .put(
                JSONObject()
                    .put("kind", "relay")
                    .put("endpoint", relay)
                    .put("priority", 100),
            )
        val json = JSONObject()
            .put("session_id", "sess_1")
            .put("expires_at", 1_760_000_000_000L)
            .put("verification_key", "vk")
            .put("candidates", candidates)
        if (peerNonce != null) {
            json.put("peer_nonce", peerNonce)
        }
        return json.toString()
    }

    private fun clientCipher(): SessionCipher = SessionCipher.agree(
        IdentityKey.fromBytes(clientSecret).getOrThrow(),
        IdentityKey.fromBytes(deviceSecret).getOrThrow().publicKey(),
        "sess_1",
        SessionRole.CLIENT,
        Epoch.of(PEER_NONCE, DEVICE_NONCE).getOrThrow(),
    ).getOrThrow()

    /** A length-prefixed routing envelope whose payload is the sealed frame. */
    private fun routingFrame(sealed: ByteArray): ByteArray {
        val outer = EnvelopeCodec.newEnvelope(
            streamKind = StreamKind.STREAM_KIND_CONTROL,
            deviceId = "dev_1",
            sessionId = "sess_1",
        ).toBuilder()
            .setPayload(com.google.protobuf.ByteString.copyFrom(sealed))
            .build()
        return EnvelopeCodec.encode(outer).getOrThrow()
    }

    private fun controlEnvelope() = EnvelopeCodec.newEnvelope(
        streamKind = StreamKind.STREAM_KIND_CONTROL,
        deviceId = "dev_1",
        sessionId = "sess_1",
        requestId = "req-hello",
    ).toBuilder().setSequence(1).build()

    private fun devicePublicBase64(): String =
        Base64.getUrlEncoder().withoutPadding().encodeToString(IdentityKey.fromBytes(deviceSecret).getOrThrow().publicKey())

    @OptIn(IdentityBoundary::class)
    private class FakeStore(private val deviceSecret: ByteArray) : EnrollmentStore {
        var cleared: ClearReason? = null
            private set

        override suspend fun info(): EnrollmentInfo =
            EnrollmentInfo("dev_1", EnrollmentState.ENROLLED, 1_000)

        override suspend fun lastClearReason(): ClearReason? = null

        override suspend fun enroll(request: EnrollmentRequest) = Unit

        override suspend fun openIdentity(): DeviceIdentity = DeviceIdentity(
            deviceId = "dev_1",
            credentialBytes = "pcdev_test".toByteArray(),
            privateKeyBytes = deviceSecret.copyOf(),
            identityPublicKey = IdentityKey.fromBytes(deviceSecret).getOrThrow().publicKey(),
        )

        override suspend fun clear(reason: ClearReason): Boolean {
            cleared = reason
            return true
        }
    }

    /**
     * A hub that models the server's one-time redemption: a second POST with the same ticket
     * nonce answers `409 ticket_replayed`, exactly like `Rendezvous::observe`. The peer
     * registers after a few polls, which is the device-first ordering that used to stop the
     * agent permanently.
     */
    private class OneShotNonceDispatcher(private val relayUrl: String) : okhttp3.mockwebserver.Dispatcher() {
        private val redeemed = mutableSetOf<String>()
        private var polls = 0
        val candidatePosts = java.util.concurrent.atomic.AtomicInteger()
        val candidatePolls = java.util.concurrent.atomic.AtomicInteger()

        override fun dispatch(request: okhttp3.mockwebserver.RecordedRequest): MockResponse = when {
            request.path?.endsWith("/sessions/next") == true ->
                MockResponse().setBody("""{"session_id":"sess_1","expires_at":1760000000000}""")

            request.path?.endsWith("/ticket") == true ->
                MockResponse().setBody(
                    """{"ticket":{"session_id":"sess_1","device_id":"dev_1","role":"device","nonce":"$DEVICE_NONCE","probe_key":"probe","own_identity_key":"${IdentityKey.fromBytes(ByteArray(32) { 0x33 }).getOrThrow().publicKeyBase64Url()}","peer_identity_key":"${IdentityKey.fromBytes(ByteArray(32) { 0x44 }).getOrThrow().publicKeyBase64Url()}","expires_at":1760000000000,"signature":"sig"},"verification_key":"vk"}""",
                )

            request.path?.endsWith("/candidates") == true && request.method == "POST" -> {
                candidatePosts.incrementAndGet()
                val body = JSONObject(request.body.readUtf8())
                assertTrue("the device must not advertise an endpoint", !body.has("endpoint"))
                val nonce = body.getJSONObject("ticket").getString("nonce")
                if (!redeemed.add(nonce)) {
                    MockResponse().setResponseCode(409).setBody("""{"error":"ticket_replayed"}""")
                } else {
                    candidatesBody(peerNonce = null)
                }
            }

            request.path?.endsWith("/candidates") == true -> {
                candidatePolls.incrementAndGet()
                polls += 1
                candidatesBody(peerNonce = if (polls >= 3) PEER_NONCE else null)
            }

            request.path?.endsWith("/relay") == true -> MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onOpen(webSocket: WebSocket, response: Response) {
                        webSocket.close(1008, "peer_closed")
                    }
                },
            )

            else -> MockResponse().setResponseCode(404).setBody("""{"error":"not_found"}""")
        }

        private fun candidatesBody(peerNonce: String?): MockResponse {
            val candidates = org.json.JSONArray().put(
                JSONObject().put("kind", "relay").put("endpoint", relayUrl).put("priority", 100),
            )
            val json = JSONObject()
                .put("session_id", "sess_1")
                .put("expires_at", 1_760_000_000_000L)
                .put("verification_key", "vk")
                .put("candidates", candidates)
            if (peerNonce != null) json.put("peer_nonce", peerNonce)
            return MockResponse().setBody(json.toString())
        }
    }

    private companion object {
        const val DEVICE_NONCE = "device-nonce-1"
        const val PEER_NONCE = "client-nonce-1"
    }
}

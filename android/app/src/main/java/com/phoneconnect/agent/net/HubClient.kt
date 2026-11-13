package com.phoneconnect.agent.net

import kotlinx.coroutines.suspendCancellableCoroutine
import okhttp3.Call
import okhttp3.Callback
import okhttp3.HttpUrl
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.HttpUrl.Companion.toHttpUrlOrNull
import org.json.JSONException
import org.json.JSONObject
import java.io.IOException
import java.util.concurrent.TimeUnit
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/** Explicit hub failures; nothing is repaired into a success-shaped answer. */
sealed class HubFailure(message: String) : Exception(message) {
    /** The hub answered with a status and a machine-readable error code. */
    data class Rejected(val status: Int, val code: String) : HubFailure("hub rejected the request: $status $code")

    /** The hub could not be reached at all. */
    data class Unreachable(val reason: String) : HubFailure("hub is unreachable: $reason")

    /** The hub answered something this build cannot read. */
    data class Malformed(val reason: String) : HubFailure("hub answered an unreadable response: $reason")
}

/** A device as `POST /api/devices/enroll` returns it. */
data class EnrolledDevice(val deviceId: String, val credential: String)

/** The ticket fields the agent needs; the signature is carried but not yet verified. */
data class RendezvousTicket(
    val sessionId: String,
    val deviceId: String,
    val role: String,
    val nonce: String,
    val probeKey: String,
    val ownIdentityKey: String,
    val peerIdentityKey: String,
    val expiresAtMs: Long,
    val signature: String,
)

/** A session the hub authorized for this device, with no ticket of its own. */
data class AssignedSession(val sessionId: String, val expiresAtMs: Long)

/** One session's rendezvous data, as the candidates route returns it. */
data class SessionCandidates(
    val sessionId: String,
    val expiresAtMs: Long,
    val verificationKey: String,
    val peerNonce: String?,
    val endpoints: List<Candidate>,
) {
    data class Candidate(val kind: String, val endpoint: String, val priority: Int)

    /** The relay route, plus any direct endpoint the server observed for the peer. */
    fun relayEndpoint(): String? =
        endpoints.filter { it.kind == "relay" }.maxByOrNull { it.priority }?.endpoint
}

/**
 * The hub's HTTP surface for one agent: enrollment, session discovery, tickets, candidates,
 * and the relay route.
 *
 * Plain `OkHttp` calls on [Dispatchers.IO]; every failure becomes a [HubFailure] so the
 * connection loop can classify it instead of guessing from nulls.
 */
class HubClient(
    private val baseUrl: HttpUrl,
    private val client: OkHttpClient = defaultClient(),
) {
    /** The relay route for one session, normalized to a WebSocket URL. */
    fun relayUrl(sessionId: String, candidates: SessionCandidates?): String {
        val endpoint = candidates?.relayEndpoint()
            ?: baseUrl.newBuilder()
                .addPathSegment("api")
                .addPathSegment("sessions")
                .addPathSegment(sessionId)
                .addPathSegment("relay")
                .build()
                .toString()
        return toWebSocketUrl(endpoint)
    }

    suspend fun enroll(token: String, identityPublicKey: String): Result<EnrolledDevice> = runCatching {
        val body = JSONObject()
            .put("token", token)
            .put("identity_key", identityPublicKey)
            .toString()
        val json = execute(
            Request.Builder()
                .url(url("api", "devices", "enroll"))
                .post(body.toRequestBody(JSON))
                .build(),
        )
        EnrolledDevice(
            deviceId = json.getString("device_id"),
            credential = json.getString("credential"),
        )
    }.mapFailure()

    /** The newest session a client authorized for this device, or `null` when there is none. */
    suspend fun assignedSession(credential: String, deviceId: String): Result<AssignedSession?> = runCatching {
        val (status, json) = executeAllowingNoContent(
            Request.Builder()
                .url(url("api", "devices", deviceId, "sessions", "next"))
                .header("Authorization", "Bearer $credential")
                .get()
                .build(),
        )
        if (status == 204 || json == null) {
            null
        } else {
            AssignedSession(
                sessionId = json.getString("session_id"),
                expiresAtMs = json.getLong("expires_at"),
            )
        }
    }.mapFailure()

    suspend fun ticket(credential: String, sessionId: String): Result<Pair<RendezvousTicket, String>> = runCatching {
        val json = execute(
            Request.Builder()
                .url(url("api", "sessions", sessionId, "ticket"))
                .header("Authorization", "Bearer $credential")
                .get()
                .build(),
        )
        parseTicket(json.getJSONObject("ticket")) to json.getString("verification_key")
    }.mapFailure()

    /**
     * Publishes this attempt's redemption nonce without advertising an endpoint.
     *
     * The nonce is half of the connection epoch; a relay-only device has no direct address to
     * publish, and a wildcard address would be handed to the peer as a probe target that can
     * never answer. The ticket is single-use, so this is called exactly once per attempt.
     */
    suspend fun registerNonce(
        credential: String,
        sessionId: String,
        ticket: RendezvousTicket,
    ): Result<SessionCandidates> = runCatching {
        val body = JSONObject().put("ticket", ticketJson(ticket)).toString()
        val json = execute(
            Request.Builder()
                .url(url("api", "sessions", sessionId, "candidates"))
                .header("Authorization", "Bearer $credential")
                .post(body.toRequestBody(JSON))
                .build(),
        )
        parseCandidates(json)
    }.mapFailure()

    /**
     * Rendezvous data for this session: the relay route and the opposite peer's redemption
     * nonce once that peer has registered. Read-only, so polling never burns a ticket.
     */
    suspend fun candidates(credential: String, sessionId: String): Result<SessionCandidates> = runCatching {
        val json = execute(
            Request.Builder()
                .url(url("api", "sessions", sessionId, "candidates"))
                .header("Authorization", "Bearer $credential")
                .get()
                .build(),
        )
        parseCandidates(json)
    }.mapFailure()

    private fun parseCandidates(json: JSONObject): SessionCandidates = SessionCandidates(
        sessionId = json.getString("session_id"),
        expiresAtMs = json.getLong("expires_at"),
        verificationKey = json.optString("verification_key"),
        peerNonce = json.optString("peer_nonce").takeIf { it.isNotEmpty() },
        endpoints = json.getJSONArray("candidates").let { array ->
            (0 until array.length()).map { index ->
                val candidate = array.getJSONObject(index)
                SessionCandidates.Candidate(
                    kind = candidate.getString("kind"),
                    endpoint = candidate.getString("endpoint"),
                    priority = candidate.getInt("priority"),
                )
            }
        },
    )

    /** The ticket exactly as the hub serialized it, so redeeming it is a round trip. */
    private fun ticketJson(ticket: RendezvousTicket): JSONObject = JSONObject()
        .put("session_id", ticket.sessionId)
        .put("device_id", ticket.deviceId)
        .put("role", ticket.role)
        .put("nonce", ticket.nonce)
        .put("probe_key", ticket.probeKey)
        .put("own_identity_key", ticket.ownIdentityKey)
        .put("peer_identity_key", ticket.peerIdentityKey)
        .put("expires_at", ticket.expiresAtMs)
        .put("signature", ticket.signature)

    private fun parseTicket(json: JSONObject): RendezvousTicket = RendezvousTicket(
        sessionId = json.getString("session_id"),
        deviceId = json.getString("device_id"),
        role = json.getString("role"),
        nonce = json.getString("nonce"),
        probeKey = json.optString("probe_key"),
        ownIdentityKey = json.getString("own_identity_key"),
        peerIdentityKey = json.getString("peer_identity_key"),
        expiresAtMs = json.getLong("expires_at"),
        signature = json.optString("signature"),
    )

    private fun url(vararg segments: String): HttpUrl = baseUrl.newBuilder()
        .apply { segments.forEach { addPathSegment(it) } }
        .build()

    private suspend fun execute(request: Request): JSONObject {
        val (status, json) = executeAllowingNoContent(request)
        if (status !in 200..299 || json == null) {
            throw rejected(status, null)
        }
        return json
    }

    private suspend fun executeAllowingNoContent(request: Request): Pair<Int, JSONObject?> {
        val response = client.newCall(request).await()
        response.use {
            val body = it.body?.string().orEmpty()
            if (it.code == 204) {
                return it.code to null
            }
            if (!it.isSuccessful) {
                throw rejected(it.code, parseErrorCode(body))
            }
            val json = try {
                JSONObject(body)
            } catch (error: JSONException) {
                throw HubFailure.Malformed("response is not JSON: ${error.message}")
            }
            return it.code to json
        }
    }

    private fun rejected(status: Int, code: String?): HubFailure =
        HubFailure.Rejected(status, code ?: "http_$status")

    private fun parseErrorCode(body: String): String? = try {
        JSONObject(body).optString("error").takeIf { it.isNotEmpty() }
    } catch (error: JSONException) {
        null
    }

    /** Maps transport faults onto [HubFailure] while leaving protocol answers untouched. */
    private fun <T> Result<T>.mapFailure(): Result<T> {
        val error = exceptionOrNull() ?: return this
        return Result.failure(
            if (error is IOException) HubFailure.Unreachable(error.message ?: "io error") else error,
        )
    }

    companion object {
        private val JSON = "application/json; charset=utf-8".toMediaType()

        /** A client with bounded connect/read timeouts; one connection at a time is enough. */
        fun defaultClient(): OkHttpClient = OkHttpClient.Builder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(30, TimeUnit.SECONDS)
            .retryOnConnectionFailure(false)
            .build()

        /**
         * Builds a client for a hub URL, refusing anything that is not HTTPS or loopback
         * HTTP: enrollment credentials travel in this connection.
         */
        fun create(baseUrl: String, client: OkHttpClient = defaultClient()): Result<HubClient> = runCatching {
            val parsed = baseUrl.trim().toHttpUrlOrNull()
                ?: throw HubFailure.Malformed("hub URL is invalid: $baseUrl")
            val loopback = parsed.host == "127.0.0.1" || parsed.host == "localhost" || parsed.host == "::1"
            if (parsed.scheme != "https" && !(parsed.scheme == "http" && loopback)) {
                throw HubFailure.Malformed("hub URL must be https (http is only allowed for loopback): $baseUrl")
            }
            HubClient(parsed, client)
        }

        /** `https`→`wss`, `http`→`ws`; a URL that is already a WebSocket URL passes through. */
        fun toWebSocketUrl(endpoint: String): String {
            val trimmed = endpoint.trim().trimEnd('/')
            return when {
                trimmed.startsWith("https://") -> "wss://" + trimmed.removePrefix("https://")
                trimmed.startsWith("http://") -> "ws://" + trimmed.removePrefix("http://")
                trimmed.startsWith("ws://") || trimmed.startsWith("wss://") -> trimmed
                else -> throw HubFailure.Malformed("relay endpoint is not an http(s) or ws(s) URL: $endpoint")
            }
        }
    }
}

private suspend fun Call.await(): Response = suspendCancellableCoroutine { continuation ->
    enqueue(
        object : Callback {
            override fun onFailure(call: Call, e: IOException) {
                if (continuation.isActive) continuation.resumeWithException(e)
            }

            override fun onResponse(call: Call, response: Response) {
                continuation.resume(response)
            }
        },
    )
    continuation.invokeOnCancellation { cancel() }
}

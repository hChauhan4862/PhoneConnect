package com.phoneconnect.agent.net

import com.phoneconnect.agent.EnrollmentStore
import com.phoneconnect.agent.IdentityBoundary
import com.phoneconnect.agent.ManagementChannel
import com.phoneconnect.agent.ManagementChannelState
import com.phoneconnect.agent.control.CommandDispatcher
import com.phoneconnect.agent.control.CommandFailure
import com.phoneconnect.agent.control.DeviceInfoHandler
import com.phoneconnect.agent.telemetry.TelemetrySampler
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import org.json.JSONException
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** One frame the management socket delivered, or the end of the socket. */
sealed interface ControlFrame {
    data class Text(val text: String) : ControlFrame

    /** The server closed the channel; [reason] is its stable close code. */
    data class Closed(val reason: String?) : ControlFrame
}

/** The management WebSocket as this channel uses it: JSON text frames in both directions. */
interface ControlSocket : AutoCloseable {
    /** False when the socket is gone and the attempt must end. */
    suspend fun send(text: String): Boolean

    suspend fun receive(): ControlFrame

    override fun close()
}

/**
 * The management channel: one authenticated WebSocket to the server carrying telemetry and
 * command results.
 *
 * This is the server-mediated half of the design's two-channel rule — JSON the server reads,
 * never sealed peer traffic. It runs inside the one [com.phoneconnect.agent.ConnectionService]
 * beside the sealed session, with its own bounded reconnect backoff, and it never creates a
 * service or a notification of its own.
 *
 * Every command is answered exactly once, with `ok`, the handler's error code, or `timeout`
 * when the server's deadline elapses first. A result never claims success it did not produce.
 */
@OptIn(IdentityBoundary::class)
class DeviceControlChannel(
    private val hub: HubClient,
    private val dispatcher: CommandDispatcher,
    private val telemetry: TelemetrySampler,
    private val deviceInfo: DeviceInfoHandler = DeviceInfoHandler(),
    private val telemetryIntervalMs: Long = DEFAULT_TELEMETRY_INTERVAL_MS,
    private val openSocket: suspend (url: String, bearer: String) -> Result<ControlSocket> =
        { url, bearer -> OkHttpControlSocket.connect(url, bearer) },
    private val pause: suspend (Long) -> Unit = { delay(it) },
    private val clock: () -> Long = System::currentTimeMillis,
) : ManagementChannel {
    /**
     * The server's clock minus this device's, taken as the largest implied offset any command
     * frame has shown. Every sample underestimates the offset by that frame's queue and
     * transit delay, so the maximum is the closest underestimate: the estimate never runs
     * ahead of the server, a fresh command is never falsely expired, and a command that
     * waited out its deadline is still caught once the wait exceeds the least delay seen.
     */
    private var serverOffsetMs: Long? = null
    override suspend fun run(
        store: EnrollmentStore,
        onState: suspend (ManagementChannelState) -> Unit,
    ) {
        var attempt = 0
        var authRefusals = 0
        while (currentCoroutineContext().isActive) {
            val identity = store.openIdentity()
            if (identity == null) {
                // No readable enrollment: nothing to connect with, and retrying cannot fix it.
                onState(ManagementChannelState.OFFLINE)
                return
            }
            val credential = String(identity.credentialForTransport(), Charsets.UTF_8)
            val deviceId = identity.deviceId
            identity.close()

            onState(
                if (attempt == 0) {
                    ManagementChannelState.CONNECTING
                } else {
                    ManagementChannelState.RETRYING
                },
            )

            var healthy = false
            try {
                val socket = openSocket(hub.controlUrl(deviceId), credential).getOrElse { error ->
                    if (error is HubFailure.Rejected && error.status in AUTH_REFUSAL_STATUSES) {
                        authRefusals += 1
                        if (authRefusals >= MAX_AUTH_REFUSALS) {
                            onState(ManagementChannelState.OFFLINE)
                            return
                        }
                        throw error
                    }
                    throw error
                }
                healthy = true
                authRefusals = 0
                onState(ManagementChannelState.ONLINE)
                socket.use { runSocket(it) }
            } catch (cancelled: CancellationException) {
                throw cancelled
            } catch (_: Exception) {
                // Every transport fault is retried: the channel is not the session, and a
                // dropped management socket must not stop the agent.
            }

            if (healthy) attempt = 0
            attempt += 1
            onState(ManagementChannelState.RETRYING)
            pause(backoffMs(attempt))
        }
    }

    /** One connected socket: announce the device, then samples up and commands down. */
    private suspend fun runSocket(socket: ControlSocket) {
        if (!socket.send(deviceInfo.hello().toString())) return
        coroutineScope {
            val samples = launch {
                while (isActive) {
                    val sample = JSONObject()
                        .put("type", "telemetry")
                        .put("sample", telemetry.sample().toJson())
                    if (!socket.send(sample.toString())) break
                    delay(telemetryIntervalMs)
                }
            }
            try {
                while (true) {
                    when (val frame = socket.receive()) {
                        is ControlFrame.Text -> handleCommand(socket, frame.text)
                        is ControlFrame.Closed -> break
                    }
                }
            } finally {
                samples.cancel()
            }
        }
    }

    private suspend fun handleCommand(socket: ControlSocket, text: String) {
        val command = try {
            JSONObject(text)
        } catch (_: JSONException) {
            // Not a command frame; the server guarantees JSON, so there is no one to answer.
            return
        }
        if (command.optString("type") != "command") return
        val requestId = command.optString("request_id")
        if (requestId.isEmpty()) return
        val name = command.optString("name")
        val deadlineMs = command
            .optLong("deadline_ms", DEFAULT_COMMAND_DEADLINE_MS)
            .coerceIn(1, MAX_COMMAND_DEADLINE_MS)

        // Arguments the handlers cannot use are refused by name, not silently treated as
        // "no arguments".
        val rawArgs = command.opt("args")
        if (rawArgs != null && rawArgs != JSONObject.NULL && rawArgs !is JSONObject) {
            socket.send(
                resultFrame(
                    requestId,
                    Result.failure(CommandFailure.invalid("args must be a JSON object")),
                ).toString(),
            )
            return
        }
        val args = rawArgs as? JSONObject

        // A command that was queued past the server's deadline must not run: the caller has
        // already been told `timeout`, and executing it now would invite a duplicate.
        val nowMs = clock()
        val expiresAtMs = command.optLong("expires_at_ms", 0L)
        if (expiresAtMs > 0L) {
            observeServerClock(expiresAtMs - deadlineMs, nowMs)
        }
        if (expiredBeforeStart(expiresAtMs, nowMs)) {
            socket.send(
                resultFrame(
                    requestId,
                    Result.failure(
                        CommandFailure(
                            "timeout",
                            "$name was queued past its deadline and was not executed",
                        ),
                    ),
                ).toString(),
            )
            return
        }

        val result = withTimeoutOrNull(deadlineMs) {
            withContext(Dispatchers.Default) { dispatcher.dispatch(name, args) }
        } ?: Result.failure(
            CommandFailure("timeout", "$name did not finish within ${deadlineMs}ms"),
        )
        socket.send(resultFrame(requestId, result).toString())
    }

    /**
     * Refuses to *start* a command whose absolute server deadline has already passed. The
     * device's own clock is only trusted through the offset learned from the channel, so
     * ordinary clock skew between the phone and the server cannot expire fresh commands.
     */
    private fun expiredBeforeStart(expiresAtMs: Long, nowMs: Long): Boolean {
        if (expiresAtMs <= 0L) return false
        val offset = serverOffsetMs ?: return false
        return nowMs + offset >= expiresAtMs
    }

    private fun observeServerClock(sentAtMs: Long, nowMs: Long) {
        val implied = sentAtMs - nowMs
        val current = serverOffsetMs
        if (current == null || implied > current) {
            serverOffsetMs = implied
        }
    }

    private fun resultFrame(requestId: String, result: Result<JSONObject>): JSONObject {
        val frame = JSONObject()
            .put("type", "result")
            .put("request_id", requestId)
        return result.fold(
            onSuccess = { output ->
                frame
                    .put("status", "ok")
                    .put("output", output)
                    .put("error", JSONObject.NULL)
                    .put("message", JSONObject.NULL)
            },
            onFailure = { error ->
                val failure = error as? CommandFailure
                    ?: CommandFailure.internal(error.message ?: error.javaClass.simpleName)
                frame
                    .put("status", "error")
                    .put("output", JSONObject.NULL)
                    .put("error", failure.code)
                    .put("message", failure.message ?: failure.code)
            },
        )
    }

    companion object {
        /** Telemetry cadence. The server calls a reading stale after 90 seconds. */
        const val DEFAULT_TELEMETRY_INTERVAL_MS: Long = 30_000

        const val DEFAULT_COMMAND_DEADLINE_MS: Long = 10_000
        const val MAX_COMMAND_DEADLINE_MS: Long = 60_000

        const val BASE_BACKOFF_MS: Long = 1_000
        const val MAX_BACKOFF_MS: Long = 60_000

        /** A credential refusal tolerated this many times before the channel stops. */
        const val MAX_AUTH_REFUSALS: Int = 5

        private val AUTH_REFUSAL_STATUSES = setOf(401, 403)
        private const val MAX_EXPONENT = 40

        /**
         * Reconnect delay for `attempt` (1-based): `1 s * 2^(attempt-1)`, capped at
         * [MAX_BACKOFF_MS]. Deterministic and bounded, so a fleet that lost the server does
         * not hammer it or wait forever.
         */
        fun backoffMs(attempt: Int): Long {
            val exponent = (attempt.coerceAtLeast(1) - 1).coerceAtMost(MAX_EXPONENT)
            if (BASE_BACKOFF_MS > (Long.MAX_VALUE shr exponent)) return MAX_BACKOFF_MS
            return (BASE_BACKOFF_MS shl exponent).coerceAtMost(MAX_BACKOFF_MS)
        }
    }
}

/**
 * The management route as an OkHttp WebSocket. Text frames only: the management protocol is
 * JSON, unlike the sealed relay's binary frames.
 */
class OkHttpControlSocket private constructor(
    private val webSocket: WebSocket,
    private val incoming: Channel<ControlFrame>,
) : ControlSocket {
    override suspend fun send(text: String): Boolean = webSocket.send(text)

    override suspend fun receive(): ControlFrame = incoming.receive()

    override fun close() {
        webSocket.close(NORMAL_CLOSURE, null)
        incoming.close()
    }

    companion object {
        private const val NORMAL_CLOSURE = 1000
        private const val BACKPRESSURE_CLOSE = 1008
        private const val HANDSHAKE_TIMEOUT_MS = 10_000L
        private const val PING_INTERVAL_SECONDS = 20L

        /** A client that keeps the channel alive without a command: pings reset the idle cap. */
        fun client(base: OkHttpClient = HubClient.defaultClient()): OkHttpClient =
            base.newBuilder().pingInterval(PING_INTERVAL_SECONDS, TimeUnit.SECONDS).build()

        suspend fun connect(
            url: String,
            bearer: String,
            client: OkHttpClient = client(),
        ): Result<ControlSocket> {
            val opened = CompletableDeferred<Result<Unit>>()
            val incoming = Channel<ControlFrame>(Channel.BUFFERED)
            val request = Request.Builder()
                .url(url)
                .header("Authorization", "Bearer $bearer")
                .build()
            val listener = object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    opened.complete(Result.success(Unit))
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                    if (!incoming.trySend(ControlFrame.Text(text)).isSuccess) {
                        // Bounded: a peer that outruns the command loop is closed rather than
                        // grown into an unbounded buffer.
                        webSocket.close(BACKPRESSURE_CLOSE, "backpressure")
                    }
                }

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    incoming.trySend(ControlFrame.Closed(reason.ifEmpty { null }))
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    incoming.trySend(ControlFrame.Closed(reason.ifEmpty { null }))
                    incoming.close()
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    val failure = handshakeFailure(response, t)
                    if (!opened.isCompleted) opened.complete(Result.failure(failure))
                    incoming.trySend(ControlFrame.Closed(failure.message))
                    incoming.close()
                }
            }
            val socket = client.newWebSocket(request, listener)
            val ready = withTimeoutOrNull(HANDSHAKE_TIMEOUT_MS) { opened.await() }
                ?: Result.failure(HubFailure.Unreachable("management handshake timed out"))
            return ready.fold(
                onSuccess = { Result.success(OkHttpControlSocket(socket, incoming)) },
                onFailure = { error ->
                    socket.cancel()
                    Result.failure(error)
                },
            )
        }

        /** The handshake answer, with the server's own code when it sent one. */
        internal fun handshakeFailure(response: Response?, error: Throwable): HubFailure = when {
            response == null -> HubFailure.Unreachable(error.message ?: "management handshake failed")
            else -> HubFailure.Rejected(response.code, errorCode(response))
        }

        private fun errorCode(response: Response): String = try {
            val body = response.peekBody(MAX_ERROR_BODY_BYTES).string()
            JSONObject(body).optString("error").takeIf { it.isNotEmpty() } ?: "http_${response.code}"
        } catch (_: Exception) {
            "http_${response.code}"
        }

        private const val MAX_ERROR_BODY_BYTES = 4L * 1024
    }
}

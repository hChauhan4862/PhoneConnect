package com.phoneconnect.agent.net

import com.phoneconnect.agent.ChannelEvent
import com.phoneconnect.agent.FrameChannel
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.withTimeoutOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okio.ByteString
import okio.ByteString.Companion.toByteString
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean

/**
 * The relay route as a [FrameChannel]: one binary WebSocket message per sealed PhoneConnect
 * frame, mirroring `WebSocketRelay` in `crates/transport/src/lib.rs`.
 *
 * Keepalive is a WebSocket ping every [KEEPALIVE_INTERVAL_SECONDS] seconds. The server closes
 * a relay direction that has carried nothing for 30 seconds, and a healthy direction may send
 * no frames at all, so the ping is what keeps the transport attached. The relay answers pings
 * itself: they are never forwarded to the peer, never enter the relay's bounded queue, and
 * never consume a sequence number.
 *
 * A `409 relay_unavailable` at the handshake is reported as
 * [HubFailure.Rejected] with `relay_unavailable`, which the caller must treat as terminal for
 * that session id. A server close frame's reason is passed through so revocation is visible.
 */
class RelayFrameChannel private constructor(
    private val webSocket: WebSocket,
    private val incoming: Channel<ChannelEvent>,
) : FrameChannel {
    private val closed = AtomicBoolean(false)

    override suspend fun send(frame: ByteArray) {
        if (!webSocket.send(frame.toByteString())) {
            throw HubFailure.Unreachable("relay socket is closed")
        }
    }

    override suspend fun receive(): ChannelEvent = incoming.receive()

    override fun close() {
        if (!closed.compareAndSet(false, true)) return
        webSocket.close(NORMAL_CLOSURE, null)
        incoming.close()
    }

    companion object {
        /**
         * A third of the server's 30-second idle timeout, the same interval the Rust
         * `PathConfig::relay_keepalive_interval` defaults to.
         */
        const val KEEPALIVE_INTERVAL_SECONDS: Long = 10
        private const val HANDSHAKE_TIMEOUT_MS = 10_000L
        private const val NORMAL_CLOSURE = 1000

        /** The client used for relay transports: pings on the Rust interval. */
        fun client(base: OkHttpClient = OkHttpClient()): OkHttpClient = base.newBuilder()
            .pingInterval(KEEPALIVE_INTERVAL_SECONDS, TimeUnit.SECONDS)
            .build()

        suspend fun connect(
            url: String,
            bearer: String,
            client: OkHttpClient = client(),
        ): Result<RelayFrameChannel> {
            val opened = CompletableDeferred<Unit>()
            val incoming = Channel<ChannelEvent>(Channel.BUFFERED)
            val request = Request.Builder()
                .url(url)
                .header("Authorization", "Bearer $bearer")
                .build()

            val listener = object : WebSocketListener() {
                override fun onOpen(webSocket: WebSocket, response: Response) {
                    opened.complete(Unit)
                }

                override fun onMessage(webSocket: WebSocket, bytes: ByteString) {
                    incoming.trySend(ChannelEvent.Frame(bytes.toByteArray()))
                }

                override fun onMessage(webSocket: WebSocket, text: String) {
                    // PhoneConnect frames are binary; a text message is a framing fault.
                    incoming.trySend(ChannelEvent.Closed("malformed_frame"))
                }

                override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
                    incoming.trySend(ChannelEvent.Closed(reason.ifEmpty { null }))
                }

                override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
                    incoming.trySend(ChannelEvent.Closed(reason.ifEmpty { null }))
                    incoming.close()
                }

                override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
                    val failure = handshakeFailure(response, t)
                    if (!opened.isCompleted) {
                        opened.completeExceptionally(failure)
                    }
                    incoming.trySend(ChannelEvent.Closed(null))
                    incoming.close()
                }
            }

            val socket = client.newWebSocket(request, listener)
            val ready = withTimeoutOrNull(HANDSHAKE_TIMEOUT_MS) {
                runCatching { opened.await() }
            } ?: Result.failure(HubFailure.Unreachable("relay handshake timed out"))
            return ready.fold(
                onSuccess = { Result.success(RelayFrameChannel(socket, incoming)) },
                onFailure = { error ->
                    socket.cancel()
                    Result.failure(error)
                },
            )
        }

        /**
         * Maps a refused WebSocket handshake. `409`, `404`, and `410` all mean "this session
         * can never relay": the protocol says create a new session rather than retry.
         */
        internal fun handshakeFailure(response: Response?, error: Throwable): HubFailure = when {
            response == null -> HubFailure.Unreachable(error.message ?: "relay handshake failed")
            response.code == 409 || response.code == 404 || response.code == 410 ->
                HubFailure.Rejected(response.code, "relay_unavailable")

            else -> HubFailure.Rejected(response.code, "relay_refused")
        }
    }
}

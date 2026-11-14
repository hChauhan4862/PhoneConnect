package com.phoneconnect.agent.net

import com.phoneconnect.agent.DeviceIdentity
import com.phoneconnect.agent.EnrollmentInfo
import com.phoneconnect.agent.EnrollmentRequest
import com.phoneconnect.agent.EnrollmentState
import com.phoneconnect.agent.EnrollmentStore
import com.phoneconnect.agent.IdentityBoundary
import com.phoneconnect.agent.ManagementChannelState
import com.phoneconnect.agent.ClearReason
import com.phoneconnect.agent.control.CommandDispatcher
import com.phoneconnect.agent.crypto.IdentityKey
import com.phoneconnect.agent.telemetry.BatteryReading
import com.phoneconnect.agent.telemetry.MemoryReading
import com.phoneconnect.agent.telemetry.TelemetrySampler
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import okhttp3.Response
import okhttp3.WebSocket
import okhttp3.WebSocketListener
import okhttp3.mockwebserver.MockResponse
import okhttp3.mockwebserver.MockWebServer
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Before
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config
import java.util.concurrent.atomic.AtomicInteger

/**
 * The management channel against a real WebSocket server: it announces the device, reports
 * telemetry, answers every command from the dispatcher, turns an unimplemented name into
 * `unknown_command`, and never retries past its bounds.
 */
@OptIn(IdentityBoundary::class)
@RunWith(RobolectricTestRunner::class)
@Config(sdk = [35])
class DeviceControlChannelTest {
    private lateinit var server: MockWebServer
    private lateinit var hub: HubClient

    private val telemetry = TelemetrySampler(
        battery = { BatteryReading(percent = 64, charging = true) },
        memory = { MemoryReading(usedBytes = 1_048_576, totalBytes = 8_388_608) },
        connectivity = { "wifi" },
        clock = { 1_760_000_000_000 },
    )

    @Before
    fun setUp() {
        server = MockWebServer()
        server.start()
        hub = HubClient.create(server.url("/").toString()).getOrThrow()
    }

    @After
    fun tearDown() {
        runCatching { server.shutdown() }
    }

    @Test
    fun `the channel announces the device and answers every command`() = runBlocking {
        val frames = Channel<JSONObject>(Channel.BUFFERED)
        val results = Channel<JSONObject>(Channel.BUFFERED)
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        val frame = JSONObject(text)
                        frames.trySend(frame)
                        when (frame.optString("type")) {
                            "hello" -> {
                                webSocket.send(command("cmd_1", "device.ping"))
                                webSocket.send(command("cmd_2", "no.such_command"))
                            }

                            "result" -> results.trySend(frame)
                            else -> Unit
                        }
                    }
                },
            ),
        )
        val channel = DeviceControlChannel(
            hub = hub,
            dispatcher = CommandDispatcher(telemetry = telemetry),
            telemetry = telemetry,
            telemetryIntervalMs = 60_000,
        )
        val states = mutableListOf<ManagementChannelState>()
        val job = launch(Dispatchers.IO) { channel.run(Store()) { states += it } }

        val first = withTimeout(20_000) { results.receive() }
        val second = withTimeout(20_000) { results.receive() }

        assertEquals("cmd_1", first.getString("request_id"))
        assertEquals("ok", first.getString("status"))
        assertEquals(true, first.getJSONObject("output").getBoolean("pong"))
        assertEquals("cmd_2", second.getString("request_id"))
        assertEquals("error", second.getString("status"))
        assertEquals("unknown_command", second.getString("error"))

        // Frames are ordered on one socket: the device announces itself before it samples.
        val hello = withTimeout(20_000) { frames.receive() }
        assertEquals("hello", hello.getString("type"))
        assertTrue("the hello names the device model", hello.has("model"))
        assertTrue("the hello names the platform version", hello.has("android_version"))

        val telemetryFrame = withTimeout(20_000) { frames.receive() }
        assertEquals("telemetry", telemetryFrame.getString("type"))
        assertEquals(64, telemetryFrame.getJSONObject("sample").getInt("battery_percent"))

        val handshake = server.takeRequest()
        assertEquals("/api/devices/dev_1/control", handshake.path)
        assertEquals("Bearer pcdev_test", handshake.headers["Authorization"])

        job.cancel()
        assertTrue("the channel reports going online", states.contains(ManagementChannelState.ONLINE))
    }

    @Test
    fun `a command that outlives its deadline answers timeout`() = runBlocking {
        val results = Channel<JSONObject>(Channel.BUFFERED)
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        val frame = JSONObject(text)
                        when (frame.optString("type")) {
                            "hello" -> webSocket.send(command("cmd_slow", "device.ping", deadlineMs = 50))
                            "result" -> results.trySend(frame)
                            else -> Unit
                        }
                    }
                },
            ),
        )
        val slow = object : CommandDispatcher(telemetry = telemetry) {
            override suspend fun dispatch(name: String, args: JSONObject?): Result<JSONObject> {
                delay(5_000)
                return Result.success(JSONObject())
            }
        }
        val channel = DeviceControlChannel(
            hub = hub,
            dispatcher = slow,
            telemetry = telemetry,
            telemetryIntervalMs = 60_000,
        )
        val job = launch(Dispatchers.IO) { channel.run(Store()) { } }

        val result = withTimeout(20_000) { results.receive() }
        job.cancel()

        assertEquals("cmd_slow", result.getString("request_id"))
        assertEquals("error", result.getString("status"))
        assertEquals("timeout", result.getString("error"))
    }

    @Test
    fun `a repeatedly refused credential stops the channel as offline`() = runBlocking {
        val attempts = AtomicInteger()
        val channel = DeviceControlChannel(
            hub = hub,
            dispatcher = CommandDispatcher(telemetry = telemetry),
            telemetry = telemetry,
            openSocket = { _, _ ->
                attempts.incrementAndGet()
                Result.failure(HubFailure.Rejected(401, "invalid_credential"))
            },
            pause = { },
        )
        val states = mutableListOf<ManagementChannelState>()

        withTimeout(20_000) { channel.run(Store()) { states += it } }

        assertEquals(
            "a refused credential is retried a bounded number of times",
            DeviceControlChannel.MAX_AUTH_REFUSALS,
            attempts.get(),
        )
        assertEquals(ManagementChannelState.OFFLINE, states.last())
    }

    @Test
    fun `a command queued past its server deadline is refused without running`() = runBlocking {
        val serverBase = 1_760_000_000_000L
        val deviceNow = java.util.concurrent.atomic.AtomicLong(1_000)
        val executed = java.util.Collections.synchronizedList(mutableListOf<String>())
        val results = Channel<JSONObject>(Channel.BUFFERED)
        val handlers = object : CommandDispatcher(telemetry = telemetry) {
            override suspend fun dispatch(name: String, args: JSONObject?): Result<JSONObject> {
                executed += name
                return Result.success(JSONObject().put("pong", true))
            }
        }
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        val frame = JSONObject(text)
                        when (frame.optString("type")) {
                            "hello" -> webSocket.send(
                                command("cmd_1", "device.ping", expiresAtMs = serverBase + 10_000),
                            )

                            "result" -> {
                                results.trySend(frame)
                                when (frame.optString("request_id")) {
                                    "cmd_1" -> {
                                        // 600 s pass while the channel is busy, then three
                                        // frames arrive: two that waited out their deadline
                                        // back to back, and one the server dispatched only now.
                                        deviceNow.addAndGet(600_000)
                                        webSocket.send(
                                            command("cmd_2", "device.info", expiresAtMs = serverBase + 10_000),
                                        )
                                        webSocket.send(
                                            command("cmd_3", "device.info", expiresAtMs = serverBase + 10_000),
                                        )
                                        webSocket.send(
                                            command(
                                                "cmd_4",
                                                "device.info",
                                                expiresAtMs = serverBase + 600_000 + 10_000,
                                            ),
                                        )
                                    }
                                }
                            }

                            else -> Unit
                        }
                    }
                },
            ),
        )
        val channel = DeviceControlChannel(
            hub = hub,
            dispatcher = handlers,
            telemetry = telemetry,
            telemetryIntervalMs = 60_000,
            clock = { deviceNow.get() },
        )
        val job = launch(Dispatchers.IO) { channel.run(Store()) { } }

        val first = withTimeout(20_000) { results.receive() }
        assertEquals("cmd_1", first.getString("request_id"))
        assertEquals("ok", first.getString("status"))

        // The second stale frame arrives right behind the first: a naive "time since the last
        // frame" estimate would be contaminated by that, so it must still be refused.
        for (staleId in listOf("cmd_2", "cmd_3")) {
            val stale = withTimeout(20_000) { results.receive() }
            assertEquals(staleId, stale.getString("request_id"))
            assertEquals("error", stale.getString("status"))
            assertEquals("timeout", stale.getString("error"))
        }

        val fresh = withTimeout(20_000) { results.receive() }
        assertEquals("cmd_4", fresh.getString("request_id"))
        assertEquals("ok", fresh.getString("status"))

        job.cancel()
        assertEquals(
            "a stale command must never reach a handler, and a fresh one must",
            listOf("device.ping", "device.info"),
            executed.toList(),
        )
    }

    @Test
    fun `arguments that are not a JSON object are refused as invalid_args`() = runBlocking {
        val executed = java.util.Collections.synchronizedList(mutableListOf<String>())
        val result = Channel<JSONObject>(Channel.BUFFERED)
        val handlers = object : CommandDispatcher(telemetry = telemetry) {
            override suspend fun dispatch(name: String, args: JSONObject?): Result<JSONObject> {
                executed += name
                return Result.success(JSONObject())
            }
        }
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        val frame = JSONObject(text)
                        when (frame.optString("type")) {
                            "hello" -> webSocket.send(
                                JSONObject()
                                    .put("type", "command")
                                    .put("request_id", "cmd_args")
                                    .put("name", "device.info")
                                    .put("args", org.json.JSONArray().put("not").put("an object"))
                                    .put("deadline_ms", 10_000)
                                    .toString(),
                            )

                            "result" -> result.trySend(frame)
                            else -> Unit
                        }
                    }
                },
            ),
        )
        val channel = DeviceControlChannel(
            hub = hub,
            dispatcher = handlers,
            telemetry = telemetry,
            telemetryIntervalMs = 60_000,
        )
        val job = launch(Dispatchers.IO) { channel.run(Store()) { } }

        val answer = withTimeout(20_000) { result.receive() }
        job.cancel()

        assertEquals("error", answer.getString("status"))
        assertEquals("invalid_args", answer.getString("error"))
        assertTrue("the handler must not run for unusable arguments", executed.isEmpty())
    }

    @Test
    fun `a forward device-clock step is revised down so fresh commands run again`() = runBlocking {
        val serverBase = 1_760_000_000_000L
        val deviceNow = java.util.concurrent.atomic.AtomicLong(1_000)
        val results = Channel<JSONObject>(Channel.BUFFERED)
        val sent = java.util.concurrent.atomic.AtomicInteger()
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        val frame = JSONObject(text)
                        when (frame.optString("type")) {
                            "hello" -> webSocket.send(
                                command("cmd_1", "device.ping", expiresAtMs = serverBase + 10_000),
                            )

                            "result" -> {
                                results.trySend(frame)
                                // An NTP correction moves the device clock forward by 600 s
                                // after the first answer; every later sample then implies a
                                // much smaller offset than the stored one.
                                if (sent.getAndIncrement() == 0) {
                                    deviceNow.addAndGet(600_000)
                                }
                                if (sent.get() <= 4) {
                                    webSocket.send(
                                        command(
                                            "cmd_${sent.get() + 1}",
                                            "device.ping",
                                            expiresAtMs = serverBase + 10_000,
                                        ),
                                    )
                                }
                            }

                            else -> Unit
                        }
                    }
                },
            ),
        )
        val channel = DeviceControlChannel(
            hub = hub,
            dispatcher = CommandDispatcher(telemetry = telemetry),
            telemetry = telemetry,
            telemetryIntervalMs = 60_000,
            clock = { deviceNow.get() },
        )
        val job = launch(Dispatchers.IO) { channel.run(Store()) { } }

        assertEquals("ok", withTimeout(20_000) { results.receive() }.getString("status"))
        // The stored estimate is still the pre-step one, so the first fresh commands look
        // expired; several agreeing lower samples revise it and the channel recovers instead of
        // refusing every command until the process restarts.
        repeat(2) {
            val refused = withTimeout(20_000) { results.receive() }
            assertEquals("error", refused.getString("status"))
            assertEquals("timeout", refused.getString("error"))
        }
        val recovered = withTimeout(20_000) { results.receive() }
        assertEquals("ok", recovered.getString("status"))

        job.cancel()
    }

    @Test
    fun `a new socket re-learns the server clock`() = runBlocking {
        val serverBase = 1_760_000_000_000L
        val deviceNow = java.util.concurrent.atomic.AtomicLong(1_000)
        val results = Channel<JSONObject>(Channel.BUFFERED)
        val sockets = java.util.concurrent.atomic.AtomicInteger()
        val listener = object : WebSocketListener() {
            override fun onOpen(webSocket: WebSocket, response: Response) {
                sockets.incrementAndGet()
            }

            override fun onMessage(webSocket: WebSocket, text: String) {
                val frame = JSONObject(text)
                when (frame.optString("type")) {
                    "hello" -> webSocket.send(
                        command("cmd_${sockets.get()}", "device.ping", expiresAtMs = serverBase + 10_000),
                    )

                    "result" -> {
                        results.trySend(frame)
                        if (sockets.get() == 1) {
                            // The device clock steps while the first socket is up, then the
                            // channel reconnects: the new socket must not inherit the stale
                            // estimate.
                            deviceNow.addAndGet(600_000)
                            webSocket.close(1008, "replaced")
                        }
                    }

                    else -> Unit
                }
            }
        }
        server.enqueue(MockResponse().withWebSocketUpgrade(listener))
        server.enqueue(MockResponse().withWebSocketUpgrade(listener))
        val channel = DeviceControlChannel(
            hub = hub,
            dispatcher = CommandDispatcher(telemetry = telemetry),
            telemetry = telemetry,
            telemetryIntervalMs = 60_000,
            pause = { },
            clock = { deviceNow.get() },
        )
        val job = launch(Dispatchers.IO) { channel.run(Store()) { } }

        assertEquals("ok", withTimeout(20_000) { results.receive() }.getString("status"))
        val second = withTimeout(20_000) { results.receive() }

        job.cancel()
        assertEquals("cmd_2", second.getString("request_id"))
        assertEquals("ok", second.getString("status"))
    }

    @Test
    fun `a command is stopped by its remaining server budget, not the full deadline`() = runBlocking {
        val serverBase = 1_760_000_000_000L
        val results = Channel<JSONObject>(Channel.BUFFERED)
        val cancelled = java.util.concurrent.atomic.AtomicBoolean(false)
        val slow = object : CommandDispatcher(telemetry = telemetry) {
            override suspend fun dispatch(name: String, args: JSONObject?): Result<JSONObject> {
                if (name == "device.ping") return Result.success(JSONObject().put("pong", true))
                try {
                    kotlinx.coroutines.delay(30_000)
                } catch (stopped: kotlinx.coroutines.CancellationException) {
                    cancelled.set(true)
                    throw stopped
                }
                return Result.success(JSONObject())
            }
        }
        server.enqueue(
            MockResponse().withWebSocketUpgrade(
                object : WebSocketListener() {
                    override fun onMessage(webSocket: WebSocket, text: String) {
                        val frame = JSONObject(text)
                        when (frame.optString("type")) {
                            "hello" -> webSocket.send(
                                command("cmd_1", "device.ping", expiresAtMs = serverBase + 10_000),
                            )

                            "result" -> {
                                results.trySend(frame)
                                if (frame.optString("request_id") == "cmd_1") {
                                    // A second command the server issued with only 1.5 s of its
                                    // absolute budget left, but a 10 s deadline.
                                    webSocket.send(
                                        command("cmd_slow", "device.info", expiresAtMs = serverBase + 1_500),
                                    )
                                }
                            }

                            else -> Unit
                        }
                    }
                },
            ),
        )
        val channel = DeviceControlChannel(
            hub = hub,
            dispatcher = slow,
            telemetry = telemetry,
            telemetryIntervalMs = 60_000,
            clock = { 1_000 },
        )
        val job = launch(Dispatchers.IO) { channel.run(Store()) { } }

        assertEquals("ok", withTimeout(20_000) { results.receive() }.getString("status"))
        val startedAt = System.nanoTime()
        val stopped = withTimeout(20_000) { results.receive() }
        val elapsedMs = (System.nanoTime() - startedAt) / 1_000_000

        job.cancel()
        assertEquals("cmd_slow", stopped.getString("request_id"))
        assertEquals("error", stopped.getString("status"))
        assertEquals("timeout", stopped.getString("error"))
        assertTrue(
            "the handler must stop near its remaining budget, not its 10 s deadline; took ${elapsedMs}ms",
            elapsedMs in 1_000..5_000,
        )
        assertTrue("the handler must be cancelled, not left running", cancelled.get())
    }

    private class Store : EnrollmentStore {
        override suspend fun info(): EnrollmentInfo =
            EnrollmentInfo("dev_1", EnrollmentState.ENROLLED, 1_000)

        override suspend fun lastClearReason(): ClearReason? = null

        override suspend fun enroll(request: EnrollmentRequest) = Unit

        override suspend fun openIdentity(): DeviceIdentity = DeviceIdentity(
            deviceId = "dev_1",
            credentialBytes = "pcdev_test".toByteArray(),
            privateKeyBytes = ByteArray(32) { 0x33 },
            identityPublicKey = IdentityKey.fromBytes(ByteArray(32) { 0x33 }).getOrThrow().publicKey(),
        )

        override suspend fun clear(reason: ClearReason): Boolean = true
    }

    private fun command(
        requestId: String,
        name: String,
        deadlineMs: Long = 10_000,
        expiresAtMs: Long = 0,
    ): String = JSONObject()
        .put("type", "command")
        .put("request_id", requestId)
        .put("name", name)
        .put("args", JSONObject.NULL)
        .put("deadline_ms", deadlineMs)
        .put("expires_at_ms", expiresAtMs)
        .toString()
}

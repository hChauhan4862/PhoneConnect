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
                                webSocket.send(command("cmd_2", "files.list"))
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
    ): String = JSONObject()
        .put("type", "command")
        .put("request_id", requestId)
        .put("name", name)
        .put("args", JSONObject.NULL)
        .put("deadline_ms", deadlineMs)
        .toString()
}

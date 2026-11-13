package com.phoneconnect.agent

import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.launch
import kotlinx.coroutines.test.advanceUntilIdle
import kotlinx.coroutines.test.runCurrent
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

@OptIn(IdentityBoundary::class, kotlinx.coroutines.ExperimentalCoroutinesApi::class)
class ConnectionSupervisorTest {
    private val policy = ReconnectPolicy(random = { 0.5 })

    @Test
    fun `backoff grows and resets to the base delay after a healthy connection`() = runTest {
        val store = FakeEnrollmentStore()
        val runner = ScriptedRunner(
            listOf(
                Step(end = failed(ReconnectReason.TRANSPORT_CLOSED)),
                Step(end = failed(ReconnectReason.TRANSPORT_CLOSED)),
                // A healthy connection in between must reset the attempt counter.
                Step(healthy = ConnectionPath.RELAY, end = failed(ReconnectReason.TRANSPORT_CLOSED)),
                Step(end = SessionEnd.Failed(ConnectionFailure.DeviceRevoked)),
            ),
        )
        val statuses = mutableListOf<ConnectionStatus>()

        val outcome = supervisor(store, runner, statuses).run()

        assertEquals(SupervisorOutcome.Terminal(ConnectionFailure.DeviceRevoked), outcome)
        assertEquals(
            listOf(1_000L, 2_000L, 1_000L),
            statuses.filterIsInstance<ConnectionStatus.Reconnecting>().map { it.retryInMs },
        )
        assertEquals(4, runner.starts)
        assertTrue(statuses.any { it is ConnectionStatus.Connected })
    }

    @Test
    fun `device revocation clears the enrollment and stops retrying`() = runTest {
        val store = FakeEnrollmentStore()
        val runner = ScriptedRunner(listOf(Step(end = SessionEnd.Failed(ConnectionFailure.DeviceRevoked))))
        val statuses = mutableListOf<ConnectionStatus>()

        val outcome = supervisor(store, runner, statuses).run()

        assertEquals(SupervisorOutcome.Terminal(ConnectionFailure.DeviceRevoked), outcome)
        assertEquals(listOf(ClearReason.REVOKED), store.clears)
        assertEquals("a revoked device must not be retried", 1, runner.starts)
        assertTrue(statuses.last() is ConnectionStatus.Terminal)
        assertEquals(null, store.info())
    }

    @Test
    fun `a terminal relay 409 ends the session but keeps the enrollment`() = runTest {
        val store = FakeEnrollmentStore()
        val runner = ScriptedRunner(listOf(Step(end = SessionEnd.Failed(ConnectionFailure.RelayUnavailable))))
        val statuses = mutableListOf<ConnectionStatus>()

        val outcome = supervisor(store, runner, statuses).run()

        assertEquals(SupervisorOutcome.Terminal(ConnectionFailure.RelayUnavailable), outcome)
        assertEquals("a relay 409 must not destroy the device credential", emptyList<ClearReason>(), store.clears)
        assertEquals(1, runner.starts)
        assertEquals("dev_1", store.info()?.deviceId)
    }

    @Test
    fun `no enrollment stops without retrying or touching storage`() = runTest {
        val store = FakeEnrollmentStore(initial = null)
        val runner = ScriptedRunner(emptyList())
        val statuses = mutableListOf<ConnectionStatus>()

        val outcome = supervisor(store, runner, statuses).run()

        assertEquals(SupervisorOutcome.Unenrolled, outcome)
        assertEquals(0, runner.starts)
        assertEquals(emptyList<ClearReason>(), store.clears)
        assertEquals(ConnectionStatus.Unenrolled, statuses.single())
    }

    @Test
    fun `a network callback wakes the backoff wait instead of waiting out the delay`() = runTest {
        val store = FakeEnrollmentStore()
        val runner = ScriptedRunner(
            listOf(
                Step(end = failed(ReconnectReason.NETWORK_UNAVAILABLE)),
                Step(end = SessionEnd.Failed(ConnectionFailure.DeviceRevoked)),
            ),
        )
        val supervisor = supervisor(store, runner, mutableListOf())

        val job = launch { supervisor.run() }
        runCurrent()
        assertEquals("the first attempt must have failed already", 1, runner.starts)

        supervisor.onNetworkAvailable()
        runCurrent()

        assertEquals("the retry must run without waiting out the announced delay", 2, runner.starts)
        assertTrue(
            "the virtual clock must still be inside the announced delay, was ${testScheduler.currentTime}",
            testScheduler.currentTime < 1_000L,
        )
        job.cancel()
        advanceUntilIdle()
    }

    @Test
    fun `cancellation of the supervisor cancels the in-flight session`() = runTest {
        val store = FakeEnrollmentStore()
        val runner = ScriptedRunner(listOf(Step(end = failed(ReconnectReason.TRANSPORT_CLOSED))))
        val supervisor = supervisor(store, runner, mutableListOf())

        val job = launch { supervisor.run() }
        runCurrent()
        job.cancel()
        advanceUntilIdle()

        assertTrue("cancelling must not clear credentials", store.clears.isEmpty())
    }

    @Test
    fun `an unexpected exception from the transport is a retryable protocol failure`() = runTest {
        val store = FakeEnrollmentStore()
        val runner = ScriptedRunner(emptyList()) { throw IllegalStateException("boom") }
        val statuses = mutableListOf<ConnectionStatus>()

        val job = launch { supervisor(store, runner, statuses).run() }
        runCurrent()

        val reconnecting = statuses.filterIsInstance<ConnectionStatus.Reconnecting>().single()
        assertEquals(ReconnectReason.PROTOCOL_ERROR, reconnecting.reason)
        job.cancel()
        advanceUntilIdle()
    }

    private fun supervisor(
        store: EnrollmentStore,
        runner: SessionRunner,
        statuses: MutableList<ConnectionStatus>,
    ) = ConnectionSupervisor(
        store = store,
        sessions = runner,
        policy = policy,
        status = { statuses += it },
        clock = { 1_000L },
    )

    private fun failed(reason: ReconnectReason) = SessionEnd.Failed(ConnectionFailure.Retryable(reason))

    private data class Step(val healthy: ConnectionPath? = null, val end: SessionEnd)

    private class ScriptedRunner(
        private val steps: List<Step>,
        private val block: (suspend () -> Unit)? = null,
    ) : SessionRunner {
        private val queue = ArrayDeque(steps)
        var starts = 0
            private set

        override suspend fun run(
            store: EnrollmentStore,
            onConnected: (ConnectionPath) -> Unit,
        ): SessionEnd {
            starts += 1
            block?.invoke()
            val step = queue.removeFirstOrNull() ?: awaitCancellation()
            step.healthy?.let(onConnected)
            return step.end
        }
    }

    private class FakeEnrollmentStore(
        initial: EnrollmentInfo? = EnrollmentInfo("dev_1", EnrollmentState.ENROLLED, 1_000L),
    ) : EnrollmentStore {
        private var enrollment: EnrollmentInfo? = initial
        private var lastClear: ClearReason? = null
        val clears = mutableListOf<ClearReason>()

        override suspend fun info(): EnrollmentInfo? = enrollment

        override suspend fun lastClearReason(): ClearReason? = lastClear

        override suspend fun enroll(request: EnrollmentRequest) {
            enrollment = EnrollmentInfo(request.deviceId, EnrollmentState.ENROLLED, request.enrolledAtMs)
        }

        override suspend fun openIdentity(): DeviceIdentity? = null

        override suspend fun clear(reason: ClearReason): Boolean {
            clears += reason
            lastClear = reason
            enrollment = null
            return true
        }
    }
}

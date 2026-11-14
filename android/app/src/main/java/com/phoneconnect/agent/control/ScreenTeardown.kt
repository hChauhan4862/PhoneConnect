package com.phoneconnect.agent.control

import java.util.concurrent.Executor
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors

/**
 * The one worker every screen capture's teardown runs on.
 *
 * A per-capture executor would leave a live `pc-screen-teardown` thread behind on every service
 * stop/start cycle. One process-wide worker is enough: teardown work is short and never runs
 * concurrently with itself, and the service shuts it down in `onDestroy` with [dispose].
 */
internal object ScreenTeardown : Executor {
    private var worker: ExecutorService = newWorker()

    @Synchronized
    override fun execute(command: Runnable) {
        worker.execute(command)
    }

    /**
     * Shuts the worker down and arms a fresh one for a later service. Work already queued still
     * runs; the thread ends afterwards, so nothing outlives the service that queued it.
     */
    @Synchronized
    fun dispose() {
        val previous = worker
        worker = newWorker()
        previous.shutdown()
    }

    fun threadName(): String = THREAD_NAME

    private fun newWorker(): ExecutorService = Executors.newSingleThreadExecutor { runnable ->
        Thread(runnable, THREAD_NAME).apply { isDaemon = true }
    }

    private const val THREAD_NAME = "pc-screen-teardown"
}

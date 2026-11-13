package com.phoneconnect.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.launch

/**
 * Boot and post-update recovery for the one connection service.
 *
 * It only asks for the service when an enrollment exists: starting a foreground service on a
 * device that has nothing to connect to would be noise, and the start may be refused anyway.
 * The enrollment read happens off the main thread through [goAsync], and a refusal is
 * recorded for the setup screen instead of crashing the receiver.
 *
 * `connectedDevice` is the service type, which is one of the types Android 15 still allows
 * to be started from `BOOT_COMPLETED`; the catch is still required because any OEM policy
 * may refuse it.
 */
open class RecoveryReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> Unit
            else -> return
        }
        val pending = runCatching { goAsync() }.getOrNull()
        val appContext = context.applicationContext
        backgroundScope().launch {
            try {
                if (enrollmentStore(appContext).info()?.state == EnrollmentState.ENROLLED) {
                    when (val result = ConnectionService.requestStart(appContext)) {
                        is StartResult.Refused -> AgentDiagnostics(appContext).recordStartRefusal(result.reason)
                        StartResult.Started -> AgentDiagnostics(appContext).clearStartRefusal()
                    }
                }
            } finally {
                pending?.finish()
            }
        }
    }

    internal open fun enrollmentStore(context: Context): EnrollmentStore = KeystoreEnrollmentStore(context)

    /** Test seam: production work runs on the IO dispatcher, off the main thread. */
    internal open fun backgroundScope(): CoroutineScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
}

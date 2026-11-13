package com.phoneconnect.agent

import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import kotlinx.coroutines.runBlocking

/**
 * Boot and post-update recovery for the one connection service.
 *
 * It only asks for the service when an enrollment exists: starting a foreground service on
 * a device that has nothing to connect to would be noise, and on recent Android it would
 * also be a notification the user cannot act on.
 */
open class RecoveryReceiver : BroadcastReceiver() {
    override fun onReceive(context: Context, intent: Intent) {
        when (intent.action) {
            Intent.ACTION_BOOT_COMPLETED, Intent.ACTION_MY_PACKAGE_REPLACED -> Unit
            else -> return
        }
        // The store read is one small preferences lookup; it must finish before onReceive
        // returns because the receiver's process may be reclaimed right after.
        val enrollment = runBlocking { enrollmentStore(context).info() }
        if (enrollment?.state == EnrollmentState.ENROLLED) {
            ConnectionService.requestStart(context)
        }
    }

    internal open fun enrollmentStore(context: Context): EnrollmentStore = KeystoreEnrollmentStore(context)
}

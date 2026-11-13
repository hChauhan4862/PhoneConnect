package com.phoneconnect.agent

import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow

/**
 * The latest [ConnectionStatus], published by the service for the in-app status screen.
 *
 * The notification is the durable surface; this is only the in-process view while the setup
 * screen is visible, so it holds no history and persists nothing.
 */
object ConnectionStatusBus {
    private val _status = MutableStateFlow<ConnectionStatus?>(null)

    val status: StateFlow<ConnectionStatus?> = _status

    fun publish(status: ConnectionStatus) {
        _status.value = status
    }
}

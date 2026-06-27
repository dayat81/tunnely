package com.tunnely.app.vpn

import com.tunnely.app.api.ApiClient
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

data class FlowEntry(
    val server: String,
    val port: Int,
    val protocol: String,
    val uplinkBytes: Long,
    val downlinkBytes: Long
) {
    val displayServer: String get() = "$server:$port"
    val displayUplink: String get() = formatBytes(uplinkBytes)
    val displayDownlink: String get() = formatBytes(downlinkBytes)

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024.0))} MB"
            else -> "${"%.2f".format(bytes / (1024.0 * 1024.0 * 1024.0))} GB"
        }
    }
}

enum class FlowSortMode {
    UPLINK,
    DOWNLINK,
    SERVER
}

class FlowMonitor(
    private val apiClient: ApiClient,
    private val prefs: VpnPreferences
) {
    companion object {
        const val POLL_INTERVAL_MS = 5000L
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var pollJob: Job? = null

    private val _flows = MutableStateFlow<List<FlowEntry>>(emptyList())
    val flows: StateFlow<List<FlowEntry>> = _flows.asStateFlow()

    private val _sortMode = MutableStateFlow(FlowSortMode.DOWNLINK)
    val sortMode: StateFlow<FlowSortMode> = _sortMode.asStateFlow()

    fun start(tunnelIp: String) {
        stop()
        pollJob = scope.launch {
            while (isActive) {
                try {
                    val data = apiClient.getTrafficData(tunnelIp)
                    _flows.value = sortFlows(data, _sortMode.value)
                } catch (e: Exception) {
                    // Silently retry on next poll
                }
                delay(POLL_INTERVAL_MS)
            }
        }
    }

    fun stop() {
        pollJob?.cancel()
        pollJob = null
        _flows.value = emptyList()
    }

    fun setSortMode(mode: FlowSortMode) {
        _sortMode.value = mode
        _flows.value = sortFlows(_flows.value, mode)
    }

    private fun sortFlows(flows: List<FlowEntry>, mode: FlowSortMode): List<FlowEntry> {
        return when (mode) {
            FlowSortMode.UPLINK -> flows.sortedByDescending { it.uplinkBytes }
            FlowSortMode.DOWNLINK -> flows.sortedByDescending { it.downlinkBytes }
            FlowSortMode.SERVER -> flows.sortedBy { it.server }
        }
    }

    fun destroy() {
        scope.cancel()
    }
}

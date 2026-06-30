package com.tunnely.app.vpn

import com.tunnely.app.api.ApiClient
import kotlinx.coroutines.*
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import org.json.JSONObject

data class FlowEntry(
    val server: String,
    val domain: String? = null,
    val port: Int,
    val protocol: String,
    val uplinkBytes: Long,
    val downlinkBytes: Long
) {
    val displayServer: String get() = if (domain != null) "$domain" else "$server:$port"
    val displayServerWithPort: String get() = if (domain != null) "$domain:$port" else "$server:$port"
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

data class ServerTrafficStats(
    val wgRx: Long = 0,
    val wgTx: Long = 0,
    val rxRate: Long = 0,
    val txRate: Long = 0,
    val activeFlows: Int = 0,
    val totalFlows: Int = 0,
    val protocols: Map<String, Int> = emptyMap(),
    val topDestinations: List<String> = emptyList()
)

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
        const val POLL_INTERVAL_MS = 3000L
    }

    private val scope = CoroutineScope(Dispatchers.IO + SupervisorJob())
    private var pollJob: Job? = null

    private val _flows = MutableStateFlow<List<FlowEntry>>(emptyList())
    val flows: StateFlow<List<FlowEntry>> = _flows.asStateFlow()

    private val _serverStats = MutableStateFlow(ServerTrafficStats())
    val serverStats: StateFlow<ServerTrafficStats> = _serverStats.asStateFlow()

    private val _sortMode = MutableStateFlow(FlowSortMode.DOWNLINK)
    val sortMode: StateFlow<FlowSortMode> = _sortMode.asStateFlow()

    fun start(tunnelIp: String) {
        stop()
        pollJob = scope.launch {
            while (isActive) {
                try {
                    // Try server-side flow data first
                    val serverFlows = try {
                        apiClient.getTrafficData(tunnelIp)
                    } catch (_: Exception) {
                        emptyList()
                    }

                    // Also get client-side flows from /proc/net/tcp
                    val localFlows = try {
                        LocalFlowReader.getActiveConnections()
                    } catch (_: Exception) {
                        emptyList()
                    }

                    // Merge: prefer server flows, supplement with local
                    val merged = if (serverFlows.isNotEmpty()) {
                        // Add local flows that aren't already in server data
                        val serverKeys = serverFlows.map { "${it.server}:${it.port}" }.toSet()
                        val extraLocal = localFlows.filter { "${it.server}:${it.port}" !in serverKeys }
                        serverFlows + extraLocal
                    } else {
                        localFlows
                    }

                    _flows.value = sortFlows(merged, _sortMode.value)

                    // Also get aggregate stats from server
                    try {
                        val statsJson = apiClient.getTrafficStatsRaw(tunnelIp)
                        if (statsJson != null) {
                            val peer = statsJson.optJSONObject("peer")
                            _serverStats.value = ServerTrafficStats(
                                wgRx = peer?.optLong("wg_rx", 0) ?: 0,
                                wgTx = peer?.optLong("wg_tx", 0) ?: 0,
                                rxRate = statsJson.optLong("rx_rate", 0),
                                txRate = statsJson.optLong("tx_rate", 0),
                                activeFlows = statsJson.optInt("active_flows", 0),
                                totalFlows = statsJson.optInt("total_flows", 0)
                            )
                        }
                    } catch (_: Exception) {
                        // Stats endpoint may not be available
                    }
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
        _serverStats.value = ServerTrafficStats()
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

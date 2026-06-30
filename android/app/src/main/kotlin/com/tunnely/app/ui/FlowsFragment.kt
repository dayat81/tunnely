package com.tunnely.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
import androidx.cardview.widget.CardView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.tunnely.app.R
import com.tunnely.app.TunnelyApp
import com.tunnely.app.api.ApiClient
import com.tunnely.app.vpn.*
import com.google.android.material.button.MaterialButton
import com.google.android.material.button.MaterialButtonToggleGroup
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class FlowsFragment : Fragment() {

    private lateinit var recyclerView: RecyclerView
    private lateinit var emptyView: TextView
    private lateinit var adapter: FlowAdapter
    private lateinit var sortToggle: MaterialButtonToggleGroup
    private lateinit var btnSortUplink: MaterialButton
    private lateinit var btnSortDownlink: MaterialButton
    private lateinit var btnSortServer: MaterialButton

    // Server stats views
    private lateinit var statsCard: CardView
    private lateinit var statsRxRate: TextView
    private lateinit var statsRxTotal: TextView
    private lateinit var statsTxRate: TextView
    private lateinit var statsTxTotal: TextView
    private lateinit var statsFlows: TextView
    private lateinit var statsFlowsTotal: TextView

    // Latency views
    private lateinit var latencyUplink: TextView
    private lateinit var latencyDownlink: TextView
    private lateinit var latencyRtt: TextView

    private var flowMonitor: FlowMonitor? = null

    // Rate calculation state — delta-based so it works when backgrounded
    private var prevRxBytes: Long = -1
    private var prevTxBytes: Long = -1
    private var prevPollTimeMs: Long = 0

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_flows, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        initViews(view)
        setupRecyclerView()
        setupSortButtons()

        // Show empty state initially
        updateEmptyState(true, false)

        // Observe VPN state to start/stop flow monitoring
        observeVpnState()
    }

    private fun initViews(view: View) {
        recyclerView = view.findViewById(R.id.flows_recycler)
        emptyView = view.findViewById(R.id.empty_view)
        sortToggle = view.findViewById(R.id.sort_toggle)
        btnSortUplink = view.findViewById(R.id.btn_sort_uplink)
        btnSortDownlink = view.findViewById(R.id.btn_sort_downlink)
        btnSortServer = view.findViewById(R.id.btn_sort_server)

        // Server stats
        statsCard = view.findViewById(R.id.stats_card)
        statsRxRate = view.findViewById(R.id.stats_rx_rate)
        statsRxTotal = view.findViewById(R.id.stats_rx_total)
        statsTxRate = view.findViewById(R.id.stats_tx_rate)
        statsTxTotal = view.findViewById(R.id.stats_tx_total)
        statsFlows = view.findViewById(R.id.stats_flows)
        statsFlowsTotal = view.findViewById(R.id.stats_flows_total)

        // Latency views
        latencyUplink = view.findViewById(R.id.latency_uplink)
        latencyDownlink = view.findViewById(R.id.latency_downlink)
        latencyRtt = view.findViewById(R.id.latency_rtt)
    }

    private fun setupRecyclerView() {
        adapter = FlowAdapter()
        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        recyclerView.adapter = adapter
    }

    private fun setupSortButtons() {
        sortToggle.addOnButtonCheckedListener { _, checkedId, isChecked ->
            if (!isChecked) return@addOnButtonCheckedListener
            when (checkedId) {
                R.id.btn_sort_downlink -> flowMonitor?.setSortMode(FlowSortMode.DOWNLINK)
                R.id.btn_sort_uplink -> flowMonitor?.setSortMode(FlowSortMode.UPLINK)
                R.id.btn_sort_server -> flowMonitor?.setSortMode(FlowSortMode.SERVER)
            }
        }

        // Default selection
        btnSortDownlink.isChecked = true
    }

    private fun observeVpnState() {
        viewLifecycleOwner.lifecycleScope.launch {
            UdpTunnelVpnService.vpnState.collectLatest { state ->
                withContext(Dispatchers.Main) {
                    when (state) {
                        VpnState.CONNECTED -> {
                            // Show stats card
                            statsCard.visibility = View.VISIBLE

                            // Observe latency stats
                            viewLifecycleOwner.lifecycleScope.launch {
                                UdpTunnelVpnService.latencyStats.collectLatest { latency ->
                                    withContext(Dispatchers.Main) {
                                        latencyUplink.text = if (latency.uplinkMs > 0) "↑ ${formatLatency(latency.uplinkMs)}" else "↑ --"
                                        latencyDownlink.text = if (latency.downlinkMs > 0) "↓ ${formatLatency(latency.downlinkMs)}" else "↓ --"
                                        latencyRtt.text = if (latency.rttMs > 0) "RTT ${formatLatency(latency.rttMs)}" else "RTT --"
                                    }
                                }
                            }

                            // Poll PacketFlowTracker every 3s (runs in VPN service I/O threads)
                            viewLifecycleOwner.lifecycleScope.launch {
                                while (UdpTunnelVpnService.vpnState.value == VpnState.CONNECTED) {
                                    val flows = PacketFlowTracker.getFlows()
                                    val stats = PacketFlowTracker.getAggregateStats()
                                    val nowMs = System.currentTimeMillis()

                                    // Compute rate from delta of total counters
                                    // This works even when backgrounded because total counters
                                    // continue to accumulate in the VPN I/O threads
                                    val rxRate = FlowsFragment.computeRate(stats.wgRx, prevRxBytes, nowMs, prevPollTimeMs)
                                    val txRate = FlowsFragment.computeRate(stats.wgTx, prevTxBytes, nowMs, prevPollTimeMs)
                                    prevRxBytes = stats.wgRx
                                    prevTxBytes = stats.wgTx
                                    prevPollTimeMs = nowMs

                                    withContext(Dispatchers.Main) {
                                        adapter.submitList(flows)
                                        updateEmptyState(flows.isEmpty(), true)
                                        statsRxRate.text = formatRate(rxRate)
                                        statsRxTotal.text = formatBytes(stats.wgRx)
                                        statsTxRate.text = formatRate(txRate)
                                        statsTxTotal.text = formatBytes(stats.wgTx)
                                        statsFlows.text = "${stats.activeFlows}"
                                        statsFlowsTotal.text = "${stats.totalFlows} total | ${PacketFlowTracker.getDebugStats()}"
                                    }
                                    kotlinx.coroutines.delay(3000)
                                }
                            }
                        }
                        else -> {
                            flowMonitor?.stop()
                            adapter.submitList(emptyList())
                            updateEmptyState(false, false)
                            statsCard.visibility = View.GONE
                            // Reset rate calculation state
                            prevRxBytes = -1
                            prevTxBytes = -1
                            prevPollTimeMs = 0
                        }
                    }
                }
            }
        }
    }

    private fun updateEmptyState(isEmpty: Boolean, isConnected: Boolean) {
        if (!isConnected) {
            emptyView.text = "Connect to VPN first"
            emptyView.visibility = View.VISIBLE
            recyclerView.visibility = View.GONE
        } else if (isEmpty) {
            emptyView.text = "No active flows yet\nBrowse a website or use an app to see connections"
            emptyView.visibility = View.VISIBLE
            recyclerView.visibility = View.GONE
        } else {
            emptyView.visibility = View.GONE
            recyclerView.visibility = View.VISIBLE
        }
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024.0))} MB"
            else -> "${"%.2f".format(bytes / (1024.0 * 1024.0 * 1024.0))} GB"
        }
    }

    private fun formatRate(bytesPerSec: Long): String {
        return when {
            bytesPerSec < 1024 -> "$bytesPerSec B/s"
            bytesPerSec < 1024 * 1024 -> "${bytesPerSec / 1024} KB/s"
            else -> "${"%.1f".format(bytesPerSec / (1024.0 * 1024.0))} MB/s"
        }
    }

    private fun formatLatency(ms: Float): String {
        return if (ms < 1) "${"%.0f".format(ms * 1000)}µs"
        else if (ms < 1000) "${"%.1f".format(ms)}ms"
        else "${"%.2f".format(ms / 1000)}s"
    }

    /**
     * Compute throughput rate from delta of total counters.
     * Works when app is backgrounded because counters accumulate in I/O threads.
     *
     * @param currentBytes Total bytes now
     * @param prevBytes Total bytes at previous poll (-1 if first poll)
     * @param nowMs Current time in ms
     * @param prevMs Previous poll time in ms (0 if first poll)
     * @return Bytes per second, or 0 if first poll / no time elapsed
     */
    companion object {
        fun computeRate(currentBytes: Long, prevBytes: Long, nowMs: Long, prevMs: Long): Long {
            if (prevBytes < 0 || prevMs == 0L) return 0  // first poll, no baseline
            val dtMs = nowMs - prevMs
            if (dtMs <= 0) return 0  // clock skew or same tick
            val deltaBytes = currentBytes - prevBytes
            if (deltaBytes < 0) return 0  // counter reset (reconnect)
            return deltaBytes * 1000 / dtMs  // bytes/sec
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        flowMonitor?.destroy()
    }
}

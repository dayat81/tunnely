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

    private var flowMonitor: FlowMonitor? = null

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
            TunnelyVpnService.vpnState.collectLatest { state ->
                withContext(Dispatchers.Main) {
                    when (state) {
                        VpnState.CONNECTED -> {
                            val app = requireActivity().application as TunnelyApp
                            val apiClient = ApiClient(
                                app.prefs.serverAddress,
                                app.prefs.serverPort
                            )

                            // Extract IP from tunnelAddress (e.g., "10.10.0.45/32" → "10.10.0.45")
                            val tunnelIp = app.prefs.tunnelAddress
                                .split(",").first().trim()
                                .split("/").first().trim()

                            flowMonitor = FlowMonitor(apiClient, app.prefs)
                            flowMonitor?.start(tunnelIp)

                            // Show stats card
                            statsCard.visibility = View.VISIBLE

                            // Observe flow data
                            viewLifecycleOwner.lifecycleScope.launch {
                                flowMonitor?.flows?.collectLatest { flows ->
                                    withContext(Dispatchers.Main) {
                                        adapter.submitList(flows)
                                        updateEmptyState(flows.isEmpty(), true)
                                    }
                                }
                            }

                            // Observe server stats
                            viewLifecycleOwner.lifecycleScope.launch {
                                flowMonitor?.serverStats?.collectLatest { stats ->
                                    withContext(Dispatchers.Main) {
                                        statsRxRate.text = formatRate(stats.rxRate)
                                        statsRxTotal.text = formatBytes(stats.wgRx)
                                        statsTxRate.text = formatRate(stats.txRate)
                                        statsTxTotal.text = formatBytes(stats.wgTx)
                                        statsFlows.text = "${stats.activeFlows}"
                                        statsFlowsTotal.text = "${stats.totalFlows} total"
                                    }
                                }
                            }
                        }
                        else -> {
                            flowMonitor?.stop()
                            adapter.submitList(emptyList())
                            updateEmptyState(false, false)
                            statsCard.visibility = View.GONE
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

    override fun onDestroyView() {
        super.onDestroyView()
        flowMonitor?.destroy()
    }
}

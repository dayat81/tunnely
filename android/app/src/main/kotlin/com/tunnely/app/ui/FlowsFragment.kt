package com.tunnely.app.ui

import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.TextView
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
        observeFlows()
        observeVpnState()
    }

    private fun initViews(view: View) {
        recyclerView = view.findViewById(R.id.flows_recycler)
        emptyView = view.findViewById(R.id.empty_view)
        sortToggle = view.findViewById(R.id.sort_toggle)
        btnSortUplink = view.findViewById(R.id.btn_sort_uplink)
        btnSortDownlink = view.findViewById(R.id.btn_sort_downlink)
        btnSortServer = view.findViewById(R.id.btn_sort_server)
    }

    private fun setupRecyclerView() {
        adapter = FlowAdapter()
        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        recyclerView.adapter = adapter
    }

    private fun setupSortButtons() {
        btnSortUplink.setOnClickListener {
            flowMonitor?.setSortMode(FlowSortMode.UPLINK)
            updateSortButtons(FlowSortMode.UPLINK)
        }
        btnSortDownlink.setOnClickListener {
            flowMonitor?.setSortMode(FlowSortMode.DOWNLINK)
            updateSortButtons(FlowSortMode.DOWNLINK)
        }
        btnSortServer.setOnClickListener {
            flowMonitor?.setSortMode(FlowSortMode.SERVER)
            updateSortButtons(FlowSortMode.SERVER)
        }

        // Default selection
        updateSortButtons(FlowSortMode.DOWNLINK)
    }

    private fun updateSortButtons(mode: FlowSortMode) {
        btnSortUplink.isEnabled = mode != FlowSortMode.UPLINK
        btnSortDownlink.isEnabled = mode != FlowSortMode.DOWNLINK
        btnSortServer.isEnabled = mode != FlowSortMode.SERVER
    }

    private fun observeFlows() {
        viewLifecycleOwner.lifecycleScope.launch {
            // This would be connected to actual FlowMonitor
            // For now, show empty state
            updateEmptyState(true)
        }
    }

    private fun observeVpnState() {
        viewLifecycleOwner.lifecycleScope.launch {
            TunnelyVpnService.vpnState.collectLatest { state ->
                withContext(Dispatchers.Main) {
                    when (state) {
                        VpnState.CONNECTED -> {
                            // Start flow monitoring
                            val app = requireActivity().application as TunnelyApp
                            val apiClient = ApiClient(
                                app.prefs.serverAddress,
                                app.prefs.serverPort
                            )
                            flowMonitor = FlowMonitor(apiClient, app.prefs)
                            flowMonitor?.start(app.prefs.tunnelAddress)

                            // Observe flow data
                            viewLifecycleOwner.lifecycleScope.launch {
                                flowMonitor?.flows?.collectLatest { flows ->
                                    withContext(Dispatchers.Main) {
                                        adapter.submitList(flows)
                                        updateEmptyState(flows.isEmpty())
                                    }
                                }
                            }
                        }
                        else -> {
                            flowMonitor?.stop()
                            adapter.submitList(emptyList())
                            updateEmptyState(true)
                        }
                    }
                }
            }
        }
    }

    private fun updateEmptyState(isEmpty: Boolean) {
        if (isEmpty) {
            emptyView.visibility = View.VISIBLE
            recyclerView.visibility = View.GONE
        } else {
            emptyView.visibility = View.GONE
            recyclerView.visibility = View.VISIBLE
        }
    }

    override fun onDestroyView() {
        super.onDestroyView()
        flowMonitor?.destroy()
    }
}

package com.tunnely.app.ui

import android.app.AlertDialog
import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.EditText
import android.widget.ProgressBar
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.tunnely.app.R
import com.tunnely.app.rtt.AppRttTarget
import com.tunnely.app.rtt.RttResult
import com.tunnely.app.rtt.RttTarget
import com.tunnely.app.rtt.RttTestRunner
import com.tunnely.app.vpn.UdpTunnelVpnService
import com.tunnely.app.vpn.VpnState
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

class RttFragment : Fragment() {

    private lateinit var btnStart: Button
    private lateinit var btnRetest: Button
    private lateinit var btnDefaultTargets: Button
    private lateinit var btnSelectApps: Button
    private lateinit var selectedAppsText: TextView
    private lateinit var progressBar: ProgressBar
    private lateinit var progressText: TextView
    private lateinit var recyclerView: RecyclerView
    private lateinit var summaryCard: MaterialCardView
    private lateinit var summaryDirect: TextView
    private lateinit var summaryVpn: TextView
    private lateinit var summaryOverhead: TextView
    private lateinit var summaryMessage: TextView

    private val adapter = RttResultAdapter()
    private var lastResults: List<RttResult>? = null
    private var useAppTargets = false
    private var selectedAppTargets = listOf<AppRttTarget>()
    private var installedApps = listOf<AppRttTarget>()

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_rtt, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        btnStart = view.findViewById(R.id.btn_start_test)
        btnRetest = view.findViewById(R.id.btn_retest)
        btnDefaultTargets = view.findViewById(R.id.btn_default_targets)
        btnSelectApps = view.findViewById(R.id.btn_select_apps)
        selectedAppsText = view.findViewById(R.id.selected_apps_text)
        progressBar = view.findViewById(R.id.progress_bar)
        progressText = view.findViewById(R.id.progress_text)
        recyclerView = view.findViewById(R.id.rtt_recycler)
        summaryCard = view.findViewById(R.id.summary_card)
        summaryDirect = view.findViewById(R.id.summary_direct)
        summaryVpn = view.findViewById(R.id.summary_vpn)
        summaryOverhead = view.findViewById(R.id.summary_overhead)
        summaryMessage = view.findViewById(R.id.summary_message)

        recyclerView.layoutManager = LinearLayoutManager(requireContext())
        recyclerView.adapter = adapter

        btnStart.setOnClickListener { startTest() }
        btnRetest.setOnClickListener { startTest() }
        btnDefaultTargets.setOnClickListener { selectDefaultTargets() }
        btnSelectApps.setOnClickListener { showAppPicker() }

        // Default mode
        selectDefaultTargets()

        // Restore results on config change
        lastResults?.let { displayResults(it) }
    }

    private fun selectDefaultTargets() {
        useAppTargets = false
        selectedAppTargets = emptyList()
        btnDefaultTargets.isEnabled = false
        btnSelectApps.isEnabled = true
        selectedAppsText.visibility = View.GONE
    }

    private fun showAppPicker() {
        // Load installed apps on first open
        if (installedApps.isEmpty()) {
            val pm = requireContext().packageManager
            val myPackage = requireContext().packageName
            installedApps = AppRttTarget.queryInstalledTargets(pm, myPackage)
        }

        if (installedApps.isEmpty()) {
            progressText.text = "⚠️ No known apps found with RTT targets"
            progressText.visibility = View.VISIBLE
            return
        }

        val appAdapter = AppRttAdapter()
        appAdapter.submitApps(installedApps)

        // Restore previous selection
        if (selectedAppTargets.isNotEmpty()) {
            appAdapter.setSelectedPackages(selectedAppTargets.map { it.packageName }.toSet())
        }

        val searchEdit = EditText(requireContext()).apply {
            hint = "Search apps…"
            setPadding(48, 24, 48, 24)
            setTextColor(resources.getColor(R.color.text_primary, null))
            setHintTextColor(resources.getColor(R.color.text_secondary, null))
            isFocusableInTouchMode = false
        }

        val recyclerView = RecyclerView(requireContext()).apply {
            layoutManager = LinearLayoutManager(requireContext())
            this.adapter = appAdapter
        }

        val container = android.widget.LinearLayout(requireContext()).apply {
            orientation = android.widget.LinearLayout.VERTICAL
            addView(searchEdit, android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                android.widget.LinearLayout.LayoutParams.WRAP_CONTENT
            ))
            addView(recyclerView, android.widget.LinearLayout.LayoutParams(
                android.widget.LinearLayout.LayoutParams.MATCH_PARENT,
                0, 1f
            ))
        }

        // Search filter
        searchEdit.addTextChangedListener(object : android.text.TextWatcher {
            override fun beforeTextChanged(s: CharSequence?, start: Int, count: Int, after: Int) {}
            override fun onTextChanged(s: CharSequence?, start: Int, before: Int, count: Int) {}
            override fun afterTextChanged(s: android.text.Editable?) {
                val query = s?.toString()?.lowercase() ?: ""
                val filtered = if (query.isEmpty()) installedApps
                else installedApps.filter {
                    it.appName.lowercase().contains(query) ||
                    it.target.host.lowercase().contains(query) ||
                    it.target.name.lowercase().contains(query)
                }
                appAdapter.submitApps(filtered)
            }
        })

        AlertDialog.Builder(requireContext())
            .setTitle("📱 Select Apps to Test")
            .setView(container)
            .setPositiveButton("Test Selected") { _, _ ->
                val selected = appAdapter.getSelectedTargets()
                if (selected.isNotEmpty()) {
                    useAppTargets = true
                    selectedAppTargets = selected
                    btnDefaultTargets.isEnabled = true
                    btnSelectApps.isEnabled = true
                    selectedAppsText.visibility = View.VISIBLE
                    selectedAppsText.text = "📱 ${selected.size} app(s) selected"
                }
            }
            .setNegativeButton("Cancel", null)
            .setNeutralButton("Select All") { _, _ ->
                useAppTargets = true
                selectedAppTargets = installedApps.toList()
                btnDefaultTargets.isEnabled = true
                selectedAppsText.visibility = View.VISIBLE
                selectedAppsText.text = "📱 ${installedApps.size} app(s) selected"
            }
            .show()
    }

    private fun getTargets(): List<RttTarget> {
        return if (useAppTargets && selectedAppTargets.isNotEmpty()) {
            selectedAppTargets.map { it.target }
        } else {
            RttTarget.DEFAULT_TARGETS
        }
    }

    private fun startTest() {
        val vpnConnected = UdpTunnelVpnService.vpnState.value == VpnState.CONNECTED
        if (!vpnConnected) {
            progressText.text = "⚠️ Connect VPN first to measure VPN latency"
            progressText.visibility = View.VISIBLE
            return
        }

        val targets = getTargets()
        if (targets.isEmpty()) {
            progressText.text = "⚠️ No targets selected"
            progressText.visibility = View.VISIBLE
            return
        }

        btnStart.isEnabled = false
        btnRetest.isEnabled = false
        progressBar.visibility = View.VISIBLE
        progressText.visibility = View.VISIBLE
        summaryCard.visibility = View.GONE

        val runner = RttTestRunner(
            vpnService = UdpTunnelVpnService.getServiceInstance()
        )

        lifecycleScope.launch {
            progressText.text = "Testing ${targets.size} targets (direct + VPN)..."

            val results = withContext(Dispatchers.IO) {
                runner.runAll(targets)
            }

            lastResults = results
            displayResults(results)

            btnStart.isEnabled = true
            btnRetest.isEnabled = true
            progressBar.visibility = View.GONE
            progressText.visibility = View.GONE
        }
    }

    private fun displayResults(results: List<RttResult>) {
        adapter.submitResults(results)

        val summary = RttResult.Summary(results)
        summaryCard.visibility = View.VISIBLE

        summaryDirect.text = "${summary.avgDirectMs}ms"
        summaryVpn.text = "${summary.avgVpnMs}ms"

        val overheadText = if (summary.avgOverheadMs >= 0) {
            "+${summary.avgOverheadMs}ms"
        } else {
            "${summary.avgOverheadMs}ms"
        }
        summaryOverhead.text = overheadText

        val overheadColor = when {
            summary.avgOverheadPercent < 20 -> Color.parseColor("#4CAF50")
            summary.avgOverheadPercent < 50 -> Color.parseColor("#FFC107")
            else -> Color.parseColor("#F44336")
        }
        summaryOverhead.setTextColor(overheadColor)

        summaryMessage.text = when {
            summary.timeoutCount > 0 ->
                "⚠️ ${summary.timeoutCount} target(s) timed out"
            summary.avgOverheadMs <= 0 ->
                "🚀 VPN is as fast as direct connection!"
            summary.avgOverheadPercent < 20 ->
                "✅ Tunnely adds only ${summary.avgOverheadMs}ms (${String.format("%.0f", summary.avgOverheadPercent)}%) overhead"
            summary.avgOverheadPercent < 50 ->
                "⚡ Tunnely adds ${summary.avgOverheadMs}ms (${String.format("%.0f", summary.avgOverheadPercent)}%) — moderate overhead"
            else ->
                "📊 Tunnely adds ${summary.avgOverheadMs}ms (${String.format("%.0f", summary.avgOverheadPercent)}%) overhead"
        }
    }
}

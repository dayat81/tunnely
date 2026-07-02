package com.tunnely.app.ui

import android.graphics.Color
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Button
import android.widget.ProgressBar
import android.widget.TextView
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import androidx.recyclerview.widget.LinearLayoutManager
import androidx.recyclerview.widget.RecyclerView
import com.google.android.material.card.MaterialCardView
import com.tunnely.app.R
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

    override fun onCreateView(
        inflater: LayoutInflater, container: ViewGroup?, savedInstanceState: Bundle?
    ): View {
        return inflater.inflate(R.layout.fragment_rtt, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        btnStart = view.findViewById(R.id.btn_start_test)
        btnRetest = view.findViewById(R.id.btn_retest)
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

        // Restore results on config change
        lastResults?.let { displayResults(it) }
    }

    private fun startTest() {
        val vpnConnected = UdpTunnelVpnService.vpnState.value == VpnState.CONNECTED
        if (!vpnConnected) {
            progressText.text = "⚠️ Connect VPN first to measure VPN latency"
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
            progressText.text = "Testing 5 targets (direct + VPN)..."

            val results = withContext(Dispatchers.IO) {
                runner.runAll(RttTarget.DEFAULT_TARGETS)
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

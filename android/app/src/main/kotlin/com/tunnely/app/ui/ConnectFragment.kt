package com.tunnely.app.ui

import android.animation.ObjectAnimator
import android.app.Activity
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.util.Log
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.view.animation.AccelerateDecelerateInterpolator
import android.widget.Button
import android.widget.TextView
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.lifecycle.lifecycleScope
import com.tunnely.app.R
import com.tunnely.app.TunnelyApp
import com.tunnely.app.api.ApiClient
import com.tunnely.app.vpn.*
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.collectLatest
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext
import java.util.Locale
import java.util.concurrent.TimeUnit

class ConnectFragment : Fragment() {

    companion object {
        private const val TAG = "ConnectFragment"
    }

    private val vpnPermissionLauncher = registerForActivityResult(
        ActivityResultContracts.StartActivityForResult()
    ) { result ->
        RemoteLogger.i(TAG, "🔴 VPN permission result: resultCode=${result.resultCode} (OK=${Activity.RESULT_OK})")
        if (result.resultCode == Activity.RESULT_OK) {
            RemoteLogger.i(TAG, "✅ VPN permission granted, calling doConnect()...")
            doConnect()
        } else {
            RemoteLogger.w(TAG, "❌ VPN permission denied! resultCode=${result.resultCode}")
            statusText.text = "Permission denied"
            statusSubtext.text = "VPN permission required"
            btnConnect.isEnabled = true
            stopPulseAnimation()
        }
    }

    private lateinit var statusCircle: View
    private lateinit var statusText: TextView
    private lateinit var statusSubtext: TextView
    private lateinit var serverEndpoint: TextView
    private lateinit var serverPubkey: TextView
    private lateinit var tunnelIp: TextView
    private lateinit var clientPubkey: TextView
    private lateinit var btnRegenerate: Button
    private lateinit var btnAutoConfig: Button
    private lateinit var btnConnect: Button
    private lateinit var trafficRx: TextView
    private lateinit var trafficTx: TextView
    private lateinit var durationText: TextView
    private lateinit var trafficCard: View

    private var pulseAnimator: ObjectAnimator? = null
    private var connectStartTime: Long = 0
    private val handler = Handler(Looper.getMainLooper())
    private var timerRunnable: Runnable? = null

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        return inflater.inflate(R.layout.fragment_connect, container, false)
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {
        super.onViewCreated(view, savedInstanceState)

        initViews(view)
        setupClickListeners()
        observeVpnState()
        observeTrafficStats()
        observeConnectionHealth()
        updateDisplay()
    }

    private fun initViews(view: View) {
        statusCircle = view.findViewById(R.id.status_circle)
        statusText = view.findViewById(R.id.status_text)
        statusSubtext = view.findViewById(R.id.status_subtext)
        serverEndpoint = view.findViewById(R.id.server_endpoint)
        serverPubkey = view.findViewById(R.id.server_pubkey)
        tunnelIp = view.findViewById(R.id.tunnel_ip)
        clientPubkey = view.findViewById(R.id.client_pubkey)
        btnRegenerate = view.findViewById(R.id.btn_regenerate)
        btnAutoConfig = view.findViewById(R.id.btn_auto_config)
        btnConnect = view.findViewById(R.id.btn_connect)
        trafficRx = view.findViewById(R.id.traffic_rx)
        trafficTx = view.findViewById(R.id.traffic_tx)
        durationText = view.findViewById(R.id.duration_text)
        trafficCard = view.findViewById(R.id.traffic_card)
    }

    private fun setupClickListeners() {
        btnConnect.setOnClickListener {
            val currentState = UdpTunnelVpnService.vpnState.value
            RemoteLogger.i(TAG, "🔵 CONNECT BUTTON CLICKED! currentState=$currentState")
            when (currentState) {
                VpnState.DISCONNECTED, VpnState.ERROR -> {
                    RemoteLogger.i(TAG, "→ Calling startConnect()")
                    startConnect()
                }
                VpnState.CONNECTED -> {
                    RemoteLogger.i(TAG, "→ Calling startDisconnect()")
                    startDisconnect()
                }
                else -> {
                    RemoteLogger.w(TAG, "→ Ignoring click, transitioning state: $currentState")
                }
            }
        }

        btnRegenerate.setOnClickListener {
            val app = requireActivity().application as TunnelyApp
            val newPubkey = app.prefs.generateKeyPair()
            clientPubkey.text = truncateKey(newPubkey)
        }

        btnAutoConfig.setOnClickListener {
            startAutoConfig()
        }
    }

    private fun observeVpnState() {
        viewLifecycleOwner.lifecycleScope.launch {
            UdpTunnelVpnService.vpnState.collectLatest { state ->
                withContext(Dispatchers.Main) {
                    updateUIForState(state)
                }
            }
        }
    }

    private fun observeTrafficStats() {
        viewLifecycleOwner.lifecycleScope.launch {
            UdpTunnelVpnService.trafficStats.collectLatest { stats ->
                withContext(Dispatchers.Main) {
                    trafficRx.text = formatBytes(stats.rxBytes)
                    trafficTx.text = formatBytes(stats.txBytes)
                }
            }
        }
    }

    private fun observeConnectionHealth() {
        viewLifecycleOwner.lifecycleScope.launch {
            UdpTunnelVpnService.connectionHealth.collectLatest { health ->
                withContext(Dispatchers.Main) {
                    // Update status subtext with handshake info when connected
                    if (UdpTunnelVpnService.vpnState.value == VpnState.CONNECTED) {
                        statusSubtext.text = health.statusText
                        // Pulse animation if waiting for handshake
                        if (!health.isHandshakeOk && health.error.isEmpty()) {
                            startPulseAnimation()
                        } else {
                            stopPulseAnimation()
                        }
                    }
                }
            }
        }
    }

    private fun updateUIForState(state: VpnState) {
        when (state) {
            VpnState.DISCONNECTED -> {
                statusCircle.setBackgroundResource(R.drawable.bg_status_circle)
                statusCircle.background.setTint(getColor(R.color.disconnected))
                statusText.text = "Disconnected"
                statusSubtext.text = "Tap CONNECT to start"
                btnConnect.text = "CONNECT"
                btnConnect.isEnabled = true
                btnConnect.setBackgroundResource(R.drawable.bg_connect_button)
                btnConnect.background.setTint(getColor(R.color.primary))
                trafficCard.visibility = View.GONE
                stopPulseAnimation()
                stopTimer()
            }
            VpnState.CONNECTING -> {
                statusCircle.setBackgroundResource(R.drawable.bg_status_circle)
                statusCircle.background.setTint(getColor(R.color.probing))
                statusText.text = "Connecting..."
                statusSubtext.text = "Establishing VPN tunnel"
                btnConnect.text = "CONNECTING..."
                btnConnect.isEnabled = false
                startPulseAnimation()
            }
            VpnState.CONNECTED -> {
                statusCircle.setBackgroundResource(R.drawable.bg_status_circle)
                statusCircle.background.setTint(getColor(R.color.connected))
                statusText.text = "Connected"
                statusSubtext.text = "VPN tunnel active"
                btnConnect.text = "DISCONNECT"
                btnConnect.setBackgroundResource(R.drawable.bg_connect_button)
                btnConnect.background.setTint(getColor(R.color.disconnected))
                btnConnect.isEnabled = true
                trafficCard.visibility = View.VISIBLE
                stopPulseAnimation()
                startTimer()
            }
            VpnState.DISCONNECTING -> {
                statusText.text = "Disconnecting..."
                statusSubtext.text = "Closing tunnel"
                btnConnect.text = "DISCONNECTING..."
                btnConnect.isEnabled = false
            }
            VpnState.ERROR -> {
                statusCircle.setBackgroundResource(R.drawable.bg_status_circle)
                statusCircle.background.setTint(getColor(R.color.disconnected))
                statusText.text = "Error"
                statusSubtext.text = "Connection failed"
                btnConnect.text = "RETRY"
                btnConnect.isEnabled = true
                stopPulseAnimation()
                stopTimer()
            }
        }
    }

    private fun updateDisplay() {
        val app = requireActivity().application as TunnelyApp
        val prefs = app.prefs

        serverEndpoint.text = "${prefs.serverAddress}:8770"
        serverPubkey.text = "UDP Tunnel (no keys)"
        tunnelIp.text = prefs.tunnelAddress.ifEmpty { "Auto-assigned" }
    }

    private fun startConnect() {
        RemoteLogger.i(TAG, "🟢 startConnect() called")
        btnConnect.isEnabled = false
        statusText.text = "Requesting VPN permission..."
        statusSubtext.text = "Checking permissions"
        statusCircle.background.setTint(getColor(R.color.probing))
        startPulseAnimation()

        // Check VPN permission FIRST (must be from Activity context)
        val prepareIntent = VpnService.prepare(requireContext())
        RemoteLogger.i(TAG, "VPN prepare result: ${if (prepareIntent != null) "NEED_PERMISSION" else "ALREADY_GRANTED"}")
        if (prepareIntent != null) {
            // Need user to grant VPN permission
            RemoteLogger.d(TAG, "Requesting VPN permission...")
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            // Permission already granted, proceed
            RemoteLogger.i(TAG, "VPN permission already granted, calling doConnect()")
            doConnect()
        }
    }

    private fun doConnect() {
        RemoteLogger.i(TAG, "🟡 doConnect() called (UDP tunnel mode)")
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val app = requireActivity().application as TunnelyApp
                val prefs = app.prefs

                // UDP tunnel mode: no keys, no registration, no API call.
                // Server auto-assigns IP on first packet.
                RemoteLogger.i(TAG, "Server: ${prefs.serverAddress} (UDP tunnel port 5555)")
                RemoteLogger.i(TAG, "Skipping WireGuard key gen + API registration (not needed for UDP tunnel)")

                // Step 1: Connect VPN via UDP tunnel
                withContext(Dispatchers.Main) {
                    statusText.text = "Connecting..."
                    statusSubtext.text = "Establishing UDP tunnel"
                }
                RemoteLogger.i(TAG, "Step 1: Calling UdpTunnelVpnService.connect()...")
                UdpTunnelVpnService.connect(requireContext(), prefs)
                connectStartTime = System.currentTimeMillis()
                RemoteLogger.i(TAG, "  ✅ UdpTunnelVpnService.connect() called")

            } catch (e: Exception) {
                RemoteLogger.e(TAG, "❌ Connect failed", e)
                withContext(Dispatchers.Main) {
                    statusText.text = "Error"
                    statusSubtext.text = e.message ?: "Connection failed"
                    btnConnect.isEnabled = true
                    stopPulseAnimation()
                }
            }
        }
    }

    private fun startDisconnect() {
        val app = requireActivity().application as TunnelyApp
        val prefs = app.prefs
        UdpTunnelVpnService.disconnect(requireContext(), prefs)
    }

    private fun startAutoConfig() {
        btnAutoConfig.isEnabled = false
        btnAutoConfig.text = "Configuring..."

        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val app = requireActivity().application as TunnelyApp
                val prefs = app.prefs
                val apiClient = ApiClient(prefs.serverAddress, prefs.serverPort)

                val registration = apiClient.registerClient(prefs.publicKey)

                prefs.serverPublicKey = registration.serverPublicKey
            } catch (e: Exception) {
                withContext(Dispatchers.Main) {
                    btnAutoConfig.text = "Config Failed"
                    btnAutoConfig.isEnabled = true
                    android.widget.Toast.makeText(
                        requireContext(),
                        "Auto-config failed: ${e.message}",
                        android.widget.Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun startPulseAnimation() {
        pulseAnimator = ObjectAnimator.ofFloat(statusCircle, "alpha", 1f, 0.3f, 1f).apply {
            duration = 1500
            repeatCount = ObjectAnimator.INFINITE
            interpolator = AccelerateDecelerateInterpolator()
            start()
        }
    }

    private fun stopPulseAnimation() {
        pulseAnimator?.cancel()
        statusCircle.alpha = 1f
    }

    private fun startTimer() {
        connectStartTime = System.currentTimeMillis()
        timerRunnable = object : Runnable {
            override fun run() {
                val elapsed = System.currentTimeMillis() - connectStartTime
                durationText.text = formatDuration(elapsed)
                handler.postDelayed(this, 1000)
            }
        }
        handler.post(timerRunnable!!)
    }

    private fun stopTimer() {
        timerRunnable?.let { handler.removeCallbacks(it) }
        timerRunnable = null
    }

    private fun formatDuration(millis: Long): String {
        val hours = TimeUnit.MILLISECONDS.toHours(millis)
        val minutes = TimeUnit.MILLISECONDS.toMinutes(millis) % 60
        val seconds = TimeUnit.MILLISECONDS.toSeconds(millis) % 60
        return String.format(Locale.US, "%02d:%02d:%02d", hours, minutes, seconds)
    }

    private fun formatBytes(bytes: Long): String {
        return when {
            bytes < 1024 -> "$bytes B"
            bytes < 1024 * 1024 -> "${bytes / 1024} KB"
            bytes < 1024 * 1024 * 1024 -> "${"%.1f".format(bytes / (1024.0 * 1024.0))} MB"
            else -> "${"%.2f".format(bytes / (1024.0 * 1024.0 * 1024.0))} GB"
        }
    }

    private fun truncateKey(key: String): String {
        if (key.length <= 16) return key
        return "${key.substring(0, 8)}...${key.substring(key.length - 8)}"
    }

    private fun getColor(colorRes: Int): Int {
        return requireContext().getColor(colorRes)
    }

    override fun onDestroyView() {
        super.onDestroyView()
        stopPulseAnimation()
        stopTimer()
    }
}

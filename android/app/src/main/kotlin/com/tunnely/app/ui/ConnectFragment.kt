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
        if (result.resultCode == Activity.RESULT_OK) {
            Log.d(TAG, "VPN permission granted, connecting...")
            doConnect()
        } else {
            Log.w(TAG, "VPN permission denied")
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
            val currentState = TunnelyVpnService.vpnState.value
            when (currentState) {
                VpnState.DISCONNECTED, VpnState.ERROR -> startConnect()
                VpnState.CONNECTED -> startDisconnect()
                else -> {} // Ignore clicks while transitioning
            }
        }

        btnRegenerate.setOnClickListener {
            val app = requireActivity().application as TunnelyApp
            val newPubkey = app.prefs.regenerateKeys()
            clientPubkey.text = truncateKey(newPubkey)
        }

        btnAutoConfig.setOnClickListener {
            startAutoConfig()
        }
    }

    private fun observeVpnState() {
        viewLifecycleOwner.lifecycleScope.launch {
            TunnelyVpnService.vpnState.collectLatest { state ->
                withContext(Dispatchers.Main) {
                    updateUIForState(state)
                }
            }
        }
    }

    private fun observeTrafficStats() {
        viewLifecycleOwner.lifecycleScope.launch {
            TunnelyVpnService.trafficStats.collectLatest { stats ->
                withContext(Dispatchers.Main) {
                    trafficRx.text = formatBytes(stats.rxBytes)
                    trafficTx.text = formatBytes(stats.txBytes)
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

        serverEndpoint.text = "${prefs.serverAddress}:${prefs.serverPort}"
        serverPubkey.text = truncateKey(prefs.serverPublicKey)
        tunnelIp.text = prefs.tunnelAddress.ifEmpty { "Not assigned" }
        clientPubkey.text = truncateKey(prefs.publicKey)
    }

    private fun startConnect() {
        btnConnect.isEnabled = false
        statusText.text = "Requesting VPN permission..."
        statusSubtext.text = "Checking permissions"
        statusCircle.background.setTint(getColor(R.color.probing))
        startPulseAnimation()

        // Check VPN permission FIRST (must be from Activity context)
        val prepareIntent = VpnService.prepare(requireContext())
        if (prepareIntent != null) {
            // Need user to grant VPN permission
            Log.d(TAG, "Requesting VPN permission...")
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            // Permission already granted, proceed
            doConnect()
        }
    }

    private fun doConnect() {
        viewLifecycleOwner.lifecycleScope.launch {
            try {
                val app = requireActivity().application as TunnelyApp
                val prefs = app.prefs

                // Step 1: Auto-register peer with server (ensures public key is registered)
                withContext(Dispatchers.Main) {
                    statusText.text = "Registering..."
                    statusSubtext.text = "Registering peer with server"
                }
                try {
                    val apiClient = ApiClient(prefs.serverAddress, prefs.serverPort)
                    val registration = apiClient.registerClient(prefs.publicKey)
                    prefs.serverPublicKey = registration.serverPublicKey
                    prefs.tunnelAddress = registration.tunnelAddress
                    Log.d(TAG, "Peer registered: ${registration.tunnelAddress}")
                } catch (e: Exception) {
                    Log.w(TAG, "Auto-register failed (may already be registered): ${e.message}")
                    // Continue anyway — peer might already be registered
                }

                // Step 2: MTU probe
                withContext(Dispatchers.Main) {
                    statusText.text = "Probing MTU..."
                    statusSubtext.text = "Discovering optimal MTU"
                }
                if (prefs.autoMtu) {
                    val mtu = MtuProber.discover(prefs.serverAddress)
                    prefs.mtu = mtu
                }

                // Step 3: Connect VPN
                withContext(Dispatchers.Main) {
                    statusText.text = "Connecting..."
                    statusSubtext.text = "Establishing VPN tunnel"
                }

                // Start VPN service and connect
                TunnelyVpnService.connect(requireContext(), prefs)

                connectStartTime = System.currentTimeMillis()

            } catch (e: Exception) {
                Log.e(TAG, "Connect failed", e)
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
        TunnelyVpnService.disconnect(requireContext(), prefs)
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
                prefs.tunnelAddress = registration.tunnelAddress

                withContext(Dispatchers.Main) {
                    updateDisplay()
                    btnAutoConfig.text = "Auto Config ✓"
                    btnAutoConfig.isEnabled = true
                }
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

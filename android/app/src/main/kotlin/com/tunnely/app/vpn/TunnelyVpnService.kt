package com.tunnely.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.os.Build
import android.util.Log
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import com.tunnely.app.MainActivity
import com.tunnely.app.R
import com.tunnely.app.api.ApiClient
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.InetNetwork
import kotlinx.coroutines.CancellationException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.launch
import java.net.InetAddress

enum class VpnState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
    ERROR
}

data class ConnectionHealth(
    val handshakeAge: Long = -1,
    val lastHandshakeEpoch: Long = 0,
    val endpoint: String = "",
    val transferRx: Long = 0,
    val transferTx: Long = 0,
    val error: String = ""
) {
    val isHandshakeOk: Boolean get() = handshakeAge in 0..300
    val statusText: String get() = when {
        error.isNotEmpty() -> "❌ $error"
        handshakeAge < 0 -> "⏳ Waiting for handshake..."
        handshakeAge > 300 -> "⚠️ Handshake stale (${handshakeAge}s ago)"
        else -> "✅ Connected (${handshakeAge}s ago)"
    }
}

data class TrafficStats(
    val rxBytes: Long = 0,
    val txBytes: Long = 0
)

/**
 * VPN service using GoBackend.setState() — the proper WireGuard Android API.
 * GoBackend handles TUN establishment, socket protect, and WireGuard lifecycle.
 * This avoids the routing loop issue (Issue #7) that plagued direct wgTurnOn.
 */
class TunnelyVpnService : LifecycleService() {

    companion object {
        private const val TAG = "TunnelyVpn"
        private const val TUNNEL_NAME = "tunnely-vpn"
        private const val NOTIFICATION_CHANNEL_ID = "tunnely_vpn"
        private const val NOTIFICATION_ID = 1
        private const val HANDSHAKE_CHECK_INTERVAL = 3000L

        private val _vpnState = MutableStateFlow(VpnState.DISCONNECTED)
        val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

        private val _trafficStats = MutableStateFlow(TrafficStats())
        val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

        private val _connectionHealth = MutableStateFlow(ConnectionHealth())
        val connectionHealth: StateFlow<ConnectionHealth> = _connectionHealth.asStateFlow()

        private var serviceInstance: TunnelyVpnService? = null
        private var backend: GoBackend? = null

        // Traffic baseline
        private var baselineRx: Long = -1
        private var baselineTx: Long = -1

        // WireGuard Tunnel object
        val tunnel = object : Tunnel {
            override fun getName(): String = TUNNEL_NAME
            override fun onStateChange(newState: Tunnel.State) {
                Log.d(TAG, "Tunnel state changed: $newState")
            }
        }

        fun connect(context: Context, prefs: VpnPreferences) {
            val intent = Intent(context, TunnelyVpnService::class.java)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                context.startForegroundService(intent)
            } else {
                context.startService(intent)
            }

            GlobalScope.launch(Dispatchers.IO) {
                var attempts = 0
                while (serviceInstance == null && attempts < 20) {
                    delay(100)
                    attempts++
                }
                serviceInstance?.doConnect(prefs)
            }
        }

        fun disconnect(context: Context, prefs: VpnPreferences) {
            GlobalScope.launch(Dispatchers.IO) {
                serviceInstance?.doDisconnect()
            }
        }
    }

    private val supervisorJob = SupervisorJob()
    private val serviceScope = kotlinx.coroutines.CoroutineScope(supervisorJob + Dispatchers.IO)
    private var connectJob: Job? = null

    override fun onCreate() {
        super.onCreate()
        serviceInstance = this
        backend = GoBackend(this)
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        super.onStartCommand(intent, flags, startId)
        startForeground(NOTIFICATION_ID, createNotification("Disconnected"))
        return START_STICKY
    }

    override fun onDestroy() {
        connectJob?.cancel()
        supervisorJob.cancel()
        backend = null
        serviceInstance = null
        super.onDestroy()
    }

    private fun doConnect(prefs: VpnPreferences) {
        connectJob?.cancel()
        _vpnState.value = VpnState.CONNECTING
        _connectionHealth.value = ConnectionHealth()

        connectJob = serviceScope.launch {
            try {
                // Step 1: Auto-register peer on server
                try {
                    val apiClient = ApiClient(prefs.serverAddress, prefs.serverPort)
                    val clientPubkey = prefs.publicKey
                    if (clientPubkey.isNotBlank()) {
                        Log.d(TAG, "Auto-registering peer: $clientPubkey")
                        apiClient.registerClient(clientPubkey)
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "Auto-register failed (non-fatal): ${e.message}")
                }

                // Step 2: Probe MTU
                try {
                    if (prefs.autoMtu) {
                        val mtu = MtuProber.discover(prefs.serverAddress)
                        if (mtu > 0) {
                            prefs.mtu = mtu
                            Log.d(TAG, "MTU probed: $mtu")
                        }
                    }
                } catch (e: Exception) {
                    Log.w(TAG, "MTU probe failed (non-fatal): ${e.message}")
                }

                // Step 3: Resolve endpoint hostname BEFORE building config
                val resolvedEndpoint = resolveEndpoint(prefs.serverAddress, prefs.serverPort)
                Log.d(TAG, "Endpoint resolved: ${prefs.serverAddress} -> $resolvedEndpoint")

                // Step 4: Build WireGuard Config using proper API
                val config = buildWireGuardConfig(prefs, resolvedEndpoint)
                    ?: throw Exception("Failed to build WireGuard config")

                // Step 5: Connect via GoBackend.setState()
                // This handles: TUN establish, socket protect, wgTurnOn — all internally
                Log.d(TAG, "Connecting via GoBackend.setState(UP)...")
                val currentBackend = backend ?: GoBackend(this@TunnelyVpnService)
                currentBackend.setState(tunnel, Tunnel.State.UP, config)
                backend = currentBackend

                Log.i(TAG, "GoBackend.setState(UP) succeeded — VPN connected!")

                // Step 6: Update state
                _vpnState.value = VpnState.CONNECTED
                _connectionHealth.value = ConnectionHealth(endpoint = resolvedEndpoint)
                updateNotification("Connected ✓")

                // Step 7: Record traffic baseline
                val uid = android.os.Process.myUid()
                baselineRx = android.net.TrafficStats.getUidRxBytes(uid)
                baselineTx = android.net.TrafficStats.getUidTxBytes(uid)
                if (baselineRx < 0) baselineRx = 0
                if (baselineTx < 0) baselineTx = 0

                // Step 8: Start monitoring loop
                while (true) {
                    delay(HANDSHAKE_CHECK_INTERVAL)
                    try {
                        // Check tunnel still up
                        val state = currentBackend.getState(tunnel)
                        if (state == Tunnel.State.DOWN) {
                            Log.w(TAG, "Tunnel went DOWN")
                            _vpnState.value = VpnState.DISCONNECTED
                            break
                        }

                        // Update traffic stats
                        val currentRx = android.net.TrafficStats.getUidRxBytes(uid)
                        val currentTx = android.net.TrafficStats.getUidTxBytes(uid)
                        if (currentRx >= 0 && currentTx >= 0) {
                            _trafficStats.value = TrafficStats(
                                rxBytes = currentRx - baselineRx,
                                txBytes = currentTx - baselineTx
                            )
                        }

                        // Update connection health via GoBackend statistics
                        try {
                            val stats = currentBackend.getStatistics(tunnel)
                            val totalRx = stats.totalRx()
                            val totalTx = stats.totalTx()
                            _connectionHealth.value = _connectionHealth.value.copy(
                                transferRx = totalRx,
                                transferTx = totalTx
                            )
                        } catch (_: Exception) {}

                    } catch (e: CancellationException) {
                        throw e
                    } catch (e: Exception) {
                        Log.w(TAG, "Monitor loop error: ${e.message}")
                    }
                }

            } catch (e: CancellationException) {
                throw e
            } catch (e: Exception) {
                Log.e(TAG, "Connect failed", e)
                _vpnState.value = VpnState.ERROR
                _connectionHealth.value = ConnectionHealth(error = e.message ?: "Unknown error")
                updateNotification("Error: ${e.message}")
                delay(3000)
                stopForeground(STOP_FOREGROUND_REMOVE)
                stopSelf()
            }
        }
    }

    private fun doDisconnect() {
        connectJob?.cancel()
        connectJob = null
        _vpnState.value = VpnState.DISCONNECTING

        try {
            val currentBackend = backend
            if (currentBackend != null) {
                try {
                    val state = currentBackend.getState(tunnel)
                    if (state == Tunnel.State.UP) {
                        currentBackend.setState(tunnel, Tunnel.State.DOWN, null)
                    }
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}

        _vpnState.value = VpnState.DISCONNECTED
        _trafficStats.value = TrafficStats()
        _connectionHealth.value = ConnectionHealth()
        updateNotification("Disconnected")
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun buildWireGuardConfig(prefs: VpnPreferences, resolvedEndpoint: String): Config? {
        return try {
            // Build Interface
            val ifaceBuilder = com.wireguard.config.Interface.Builder()
                .parsePrivateKey(prefs.decodePrivateKeyBase64())
                .parseAddresses(prefs.tunnelAddress)
                .parseMtu(prefs.mtu.toString())
                .parseDnsServers(prefs.dnsServers)

            // Split tunneling: include only selected apps
            if (prefs.splitTunneling && prefs.splitApps.isNotEmpty()) {
                for (packageName in prefs.splitApps) {
                    try {
                        ifaceBuilder.includeApplication(packageName)
                        Log.d(TAG, "Split tunnel: included $packageName")
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to include $packageName: ${e.message}")
                    }
                }
                Log.i(TAG, "Split tunneling: ${prefs.splitApps.size} apps")
            }

            val iface = ifaceBuilder.build()

            // Build Peer
            val peerBuilder = com.wireguard.config.Peer.Builder()
                .parsePublicKey(prefs.decodeServerPublicKeyBase64())
                .parseEndpoint(resolvedEndpoint)
                .parsePersistentKeepalive("25")

            // Add allowed IPs
            val allowedIpList = prefs.allowedIps.split(",")
                .map { it.trim() }
                .filter { it.isNotBlank() }
                .map { InetNetwork.parse(it) }
            peerBuilder.addAllowedIps(allowedIpList)

            val peer = peerBuilder.build()

            // Build Config
            Config.Builder()
                .setInterface(iface)
                .addPeer(peer)
                .build()
        } catch (e: Exception) {
            Log.e(TAG, "Failed to build config: ${e.message}", e)
            null
        }
    }

    private suspend fun resolveEndpoint(host: String, port: Int): String {
        if (isIpAddress(host)) return "$host:$port"

        val maxRetries = 3
        var lastException: Exception? = null
        for (attempt in 1..maxRetries) {
            try {
                val addr = java.net.InetAddress.getByName(host)
                val ip = addr.hostAddress
                    ?: throw Exception("DNS resolution returned null for '$host'")
                if (!isIpAddress(ip)) {
                    throw Exception("DNS resolution returned non-IP value '$ip' for '$host'")
                }
                Log.d(TAG, "Resolved endpoint: $host -> $ip:$port (attempt $attempt)")
                return "$ip:$port"
            } catch (e: java.net.UnknownHostException) {
                lastException = e
                Log.w(TAG, "Endpoint resolution error for '$host' (attempt $attempt/$maxRetries): ${e.message}")
                if (attempt < maxRetries) {
                    delay(500L * attempt)
                }
            }
        }
        throw Exception("Failed to resolve endpoint hostname '$host' after $maxRetries attempts: ${lastException?.message}", lastException)
    }

    private fun isIpAddress(host: String): Boolean {
        return host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) || host.contains(":")
    }

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "Tunnely VPN",
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Tunnely VPN connection status" }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(status: String): Notification {
        val pendingIntent = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Tunnely")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pendingIntent)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, createNotification(status))
    }
}

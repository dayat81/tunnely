package com.tunnely.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import android.os.ParcelFileDescriptor
import android.util.Log
import androidx.core.app.NotificationCompat
import com.tunnely.app.MainActivity
import com.tunnely.app.R
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.GlobalScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import java.net.InetAddress

enum class VpnState {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    DISCONNECTING,
    ERROR
}

/** Connection health — tracks WireGuard handshake status */
data class ConnectionHealth(
    val handshakeAge: Long = -1,       // seconds since last handshake (-1 = never)
    val lastHandshakeEpoch: Long = 0,  // epoch seconds of last handshake
    val endpoint: String = "",         // resolved endpoint
    val transferRx: Long = 0,          // bytes received via WireGuard
    val transferTx: Long = 0,          // bytes sent via WireGuard
    val error: String = ""             // error message if any
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

class TunnelyVpnService : VpnService() {

    companion object {
        private const val TAG = "TunnelyVpn"
        const val TUNNEL_NAME = "tunnely-vpn"
        const val NOTIFICATION_CHANNEL_ID = "tunnely_vpn"
        const val NOTIFICATION_ID = 1
        private const val HANDSHAKE_TIMEOUT_MS = 20000L  // 20s to wait for handshake

        private val _vpnState = MutableStateFlow(VpnState.DISCONNECTED)
        val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

        private val _trafficStats = MutableStateFlow(TrafficStats())
        val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

        private val _connectionHealth = MutableStateFlow(ConnectionHealth())
        val connectionHealth: StateFlow<ConnectionHealth> = _connectionHealth.asStateFlow()

        private var serviceInstance: TunnelyVpnService? = null
        private var tunnelHandle: Int = -1
        private var tunFd: ParcelFileDescriptor? = null

        // Traffic baseline (recorded when VPN connects)
        private var baselineRx: Long = -1
        private var baselineTx: Long = -1

        // WireGuard native functions via reflection
        private var wgTurnOnMethod: java.lang.reflect.Method? = null
        private var wgTurnOffMethod: java.lang.reflect.Method? = null
        private var wgGetSocketV4Method: java.lang.reflect.Method? = null
        private var wgGetSocketV6Method: java.lang.reflect.Method? = null
        private var wgGetBytesMethod: java.lang.reflect.Method? = null
        private var wgGetConfigMethod: java.lang.reflect.Method? = null
        private var goBackendVpnServiceField: java.lang.reflect.Field? = null

        init {
            try {
                System.loadLibrary("wg-go")
                Log.d(TAG, "Loaded libwg-go.so")
            } catch (e: UnsatisfiedLinkError) {
                try {
                    System.loadLibrary("wg")
                    Log.d(TAG, "Loaded libwg.so")
                } catch (e2: UnsatisfiedLinkError) {
                    Log.e(TAG, "Failed to load WireGuard native library", e2)
                }
            }

            try {
                val goBackendClass = Class.forName("com.wireguard.android.backend.GoBackend")
                wgTurnOnMethod = goBackendClass.getDeclaredMethod(
                    "wgTurnOn", String::class.java, Int::class.javaPrimitiveType, String::class.java
                ).apply { isAccessible = true }
                wgTurnOffMethod = goBackendClass.getDeclaredMethod(
                    "wgTurnOff", Int::class.javaPrimitiveType
                ).apply { isAccessible = true }
                wgGetSocketV4Method = goBackendClass.getDeclaredMethod(
                    "wgGetSocketV4", Int::class.javaPrimitiveType
                ).apply { isAccessible = true }
                wgGetSocketV6Method = goBackendClass.getDeclaredMethod(
                    "wgGetSocketV6", Int::class.javaPrimitiveType
                ).apply { isAccessible = true }
                try {
                    wgGetBytesMethod = goBackendClass.getDeclaredMethod(
                        "wgGetBytes", Int::class.javaPrimitiveType
                    ).apply { isAccessible = true }
                } catch (_: Exception) {}
                try {
                    wgGetConfigMethod = goBackendClass.getDeclaredMethod(
                        "wgGetConfig", String::class.java
                    ).apply { isAccessible = true }
                } catch (_: Exception) {
                    Log.w(TAG, "wgGetConfig not available — handshake check disabled")
                }

                // CRITICAL: Access GoBackend.vpnService CompletableFuture
                // WireGuard Go code uses this to call protect() on its UDP sockets
                // Without this, WireGuard handshake packets get routed through TUN (loop!)
                try {
                    goBackendVpnServiceField = goBackendClass.getDeclaredField("vpnService")
                    goBackendVpnServiceField?.isAccessible = true
                    Log.d(TAG, "GoBackend.vpnService field accessible — socket protect will work")
                } catch (_: Exception) {
                    Log.w(TAG, "GoBackend.vpnService field not accessible — manual protect only")
                }

                Log.d(TAG, "GoBackend native methods accessible via reflection")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to access GoBackend methods", e)
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
                serviceInstance?.connect(prefs)
            }
        }

        fun disconnect(context: Context, prefs: VpnPreferences) {
            GlobalScope.launch(Dispatchers.IO) {
                serviceInstance?.disconnect(prefs)
            }
        }
    }

    inner class LocalBinder : Binder() {
        fun getService(): TunnelyVpnService = this@TunnelyVpnService
    }

    private val binder = LocalBinder()

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
        serviceInstance = this
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                createNotification("Disconnected"),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, createNotification("Disconnected"))
        }
        return START_STICKY
    }

    override fun onDestroy() {
        super.onDestroy()
        try {
            if (tunnelHandle >= 0) {
                wgTurnOffMethod?.invoke(null, tunnelHandle)
                tunnelHandle = -1
            }
            tunFd?.close()
            tunFd = null
        } catch (e: Exception) {
            Log.e(TAG, "Error in onDestroy", e)
        }
        serviceInstance = null
    }

    private fun createNotificationChannel() {
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "Tunnely VPN",
            NotificationManager.IMPORTANCE_LOW
        ).apply {
            description = "Tunnely VPN connection status"
        }
        val nm = getSystemService(NotificationManager::class.java)
        nm.createNotificationChannel(channel)
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

    suspend fun connect(prefs: VpnPreferences) {
        try {
            _vpnState.value = VpnState.CONNECTING
            _connectionHealth.value = ConnectionHealth()

            // CRITICAL: Resolve hostname BEFORE establishing TUN.
            val resolvedEndpoint = resolveEndpoint(prefs.serverAddress, prefs.serverPort)
            Log.d(TAG, "Endpoint resolved: ${prefs.serverAddress} -> $resolvedEndpoint")

            // Build VPN tunnel
            val builder = Builder()
                .setSession(TUNNEL_NAME)
                .setMtu(prefs.mtu)

            // Addresses
            for (addr in prefs.tunnelAddress.split(",").map { it.trim() }) {
                if (addr.isNotBlank()) {
                    val parts = addr.split("/")
                    if (parts.size == 2) {
                        builder.addAddress(parts[0], parts[1].toInt())
                    }
                }
            }

            // DNS
            for (dns in prefs.dnsServers.split(",").map { it.trim() }) {
                if (dns.isNotBlank()) {
                    for (resolved in InetAddress.getAllByName(dns)) {
                        builder.addDnsServer(resolved)
                    }
                }
            }

            // Routes
            for (route in prefs.allowedIps.split(",").map { it.trim() }) {
                if (route.isNotBlank()) {
                    val parts = route.split("/")
                    if (parts.size == 2) {
                        builder.addRoute(parts[0], parts[1].toInt())
                    }
                }
            }

            // Split tunneling
            if (prefs.splitTunneling && prefs.splitApps.isNotEmpty()) {
                for (packageName in prefs.splitApps) {
                    try {
                        builder.addAllowedApplication(packageName)
                        Log.d(TAG, "Split tunnel: added $packageName")
                    } catch (e: Exception) {
                        Log.w(TAG, "Failed to add $packageName to split tunnel", e)
                    }
                }
                Log.i(TAG, "Split tunneling enabled for ${prefs.splitApps.size} apps")
            } else {
                Log.i(TAG, "Split tunneling disabled — all traffic through VPN")
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                builder.setMetered(false)
            builder.setBlocking(true)

            val fd = builder.establish()
                ?: throw Exception("Failed to establish TUN - VPN permission not granted?")
            tunFd = fd

            // Build WireGuard UAPI config
            val privateKeyBytes = prefs.decodePrivateKey()
            val privateKeyHex = bytesToHex(privateKeyBytes)
            val serverKeyBytes = prefs.decodeServerPublicKey()
            val serverKeyHex = bytesToHex(serverKeyBytes)

            val wgConfig = buildString {
                append("private_key=$privateKeyHex\n")
                append("replace_peers=true\n")
                append("public_key=$serverKeyHex\n")
                append("endpoint=$resolvedEndpoint\n")
                append("persistent_keepalive_interval=25\n")
                append("replace_allowed_ips=true\n")
                for (ip in prefs.allowedIps.split(",").map { it.trim() }) {
                    if (ip.isNotBlank()) {
                        append("allowed_ip=$ip\n")
                    }
                }
            }

            Log.d(TAG, "Starting WireGuard tunnel...")
            Log.d(TAG, "Config (no keys): replace_peers=true, endpoint=${prefs.serverAddress}:${prefs.serverPort}")

            // CRITICAL: Set GoBackend.vpnService so WireGuard Go code can call protect()
            // on its UDP sockets BEFORE sending handshake packets.
            // Without this, handshake packets get routed through TUN → loop → never connects.
            try {
                val futureClass = Class.forName("java.util.concurrent.CompletableFuture")
                val completedFutureMethod = futureClass.getMethod("completedFuture", Any::class.java)
                val future = completedFutureMethod.invoke(null, this@TunnelyVpnService)
                goBackendVpnServiceField?.set(null, future)
                Log.i(TAG, "GoBackend.vpnService set — WireGuard socket protect enabled")
            } catch (e: Exception) {
                Log.w(TAG, "Failed to set GoBackend.vpnService: ${e.message} — manual protect only")
            }

            val handle = wgTurnOnMethod?.invoke(null, TUNNEL_NAME, fd.detachFd(), wgConfig) as? Int
                ?: throw Exception("wgTurnOn returned null")

            if (handle < 0) {
                throw Exception("wgTurnOn failed with code: $handle")
            }

            tunnelHandle = handle
            Log.d(TAG, "WireGuard tunnel started, handle: $tunnelHandle")

            try {
                val sock4 = wgGetSocketV4Method?.invoke(null, tunnelHandle) as? Int ?: -1
                val sock6 = wgGetSocketV6Method?.invoke(null, tunnelHandle) as? Int ?: -1
                if (sock4 >= 0) protect(sock4)
                if (sock6 >= 0) protect(sock6)
            } catch (e: Exception) {
                Log.w(TAG, "Socket protect failed (non-fatal)", e)
            }

            _vpnState.value = VpnState.CONNECTED
            _connectionHealth.value = ConnectionHealth(endpoint = resolvedEndpoint)
            updateNotification("Connected — waiting for handshake...")

            // Record baseline and start traffic stats polling
            val uid = android.os.Process.myUid()
            baselineRx = android.net.TrafficStats.getUidRxBytes(uid)
            baselineTx = android.net.TrafficStats.getUidTxBytes(uid)
            if (baselineRx < 0) baselineRx = 0
            if (baselineTx < 0) baselineTx = 0

            // Start handshake verification + traffic polling
            GlobalScope.launch(Dispatchers.IO) {
                val startTime = System.currentTimeMillis()
                var handshakeVerified = false

                while (_vpnState.value == VpnState.CONNECTED && tunnelHandle >= 0) {
                    try {
                        // Check handshake via wgGetConfig
                        val health = checkConnectionHealth(resolvedEndpoint)
                        _connectionHealth.value = health

                        if (health.isHandshakeOk && !handshakeVerified) {
                            handshakeVerified = true
                            updateNotification("Connected ✓")
                            Log.i(TAG, "WireGuard handshake verified! (${health.handshakeAge}s ago)")
                        }

                        // If handshake hasn't happened after timeout, log warning
                        if (!handshakeVerified) {
                            val elapsed = System.currentTimeMillis() - startTime
                            if (elapsed > HANDSHAKE_TIMEOUT_MS) {
                                Log.w(TAG, "Handshake not received after ${elapsed/1000}s — " +
                                    "endpoint=$resolvedEndpoint may be unreachable")
                                updateNotification("⚠️ No handshake — check network")
                                // Don't disconnect — keep trying (could be slow network)
                            }
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
                    } catch (e: Exception) {
                        Log.w(TAG, "Health check poll failed", e)
                    }
                    delay(2000)
                }
            }

        } catch (e: Exception) {
            Log.e(TAG, "Connect failed", e)
            _vpnState.value = VpnState.ERROR
            _connectionHealth.value = ConnectionHealth(error = e.message ?: "Unknown error")
            throw e
        }
    }

    /**
     * Check WireGuard handshake status via wgGetConfig reflection.
     * Parses UAPI output for last_handshake_time, endpoint, rx/tx bytes.
     */
    private fun checkConnectionHealth(resolvedEndpoint: String): ConnectionHealth {
        try {
            val config = wgGetConfigMethod?.invoke(null, TUNNEL_NAME) as? String
            if (config != null) {
                var lastHandshake: Long = 0
                var endpoint = ""
                var rxBytes: Long = 0
                var txBytes: Long = 0

                for (line in config.lines()) {
                    val trimmed = line.trim()
                    when {
                        trimmed.startsWith("last_handshake_time=") -> {
                            lastHandshake = trimmed.substringAfter("=").toLongOrNull() ?: 0
                        }
                        trimmed.startsWith("endpoint=") -> {
                            endpoint = trimmed.substringAfter("=")
                        }
                        trimmed.startsWith("rx_bytes=") -> {
                            rxBytes = trimmed.substringAfter("=").toLongOrNull() ?: 0
                        }
                        trimmed.startsWith("tx_bytes=") -> {
                            txBytes = trimmed.substringAfter("=").toLongOrNull() ?: 0
                        }
                    }
                }

                val now = System.currentTimeMillis() / 1000
                val handshakeAge = if (lastHandshake > 0) now - lastHandshake else -1

                return ConnectionHealth(
                    handshakeAge = handshakeAge,
                    lastHandshakeEpoch = lastHandshake,
                    endpoint = endpoint.ifEmpty { resolvedEndpoint },
                    transferRx = rxBytes,
                    transferTx = txBytes
                )
            }
        } catch (e: Exception) {
            Log.w(TAG, "wgGetConfig failed: ${e.message}")
        }

        // Fallback: no wgGetConfig, return unknown health
        return ConnectionHealth(endpoint = resolvedEndpoint)
    }

    suspend fun disconnect(prefs: VpnPreferences) {
        try {
            _vpnState.value = VpnState.DISCONNECTING
            if (tunnelHandle >= 0) {
                wgTurnOffMethod?.invoke(null, tunnelHandle)
                tunnelHandle = -1
            }
            tunFd?.close()
            tunFd = null
        } catch (e: Exception) {
            Log.e(TAG, "Disconnect error", e)
        } finally {
            _vpnState.value = VpnState.DISCONNECTED
            _trafficStats.value = TrafficStats()
            _connectionHealth.value = ConnectionHealth()
            updateNotification("Disconnected")
        }
    }

    private fun updateNotification(status: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, createNotification(status))
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
                    Thread.sleep(500L * attempt)
                }
            }
        }
        throw Exception("Failed to resolve endpoint hostname '$host' after $maxRetries attempts: ${lastException?.message}", lastException)
    }

    private fun isIpAddress(host: String): Boolean {
        return host.matches(Regex("^\\d{1,3}(\\.\\d{1,3}){3}$")) || host.contains(":")
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

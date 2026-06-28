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
import android.util.Base64
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

        private val _vpnState = MutableStateFlow(VpnState.DISCONNECTED)
        val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

        private val _trafficStats = MutableStateFlow(TrafficStats())
        val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

        private var serviceInstance: TunnelyVpnService? = null
        private var tunnelHandle: Int = -1
        private var tunFd: ParcelFileDescriptor? = null

        // Native WireGuard functions (loaded from tunnel library's .so)
        private var wgTurnOnMethod: java.lang.reflect.Method? = null
        private var wgTurnOffMethod: java.lang.reflect.Method? = null
        private var wgGetSocketV4Method: java.lang.reflect.Method? = null
        private var wgGetSocketV6Method: java.lang.reflect.Method? = null

        init {
            try {
                // Load native library (shipped with wireguard tunnel dependency)
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

            // Use reflection to access GoBackend's native methods
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
                Log.d(TAG, "GoBackend native methods accessible via reflection")
            } catch (e: Exception) {
                Log.e(TAG, "Failed to access GoBackend methods", e)
            }
        }

        fun connect(context: Context, prefs: VpnPreferences) {
            val intent = Intent(context, TunnelyVpnService::class.java)
            context.startService(intent)

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

            // Build VPN tunnel using Android VpnService.Builder
            val builder = Builder()
                .setSession(TUNNEL_NAME)
                .setMtu(prefs.mtu)

            // Add addresses
            for (addr in prefs.tunnelAddress.split(",").map { it.trim() }) {
                if (addr.isNotBlank()) {
                    val parts = addr.split("/")
                    if (parts.size == 2) {
                        builder.addAddress(parts[0], parts[1].toInt())
                    }
                }
            }

            // Add DNS servers
            for (dns in prefs.dnsServers.split(",").map { it.trim() }) {
                if (dns.isNotBlank()) {
                    for (resolved in InetAddress.getAllByName(dns)) {
                        builder.addDnsServer(resolved)
                    }
                }
            }

            // Add routes
            for (route in prefs.allowedIps.split(",").map { it.trim() }) {
                if (route.isNotBlank()) {
                    val parts = route.split("/")
                    if (parts.size == 2) {
                        builder.addRoute(parts[0], parts[1].toInt())
                    }
                }
            }

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q)
                builder.setMetered(false)
            builder.setBlocking(true)

            // Establish TUN interface
            val fd = builder.establish()
                ?: throw Exception("Failed to establish TUN interface")
            tunFd = fd

            // Build WireGuard userspace config string
            val privateKeyBytes = prefs.decodePrivateKey()
            val privateKeyHex = bytesToHex(privateKeyBytes)
            val serverKeyBytes = prefs.decodeServerPublicKey()
            val serverKeyHex = bytesToHex(serverKeyBytes)

            val wgConfig = buildString {
                append("private_key=$privateKeyHex\n")
                append("listen_port=0\n")
                append("mtu=${prefs.mtu}\n")
                append("replace_peers=true\n")
                append("public_key=$serverKeyHex\n")
                append("endpoint=${prefs.serverAddress}:${prefs.serverPort}\n")
                append("persistent_keepalive_interval=25\n")
                append("replace_allowed_ips=true\n")
                for (ip in prefs.allowedIps.split(",").map { it.trim() }) {
                    if (ip.isNotBlank()) {
                        append("allowed_ip=$ip\n")
                    }
                }
            }

            Log.d(TAG, "Starting WireGuard tunnel via reflection...")
            Log.d(TAG, "Config: $wgConfig")

            // Call wgTurnOn via reflection
            val handle = wgTurnOnMethod?.invoke(null, TUNNEL_NAME, fd.detachFd(), wgConfig) as? Int
                ?: throw Exception("wgTurnOn returned null")

            if (handle < 0) {
                throw Exception("wgTurnOn failed with code: $handle")
            }

            tunnelHandle = handle
            Log.d(TAG, "WireGuard tunnel started, handle: $tunnelHandle")

            // Protect sockets from VPN routing
            try {
                val sock4 = wgGetSocketV4Method?.invoke(null, tunnelHandle) as? Int ?: -1
                val sock6 = wgGetSocketV6Method?.invoke(null, tunnelHandle) as? Int ?: -1
                if (sock4 >= 0) protect(sock4)
                if (sock6 >= 0) protect(sock6)
            } catch (e: Exception) {
                Log.w(TAG, "Socket protect failed (non-fatal)", e)
            }

            _vpnState.value = VpnState.CONNECTED
            updateNotification()

        } catch (e: Exception) {
            Log.e(TAG, "Connect failed", e)
            _vpnState.value = VpnState.ERROR
            throw e
        }
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

            _vpnState.value = VpnState.DISCONNECTED
            _trafficStats.value = TrafficStats()
            updateNotification()

        } catch (e: Exception) {
            Log.e(TAG, "Disconnect failed", e)
            _vpnState.value = VpnState.ERROR
            throw e
        }
    }

    private fun updateNotification() {
        val nm = getSystemService(NotificationManager::class.java)
        val status = when (_vpnState.value) {
            VpnState.CONNECTED -> "Connected"
            VpnState.CONNECTING -> "Connecting..."
            VpnState.DISCONNECTING -> "Disconnecting..."
            VpnState.ERROR -> "Error"
            VpnState.DISCONNECTED -> "Disconnected"
        }
        nm.notify(NOTIFICATION_ID, createNotification(status))
    }

    fun updateTrafficStats(rx: Long, tx: Long) {
        _trafficStats.value = TrafficStats(rx, tx)
    }

    private fun bytesToHex(bytes: ByteArray): String {
        return bytes.joinToString("") { "%02x".format(it) }
    }
}

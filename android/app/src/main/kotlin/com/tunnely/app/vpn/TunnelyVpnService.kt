package com.tunnely.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Intent
import android.net.VpnService
import android.os.Binder
import android.os.Build
import android.os.IBinder
import androidx.core.app.NotificationCompat
import com.wireguard.android.backend.GoBackend
import com.wireguard.android.backend.Tunnel
import com.wireguard.config.Config
import com.wireguard.config.InetNetwork
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.tunnely.app.MainActivity
import com.tunnely.app.R
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
        const val TUNNEL_NAME = "tunnely-vpn"
        const val NOTIFICATION_CHANNEL_ID = "tunnely_vpn"
        const val NOTIFICATION_ID = 1

        private val _vpnState = MutableStateFlow(VpnState.DISCONNECTED)
        val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

        private val _trafficStats = MutableStateFlow(TrafficStats())
        val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

        private var backend: GoBackend? = null
        private var serviceInstance: TunnelyVpnService? = null

        val tunnel = object : Tunnel {
            override fun getName(): String = TUNNEL_NAME
            override fun onStateChange(newState: Tunnel.State) {}
        }

        fun connect(context: Context, prefs: VpnPreferences) {
            // Start the service
            val intent = Intent(context, TunnelyVpnService::class.java)
            context.startService(intent)

            // Connect via coroutine
            kotlinx.coroutines.GlobalScope.launch(kotlinx.coroutines.Dispatchers.IO) {
                // Wait for service to be ready
                var attempts = 0
                while (serviceInstance == null && attempts < 20) {
                    kotlinx.coroutines.delay(100)
                    attempts++
                }
                serviceInstance?.connect(prefs)
            }
        }

        fun disconnect(context: Context, prefs: VpnPreferences) {
            kotlinx.coroutines.GlobalScope.launch(kotlinx.coroutines.Dispatchers.IO) {
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
        startForeground(NOTIFICATION_ID, createNotification("Disconnected"))
        return START_STICKY
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

            if (backend == null) {
                backend = GoBackend(this)
            }

            val config = buildConfig(prefs)

            backend!!.setState(tunnel, Tunnel.State.UP, config)

            _vpnState.value = VpnState.CONNECTED
            updateNotification()

        } catch (e: Exception) {
            _vpnState.value = VpnState.ERROR
            throw e
        }
    }

    suspend fun disconnect(prefs: VpnPreferences) {
        try {
            _vpnState.value = VpnState.DISCONNECTING
            if (backend != null) {
                val config = buildConfig(prefs)
                backend!!.setState(tunnel, Tunnel.State.DOWN, config)
            }
            _vpnState.value = VpnState.DISCONNECTED
            _trafficStats.value = TrafficStats()
            updateNotification()
        } catch (e: Exception) {
            _vpnState.value = VpnState.ERROR
            throw e
        }
    }

    private fun buildConfig(prefs: VpnPreferences): Config {
        val ifaceBuilder = Interface.Builder()
            .parsePrivateKey(prefs.privateKey)
            .parseAddresses(prefs.tunnelAddress)
            .parseMtu(prefs.mtu.toString())

        // Add DNS servers
        for (dns in prefs.dnsServers.split(",").map { it.trim() }) {
            if (dns.isNotBlank()) {
                for (addr in InetAddress.getAllByName(dns)) {
                    ifaceBuilder.addDnsServer(addr)
                }
            }
        }

        // Split tunneling: exclude selected apps
        if (prefs.splitTunneling && prefs.splitApps.isNotEmpty()) {
            ifaceBuilder.excludeApplications(prefs.splitApps)
        }

        val peerBuilder = Peer.Builder()
            .parsePublicKey(prefs.serverPublicKey)
            .parseEndpoint("${prefs.serverAddress}:${prefs.serverPort}")
            .parsePersistentKeepalive("25")

        val allowedIpList = prefs.allowedIps.split(",").map { it.trim() }
            .filter { it.isNotBlank() }
            .map { InetNetwork.parse(it) }
        peerBuilder.addAllowedIps(allowedIpList)

        return Config.Builder()
            .setInterface(ifaceBuilder.build())
            .addPeer(peerBuilder.build())
            .build()
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
}

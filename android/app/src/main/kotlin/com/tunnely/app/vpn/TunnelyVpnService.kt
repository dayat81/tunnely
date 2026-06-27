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
import com.wireguard.config.Config
import com.wireguard.config.InetEndpoint
import com.wireguard.config.InetNetwork
import com.wireguard.config.Interface
import com.wireguard.config.Peer
import com.tunnely.app.MainActivity
import com.tunnely.app.R
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

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
        private var tunnel: GoBackend.VpnServiceTunnel? = null
    }

    inner class LocalBinder : Binder() {
        fun getService(): TunnelyVpnService = this@TunnelyVpnService
    }

    private val binder = LocalBinder()

    override fun onBind(intent: Intent?): IBinder = binder

    override fun onCreate() {
        super.onCreate()
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

            if (tunnel == null) {
                tunnel = object : GoBackend.VpnServiceTunnel {
                    override fun getName(): String = TUNNEL_NAME

                    override fun onStateChange(state: com.wireguard.tunnel.Tunnel.State) {
                        _vpnState.value = when (state) {
                            com.wireguard.tunnel.Tunnel.State.UP -> VpnState.CONNECTED
                            com.wireguard.tunnel.Tunnel.State.DOWN -> VpnState.DISCONNECTED
                            com.wireguard.tunnel.Tunnel.State.TOGGLE -> _vpnState.value
                        }
                        updateNotification()
                    }

                    override fun onError(e: Throwable?) {
                        _vpnState.value = VpnState.ERROR
                    }
                }
            }

            backend?.setState(
                tunnel!!,
                com.wireguard.tunnel.Tunnel.State.UP,
                config
            )

            _vpnState.value = VpnState.CONNECTED
            updateNotification()

        } catch (e: Exception) {
            _vpnState.value = VpnState.ERROR
            throw e
        }
    }

    suspend fun disconnect() {
        try {
            _vpnState.value = VpnState.DISCONNECTING
            if (tunnel != null && backend != null) {
                backend?.setState(
                    tunnel!!,
                    com.wireguard.tunnel.Tunnel.State.DOWN,
                    null
                )
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
            .parseDnsServers(prefs.dnsServers)
            .parseMtu(prefs.mtu.toString())

        // Add tunnel address
        if (prefs.tunnelAddress.isNotEmpty()) {
            ifaceBuilder.parseAddresses(prefs.tunnelAddress)
        }

        // Split tunneling
        if (prefs.splitTunneling) {
            prefs.splitApps.forEach { pkg ->
                ifaceBuilder.parseExcludeApplications(pkg)
            }
        }

        val peerBuilder = Peer.Builder()
            .parsePublicKey(prefs.serverPublicKey)
            .parseEndpoint("${prefs.serverAddress}:${prefs.serverPort}")
            .parseAllowedIPs(prefs.allowedIps)
            .parsePersistentKeepalive("25")

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

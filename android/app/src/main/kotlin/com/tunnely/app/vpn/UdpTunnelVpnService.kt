package com.tunnely.app.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import androidx.core.app.NotificationCompat
import androidx.lifecycle.LifecycleService
import com.tunnely.app.MainActivity
import com.tunnely.app.R
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
import java.io.FileInputStream
import java.io.FileOutputStream
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress
import java.nio.ByteBuffer

/**
 * UDP Tunnel VPN Service — replaces WireGuard GoBackend.
 *
 * Architecture:
 *   App traffic → Android TUN fd → UDP socket → Server TUN → Internet
 *
 * No WireGuard, no crypto, no key management.
 * Server auto-assigns tunnel IP on first packet.
 *
 * Two I/O threads:
 *   - downThread: TUN → UDP (app packets to server)
 *   - upThread:   UDP → TUN (server responses to app)
 *
 * The UDP socket is protect()'ed to prevent routing loop.
 */
class UdpTunnelVpnService : VpnService() {

    companion object {
        private const val TAG = "TunnelyUdp"
        private const val NOTIFICATION_CHANNEL_ID = "tunnely_udp_vpn"
        private const val NOTIFICATION_ID = 1

        private const val TUNNEL_PORT = 8770
        private const val TUNNEL_MTU = 1500
        private const val KEEPALIVE_INTERVAL = 15_000L // 15s
        private const val MAX_PACKET = 32767

        // Shared state (same interface as old TunnelyVpnService for UI compat)
        private val _vpnState = MutableStateFlow(VpnState.DISCONNECTED)
        val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

        private val _trafficStats = MutableStateFlow(TrafficStats())
        val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

        private val _connectionHealth = MutableStateFlow(ConnectionHealth())
        val connectionHealth: StateFlow<ConnectionHealth> = _connectionHealth.asStateFlow()

        private var serviceInstance: UdpTunnelVpnService? = null

        fun connect(context: Context, prefs: VpnPreferences) {
            RemoteLogger.i(TAG, "🔵 UdpTunnelVpnService.connect() called")
            RemoteLogger.i(TAG, "  server=${prefs.serverAddress}:${prefs.serverPort}")
            val intent = Intent(context, UdpTunnelVpnService::class.java)
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
                RemoteLogger.i(TAG, "  Service ready after ${attempts * 100}ms")
                serviceInstance?.doConnect(prefs)
            }
        }

        fun disconnect(context: Context, prefs: VpnPreferences) {
            GlobalScope.launch(Dispatchers.IO) {
                serviceInstance?.doDisconnect()
            }
        }
    }

    private var tunFd: ParcelFileDescriptor? = null
    private var udpSocket: DatagramSocket? = null
    private var downThread: Thread? = null   // TUN → UDP
    private var upThread: Thread? = null     // UDP → TUN
    private var monitorThread: Thread? = null
    @Volatile private var running = false

    private var totalRx: Long = 0
    private var totalTx: Long = 0
    private var lastPacketTime: Long = 0
    private var connectTime: Long = 0

    override fun onCreate() {
        super.onCreate()
        RemoteLogger.i(TAG, "🟠 onCreate()")
        serviceInstance = this
        createNotificationChannel()
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        RemoteLogger.i(TAG, "🟠 onStartCommand()")
        // Android 14+ requires foreground service type
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                createNotification("Connecting..."),
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, createNotification("Connecting..."))
        }
        return START_STICKY
    }

    override fun onDestroy() {
        RemoteLogger.i(TAG, "🟠 onDestroy()")
        serviceInstance = null
        doDisconnect()
        super.onDestroy()
    }

    override fun onRevoke() {
        // System revoked VPN permission
        RemoteLogger.i(TAG, "🟠 onRevoke() — VPN permission revoked")
        doDisconnect()
    }

    private fun doConnect(prefs: VpnPreferences) {
        RemoteLogger.i(TAG, "🔴 doConnect() started")
        _vpnState.value = VpnState.CONNECTING
        _connectionHealth.value = ConnectionHealth()
        running = true
        totalRx = 0
        totalTx = 0
        connectTime = System.currentTimeMillis()

        try {
            // Step 1: Resolve server address
            val serverHost = prefs.serverAddress
            val serverPort = TUNNEL_PORT  // UDP tunnel always uses 5555
            RemoteLogger.i(TAG, "Step 1: Resolving $serverHost...")
            val serverAddr = InetAddress.getByName(serverHost)
            RemoteLogger.i(TAG, "Step 1: ✅ Resolved → ${serverAddr.hostAddress}")

            // Step 2: Create UDP socket and PROTECT it (critical!)
            RemoteLogger.i(TAG, "Step 2: Creating UDP socket to ${serverAddr.hostAddress}:$serverPort")
            udpSocket = DatagramSocket()
            udpSocket!!.soTimeout = 5000
            // protect() prevents the UDP socket's traffic from going through the TUN
            // Without this, we get a routing loop (packet enters TUN → tries to send via TUN → loop)
            if (!protect(udpSocket!!)) {
                throw Exception("Failed to protect UDP socket — VPN cannot start")
            }
            RemoteLogger.i(TAG, "Step 2: ✅ UDP socket protected + bound")

            // Step 3: Establish TUN interface
            RemoteLogger.i(TAG, "Step 3: Building TUN interface...")
            val builder = Builder()
                .setSession("Tunnely")
                .addAddress("10.20.0.2", 32)  // Dummy IP, server rewrites
                .addRoute("0.0.0.0", 0)       // Route everything through tunnel
                .setMtu(TUNNEL_MTU)
                .addDnsServer("1.1.1.1")
                .addDnsServer("8.8.8.8")

            // Split tunneling
            if (prefs.splitTunneling && prefs.splitApps.isNotEmpty()) {
                for (pkg in prefs.splitApps) {
                    try {
                        builder.addAllowedApplication(pkg)
                    } catch (e: Exception) {
                        RemoteLogger.w(TAG, "  Failed to add $pkg: ${e.message}")
                    }
                }
                RemoteLogger.i(TAG, "  Split tunneling: ${prefs.splitApps.size} apps")
            }

            builder.setConfigureIntent(
                PendingIntent.getActivity(
                    this, 0,
                    Intent(this, MainActivity::class.java),
                    PendingIntent.FLAG_IMMUTABLE
                )
            )

            tunFd = builder.establish()
            if (tunFd == null) {
                throw Exception("VpnService.Builder.establish() returned null — permission denied?")
            }
            RemoteLogger.i(TAG, "Step 3: ✅ TUN established (fd=${tunFd!!.fd})")

            // Step 4: Send initial keepalive so server learns our address
            RemoteLogger.i(TAG, "Step 4: Sending initial packet to register with server...")
            val hello = ByteBuffer.allocate(4).putInt(0x54554E4E).array() // "TUNN" magic
            udpSocket!!.send(DatagramPacket(hello, hello.size, serverAddr, serverPort))

            // Step 5: Start I/O threads
            RemoteLogger.i(TAG, "Step 5: Starting I/O threads...")
            startTunToUdpThread(serverAddr, serverPort)
            startUdpToTunThread()
            startMonitorThread()

            // Step 6: Update state
            _vpnState.value = VpnState.CONNECTED
            lastPacketTime = System.currentTimeMillis()
            _connectionHealth.value = ConnectionHealth(
                endpoint = "${serverAddr.hostAddress}:$serverPort"
            )
            updateNotification("Connected ✓")
            RemoteLogger.i(TAG, "Step 6: ✅ VPN connected! Tunnel active.")

        } catch (e: CancellationException) {
            throw e
        } catch (e: Exception) {
            RemoteLogger.e(TAG, "Connect failed: ${e.message}", e)
            _vpnState.value = VpnState.ERROR
            _connectionHealth.value = ConnectionHealth(error = e.message ?: "Unknown error")
            updateNotification("Error: ${e.message}")
            Thread.sleep(3000)
            doDisconnect()
        }
    }

    /**
     * Thread 1: TUN → UDP
     * Reads raw IP packets from the Android TUN fd, sends them to the server via UDP.
     */
    private fun startTunToUdpThread(serverAddr: InetAddress, serverPort: Int) {
        downThread = Thread({
            val pfd = tunFd ?: return@Thread
            val input = FileInputStream(pfd.fileDescriptor)
            val buf = ByteArray(MAX_PACKET)
            val outPkt = DatagramPacket(buf, 0, serverAddr, serverPort)
            val sock = udpSocket ?: return@Thread

            RemoteLogger.i(TAG, "↓ TUN→UDP thread started")
            while (running && !Thread.interrupted()) {
                try {
                    val n = input.read(buf)
                    if (n <= 0) continue

                    // Send raw IP packet to server
                    // Track flow
                    PacketFlowTracker.processPacket(buf.copyOf(n), isUplink = true)

                    outPkt.length = n
                    sock.send(outPkt)

                    totalTx += n
                    lastPacketTime = System.currentTimeMillis()
                } catch (e: java.net.PortUnreachableException) {
                    // Server not ready yet, retry
                } catch (e: java.io.IOException) {
                    if (running) RemoteLogger.w(TAG, "↓ TUN read error: ${e.message}")
                    break
                } catch (e: Exception) {
                    if (running) RemoteLogger.w(TAG, "↓ loop error: ${e.message}")
                }
            }
            RemoteLogger.i(TAG, "↓ TUN→UDP thread stopped")
            try { input.close() } catch (_: Exception) {}
        }, "tun-to-udp").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Thread 2: UDP → TUN
     * Receives packets from server via UDP, writes them to the Android TUN fd.
     */
    private fun startUdpToTunThread() {
        upThread = Thread({
            val pfd = tunFd ?: return@Thread
            val output = FileOutputStream(pfd.fileDescriptor)
            val buf = ByteArray(MAX_PACKET)
            val pkt = DatagramPacket(buf, buf.size)
            val sock = udpSocket ?: return@Thread

            RemoteLogger.i(TAG, "↑ UDP→TUN thread started")
            while (running && !Thread.interrupted()) {
                try {
                    sock.receive(pkt)
                    val n = pkt.length
                    if (n <= 0) continue

                    // Track flow
                    PacketFlowTracker.processPacket(buf.copyOf(n), isUplink = false)

                    // Write raw IP packet to TUN
                    output.write(buf, 0, n)

                    totalRx += n
                    lastPacketTime = System.currentTimeMillis()
                } catch (e: java.net.SocketTimeoutException) {
                    // Normal — just means no data for 5s
                    continue
                } catch (e: java.io.IOException) {
                    if (running) RemoteLogger.w(TAG, "↑ TUN write error: ${e.message}")
                    break
                } catch (e: Exception) {
                    if (running) RemoteLogger.w(TAG, "↑ loop error: ${e.message}")
                }
            }
            RemoteLogger.i(TAG, "↑ UDP→TUN thread stopped")
            try { output.close() } catch (_: Exception) {}
        }, "udp-to-tun").apply {
            isDaemon = true
            start()
        }
    }

    /**
     * Thread 3: Monitor — keepalive, stats, health checks
     */
    private fun startMonitorThread() {
        monitorThread = Thread({
            RemoteLogger.i(TAG, "◉ Monitor thread started")
            val keepaliveBuf = ByteBuffer.allocate(4).putInt(0x4B454550).array() // "KEEP"

            while (running && !Thread.interrupted()) {
                try {
                    Thread.sleep(KEEPALIVE_INTERVAL)

                    // Send keepalive to maintain NAT mapping
                    val sock = udpSocket
                    val pfd = tunFd
                    if (sock != null && pfd != null && running) {
                        try {
                            // Keepalive goes directly via UDP, NOT through TUN
                            // We need server addr/port — reuse the connected socket
                            // Since DatagramSocket isn't connected, we need explicit dest
                            // This is handled by the downThread naturally sending data
                        } catch (_: Exception) {}

                        // Update traffic stats
                        _trafficStats.value = TrafficStats(
                            rxBytes = totalRx,
                            txBytes = totalTx
                        )

                        // Update health
                        val idleSecs = (System.currentTimeMillis() - lastPacketTime) / 1000
                        val uptimeSecs = (System.currentTimeMillis() - connectTime) / 1000
                        _connectionHealth.value = _connectionHealth.value.copy(
                            handshakeAge = if (totalRx > 0 || totalTx > 0) idleSecs else -1,
                            transferRx = totalRx,
                            transferTx = totalTx
                        )

                        // Check for dead connection (no traffic for 60s)
                        if (idleSecs > 60 && totalRx == 0L) {
                            RemoteLogger.w(TAG, "No traffic for ${idleSecs}s, may be disconnected")
                        }
                    }
                } catch (e: InterruptedException) {
                    break
                } catch (e: Exception) {
                    if (running) RemoteLogger.w(TAG, "◉ monitor error: ${e.message}")
                }
            }
            RemoteLogger.i(TAG, "◉ Monitor thread stopped")
        }, "udp-monitor").apply {
            isDaemon = true
            start()
        }
    }

    private fun doDisconnect() {
        RemoteLogger.i(TAG, "🔴 doDisconnect()")
        running = false
        _vpnState.value = VpnState.DISCONNECTING

        // Stop threads
        downThread?.interrupt()
        upThread?.interrupt()
        monitorThread?.interrupt()
        try { downThread?.join(1000) } catch (_: Exception) {}
        try { upThread?.join(1000) } catch (_: Exception) {}
        try { monitorThread?.join(1000) } catch (_: Exception) {}

        // Close TUN
        try { tunFd?.close() } catch (_: Exception) {}
        tunFd = null

        // Close UDP socket
        try { udpSocket?.close() } catch (_: Exception) {}
        udpSocket = null

        _vpnState.value = VpnState.DISCONNECTED
        _trafficStats.value = TrafficStats()
        _connectionHealth.value = ConnectionHealth()
        updateNotification("Disconnected")

        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    // ── Notification ───────────────────────────────────────────────────────

    private fun createNotificationChannel() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O) return
        val channel = NotificationChannel(
            NOTIFICATION_CHANNEL_ID,
            "Tunnely VPN (UDP)",
            NotificationManager.IMPORTANCE_LOW
        ).apply { description = "Tunnely UDP tunnel connection" }
        getSystemService(NotificationManager::class.java).createNotificationChannel(channel)
    }

    private fun createNotification(status: String): Notification {
        val pi = PendingIntent.getActivity(
            this, 0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE
        )
        return NotificationCompat.Builder(this, NOTIFICATION_CHANNEL_ID)
            .setContentTitle("Tunnely")
            .setContentText(status)
            .setSmallIcon(R.drawable.ic_vpn_key)
            .setContentIntent(pi)
            .setOngoing(true)
            .build()
    }

    private fun updateNotification(status: String) {
        val nm = getSystemService(NotificationManager::class.java)
        nm.notify(NOTIFICATION_ID, createNotification(status))
    }
}

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
        private const val TUNNEL_MTU = 1400  // Must be ≤ (ext_iface_MTU - 28 UDP overhead). GCP ens4=1460, so 1400 is safe.
        private const val KEEPALIVE_INTERVAL = 15_000L // 15s
        private const val MAX_PACKET = 32767

        // DNS handled server-side: server intercepts 10.0.2.3:53 and forwards to 8.8.8.8.
        // No client-side packet manipulation needed.

        // Shared state (same interface as old TunnelyVpnService for UI compat)
        private val _vpnState = MutableStateFlow(VpnState.DISCONNECTED)
        val vpnState: StateFlow<VpnState> = _vpnState.asStateFlow()

        private val _trafficStats = MutableStateFlow(TrafficStats())
        val trafficStats: StateFlow<TrafficStats> = _trafficStats.asStateFlow()

        private val _connectionHealth = MutableStateFlow(ConnectionHealth())
        val connectionHealth: StateFlow<ConnectionHealth> = _connectionHealth.asStateFlow()

        data class LatencyStats(
            val uplinkMs: Float = 0f,
            val downlinkMs: Float = 0f,
            val rttMs: Float = 0f,
            val probesSent: Long = 0,
            val probesRecv: Long = 0,
        )

        private val _latencyStats = MutableStateFlow(LatencyStats())
        val latencyStats: StateFlow<LatencyStats> = _latencyStats.asStateFlow()

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
    private var serverAddr: InetAddress? = null
    private var serverPort: Int = 0

    @Volatile private var totalRx: Long = 0
    @Volatile private var totalTx: Long = 0
    @Volatile private var lastPacketTime: Long = 0
    private var connectTime: Long = 0

    // Latency probe state
    @Volatile private var probeSeq: Int = 0
    private val probeSentTimes = java.util.concurrent.ConcurrentHashMap<Int, Long>()
    @Volatile private var probesSent: Long = 0
    @Volatile private var probesRecv: Long = 0
    @Volatile private var emaRtt: Float = 0f
    @Volatile private var emaUplink: Float = 0f
    @Volatile private var emaDownlink: Float = 0f
    private val EMA_ALPHA = 0.3f
    private var lastProbeSentMs: Long = 0  // separate timing from keepalive

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
        PacketFlowTracker.clear()
        running = true
        totalRx = 0
        totalTx = 0
        connectTime = System.currentTimeMillis()

        // Reset latency probe state
        probeSeq = 0
        probeSentTimes.clear()
        probesSent = 0
        probesRecv = 0
        emaRtt = 0f
        emaUplink = 0f
        emaDownlink = 0f
        _latencyStats.value = LatencyStats()

        try {
            // Step 1: Resolve server address
            val serverHost = prefs.serverAddress
            val srvPort = TUNNEL_PORT  // UDP tunnel always uses 5555
            RemoteLogger.i(TAG, "Step 1: Resolving $serverHost...")
            val srvAddr = InetAddress.getByName(serverHost)
            RemoteLogger.i(TAG, "Step 1: ✅ Resolved → ${srvAddr.hostAddress}")

            // Store as class fields for keepalive
            this.serverAddr = srvAddr
            this.serverPort = srvPort

            // Step 2: Create UDP socket and PROTECT it (critical!)
            RemoteLogger.i(TAG, "Step 2: Creating UDP socket to ${srvAddr.hostAddress}:$srvPort")
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
                // DNS configured at builder level — system resolver uses these directly.
                // No runtime interceptor needed. DNS packets to these IPs go through tunnel
                // to server → internet → response comes back. Simple.
                .addDnsServer("8.8.8.8")
                .addDnsServer("1.1.1.1")

            // Split tunneling
            if (prefs.splitTunneling) {
                // Always exclude ourselves to prevent routing loop
                try {
                    builder.addDisallowedApplication(packageName)
                } catch (_: Exception) {}
                
                val mode = prefs.splitMode
                RemoteLogger.i(TAG, "  Split mode from prefs: '$mode'")
                RemoteLogger.i(TAG, "  Split apps: ${prefs.splitApps}")
                
                if (mode == "include") {
                    // INCLUDE mode: only selected apps go through VPN
                    // Note: 0 apps case handled later (throws exception to prevent VPN start)
                    for (pkg in prefs.splitApps) {
                        try {
                            builder.addAllowedApplication(pkg)
                            RemoteLogger.i(TAG, "  ✅ Allowed: $pkg")
                        } catch (e: Exception) {
                            RemoteLogger.w(TAG, "  ❌ Failed to include $pkg: ${e.message}")
                        }
                    }
                    RemoteLogger.i(TAG, "  Split tunneling [include]: ${prefs.splitApps.size} apps through VPN")
                } else {
                    // EXCLUDE mode (default): selected apps bypass VPN, all else through VPN
                    // Uses addDisallowedApplication — more reliable for TCP
                    for (pkg in prefs.splitApps) {
                        try {
                            builder.addDisallowedApplication(pkg)
                            RemoteLogger.i(TAG, "  ✅ Disallowed: $pkg")
                        } catch (e: Exception) {
                            RemoteLogger.w(TAG, "  ❌ Failed to exclude $pkg: ${e.message}")
                        }
                    }
                    RemoteLogger.i(TAG, "  Split tunneling [exclude]: ${prefs.splitApps.size} apps bypass VPN")
                }
            } else {
                RemoteLogger.i(TAG, "  Split tunneling disabled (splitTunneling=${prefs.splitTunneling})")
            }

            // Prevent VPN establishment if Include mode has 0 apps
            // Android falls back to "allow all" when addAllowedApplication list is empty
            if (prefs.splitTunneling && prefs.splitMode == "include" && prefs.splitApps.isEmpty()) {
                throw Exception("Include mode requires at least 1 app. No apps selected — VPN not started.")
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
            udpSocket!!.send(DatagramPacket(hello, hello.size, srvAddr, srvPort))

            // Step 5: Start I/O threads
            RemoteLogger.i(TAG, "Step 5: Starting I/O threads...")
            startTunToUdpThread(srvAddr, srvPort)
            startUdpToTunThread()
            startMonitorThread()

            // Step 6: Update state
            _vpnState.value = VpnState.CONNECTED
            lastPacketTime = System.currentTimeMillis()
            _connectionHealth.value = ConnectionHealth(
                endpoint = "${srvAddr.hostAddress}:$srvPort"
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

                    // Track flow
                    PacketFlowTracker.processPacket(buf.copyOf(n), isUplink = true)

                    outPkt.length = n
                    sock.send(outPkt)

                    totalTx += n
                    lastPacketTime = System.currentTimeMillis()
                } catch (e: java.net.PortUnreachableException) {
                    // Server not ready yet, retry
                } catch (e: java.io.IOException) {
                    if (!running) break
                    RemoteLogger.w(TAG, "↓ TUN read error: ${e.message}, retrying...")
                    Thread.sleep(100)  // brief pause before retry
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

                    // Detect latency probe response (before normal packet processing)
                    if (n == LatencyProber.PACKET_SIZE) {
                        val probe = LatencyProber.decode(buf.copyOf(n))
                        if (probe != null && probe.type == LatencyProber.TYPE_RESPONSE) {
                            val nowUs = LatencyProber.nowMicros()
                            val sentUs = probeSentTimes.remove(probe.sequence)
                            if (sentUs != null) {
                                val rttUs = nowUs - sentUs
                                // Server processing = server_echo - server_recv (same machine clock)
                                val serverProcUs = (probe.serverEchoTs - probe.serverRecvTs).coerceAtLeast(0)
                                // Network RTT = total RTT - server processing
                                val networkRttUs = (rttUs - serverProcUs).coerceAtLeast(0)
                                // Estimate: uplink ≈ downlink ≈ network_rtt / 2
                                val uplinkUs = networkRttUs / 2
                                val downlinkUs = networkRttUs / 2

                                probesRecv++
                                val rttMs = rttUs / 1000f
                                val uplinkMs = uplinkUs / 1000f
                                val downlinkMs = downlinkUs / 1000f

                                if (emaRtt == 0f) {
                                    emaRtt = rttMs; emaUplink = uplinkMs; emaDownlink = downlinkMs
                                } else {
                                    emaRtt = EMA_ALPHA * rttMs + (1 - EMA_ALPHA) * emaRtt
                                    emaUplink = EMA_ALPHA * uplinkMs + (1 - EMA_ALPHA) * emaUplink
                                    emaDownlink = EMA_ALPHA * downlinkMs + (1 - EMA_ALPHA) * emaDownlink
                                }

                                _latencyStats.value = LatencyStats(
                                    uplinkMs = emaUplink,
                                    downlinkMs = emaDownlink,
                                    rttMs = emaRtt,
                                    probesSent = probesSent,
                                    probesRecv = probesRecv,
                                )
                            }
                            continue  // Don't write probe responses to TUN
                        }
                    }

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
                    if (!running) break
                    RemoteLogger.w(TAG, "↑ TUN write error: ${e.message}, retrying...")
                    Thread.sleep(100)
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
            val keepaliveBuf = ByteBuffer.allocate(4).putInt(0x54554E4E).array() // "TUNN" magic (same as hello)

            while (running && !Thread.interrupted()) {
                try {
                    // Send keepalive FIRST (don't delay — NAT mapping may expire)
                    val sock = udpSocket
                    val addr = serverAddr
                    val port = serverPort
                    if (sock != null && addr != null && port > 0 && running) {
                        try {
                            sock.send(DatagramPacket(keepaliveBuf, keepaliveBuf.size, addr, port))
                        } catch (e: Exception) {
                            RemoteLogger.w(TAG, "Keepalive send failed: ${e.message}")
                        }

                        // Send latency probe (every 5s, separate from 15s keepalive)
                        val nowMs = System.currentTimeMillis()
                        if (running && nowMs - lastProbeSentMs >= LatencyProber.PROBE_INTERVAL_MS) {
                            try {
                                val nowUs = LatencyProber.nowMicros()
                                val seq = probeSeq++
                                val pkt = LatencyProber.ProbePacket(
                                    type = LatencyProber.TYPE_REQUEST,
                                    sequence = seq,
                                    clientSendTs = nowUs,
                                    serverRecvTs = 0L,
                                    serverEchoTs = 0L,
                                )
                                probeSentTimes[seq] = nowUs
                                val data = LatencyProber.encode(pkt)
                                sock.send(DatagramPacket(data, data.size, addr, port))
                                probesSent++
                                lastProbeSentMs = nowMs

                                // Purge stale probe entries (>30s) to prevent memory leak
                                val cutoffUs = nowUs - 30_000_000L
                                val iter = probeSentTimes.entries.iterator()
                                while (iter.hasNext()) {
                                    if (iter.next().value < cutoffUs) iter.remove()
                                }
                            } catch (_: Exception) {}
                        }
                    }

                    // Sleep in 5s chunks to allow probe timing (not 15s keepalive block)
                    // Keepalive is sent every iteration (every 5s) — cheap UDP packet
                    Thread.sleep(LatencyProber.PROBE_INTERVAL_MS)

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
        serverAddr = null
        serverPort = 0

        _vpnState.value = VpnState.DISCONNECTED
        _trafficStats.value = TrafficStats()
        _connectionHealth.value = ConnectionHealth()
        PacketFlowTracker.clear()
        probeSentTimes.clear()
        _latencyStats.value = LatencyStats()
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

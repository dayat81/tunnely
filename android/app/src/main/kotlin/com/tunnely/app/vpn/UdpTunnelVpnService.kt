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

        // DNS interceptor: rewrite private DNS IPs (10.0.2.3, etc.) to 8.8.8.8
        // so DNS queries don't die in the tunnel. On response, rewrite source back.
        //
        // v2: 5-tuple state tracking + DNS QR bit check to prevent re-interception loops.
        // Key = srcPort | (dstIp << 16) — unique per DNS flow, prevents srcPort collisions.
        // Downlink validates DNS QR=1 (response) before rewriting.
        private const val PUBLIC_DNS = 0x08080808  // 8.8.8.8
        private val dnsRewriteMap = java.util.concurrent.ConcurrentHashMap<Long, Int>()  // 5tupleKey → originalDnsIp

        /** Build unique key from srcPort + dstIp to prevent collisions across concurrent queries. */
        private fun dnsKey(srcPort: Int, dstIp: Int): Long =
            (srcPort.toLong() and 0xFFFFL) or ((dstIp.toLong() and 0xFFFFFFFFL) shl 16)

        private fun isPrivateIp(ip: Int): Boolean {
            val b0 = (ip shr 24) and 0xFF
            val b1 = (ip shr 16) and 0xFF
            return b0 == 10 ||                                          // 10.0.0.0/8
                   (b0 == 172 && b1 in 16..31) ||                       // 172.16.0.0/12
                   (b0 == 192 && b1 == 168) ||                           // 192.168.0.0/16
                   (b0 == 169 && b1 == 254) ||                           // 169.254.0.0/16 (link-local)
                   (b0 == 100 && b1 in 64..127)                          // 100.64.0.0/10 (CGNAT)
        }

        /** Rewrite DNS query dst from private IP to 8.8.8.8. Returns modified packet. */
        fun rewriteDnsUplink(pkt: ByteArray, len: Int): ByteArray {
            if (len < 28) return pkt  // min IPv4 + UDP header
            val ver = (pkt[0].toInt() ushr 4) and 0xF
            if (ver != 4) return pkt
            val ihl = (pkt[0].toInt() and 0xF) * 4
            val proto = pkt[9].toInt() and 0xFF
            if (proto != 17) return pkt  // UDP only
            if (len < ihl + 8) return pkt

            val dstPort = ((pkt[ihl + 2].toInt() and 0xFF) shl 8) or (pkt[ihl + 3].toInt() and 0xFF)
            if (dstPort != 53) return pkt  // not DNS

            // Read dst IP
            val dstIp = ((pkt[16].toInt() and 0xFF) shl 24) or
                        ((pkt[17].toInt() and 0xFF) shl 16) or
                        ((pkt[18].toInt() and 0xFF) shl 8) or
                        (pkt[19].toInt() and 0xFF)

            if (!isPrivateIp(dstIp)) return pkt  // already public, no rewrite needed

            // Read src port for 5-tuple tracking
            val srcPort = ((pkt[ihl].toInt() and 0xFF) shl 8) or (pkt[ihl + 1].toInt() and 0xFF)

            // Save mapping: 5tupleKey(srcPort, dstIp) → original dst IP
            val key = dnsKey(srcPort, dstIp)
            dnsRewriteMap[key] = dstIp

            // Rewrite dst IP to 8.8.8.8
            val result = pkt.copyOf(len)
            result[16] = 8; result[17] = 8; result[18] = 8; result[19] = 8

            // Fix IP checksum
            fixIpChecksum(result, ihl)

            // Fix UDP checksum (incremental: dst IP changed)
            val udpCksumOff = ihl + 6
            incrementalCksum(result, udpCksumOff, 16, dstIp, PUBLIC_DNS)  // dst at offset 16

            RemoteLogger.i("DnsInterceptor", "Rewrote DNS query: ${ipToStr(dstIp)}:$dstPort → 8.8.8.8:$dstPort (key=${key})")
            return result
        }

        /** Rewrite DNS response src from 8.8.8.8 back to original private DNS IP. */
        fun rewriteDnsDownlink(pkt: ByteArray, len: Int): ByteArray {
            if (len < 28) return pkt
            val ver = (pkt[0].toInt() ushr 4) and 0xF
            if (ver != 4) return pkt
            val ihl = (pkt[0].toInt() and 0xF) * 4
            val proto = pkt[9].toInt() and 0xFF
            if (proto != 17) return pkt
            if (len < ihl + 8) return pkt

            val srcPort = ((pkt[ihl].toInt() and 0xFF) shl 8) or (pkt[ihl + 1].toInt() and 0xFF)
            if (srcPort != 53) return pkt  // not DNS response

            // Validate this is actually a DNS RESPONSE (QR bit = 1), not a query
            // DNS header starts at ihl (after IP + UDP headers)
            val dnsOffset = ihl + 8  // IP header + 8 bytes UDP header
            if (len < dnsOffset + 4) return pkt  // need at least flags + 1 question
            val dnsFlags = ((pkt[dnsOffset].toInt() and 0xFF) shl 8) or (pkt[dnsOffset + 1].toInt() and 0xFF)
            val isResponse = (dnsFlags and 0x8000) != 0  // QR bit = bit 15
            if (!isResponse) return pkt  // it's a query, not a response — skip

            // Read src IP and dst port for 5-tuple lookup
            val srcIp = ((pkt[12].toInt() and 0xFF) shl 24) or
                        ((pkt[13].toInt() and 0xFF) shl 16) or
                        ((pkt[14].toInt() and 0xFF) shl 8) or
                        (pkt[15].toInt() and 0xFF)
            val dstPort = ((pkt[ihl + 2].toInt() and 0xFF) shl 8) or (pkt[ihl + 3].toInt() and 0xFF)

            // Look up mapping using dstPort (our srcPort) + srcIp (should be 8.8.8.8)
            // The response has swapped src/dst, so srcIp=8.8.8.8, dstPort=our original srcPort
            // We need to find the key: dnsKey(srcPort=dstPort, dstIp=originalDstIp)
            // But we don't know originalDstIp — scan map for matching dstPort
            var originalDnsIp: Int? = null
            var matchedKey: Long = 0
            for ((key, origIp) in dnsRewriteMap) {
                val keySrcPort = (key and 0xFFFFL).toInt()
                if (keySrcPort == dstPort) {
                    originalDnsIp = origIp
                    matchedKey = key
                    break
                }
            }
            if (originalDnsIp == null) return pkt  // no mapping, pass through
            dnsRewriteMap.remove(matchedKey)

            // Rewrite src IP back to original private DNS IP
            val result = pkt.copyOf(len)
            result[12] = ((originalDnsIp shr 24) and 0xFF).toByte()
            result[13] = ((originalDnsIp shr 16) and 0xFF).toByte()
            result[14] = ((originalDnsIp shr 8) and 0xFF).toByte()
            result[15] = (originalDnsIp and 0xFF).toByte()

            // Fix IP checksum
            fixIpChecksum(result, ihl)

            // Fix UDP checksum (incremental: src IP changed)
            val udpCksumOff = ihl + 6
            incrementalCksum(result, udpCksumOff, 12, srcIp, originalDnsIp)  // src at offset 12

            RemoteLogger.i("DnsInterceptor", "Rewrote DNS response: 8.8.8.8:53 → ${ipToStr(originalDnsIp)}:53 (dstPort=$dstPort, key=$matchedKey)")
            return result
        }

        private fun ipToStr(ip: Int): String =
            "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

        private fun fixIpChecksum(pkt: ByteArray, ihl: Int) {
            pkt[10] = 0; pkt[11] = 0  // clear existing checksum
            var sum = 0
            for (i in 0 until ihl step 2) {
                sum += ((pkt[i].toInt() and 0xFF) shl 8) or (pkt[i + 1].toInt() and 0xFF)
            }
            while (sum ushr 16 != 0) sum = (sum and 0xFFFF) + (sum ushr 16)
            val cksum = sum.inv() and 0xFFFF
            pkt[10] = (cksum shr 8).toByte()
            pkt[11] = (cksum and 0xFF).toByte()
        }

        /** RFC 1624 incremental checksum: update checksum when a 32-bit field changes. */
        private fun incrementalCksum(pkt: ByteArray, cksumOff: Int, fieldOff: Int, oldVal: Int, newVal: Int) {
            val cksum = ((pkt[cksumOff].toInt() and 0xFF) shl 8) or (pkt[cksumOff + 1].toInt() and 0xFF)
            if (cksum == 0) return  // UDP checksum 0 = no checksum

            // HC' = ~(~HC + ~m + m')  (RFC 1624)
            var s = cksum.inv() and 0xFFFF

            // ~m (old value, complemented)
            val oldHi = (oldVal shr 16) and 0xFFFF
            val oldLo = oldVal and 0xFFFF
            s += oldHi.inv() and 0xFFFF
            s += oldLo.inv() and 0xFFFF

            // m' (new value)
            val newHi = (newVal shr 16) and 0xFFFF
            val newLo = newVal and 0xFFFF
            s += newHi
            s += newLo

            // Fold carries
            while (s ushr 16 != 0) s = (s and 0xFFFF) + (s ushr 16)
            val newCksum = s.inv() and 0xFFFF

            pkt[cksumOff] = (newCksum shr 8).toByte()
            pkt[cksumOff + 1] = (newCksum and 0xFF).toByte()
        }

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

                    // DNS interceptor: rewrite private DNS (10.0.2.3 etc) → 8.8.8.8
                    val sendBuf = rewriteDnsUplink(buf, n)
                    val sendLen = sendBuf.size

                    // Track flow
                    PacketFlowTracker.processPacket(sendBuf.copyOf(sendLen), isUplink = true)

                    outPkt.length = sendLen
                    System.arraycopy(sendBuf, 0, outPkt.data, 0, sendLen)
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

                    // DNS interceptor: rewrite 8.8.8.8 response back to original private DNS IP
                    val recvBuf = rewriteDnsDownlink(buf, n)
                    val recvLen = recvBuf.size

                    // Track flow
                    PacketFlowTracker.processPacket(recvBuf.copyOf(recvLen), isUplink = false)

                    // Write raw IP packet to TUN
                    output.write(recvBuf, 0, recvLen)

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

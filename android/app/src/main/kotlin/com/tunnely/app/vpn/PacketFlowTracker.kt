package com.tunnely.app.vpn

import java.net.InetAddress
import java.util.concurrent.ConcurrentHashMap

/**
 * Lightweight packet-level flow tracker.
 * Parses IP/TCP/UDP headers to extract per-connection stats.
 * Extracts SNI domain names from TLS ClientHello packets.
 * Thread-safe — called from both I/O threads in UdpTunnelVpnService.
 *
 * Flow key = (remote_ip, remote_port, protocol) where "remote" is the
 * internet host (not the tunnel endpoint).
 */
object PacketFlowTracker {

    private const val MAX_FLOWS = 500
    private const val FLOW_TIMEOUT_MS = 300_000L // 5 min

    data class FlowStats(
        val remoteIp: String,
        val remotePort: Int,
        val protocol: String,
        @Volatile var domain: String? = null,
        @Volatile var uplinkBytes: Long = 0,   // TUN → UDP (client → internet)
        @Volatile var downlinkBytes: Long = 0, // UDP → TUN (internet → client)
        @Volatile var lastSeen: Long = System.currentTimeMillis()
    )

    // Debug counters — visible via getDebugStats()
    @Volatile var totalPacketsProcessed: Long = 0
    @Volatile var uplinkTcpPackets: Long = 0
    @Volatile var sniDomainsExtracted: Long = 0
    @Volatile var cacheHits: Long = 0

    private val flows = ConcurrentHashMap<String, FlowStats>()

    /** Debug stats for troubleshooting SNI extraction */
    fun getDebugStats(): String {
        val flowDomains = flows.values
            .sortedByDescending { it.uplinkBytes + it.downlinkBytes }
            .take(3)
            .map { f -> "${f.remoteIp}:${f.remotePort}=${f.domain ?: "NULL"}" }
            .joinToString("; ")
        return "packets=$totalPacketsProcessed, uplinkTcp=$uplinkTcpPackets, " +
            "sniExtracted=$sniDomainsExtracted, cacheHits=$cacheHits, " +
            "flows=${flows.size}, cacheSize=${DomainCache.size()}\n" +
            "domains: $flowDomains"
    }

    /**
     * Process a raw IP packet and update flow stats.
     * Also extracts SNI domain from TLS ClientHello packets.
     *
     * @param packet Raw IP packet bytes
     * @param isUplink true = TUN→UDP (outgoing), false = UDP→TUN (incoming)
     */
    fun processPacket(packet: ByteArray, isUplink: Boolean) {
        if (packet.size < 20) return

        val version = (packet[0].toInt() and 0xF0) shr 4
        if (version != 4) return // IPv4 only for now

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || packet.size < ihl) return

        val protocol = packet[9].toInt() and 0xFF
        val srcIp = ipToString(packet, 12)
        val dstIp = ipToString(packet, 16)

        var srcPort = 0
        var dstPort = 0

        if (packet.size >= ihl + 4) {
            srcPort = ((packet[ihl].toInt() and 0xFF) shl 8) or (packet[ihl + 1].toInt() and 0xFF)
            dstPort = ((packet[ihl + 2].toInt() and 0xFF) shl 8) or (packet[ihl + 3].toInt() and 0xFF)
        }

        val protoName = when (protocol) {
            6 -> "TCP"
            17 -> "UDP"
            1 -> "ICMP"
            else -> "IP/$protocol"
        }

        totalPacketsProcessed++

        // For uplink: remote = dst (internet host)
        // For downlink: remote = src (internet host)
        val remoteIp: String
        val remotePort: Int
        if (isUplink) {
            remoteIp = dstIp
            remotePort = dstPort
        } else {
            remoteIp = srcIp
            remotePort = srcPort
        }

        // Extract SNI domain from TLS ClientHello (uplink only)
        // Works on any TCP port (443, 8443, etc.) — SniParser doesn't check port
        var domain: String? = null
        if (isUplink && protoName == "TCP") {
            uplinkTcpPackets++
            domain = SniParser.extractSni(packet)
            if (domain != null) {
                sniDomainsExtracted++
                DomainCache.putDomain(remoteIp, domain)
            }
        }

        // Try cache for non-SNI packets (downlink or already cached)
        if (domain == null) {
            domain = DomainCache.getDomain(remoteIp)
            if (domain != null) cacheHits++
        }

        val key = "$remoteIp:$remotePort/$protoName"
        val now = System.currentTimeMillis()
        val packetLen = packet.size.toLong()

        flows.compute(key) { _, existing ->
            if (existing != null) {
                if (isUplink) existing.uplinkBytes += packetLen
                else existing.downlinkBytes += packetLen
                existing.lastSeen = now
                // Update domain if we found one
                if (domain != null && existing.domain == null) {
                    existing.domain = domain
                }
                existing
            } else {
                // Evict oldest if at capacity
                if (flows.size >= MAX_FLOWS) {
                    val oldest = flows.entries.minByOrNull { it.value.lastSeen }
                    oldest?.let { flows.remove(it.key) }
                }
                FlowStats(
                    remoteIp = remoteIp,
                    remotePort = remotePort,
                    protocol = protoName,
                    domain = domain,
                    uplinkBytes = if (isUplink) packetLen else 0,
                    downlinkBytes = if (!isUplink) packetLen else 0,
                    lastSeen = now
                )
            }
        }
    }

    /**
     * Get current flows as a list sorted by total bytes descending.
     * Cleans up stale flows on each call.
     */
    fun getFlows(): List<FlowEntry> {
        val now = System.currentTimeMillis()

        // Remove stale flows
        flows.entries.removeIf { now - it.value.lastSeen > FLOW_TIMEOUT_MS }

        return flows.values
            .sortedByDescending { it.uplinkBytes + it.downlinkBytes }
            .map { f ->
                FlowEntry(
                    server = f.remoteIp,
                    domain = f.domain,
                    port = f.remotePort,
                    protocol = f.protocol,
                    uplinkBytes = f.uplinkBytes,
                    downlinkBytes = f.downlinkBytes
                )
            }
    }

    /**
     * Get aggregate stats for display.
     */
    fun getAggregateStats(): ServerTrafficStats {
        val now = System.currentTimeMillis()
        flows.entries.removeIf { now - it.value.lastSeen > FLOW_TIMEOUT_MS }

        val activeCount = flows.values.count { now - it.lastSeen < 30_000 }
        val totalUp = flows.values.sumOf { it.uplinkBytes }
        val totalDown = flows.values.sumOf { it.downlinkBytes }

        return ServerTrafficStats(
            wgRx = totalDown,
            wgTx = totalUp,
            activeFlows = activeCount,
            totalFlows = flows.size
        )
    }

    fun clear() {
        flows.clear()
        DomainCache.clear()
        totalPacketsProcessed = 0
        uplinkTcpPackets = 0
        sniDomainsExtracted = 0
        cacheHits = 0
    }

    private fun ipToString(packet: ByteArray, offset: Int): String {
        return "${packet[offset].toInt() and 0xFF}." +
            "${packet[offset + 1].toInt() and 0xFF}." +
            "${packet[offset + 2].toInt() and 0xFF}." +
            "${packet[offset + 3].toInt() and 0xFF}"
    }
}

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
    @Volatile var tlsRecordsSeen: Long = 0      // TCP packets with TLS content type 0x16
    @Volatile var clientHellosSeen: Long = 0     // TLS records with handshake type 0x01
    @Volatile var sniParseAttempts: Long = 0     // ClientHello records passed to SNI parser
    @Volatile var sniParseFailures: Long = 0     // SNI parser returned null
    @Volatile var dnsDomainsExtracted: Long = 0  // domains from DNS A record responses

    private val flows = ConcurrentHashMap<String, FlowStats>()

    // Server-side SNI domain map — populated from /api/vpn/stats
    @Volatile var serverSniMap: Map<String, String> = emptyMap()

    /** Debug stats for troubleshooting SNI extraction */
    fun getDebugStats(): String {
        val flowDomains = flows.values
            .sortedByDescending { it.uplinkBytes + it.downlinkBytes }
            .take(3)
            .map { f ->
                val cached = DomainCache.getDomain(f.remoteIp)
                "${f.remoteIp}:${f.remotePort} domain=${f.domain ?: "NULL"} cached=${cached ?: "NULL"}"
            }
            .joinToString("; ")
        return "pkts=$totalPacketsProcessed tcp=$uplinkTcpPackets " +
            "tls=$tlsRecordsSeen ch=$clientHellosSeen " +
            "parse=$sniParseAttempts fail=$sniParseFailures " +
            "sni=$sniDomainsExtracted dns=$dnsDomainsExtracted cache=$cacheHits/${DomainCache.size()}\n" +
            "err:${SniParser.lastError} sid=${SniParser.lastSessionIdLen} " +
            "cs=${SniParser.lastCipherSuitesLen} comp=${SniParser.lastCompressionLen} " +
            "ext=${SniParser.lastExtensionsLen}/${SniParser.lastExtensionsEnd}/${SniParser.lastPacketSize}\n" +
            "$flowDomains"
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
            // Check TLS record header before calling SniParser
            val tcpDataOffset = if (packet.size >= ihl + 12) {
                ((packet[ihl + 12].toInt() and 0xF0) shr 4) * 4
            } else 0
            val payloadStart = ihl + tcpDataOffset
            if (packet.size > payloadStart + 5) {
                val tlsContentType = packet[payloadStart].toInt() and 0xFF
                if (tlsContentType == 0x16) { // TLS Handshake
                    tlsRecordsSeen++
                    val handshakeType = packet[payloadStart + 5].toInt() and 0xFF
                    if (handshakeType == 0x01) { // ClientHello
                        clientHellosSeen++
                        sniParseAttempts++
                        domain = SniParser.extractSni(packet)
                        if (domain != null) {
                            sniDomainsExtracted++
                            DomainCache.putDomain(remoteIp, domain)
                        } else {
                            sniParseFailures++
                        }
                    }
                }
            }
        }

        // Extract domain from DNS response A records (both uplink query + downlink response)
        if (protoName == "UDP" && (dstPort == 53 || srcPort == 53)) {
            parseDnsForDomainCache(packet, ihl, isUplink)
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
                // Priority: FlowStats.domain → DomainCache → ServerSniMap
                val domain = f.domain
                    ?: DomainCache.getDomain(f.remoteIp)
                    ?: serverSniMap[f.remoteIp]
                FlowEntry(
                    server = f.remoteIp,
                    domain = domain,
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
        serverSniMap = emptyMap()
        pendingDnsQueries.clear()
        totalPacketsProcessed = 0
        uplinkTcpPackets = 0
        sniDomainsExtracted = 0
        cacheHits = 0
        tlsRecordsSeen = 0
        clientHellosSeen = 0
        sniParseAttempts = 0
        sniParseFailures = 0
        dnsDomainsExtracted = 0
    }

    // Pending DNS queries: transaction ID → queried domain name
    // Used to match uplink queries with downlink responses
    private val pendingDnsQueries = ConcurrentHashMap<Int, String>()

    /**
     * Parse DNS packets to extract IP→domain mappings.
     * Works on both queries (to capture the question) and responses (to map A records).
     * Populates DomainCache so subsequent TCP/QUIC connections to those IPs show the domain.
     */
    private fun parseDnsForDomainCache(packet: ByteArray, ihl: Int, isUplink: Boolean) {
        try {
            val udpPayloadOffset = ihl + 8
            if (packet.size < udpPayloadOffset + 12) return  // minimum DNS header

            val dnsData = packet.copyOfRange(udpPayloadOffset, packet.size)
            val txId = ((dnsData[0].toInt() and 0xFF) shl 8) or (dnsData[1].toInt() and 0xFF)
            val flags = ((dnsData[2].toInt() and 0xFF) shl 8) or (dnsData[3].toInt() and 0xFF)
            val isResponse = (flags and 0x8000) != 0
            val qdCount = ((dnsData[4].toInt() and 0xFF) shl 8) or (dnsData[5].toInt() and 0xFF)
            val anCount = ((dnsData[6].toInt() and 0xFF) shl 8) or (dnsData[7].toInt() and 0xFF)

            if (!isResponse) {
                // Uplink query — extract and store the queried domain
                if (qdCount > 0) {
                    val qname = parseDnsQname(dnsData, 12)
                    if (qname != null && qname.isNotEmpty()) {
                        pendingDnsQueries[txId] = qname.lowercase()
                        // Purge stale entries (keep max 200)
                        if (pendingDnsQueries.size > 200) {
                            val iter = pendingDnsQueries.iterator()
                            var removed = 0
                            while (iter.hasNext() && removed < 100) {
                                iter.next(); iter.remove(); removed++
                            }
                        }
                    }
                }
            } else if (anCount > 0) {
                // Downlink response — extract A records and map to domain
                val qname = pendingDnsQueries.remove(txId)
                    ?: parseDnsQname(dnsData, 12)  // fallback: parse from response

                if (qname == null) return

                // Skip question section
                var offset = 12
                for (i in 0 until qdCount) {
                    offset = skipDnsName(dnsData, offset)
                    offset += 4  // QTYPE + QCLASS
                }

                // Parse answer section for A records
                for (i in 0 until anCount) {
                    if (offset >= dnsData.size) break
                    offset = skipDnsName(dnsData, offset)
                    if (offset + 10 > dnsData.size) break

                    val rtype = ((dnsData[offset].toInt() and 0xFF) shl 8) or (dnsData[offset + 1].toInt() and 0xFF)
                    val rdlength = ((dnsData[offset + 8].toInt() and 0xFF) shl 8) or (dnsData[offset + 9].toInt() and 0xFF)
                    offset += 10

                    if (rtype == 1 && rdlength == 4 && offset + 4 <= dnsData.size) {
                        // A record — map IP to domain
                        val ip = "${dnsData[offset].toInt() and 0xFF}.${dnsData[offset + 1].toInt() and 0xFF}." +
                            "${dnsData[offset + 2].toInt() and 0xFF}.${dnsData[offset + 3].toInt() and 0xFF}"
                        DomainCache.putDomain(ip, qname)
                        dnsDomainsExtracted++
                    }
                    offset += rdlength
                }
            }
        } catch (_: Exception) {
            // Non-fatal — DNS parsing shouldn't crash the I/O thread
        }
    }

    /** Parse DNS QNAME starting at offset. Returns domain string or null. */
    private fun parseDnsQname(data: ByteArray, startOffset: Int): String? {
        val labels = mutableListOf<String>()
        var offset = startOffset
        var jumped = false
        var jumpLimit = 10

        while (jumpLimit > 0) {
            if (offset >= data.size) return null
            val length = data[offset].toInt() and 0xFF
            if (length == 0) break
            if ((length and 0xC0) == 0xC0) {
                // Pointer — follow it
                if (offset + 1 >= data.size) return null
                if (!jumped) jumped = true
                offset = ((length and 0x3F) shl 8) or (data[offset + 1].toInt() and 0xFF)
                jumpLimit--
                continue
            }
            offset++
            if (offset + length > data.size) return null
            labels.add(String(data, offset, length, Charsets.US_ASCII))
            offset += length
        }
        return if (labels.isEmpty()) null else labels.joinToString(".")
    }

    /** Skip a DNS name (may include pointers) and return offset after it. */
    private fun skipDnsName(data: ByteArray, startOffset: Int): Int {
        var offset = startOffset
        while (offset < data.size) {
            val length = data[offset].toInt() and 0xFF
            if (length == 0) return offset + 1
            if ((length and 0xC0) == 0xC0) return offset + 2  // pointer
            offset += 1 + length
        }
        return offset
    }

    private fun ipToString(packet: ByteArray, offset: Int): String {
        return "${packet[offset].toInt() and 0xFF}." +
            "${packet[offset + 1].toInt() and 0xFF}." +
            "${packet[offset + 2].toInt() and 0xFF}." +
            "${packet[offset + 3].toInt() and 0xFF}"
    }
}

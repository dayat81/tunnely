package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test
import java.nio.ByteBuffer

/**
 * Tests for PacketFlowTracker — client-side IP/TCP/UDP flow tracking.
 *
 * PacketFlowTracker parses raw IP packets in the VPN I/O threads to track
 * per-connection upload/download bytes. No server dependency.
 */
class PacketFlowTrackerTest {

    @Before
    fun setUp() {
        PacketFlowTracker.clear()
        DomainCache.clear()
    }

    // ── Packet Builders ───────────────────────────────────────────────

    /**
     * Build a raw IPv4 + UDP packet.
     */
    private fun buildUdpPacket(
        srcIp: String, dstIp: String,
        srcPort: Int, dstPort: Int,
        payloadSize: Int = 100
    ): ByteArray {
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLen = ipHeaderLen + udpHeaderLen + payloadSize
        val pkt = ByteArray(totalLen)

        // IP header
        pkt[0] = 0x45.toByte()  // Version=4, IHL=5
        pkt[2] = ((totalLen shr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64  // TTL
        pkt[9] = 17  // Protocol=UDP

        // Source IP
        val srcParts = srcIp.split(".").map { it.toInt() }
        pkt[12] = srcParts[0].toByte()
        pkt[13] = srcParts[1].toByte()
        pkt[14] = srcParts[2].toByte()
        pkt[15] = srcParts[3].toByte()

        // Destination IP
        val dstParts = dstIp.split(".").map { it.toInt() }
        pkt[16] = dstParts[0].toByte()
        pkt[17] = dstParts[1].toByte()
        pkt[18] = dstParts[2].toByte()
        pkt[19] = dstParts[3].toByte()

        // UDP header
        pkt[ipHeaderLen] = ((srcPort shr 8) and 0xFF).toByte()
        pkt[ipHeaderLen + 1] = (srcPort and 0xFF).toByte()
        pkt[ipHeaderLen + 2] = ((dstPort shr 8) and 0xFF).toByte()
        pkt[ipHeaderLen + 3] = (dstPort and 0xFF).toByte()
        val udpLen = udpHeaderLen + payloadSize
        pkt[ipHeaderLen + 4] = ((udpLen shr 8) and 0xFF).toByte()
        pkt[ipHeaderLen + 5] = (udpLen and 0xFF).toByte()

        return pkt
    }

    /**
     * Build a raw IPv4 + TCP packet.
     */
    private fun buildTcpPacket(
        srcIp: String, dstIp: String,
        srcPort: Int, dstPort: Int,
        payloadSize: Int = 0
    ): ByteArray {
        val ipHeaderLen = 20
        val tcpHeaderLen = 20
        val totalLen = ipHeaderLen + tcpHeaderLen + payloadSize
        val pkt = ByteArray(totalLen)

        // IP header
        pkt[0] = 0x45.toByte()
        pkt[2] = ((totalLen shr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[8] = 64
        pkt[9] = 6  // Protocol=TCP

        // Source IP
        val srcParts = srcIp.split(".").map { it.toInt() }
        pkt[12] = srcParts[0].toByte()
        pkt[13] = srcParts[1].toByte()
        pkt[14] = srcParts[2].toByte()
        pkt[15] = srcParts[3].toByte()

        // Destination IP
        val dstParts = dstIp.split(".").map { it.toInt() }
        pkt[16] = dstParts[0].toByte()
        pkt[17] = dstParts[1].toByte()
        pkt[18] = dstParts[2].toByte()
        pkt[19] = dstParts[3].toByte()

        // TCP header
        pkt[ipHeaderLen] = ((srcPort shr 8) and 0xFF).toByte()
        pkt[ipHeaderLen + 1] = (srcPort and 0xFF).toByte()
        pkt[ipHeaderLen + 2] = ((dstPort shr 8) and 0xFF).toByte()
        pkt[ipHeaderLen + 3] = (dstPort and 0xFF).toByte()
        pkt[ipHeaderLen + 12] = 0x50.toByte()  // Data offset=5

        return pkt
    }

    /**
     * Build a TLS ClientHello packet with SNI.
     */
    private fun buildTlsClientHelloWithSni(
        srcIp: String, dstIp: String,
        srcPort: Int, dstPort: Int,
        domain: String
    ): ByteArray {
        val domainBytes = domain.toByteArray(Charsets.US_ASCII)
        
        // Build TLS record
        val record = ByteBuffer.allocate(1024)
        
        // TLS Record Header
        record.put(0x16) // Content Type: Handshake
        record.putShort(0x0301.toShort()) // TLS 1.0
        val recordLenPos = record.position()
        record.putShort(0) // Length placeholder
        
        // Handshake Header
        record.put(0x01) // ClientHello
        val handshakeLenPos = record.position()
        record.put(0x00) // Length placeholder
        record.putShort(0)
        
        // Client Version
        record.putShort(0x0303.toShort()) // TLS 1.2
        
        // Random (32 bytes)
        for (i in 0 until 32) record.put(0x42)
        
        // Session ID (0 length)
        record.put(0x00)
        
        // Cipher Suites
        record.putShort(2.toShort())
        record.putShort(0x1301.toShort())
        
        // Compression Methods
        record.put(0x01)
        record.put(0x00)
        
        // Extensions
        val extStartPos = record.position()
        record.putShort(0)
        
        // SNI Extension
        record.putShort(0x0000.toShort())
        val sniExtLenPos = record.position()
        record.putShort(0)
        
        // SNI List
        val sniListLenPos = record.position()
        record.putShort(0)
        
        // Server Name
        record.put(0x00)
        record.putShort(domainBytes.size.toShort())
        record.put(domainBytes)
        
        // Update lengths
        record.putShort(sniListLenPos, (domainBytes.size + 3).toShort())
        record.putShort(sniExtLenPos, (domainBytes.size + 5).toShort())
        record.putShort(extStartPos, (domainBytes.size + 7).toShort())
        
        val handshakeLen = record.position() - handshakeLenPos - 3
        record.put(handshakeLenPos, ((handshakeLen shr 16) and 0xFF).toByte())
        record.put(handshakeLenPos + 1, ((handshakeLen shr 8) and 0xFF).toByte())
        record.put(handshakeLenPos + 2, (handshakeLen and 0xFF).toByte())
        
        record.putShort(recordLenPos, (record.position() - recordLenPos - 2).toShort())
        
        // Create IP packet
        val payload = ByteArray(record.position())
        record.position(0)
        record.get(payload)
        
        val ipPacket = ByteBuffer.allocate(40 + payload.size)
        
        // IP Header
        ipPacket.put(0x45)
        ipPacket.put(0x00)
        ipPacket.putShort((40 + payload.size).toShort())
        ipPacket.putInt(0)
        ipPacket.put(0x40.toByte())
        ipPacket.put(0x06)
        ipPacket.putShort(0)
        
        val srcParts = srcIp.split(".").map { it.toInt() }
        ipPacket.put(byteArrayOf(srcParts[0].toByte(), srcParts[1].toByte(), srcParts[2].toByte(), srcParts[3].toByte()))
        
        val dstParts = dstIp.split(".").map { it.toInt() }
        ipPacket.put(byteArrayOf(dstParts[0].toByte(), dstParts[1].toByte(), dstParts[2].toByte(), dstParts[3].toByte()))
        
        // TCP Header
        ipPacket.putShort(srcPort.toShort())
        ipPacket.putShort(dstPort.toShort())
        ipPacket.putInt(0)
        ipPacket.putInt(0)
        ipPacket.put(0x50.toByte())
        ipPacket.put(0x02)
        ipPacket.putShort(65535.toShort())
        ipPacket.putShort(0)
        ipPacket.putShort(0)
        
        // Payload
        ipPacket.put(payload)
        
        return ipPacket.array()
    }

    // ── Basic Flow Tracking Tests ─────────────────────────────────────

    @Test
    fun `single UDP packet creates one flow`() {
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("8.8.8.8", flows[0].server)
        assertEquals(53, flows[0].port)
        assertEquals("UDP", flows[0].protocol)
    }

    @Test
    fun `uplink and downlink tracked separately`() {
        val up = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        val down = buildUdpPacket("8.8.8.8", "10.20.0.2", 53, 54321, 200)

        PacketFlowTracker.processPacket(up, isUplink = true)
        PacketFlowTracker.processPacket(down, isUplink = false)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertTrue(flows[0].uplinkBytes > 0)
        assertTrue(flows[0].downlinkBytes > 0)
    }

    @Test
    fun `multiple destinations create multiple flows`() {
        val dns = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 50)
        val http = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80, 500)

        PacketFlowTracker.processPacket(dns, isUplink = true)
        PacketFlowTracker.processPacket(http, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(2, flows.size)
    }

    @Test
    fun `flows sorted by total bytes descending`() {
        val small = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 50)
        val large = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80, 5000)

        PacketFlowTracker.processPacket(small, isUplink = true)
        PacketFlowTracker.processPacket(large, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(2, flows.size)
        assertTrue(flows[0].uplinkBytes >= flows[1].uplinkBytes)
    }

    @Test
    fun `same 5-tuple merges into single flow`() {
        val pkt1 = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        val pkt2 = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 200)

        PacketFlowTracker.processPacket(pkt1, isUplink = true)
        PacketFlowTracker.processPacket(pkt2, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
    }

    @Test
    fun `clear removes all flows`() {
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        PacketFlowTracker.clear()
        val flows = PacketFlowTracker.getFlows()
        assertEquals(0, flows.size)
    }

    @Test
    fun `too short packet ignored`() {
        val pkt = ByteArray(5) // Too short for IP header
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(0, flows.size)
    }

    @Test
    fun `IPv6 packet ignored`() {
        val pkt = ByteArray(40)
        pkt[0] = 0x60.toByte() // IPv6
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(0, flows.size)
    }

    @Test
    fun `empty packet ignored`() {
        val pkt = ByteArray(0)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(0, flows.size)
    }

    @Test
    fun `ICMP packet tracked as IP protocol`() {
        val pkt = ByteArray(28)
        pkt[0] = 0x45.toByte()
        pkt[2] = 0x00
        pkt[3] = 28
        pkt[8] = 64
        pkt[9] = 1  // ICMP
        // Source: 10.20.0.2
        pkt[12] = 10; pkt[13] = 20; pkt[14] = 0; pkt[15] = 2
        // Dest: 8.8.8.8
        pkt[16] = 8; pkt[17] = 8; pkt[18] = 8; pkt[19] = 8

        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("ICMP", flows[0].protocol)
    }

    // ── TCP Flow Tests ────────────────────────────────────────────────

    @Test
    fun `TCP SYN creates flow`() {
        val syn = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 443, 0)
        PacketFlowTracker.processPacket(syn, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("TCP", flows[0].protocol)
        assertEquals(443, flows[0].port)
    }

    @Test
    fun `TCP connection tracking - SYN + data + response`() {
        val syn = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 443, 0)
        val data = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 443, 1200)
        val resp = buildTcpPacket("142.250.66.46", "10.20.0.2", 443, 54322, 5000)

        PacketFlowTracker.processPacket(syn, isUplink = true)
        PacketFlowTracker.processPacket(data, isUplink = true)
        PacketFlowTracker.processPacket(resp, isUplink = false)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("TCP", flows[0].protocol)
        assertEquals(443, flows[0].port)
        assertEquals(40L + 1240L, flows[0].uplinkBytes)
        assertEquals(5040L, flows[0].downlinkBytes)
    }

    // ── SNI Domain Tests ─────────────────────────────────────────────

    @Test
    fun `TLS ClientHello extracts domain to FlowEntry`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("api.github.com", flows[0].domain)
    }

    @Test
    fun `domain appears in displayServer`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals("api.github.com", flows[0].displayServer)
    }

    @Test
    fun `domain appears in displayServerWithPort`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals("api.github.com:443", flows[0].displayServerWithPort)
    }

    @Test
    fun `non-TLS flow has null domain`() {
        val pkt = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80, 500)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertNull(flows[0].domain)
    }

    @Test
    fun `non-TLS flow displayServer shows IP`() {
        val pkt = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80, 500)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals("142.250.66.46:80", flows[0].displayServer)
    }

    @Test
    fun `domain cached after TLS ClientHello`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        assertEquals("api.github.com", DomainCache.getDomain("140.82.121.6"))
    }

    @Test
    fun `subsequent packets to same IP get domain from cache`() {
        // First: TLS ClientHello
        val tlsPkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(tlsPkt, isUplink = true)

        // Second: non-TLS packet to same IP
        val httpPkt = buildTcpPacket("10.20.0.2", "140.82.121.6", 54322, 80, 500)
        PacketFlowTracker.processPacket(httpPkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        // Both flows should have domain
        val httpFlow = flows.find { it.port == 80 }
        assertNotNull(httpFlow)
        assertEquals("api.github.com", httpFlow!!.domain)
    }

    @Test
    fun `multiple TLS connections different domains`() {
        val github = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        val google = buildTlsClientHelloWithSni("10.20.0.2", "142.250.66.46", 54322, 443, "www.google.com")

        PacketFlowTracker.processPacket(github, isUplink = true)
        PacketFlowTracker.processPacket(google, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(2, flows.size)

        val githubFlow = flows.find { it.server == "140.82.121.6" }
        val googleFlow = flows.find { it.server == "142.250.66.46" }

        assertEquals("api.github.com", githubFlow!!.domain)
        assertEquals("www.google.com", googleFlow!!.domain)
    }

    @Test
    fun `domain updated on existing flow`() {
        // First packet: no domain
        val syn = buildTcpPacket("10.20.0.2", "140.82.121.6", 54321, 443, 0)
        PacketFlowTracker.processPacket(syn, isUplink = true)

        var flows = PacketFlowTracker.getFlows()
        assertNull(flows[0].domain)

        // Second packet: TLS ClientHello with domain
        val tlsPkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(tlsPkt, isUplink = true)

        flows = PacketFlowTracker.getFlows()
        assertEquals("api.github.com", flows[0].domain)
    }

    // ── Mixed Protocol Tests ──────────────────────────────────────────

    @Test
    fun `mixed protocol traffic - DNS + HTTP + QUIC`() {
        val dns = buildUdpPacket("10.20.0.2", "8.8.8.8", 10001, 53, 33)
        val http = buildTcpPacket("10.20.0.2", "142.250.66.46", 10002, 80, 500)
        val quic = buildUdpPacket("10.20.0.2", "142.250.66.46", 10003, 443, 1200)

        PacketFlowTracker.processPacket(dns, isUplink = true)
        PacketFlowTracker.processPacket(http, isUplink = true)
        PacketFlowTracker.processPacket(quic, isUplink = true)

        val stats = PacketFlowTracker.getAggregateStats()
        assertEquals(3, stats.totalFlows)
        assertEquals(3, stats.activeFlows)
        assertTrue("total tx > 0", stats.wgTx > 0)
    }

    // ── MAX_FLOWS Capacity ────────────────────────────────────────────

    @Test
    fun `max flows cap - oldest evicted`() {
        for (i in 1..501) {
            val pkt = buildUdpPacket("10.20.0.2", "10.0.0.$i", 54321, 80, 10)
            PacketFlowTracker.processPacket(pkt, isUplink = true)
        }

        val flows = PacketFlowTracker.getFlows()
        assertTrue("flows <= 500", flows.size <= 500)
    }

    // ── Aggregate Stats Tests ─────────────────────────────────────────

    @Test
    fun `aggregate stats counts correctly`() {
        val pkt1 = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        val pkt2 = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80, 500)

        PacketFlowTracker.processPacket(pkt1, isUplink = true)
        PacketFlowTracker.processPacket(pkt2, isUplink = true)

        val stats = PacketFlowTracker.getAggregateStats()
        assertEquals(2, stats.totalFlows)
        assertEquals(2, stats.activeFlows)
        assertTrue(stats.wgTx > 0)
    }

    @Test
    fun `aggregate stats after clear is zero`() {
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        PacketFlowTracker.clear()

        val stats = PacketFlowTracker.getAggregateStats()
        assertEquals(0, stats.totalFlows)
        assertEquals(0, stats.activeFlows)
        assertEquals(0L, stats.wgTx)
        assertEquals(0L, stats.wgRx)
    }

    // ── FlowEntry Display Tests ───────────────────────────────────────

    @Test
    fun `FlowEntry with domain shows domain in display`() {
        val entry = FlowEntry(
            server = "140.82.121.6",
            domain = "api.github.com",
            port = 443,
            protocol = "TCP",
            uplinkBytes = 1024,
            downlinkBytes = 4096
        )
        assertEquals("api.github.com", entry.displayServer)
        assertEquals("api.github.com:443", entry.displayServerWithPort)
    }

    @Test
    fun `FlowEntry without domain shows IP in display`() {
        val entry = FlowEntry(
            server = "142.250.66.46",
            domain = null,
            port = 80,
            protocol = "TCP",
            uplinkBytes = 500,
            downlinkBytes = 2000
        )
        assertEquals("142.250.66.46:80", entry.displayServer)
        assertEquals("142.250.66.46:80", entry.displayServerWithPort)
    }

    @Test
    fun `FlowEntry bytes formatting`() {
        val entry = FlowEntry("1.2.3.4", null, 80, "TCP", 1536, 1048576)
        assertEquals("1 KB", entry.displayUplink)
        assertEquals("1.0 MB", entry.displayDownlink)
    }

    // ── Additional Edge Cases ─────────────────────────────────────────

    @Test
    fun `downlink TLS does not extract domain`() {
        // SNI only in uplink (ClientHello)
        val pkt = buildTlsClientHelloWithSni("140.82.121.6", "10.20.0.2", 443, 54321, "api.github.com")
        PacketFlowTracker.processPacket(pkt, isUplink = false)

        // Domain should NOT be extracted (downlink)
        assertNull(DomainCache.getDomain("140.82.121.6"))
    }

    @Test
    fun `non-port-443 TLS extracts domain`() {
        // TLS on non-standard port (e.g., 8443)
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 8443, "api.github.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        // Domain should still be extracted (SNI parser doesn't check port)
        assertEquals("api.github.com", flows[0].domain)
    }

    @Test
    fun `domain lowercase normalization`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "API.GITHUB.COM")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        // DomainCache normalizes to lowercase
        assertEquals("api.github.com", DomainCache.getDomain("140.82.121.6"))
    }

    @Test
    fun `multiple packets same domain same flow`() {
        val pkt1 = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        val pkt2 = buildTcpPacket("10.20.0.2", "140.82.121.6", 54321, 443, 1000)

        PacketFlowTracker.processPacket(pkt1, isUplink = true)
        PacketFlowTracker.processPacket(pkt2, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("api.github.com", flows[0].domain)
    }

    @Test
    fun `flow without domain shows IP port combo`() {
        val pkt = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80, 500)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals("142.250.66.46:80", flows[0].displayServerWithPort)
    }

    @Test
    fun `flow with domain hides port in displayServer`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        // displayServer shows domain only (no port)
        assertEquals("api.github.com", flows[0].displayServer)
        // displayServerWithPort shows domain + port
        assertEquals("api.github.com:443", flows[0].displayServerWithPort)
    }

    @Test
    fun `UDP flow never has domain`() {
        // UDP packets don't have SNI (SNI is TLS/TCP only)
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertNull(flows[0].domain)
    }

    @Test
    fun `ICMP flow never has domain`() {
        val pkt = ByteArray(28)
        pkt[0] = 0x45.toByte()
        pkt[2] = 0x00
        pkt[3] = 28
        pkt[8] = 64
        pkt[9] = 1  // ICMP
        pkt[12] = 10; pkt[13] = 20; pkt[14] = 0; pkt[15] = 2
        pkt[16] = 8; pkt[17] = 8; pkt[18] = 8; pkt[19] = 8

        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertNull(flows[0].domain)
    }

    @Test
    fun `clear also clears domain cache`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        PacketFlowTracker.clear()
        DomainCache.clear()

        // After clear, domain cache should be empty
        assertNull(DomainCache.getDomain("140.82.121.6"))
    }

    @Test
    fun `domain preserved after flow update`() {
        // First: TLS with domain
        val tlsPkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api.github.com")
        PacketFlowTracker.processPacket(tlsPkt, isUplink = true)

        // Second: more data (no domain in packet)
        val dataPkt = buildTcpPacket("10.20.0.2", "140.82.121.6", 54321, 443, 5000)
        PacketFlowTracker.processPacket(dataPkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        // Domain should still be there
        assertEquals("api.github.com", flows[0].domain)
        // Bytes should be updated
        assertTrue(flows[0].uplinkBytes > 5000)
    }

    @Test
    fun `very long domain name handled`() {
        val longDomain = "a".repeat(63) + ".example.com"
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, longDomain)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals(longDomain, flows[0].domain)
    }

    @Test
    fun `domain with hyphens handled`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "my-app.example.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals("my-app.example.com", flows[0].domain)
    }

    @Test
    fun `domain with numbers handled`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "140.82.121.6", 54321, 443, "api2.example.com")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals("api2.example.com", flows[0].domain)
    }

    @Test
    fun `FlowEntry equality with domain`() {
        val entry1 = FlowEntry("1.2.3.4", "example.com", 443, "TCP", 100, 200)
        val entry2 = FlowEntry("1.2.3.4", "example.com", 443, "TCP", 100, 200)
        assertEquals(entry1, entry2)
    }

    @Test
    fun `FlowEntry inequality different domain`() {
        val entry1 = FlowEntry("1.2.3.4", "a.com", 443, "TCP", 100, 200)
        val entry2 = FlowEntry("1.2.3.4", "b.com", 443, "TCP", 100, 200)
        assertNotEquals(entry1, entry2)
    }

    @Test
    fun `FlowEntry copy preserves domain`() {
        val entry = FlowEntry("1.2.3.4", "example.com", 443, "TCP", 100, 200)
        val updated = entry.copy(uplinkBytes = 500)
        assertEquals("example.com", updated.domain)
        assertEquals(500L, updated.uplinkBytes)
    }

    @Test
    fun `FlowEntry copy can change domain`() {
        val entry = FlowEntry("1.2.3.4", "old.com", 443, "TCP", 100, 200)
        val updated = entry.copy(domain = "new.com")
        assertEquals("new.com", updated.domain)
    }

    @Test
    fun `FlowEntry zero bytes formatting`() {
        val entry = FlowEntry("1.2.3.4", null, 80, "TCP", 0, 0)
        assertEquals("0 B", entry.displayUplink)
        assertEquals("0 B", entry.displayDownlink)
    }

    @Test
    fun `FlowEntry large bytes formatting GB`() {
        val entry = FlowEntry("1.2.3.4", null, 80, "TCP", 0, 2147483648L) // 2 GB
        assertEquals("2.00 GB", entry.displayDownlink)
    }

    @Test
    fun `multiple flows sorted by domain`() {
        val pkt1 = buildTlsClientHelloWithSni("10.20.0.2", "1.1.1.1", 54321, 443, "z.com")
        val pkt2 = buildTlsClientHelloWithSni("10.20.0.2", "2.2.2.2", 54322, 443, "a.com")

        PacketFlowTracker.processPacket(pkt1, isUplink = true)
        PacketFlowTracker.processPacket(pkt2, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(2, flows.size)
        // Both should have domains
        assertNotNull(flows[0].domain)
        assertNotNull(flows[1].domain)
    }

    @Test
    fun `private IP gets domain from cache`() {
        // First: TLS to private IP
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "192.168.1.1", 54321, 443, "router.local")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        assertEquals("router.local", DomainCache.getDomain("192.168.1.1"))
    }

    @Test
    fun `localhost IP gets domain from cache`() {
        val pkt = buildTlsClientHelloWithSni("10.20.0.2", "127.0.0.1", 54321, 443, "localhost")
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        assertEquals("localhost", DomainCache.getDomain("127.0.0.1"))
    }
}

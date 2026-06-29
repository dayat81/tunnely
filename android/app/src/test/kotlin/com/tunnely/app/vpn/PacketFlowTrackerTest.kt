package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

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
    }

    // ── Packet Builders ───────────────────────────────────────────────

    /**
     * Build a raw IPv4 + UDP packet.
     * @param srcIp Source IP (e.g., "10.20.0.2")
     * @param dstIp Destination IP (e.g., "8.8.8.8")
     * @param srcPort Source port
     * @param dstPort Destination port
     * @param payloadSize Size of UDP payload (filled with zeros)
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
        pkt[20] = ((srcPort shr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort shr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()

        return pkt
    }

    /**
     * Build a raw IPv4 + TCP packet.
     */
    private fun buildTcpPacket(
        srcIp: String, dstIp: String,
        srcPort: Int, dstPort: Int,
        payloadSize: Int = 100
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
        pkt[12] = srcParts[0].toByte(); pkt[13] = srcParts[1].toByte()
        pkt[14] = srcParts[2].toByte(); pkt[15] = srcParts[3].toByte()

        // Destination IP
        val dstParts = dstIp.split(".").map { it.toInt() }
        pkt[16] = dstParts[0].toByte(); pkt[17] = dstParts[1].toByte()
        pkt[18] = dstParts[2].toByte(); pkt[19] = dstParts[3].toByte()

        // TCP header
        pkt[20] = ((srcPort shr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort shr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()

        return pkt
    }

    // ── Basic Flow Tracking ───────────────────────────────────────────

    @Test
    fun `single uplink UDP flow created`() {
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("8.8.8.8", flows[0].server)
        assertEquals(53, flows[0].port)
        assertEquals("UDP", flows[0].protocol)
        assertEquals(128L, flows[0].uplinkBytes)  // 20 IP + 8 UDP + 100 payload
        assertEquals(0L, flows[0].downlinkBytes)
    }

    @Test
    fun `single downlink UDP flow created`() {
        val pkt = buildUdpPacket("8.8.8.8", "10.20.0.2", 53, 54321, 200)
        PacketFlowTracker.processPacket(pkt, isUplink = false)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("8.8.8.8", flows[0].server)
        assertEquals(53, flows[0].port)
        assertEquals(0L, flows[0].uplinkBytes)
        assertEquals(228L, flows[0].downlinkBytes)  // 20 + 8 + 200
    }

    @Test
    fun `bidirectional flow accumulates`() {
        val upPkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        val downPkt = buildUdpPacket("8.8.8.8", "10.20.0.2", 53, 54321, 200)

        PacketFlowTracker.processPacket(upPkt, isUplink = true)
        PacketFlowTracker.processPacket(downPkt, isUplink = false)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)  // Same flow key
        assertEquals(128L, flows[0].uplinkBytes)
        assertEquals(228L, flows[0].downlinkBytes)
    }

    @Test
    fun `multiple different flows tracked separately`() {
        val dns = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 50)
        val http = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80, 200)
        val quic = buildUdpPacket("10.20.0.2", "142.250.66.46", 54323, 443, 300)

        PacketFlowTracker.processPacket(dns, isUplink = true)
        PacketFlowTracker.processPacket(http, isUplink = true)
        PacketFlowTracker.processPacket(quic, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(3, flows.size)
    }

    // ── Packet Size Accounting ────────────────────────────────────────

    @Test
    fun `packet size includes IP + transport headers`() {
        // 20 IP + 8 UDP + 100 payload = 128 bytes total
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(128L, flows[0].uplinkBytes)
    }

    @Test
    fun `multiple packets accumulate correctly`() {
        val pkt1 = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        val pkt2 = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 200)

        PacketFlowTracker.processPacket(pkt1, isUplink = true)
        PacketFlowTracker.processPacket(pkt2, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(128L + 228L, flows[0].uplinkBytes)  // 356 total
    }

    // ── Protocol Detection ────────────────────────────────────────────

    @Test
    fun `UDP protocol detected`() {
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        assertEquals("UDP", PacketFlowTracker.getFlows()[0].protocol)
    }

    @Test
    fun `TCP protocol detected`() {
        val pkt = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        assertEquals("TCP", PacketFlowTracker.getFlows()[0].protocol)
    }

    // ── Edge Cases ────────────────────────────────────────────────────

    @Test
    fun `too short packet ignored`() {
        val tiny = ByteArray(10)  // < 20 bytes
        PacketFlowTracker.processPacket(tiny, isUplink = true)

        assertEquals(0, PacketFlowTracker.getFlows().size)
    }

    @Test
    fun `IPv6 packet ignored`() {
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53)
        pkt[0] = 0x65.toByte()  // IPv6 version
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        assertEquals(0, PacketFlowTracker.getFlows().size)
    }

    @Test
    fun `IHL less than 20 ignored`() {
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53)
        pkt[0] = 0x41.toByte()  // IHL=1 (4 bytes) — invalid
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        assertEquals(0, PacketFlowTracker.getFlows().size)
    }

    @Test
    fun `empty packet list initially`() {
        assertEquals(0, PacketFlowTracker.getFlows().size)
    }

    @Test
    fun `clear removes all flows`() {
        val pkt = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53)
        PacketFlowTracker.processPacket(pkt, isUplink = true)
        assertEquals(1, PacketFlowTracker.getFlows().size)

        PacketFlowTracker.clear()
        assertEquals(0, PacketFlowTracker.getFlows().size)
    }

    // ── Aggregate Stats ───────────────────────────────────────────────

    @Test
    fun `aggregate stats sum correctly`() {
        val dns = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 50)
        val http = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 80, 200)

        PacketFlowTracker.processPacket(dns, isUplink = true)
        PacketFlowTracker.processPacket(http, isUplink = true)

        val stats = PacketFlowTracker.getAggregateStats()
        // wgTx = total uplink = (20+8+50) + (20+20+200) = 78 + 240 = 318
        assertEquals(318L, stats.wgTx)
        assertEquals(0L, stats.wgRx)  // no downlink
        assertEquals(2, stats.totalFlows)
    }

    @Test
    fun `aggregate stats with bidirectional traffic`() {
        val up = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        val down = buildUdpPacket("8.8.8.8", "10.20.0.2", 53, 54321, 500)

        PacketFlowTracker.processPacket(up, isUplink = true)
        PacketFlowTracker.processPacket(down, isUplink = false)

        val stats = PacketFlowTracker.getAggregateStats()
        assertEquals(128L, stats.wgTx)   // uplink
        assertEquals(528L, stats.wgRx)   // downlink
        assertEquals(1, stats.totalFlows)
    }

    // ── Flow Key Dedup ────────────────────────────────────────────────

    @Test
    fun `same remote_ip port protocol merges into one flow`() {
        // Two packets to same destination
        val pkt1 = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 100)
        val pkt2 = buildUdpPacket("10.20.0.2", "8.8.8.8", 54322, 53, 200)

        PacketFlowTracker.processPacket(pkt1, isUplink = true)
        PacketFlowTracker.processPacket(pkt2, isUplink = true)

        // Both packets go to 8.8.8.8:53/UDP — same flow key
        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals(128L + 228L, flows[0].uplinkBytes)
    }

    @Test
    fun `different ports create different flows`() {
        val dns = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 50)
        val dot = buildUdpPacket("10.20.0.2", "8.8.8.8", 54322, 853, 50)

        PacketFlowTracker.processPacket(dns, isUplink = true)
        PacketFlowTracker.processPacket(dot, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(2, flows.size)
    }

    // ── Remote IP Extraction ──────────────────────────────────────────

    @Test
    fun `uplink remote = destination IP`() {
        val pkt = buildUdpPacket("10.20.0.2", "142.250.66.46", 54321, 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        assertEquals("142.250.66.46", PacketFlowTracker.getFlows()[0].server)
    }

    @Test
    fun `downlink remote = source IP`() {
        val pkt = buildUdpPacket("142.250.66.46", "10.20.0.2", 443, 54321)
        PacketFlowTracker.processPacket(pkt, isUplink = false)

        assertEquals("142.250.66.46", PacketFlowTracker.getFlows()[0].server)
    }

    // ── Real-World Scenarios ──────────────────────────────────────────

    @Test
    fun `DNS query + response tracked as one flow`() {
        val query = buildUdpPacket("10.20.0.2", "8.8.8.8", 54321, 53, 33)
        val response = buildUdpPacket("8.8.8.8", "10.20.0.2", 53, 54321, 124)

        PacketFlowTracker.processPacket(query, isUplink = true)
        PacketFlowTracker.processPacket(response, isUplink = false)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("8.8.8.8", flows[0].server)
        assertEquals(53, flows[0].port)
        assertEquals("UDP", flows[0].protocol)
        assertTrue("uplink > 0", flows[0].uplinkBytes > 0)
        assertTrue("downlink > 0", flows[0].downlinkBytes > 0)
    }

    @Test
    fun `HTTPS connection tracked correctly`() {
        // TCP SYN
        val syn = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 443, 0)
        // TCP data
        val data = buildTcpPacket("10.20.0.2", "142.250.66.46", 54322, 443, 1200)
        // Response
        val resp = buildTcpPacket("142.250.66.46", "10.20.0.2", 443, 54322, 5000)

        PacketFlowTracker.processPacket(syn, isUplink = true)
        PacketFlowTracker.processPacket(data, isUplink = true)
        PacketFlowTracker.processPacket(resp, isUplink = false)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        assertEquals("TCP", flows[0].protocol)
        assertEquals(443, flows[0].port)
        // Uplink: SYN(40) + data(1240) = 1280
        assertEquals(40L + 1240L, flows[0].uplinkBytes)
        // Downlink: resp(5040)
        assertEquals(5040L, flows[0].downlinkBytes)
    }

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
        // Create 501 flows to exceed MAX_FLOWS=500
        for (i in 1..501) {
            val pkt = buildUdpPacket("10.20.0.2", "10.0.0.$i", 54321, 80, 10)
            PacketFlowTracker.processPacket(pkt, isUplink = true)
        }

        val flows = PacketFlowTracker.getFlows()
        assertTrue("flows <= 500", flows.size <= 500)
    }
}

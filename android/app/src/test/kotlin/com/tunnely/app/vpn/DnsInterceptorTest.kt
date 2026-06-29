package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Unit tests for the minimal DNS interceptor in UdpTunnelVpnService.
 *
 * Tests verify:
 * - Uplink: 10.0.2.3:53 → 8.8.8.8:53 (emulator DNS rewrite)
 * - Downlink: 8.8.8.8:53 → 10.0.2.3:53 (response rewrite back)
 * - Non-emulator DNS passes through untouched
 * - Non-DNS UDP passes through untouched
 * - QR bit validation (only responses trigger downlink rewrite)
 * - Single-use map (second response for same srcPort passes through)
 * - Short/invalid packets pass through safely
 */
class DnsInterceptorTest {

    // Test constants matching UdpTunnelVpnService companion object
    private val EMULATOR_DNS = 0x0A000203  // 10.0.2.3
    private val PUBLIC_DNS = 0x08080808    // 8.8.8.8
    private val CLIENT_IP = 0x0A140002    // 10.20.0.2

    @Before
    fun setUp() {
        // Clear the dnsMap before each test
        // dnsMap is a ConcurrentHashMap in companion object, reset via reflection
        val field = UdpTunnelVpnService::class.java.getDeclaredField("dnsMap")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val map = field.get(null) as java.util.concurrent.ConcurrentHashMap<Any, Any>
        map.clear()
    }

    // ── Packet Builders ────────────────────────────────────────────────

    /**
     * Build a raw IPv4 UDP packet.
     * @param srcIp   Source IP as Int (e.g., 0x0A140002 = 10.20.0.2)
     * @param dstIp   Destination IP as Int
     * @param srcPort Source port
     * @param dstPort Destination port
     * @param payload UDP payload bytes (e.g., DNS query)
     */
    private fun buildUdpPacket(
        srcIp: Int, dstIp: Int,
        srcPort: Int, dstPort: Int,
        payload: ByteArray = ByteArray(0)
    ): ByteArray {
        val ipHeaderLen = 20
        val udpHeaderLen = 8
        val totalLen = ipHeaderLen + udpHeaderLen + payload.size
        val pkt = ByteArray(totalLen)

        // IP header
        pkt[0] = 0x45.toByte()           // Version=4, IHL=5 (20 bytes)
        pkt[1] = 0x00                    // DSCP/ECN
        pkt[2] = ((totalLen shr 8) and 0xFF).toByte()
        pkt[3] = (totalLen and 0xFF).toByte()
        pkt[4] = 0x00; pkt[5] = 0x00    // Identification
        pkt[6] = 0x40.toByte(); pkt[7] = 0x00  // Flags=DF, Fragment=0
        pkt[8] = 0x40.toByte()           // TTL=64
        pkt[9] = 17                      // Protocol=UDP
        pkt[10] = 0; pkt[11] = 0        // Checksum (let kernel calc)

        // Source IP (bytes 12-15)
        pkt[12] = ((srcIp shr 24) and 0xFF).toByte()
        pkt[13] = ((srcIp shr 16) and 0xFF).toByte()
        pkt[14] = ((srcIp shr 8) and 0xFF).toByte()
        pkt[15] = (srcIp and 0xFF).toByte()

        // Destination IP (bytes 16-19)
        pkt[16] = ((dstIp shr 24) and 0xFF).toByte()
        pkt[17] = ((dstIp shr 16) and 0xFF).toByte()
        pkt[18] = ((dstIp shr 8) and 0xFF).toByte()
        pkt[19] = (dstIp and 0xFF).toByte()

        // UDP header (starts at byte 20)
        pkt[20] = ((srcPort shr 8) and 0xFF).toByte()
        pkt[21] = (srcPort and 0xFF).toByte()
        pkt[22] = ((dstPort shr 8) and 0xFF).toByte()
        pkt[23] = (dstPort and 0xFF).toByte()
        val udpLen = udpHeaderLen + payload.size
        pkt[24] = ((udpLen shr 8) and 0xFF).toByte()
        pkt[25] = (udpLen and 0xFF).toByte()
        pkt[26] = 0; pkt[27] = 0        // UDP checksum (0 = no checksum)

        // Payload
        System.arraycopy(payload, 0, pkt, ipHeaderLen + udpHeaderLen, payload.size)

        return pkt
    }

    /**
     * Build a minimal DNS query payload (transaction ID + flags + 1 question).
     */
    private fun buildDnsQuery(txId: Int = 0x1234): ByteArray {
        return byteArrayOf(
            ((txId shr 8) and 0xFF).toByte(), (txId and 0xFF).toByte(),  // Transaction ID
            0x01.toByte(), 0x00.toByte(),  // Flags: standard query, recursion desired
            0x00.toByte(), 0x01.toByte(),  // Questions: 1
            0x00.toByte(), 0x00.toByte(),  // Answers: 0
            0x00.toByte(), 0x00.toByte(),  // Authority: 0
            0x00.toByte(), 0x00.toByte(),  // Additional: 0
            // QNAME: google.com
            0x06, 'g'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(),
            'g'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,  // Root label
            0x00, 0x01.toByte(),  // QTYPE: A
            0x00, 0x01.toByte()   // QCLASS: IN
        )
    }

    /**
     * Build a minimal DNS response payload (txId + response flags + 1 answer).
     */
    private fun buildDnsResponse(txId: Int = 0x1234): ByteArray {
        return byteArrayOf(
            ((txId shr 8) and 0xFF).toByte(), (txId and 0xFF).toByte(),  // Transaction ID
            0x81.toByte(), 0x80.toByte(),  // Flags: response, recursion desired+available
            0x00.toByte(), 0x01.toByte(),  // Questions: 1
            0x00.toByte(), 0x01.toByte(),  // Answers: 1
            0x00.toByte(), 0x00.toByte(),  // Authority: 0
            0x00.toByte(), 0x00.toByte(),  // Additional: 0
            // QNAME: google.com
            0x06, 'g'.code.toByte(), 'o'.code.toByte(), 'o'.code.toByte(),
            'g'.code.toByte(), 'l'.code.toByte(), 'e'.code.toByte(),
            0x03, 'c'.code.toByte(), 'o'.code.toByte(), 'm'.code.toByte(),
            0x00,  // Root label
            0x00, 0x01.toByte(),  // QTYPE: A
            0x00, 0x01.toByte(),  // QCLASS: IN
            // Answer: google.com A 142.250.66.46
            0xC0.toByte(), 0x0C.toByte(),  // Name pointer to offset 12
            0x00, 0x01.toByte(),  // TYPE: A
            0x00, 0x01.toByte(),  // CLASS: IN
            0x00, 0x00, 0x00, 0x3C,  // TTL: 60
            0x00, 0x04.toByte(),  // RDLENGTH: 4
            0x8E.toByte(), 0xFA.toByte(), 0x42.toByte(), 0x2E.toByte()  // RDATA: 142.250.66.46
        )
    }

    // Helper to read IP from packet bytes
    private fun readIp(pkt: ByteArray, off: Int): Int =
        ((pkt[off].toInt() and 0xFF) shl 24) or
        ((pkt[off + 1].toInt() and 0xFF) shl 16) or
        ((pkt[off + 2].toInt() and 0xFF) shl 8) or
        (pkt[off + 3].toInt() and 0xFF)

    private fun ipToStr(ip: Int): String =
        "${(ip shr 24) and 0xFF}.${(ip shr 16) and 0xFF}.${(ip shr 8) and 0xFF}.${ip and 0xFF}"

    // ══════════════════════════════════════════════════════════════════════
    //  UPLINK TESTS: rewriteDnsUplink
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `uplink - rewrites 10_0_2_3 DNS query to 8_8_8_8`() {
        val dnsQuery = buildDnsQuery(txId = 0xABCD)
        val pkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 54321, 53, dnsQuery)

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        // dst IP should be 8.8.8.8
        val newDst = readIp(result, 16)
        assertEquals("dst IP should be 8.8.8.8", "8.8.8.8", ipToStr(newDst))

        // src IP unchanged
        val srcIp = readIp(result, 12)
        assertEquals("src IP should be unchanged", "10.20.0.2", ipToStr(srcIp))

        // src port unchanged
        val srcPort = ((result[20].toInt() and 0xFF) shl 8) or (result[21].toInt() and 0xFF)
        assertEquals("src port should be 54321", 54321, srcPort)

        // dst port unchanged
        val dstPort = ((result[22].toInt() and 0xFF) shl 8) or (result[23].toInt() and 0xFF)
        assertEquals("dst port should be 53", 53, dstPort)
    }

    @Test
    fun `uplink - clears IP and UDP checksums`() {
        val dnsQuery = buildDnsQuery()
        val pkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 54321, 53, dnsQuery)
        // Set non-zero checksums to verify they get cleared
        pkt[10] = 0x12.toByte(); pkt[11] = 0x34.toByte()  // IP checksum
        pkt[26] = 0x56.toByte(); pkt[27] = 0x78.toByte()  // UDP checksum

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        assertEquals("IP checksum should be zeroed", 0, result[10].toInt() and 0xFF)
        assertEquals("IP checksum should be zeroed", 0, result[11].toInt() and 0xFF)
        assertEquals("UDP checksum should be zeroed", 0, result[26].toInt() and 0xFF)
        assertEquals("UDP checksum should be zeroed", 0, result[27].toInt() and 0xFF)
    }

    @Test
    fun `uplink - stores mapping in dnsMap for downlink lookup`() {
        val dnsQuery = buildDnsQuery(txId = 0xAAAA)
        val pkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 12345, 53, dnsQuery)

        UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        // Verify mapping exists by checking the dnsMap field
        val field = UdpTunnelVpnService::class.java.getDeclaredField("dnsMap")
        field.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val map = field.get(null) as java.util.concurrent.ConcurrentHashMap<Any, Any>
        assertTrue("dnsMap should contain srcPort 12345", map.containsKey(12345))
    }

    @Test
    fun `uplink - passes through public DNS (8_8_8_8) untouched`() {
        val dnsQuery = buildDnsQuery()
        val pkt = buildUdpPacket(CLIENT_IP, PUBLIC_DNS, 54321, 53, dnsQuery)
        val original = pkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        assertArrayEquals("public DNS packet should be unchanged", original, result)
    }

    @Test
    fun `uplink - passes through cloudflare DNS (1_1_1_1) untouched`() {
        val cloudflare = 0x01010101  // 1.1.1.1
        val dnsQuery = buildDnsQuery()
        val pkt = buildUdpPacket(CLIENT_IP, cloudflare, 54321, 53, dnsQuery)
        val original = pkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        assertArrayEquals("1.1.1.1 packet should be unchanged", original, result)
    }

    @Test
    fun `uplink - passes through non-DNS UDP (port 443) untouched`() {
        val pkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 54321, 443, ByteArray(10))
        val original = pkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        assertArrayEquals("non-DNS packet should be unchanged", original, result)
    }

    @Test
    fun `uplink - passes through TCP packets untouched`() {
        // Build a packet with protocol=TCP (6) instead of UDP (17)
        val pkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 54321, 53, ByteArray(10))
        pkt[9] = 6  // Change to TCP
        val original = pkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        assertArrayEquals("TCP packet should be unchanged", original, result)
    }

    @Test
    fun `uplink - passes through short packets safely`() {
        val shortPkt = ByteArray(10)  // Too short for IP header

        val result = UdpTunnelVpnService.rewriteDnsUplink(shortPkt, shortPkt.size)

        assertArrayEquals("short packet should be unchanged", shortPkt, result)
    }

    @Test
    fun `uplink - passes through non-IPv4 packets safely`() {
        val pkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 54321, 53, buildDnsQuery())
        pkt[0] = 0x65.toByte()  // IPv6 version
        val original = pkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        assertArrayEquals("IPv6 packet should be unchanged", original, result)
    }

    @Test
    fun `uplink - rewrites 192_168_x_x DNS but NOT intercepted (only 10_0_2_3)`() {
        // 192.168.1.1 should NOT be intercepted (only 10.0.2.3 is)
        val router = 0xC0A80101.toInt()  // 192.168.1.1
        val dnsQuery = buildDnsQuery()
        val pkt = buildUdpPacket(CLIENT_IP, router, 54321, 53, dnsQuery)
        val original = pkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        assertArrayEquals("192.168.1.1 should NOT be intercepted", original, result)
    }

    @Test
    fun `uplink - rewrites 10_0_2_2 DNS but NOT intercepted (only 10_0_2_3)`() {
        // 10.0.2.2 (emulator gateway) should NOT be intercepted
        val gateway = 0x0A000202  // 10.0.2.2
        val dnsQuery = buildDnsQuery()
        val pkt = buildUdpPacket(CLIENT_IP, gateway, 54321, 53, dnsQuery)
        val original = pkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        assertArrayEquals("10.0.2.2 should NOT be intercepted", original, result)
    }

    @Test
    fun `uplink - preserves payload intact after rewrite`() {
        val dnsQuery = buildDnsQuery(txId = 0xBEEF)
        val pkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 54321, 53, dnsQuery)

        val result = UdpTunnelVpnService.rewriteDnsUplink(pkt, pkt.size)

        // Payload starts at byte 28 (20 IP + 8 UDP)
        val payload = result.copyOfRange(28, result.size)
        val expectedPayload = dnsQuery.copyOf()
        assertArrayEquals("DNS payload should be unchanged", expectedPayload, payload)
    }

    // ══════════════════════════════════════════════════════════════════════
    //  DOWNLINK TESTS: rewriteDnsDownlink
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `downlink - rewrites 8_8_8_8 response back to 10_0_2_3`() {
        // First: send uplink to create mapping
        val dnsQuery = buildDnsQuery(txId = 0xABCD)
        val upPkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 54321, 53, dnsQuery)
        UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)

        // Then: simulate response from 8.8.8.8
        val dnsResp = buildDnsResponse(txId = 0xABCD)
        val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, 54321, dnsResp)

        val result = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)

        // src IP should be rewritten to 10.0.2.3
        val newSrc = readIp(result, 12)
        assertEquals("src IP should be 10.0.2.3", "10.0.2.3", ipToStr(newSrc))

        // dst IP unchanged
        val dstIp = readIp(result, 16)
        assertEquals("dst IP should be 10.20.0.2", "10.20.0.2", ipToStr(dstIp))
    }

    @Test
    fun `downlink - clears checksums after rewrite`() {
        // Create mapping
        val dnsQuery = buildDnsQuery()
        val upPkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 11111, 53, dnsQuery)
        UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)

        // Response
        val dnsResp = buildDnsResponse()
        val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, 11111, dnsResp)
        downPkt[10] = 0x12.toByte(); downPkt[11] = 0x34.toByte()
        downPkt[26] = 0x56.toByte(); downPkt[27] = 0x78.toByte()

        val result = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)

        assertEquals("IP checksum should be zeroed", 0, result[10].toInt() and 0xFF)
        assertEquals("UDP checksum should be zeroed", 0, result[26].toInt() and 0xFF)
    }

    @Test
    fun `downlink - single-use map entry removed after first match`() {
        // Create mapping
        val dnsQuery = buildDnsQuery()
        val upPkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 22222, 53, dnsQuery)
        UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)

        // First response — should match
        val dnsResp = buildDnsResponse()
        val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, 22222, dnsResp)
        val result1 = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)
        val src1 = readIp(result1, 12)
        assertEquals("first response should be rewritten to 10.0.2.3", "10.0.2.3", ipToStr(src1))

        // Second response — same srcPort, no mapping left
        val downPkt2 = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, 22222, dnsResp)
        val result2 = UdpTunnelVpnService.rewriteDnsDownlink(downPkt2, downPkt2.size)
        val src2 = readIp(result2, 12)
        assertEquals("second response should pass through (8.8.8.8)", "8.8.8.8", ipToStr(src2))
    }

    @Test
    fun `downlink - QR bit check passes DNS query through`() {
        // Create mapping
        val dnsQuery = buildDnsQuery()
        val upPkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 33333, 53, dnsQuery)
        UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)

        // Send a DNS QUERY (not response) from 8.8.8.8:53 — QR bit = 0
        val fakeQuery = buildDnsQuery()  // QR=0 (query)
        val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, 33333, fakeQuery)
        val original = downPkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)

        // Should pass through because QR=0 (it's a query, not a response)
        val srcIp = readIp(result, 12)
        assertEquals("DNS query should pass through", "8.8.8.8", ipToStr(srcIp))
    }

    @Test
    fun `downlink - passes through when no mapping exists`() {
        val dnsResp = buildDnsResponse()
        // Response from 8.8.8.8 but no prior uplink mapping for srcPort 44444
        val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, 44444, dnsResp)
        val original = downPkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)

        assertArrayEquals("no mapping → pass through unchanged", original, result)
    }

    @Test
    fun `downlink - passes through non-8_8_8_8 source`() {
        // Create mapping
        val dnsQuery = buildDnsQuery()
        val upPkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 55555, 53, dnsQuery)
        UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)

        // Response from a DIFFERENT DNS server (e.g., 9.9.9.9)
        val otherDns = 0x09090909  // 9.9.9.9
        val dnsResp = buildDnsResponse()
        val downPkt = buildUdpPacket(otherDns, CLIENT_IP, 53, 55555, dnsResp)
        val original = downPkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)

        assertArrayEquals("non-8.8.8.8 source should pass through", original, result)
    }

    @Test
    fun `downlink - passes through non-DNS source port`() {
        // Create mapping
        val dnsQuery = buildDnsQuery()
        val upPkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, 66666, 53, dnsQuery)
        UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)

        // Response from 8.8.8.8 but NOT port 53 (e.g., QUIC port 443)
        val dnsResp = buildDnsResponse()
        val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 443, 66666, dnsResp)
        val original = downPkt.copyOf()

        val result = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)

        assertArrayEquals("non-port-53 source should pass through", original, result)
    }

    @Test
    fun `downlink - passes through short packets safely`() {
        val shortPkt = ByteArray(10)

        val result = UdpTunnelVpnService.rewriteDnsDownlink(shortPkt, shortPkt.size)

        assertArrayEquals("short packet should be unchanged", shortPkt, result)
    }

    // ══════════════════════════════════════════════════════════════════════
    //  ROUND-TRIP TESTS: uplink + downlink together
    // ══════════════════════════════════════════════════════════════════════

    @Test
    fun `roundtrip - emulator DNS query and response`() {
        val txId = 0x4321
        val srcPort = 77777

        // Uplink: client sends DNS to 10.0.2.3
        val dnsQuery = buildDnsQuery(txId)
        val upPkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, srcPort, 53, dnsQuery)
        val upResult = UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)

        // Verify uplink rewrite
        assertEquals("8.8.8.8", ipToStr(readIp(upResult, 16)))  // dst = 8.8.8.8
        assertEquals("10.20.0.2", ipToStr(readIp(upResult, 12)))  // src unchanged

        // Downlink: server sends response from 8.8.8.8
        val dnsResp = buildDnsResponse(txId)
        val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, srcPort, dnsResp)
        val downResult = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)

        // Verify downlink rewrite
        assertEquals("10.0.2.3", ipToStr(readIp(downResult, 12)))  // src = 10.0.2.3 (back to original)
        assertEquals("10.20.0.2", ipToStr(readIp(downResult, 16)))  // dst unchanged

        // Verify payload preserved
        val queryPayload = upResult.copyOfRange(28, upResult.size)
        assertArrayEquals("query payload preserved", dnsQuery, queryPayload)
        val respPayload = downResult.copyOfRange(28, downResult.size)
        assertArrayEquals("response payload preserved", dnsResp, respPayload)
    }

    @Test
    fun `roundtrip - multiple concurrent queries with different srcPorts`() {
        val txIds = intArrayOf(0x1111, 0x2222, 0x3333)
        val srcPorts = intArrayOf(10001, 10002, 10003)

        // Send 3 uplink queries
        for (i in txIds.indices) {
            val dnsQuery = buildDnsQuery(txIds[i])
            val upPkt = buildUdpPacket(CLIENT_IP, EMULATOR_DNS, srcPorts[i], 53, dnsQuery)
            UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)
        }

        // Receive 3 responses (in reverse order to test independence)
        for (i in txIds.indices.reversed()) {
            val dnsResp = buildDnsResponse(txIds[i])
            val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, srcPorts[i], dnsResp)
            val result = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)

            assertEquals(
                "response $i should be rewritten to 10.0.2.3",
                "10.0.2.3", ipToStr(readIp(result, 12))
            )
        }
    }

    @Test
    fun `roundtrip - public DNS query passes through both directions`() {
        // Query to 8.8.8.8 (public) — should NOT be intercepted
        val dnsQuery = buildDnsQuery()
        val upPkt = buildUdpPacket(CLIENT_IP, PUBLIC_DNS, 88888, 53, dnsQuery)
        val upOriginal = upPkt.copyOf()
        val upResult = UdpTunnelVpnService.rewriteDnsUplink(upPkt, upPkt.size)
        assertArrayEquals("public DNS uplink should pass through", upOriginal, upResult)

        // Response from 8.8.8.8 — no mapping, should pass through
        val dnsResp = buildDnsResponse()
        val downPkt = buildUdpPacket(PUBLIC_DNS, CLIENT_IP, 53, 88888, dnsResp)
        val downOriginal = downPkt.copyOf()
        val downResult = UdpTunnelVpnService.rewriteDnsDownlink(downPkt, downPkt.size)
        assertArrayEquals("public DNS downlink should pass through", downOriginal, downResult)
    }
}

package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Tests for client-side DNS parsing in PacketFlowTracker.
 * Verifies that DNS queries/responses are parsed and DomainCache is populated.
 */
class DnsParsingTest {

    @Before
    fun setup() {
        PacketFlowTracker.clear()
    }

    // --- Helper: build DNS query packet ---

    private fun buildDnsQueryPacket(
        domain: String,
        txId: Int = 0x1234,
        srcIp: String = "10.20.0.2",
        dstIp: String = "8.8.8.8"
    ): ByteArray {
        val dnsPayload = buildDnsQueryPayload(domain, txId)
        return buildUdpIpPacket(srcIp, 12345, dstIp, 53, dnsPayload)
    }

    private fun buildDnsQueryPayload(domain: String, txId: Int): ByteArray {
        val parts = domain.split(".")
        val question = ByteArray(parts.sumOf { 1 + it.length } + 1 + 4) // labels + root + QTYPE + QCLASS
        var offset = 0
        for (part in parts) {
            question[offset++] = part.length.toByte()
            part.toByteArray().copyInto(question, offset)
            offset += part.length
        }
        question[offset++] = 0 // root
        question[offset++] = 0; question[offset++] = 1  // QTYPE = A
        question[offset++] = 0; question[offset++] = 1  // QCLASS = IN

        val header = ByteArray(12)
        header[0] = ((txId shr 8) and 0xFF).toByte()
        header[1] = (txId and 0xFF).toByte()
        header[2] = 0x01.toByte() // flags: standard query
        header[3] = 0x00.toByte()
        header[5] = 1 // QDCOUNT = 1

        return header + question
    }

    // --- Helper: build DNS response packet ---

    private fun buildDnsResponsePacket(
        domain: String,
        ips: List<String>,
        txId: Int = 0x1234,
        srcIp: String = "8.8.8.8",
        dstIp: String = "10.20.0.2"
    ): ByteArray {
        val dnsPayload = buildDnsResponsePayload(domain, ips, txId)
        return buildUdpIpPacket(srcIp, 53, dstIp, 12345, dnsPayload)
    }

    private fun buildDnsResponsePayload(domain: String, ips: List<String>, txId: Int): ByteArray {
        val parts = domain.split(".")
        val question = ByteArray(parts.sumOf { 1 + it.length } + 1 + 4)
        var offset = 0
        for (part in parts) {
            question[offset++] = part.length.toByte()
            part.toByteArray().copyInto(question, offset)
            offset += part.length
        }
        question[offset++] = 0
        question[offset++] = 0; question[offset++] = 1  // QTYPE = A
        question[offset++] = 0; question[offset++] = 1  // QCLASS = IN

        val header = ByteArray(12)
        header[0] = ((txId shr 8) and 0xFF).toByte()
        header[1] = (txId and 0xFF).toByte()
        header[2] = 0x81.toByte() // flags: response
        header[3] = 0x80.toByte()
        header[5] = 1 // QDCOUNT = 1
        header[7] = ips.size.toByte() // ANCOUNT

        // Answer section: pointer to qname + A record
        val answers = ByteArray(ips.size * 16) // each: 2(name ptr) + 10(rr header) + 4(ip)
        var aOff = 0
        for (ip in ips) {
            answers[aOff++] = 0xC0.toByte() // pointer
            answers[aOff++] = 0x0C.toByte() // offset 12 (question)
            answers[aOff++] = 0; answers[aOff++] = 1  // TYPE = A
            answers[aOff++] = 0; answers[aOff++] = 1  // CLASS = IN
            answers[aOff++] = 0; answers[aOff++] = 0
            answers[aOff++] = 0x01; answers[aOff++] = 0x2C.toByte() // TTL = 300
            answers[aOff++] = 0; answers[aOff++] = 4  // RDLENGTH = 4
            val octets = ip.split(".")
            for (o in octets) {
                answers[aOff++] = o.toInt().toByte()
            }
        }

        return header + question + answers.copyOf(aOff)
    }

    // --- Helper: build raw IP/UDP packet ---

    private fun buildUdpIpPacket(
        srcIp: String, srcPort: Int,
        dstIp: String, dstPort: Int,
        payload: ByteArray
    ): ByteArray {
        val ipHeader = ByteArray(20)
        ipHeader[0] = 0x45.toByte() // IPv4, IHL=5
        val totalLen = 20 + 8 + payload.size
        ipHeader[2] = ((totalLen shr 8) and 0xFF).toByte()
        ipHeader[3] = (totalLen and 0xFF).toByte()
        ipHeader[8] = 64 // TTL
        ipHeader[9] = 17 // UDP
        val srcParts = srcIp.split(".")
        for (i in 0..3) ipHeader[12 + i] = srcParts[i].toInt().toByte()
        val dstParts = dstIp.split(".")
        for (i in 0..3) ipHeader[16 + i] = dstParts[i].toInt().toByte()

        val udpHeader = ByteArray(8)
        udpHeader[0] = ((srcPort shr 8) and 0xFF).toByte()
        udpHeader[1] = (srcPort and 0xFF).toByte()
        udpHeader[2] = ((dstPort shr 8) and 0xFF).toByte()
        udpHeader[3] = (dstPort and 0xFF).toByte()
        val udpLen = 8 + payload.size
        udpHeader[4] = ((udpLen shr 8) and 0xFF).toByte()
        udpHeader[5] = (udpLen and 0xFF).toByte()

        return ipHeader + udpHeader + payload
    }

    // --- Tests: DNS query parsing ---

    @Test
    fun testDnsQueryExtractsDomain() {
        val query = buildDnsQueryPacket("instagram.com")
        PacketFlowTracker.processPacket(query, isUplink = true)

        // The query itself doesn't populate DomainCache, but should store pending query
        // We verify by sending a response
        val response = buildDnsResponsePacket("instagram.com", listOf("57.144.144.1"))
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("instagram.com", DomainCache.getDomain("57.144.144.1"))
        assertEquals(1, PacketFlowTracker.dnsDomainsExtracted)
    }

    @Test
    fun testDnsResponseMultipleARecords() {
        val query = buildDnsQueryPacket("google.com")
        PacketFlowTracker.processPacket(query, isUplink = true)

        val response = buildDnsResponsePacket("google.com", listOf("142.250.185.78", "142.250.185.110"))
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("google.com", DomainCache.getDomain("142.250.185.78"))
        assertEquals("google.com", DomainCache.getDomain("142.250.185.110"))
        assertEquals(2, PacketFlowTracker.dnsDomainsExtracted)
    }

    @Test
    fun testDnsResponseWithoutQueryStillWorks() {
        // Response without a preceding query — should still parse QNAME from response
        val response = buildDnsResponsePacket("whatsapp.com", listOf("157.240.1.35"), txId = 0x5678)
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("whatsapp.com", DomainCache.getDomain("157.240.1.35"))
    }

    @Test
    fun testDnsQueryThenDifferentTxIdResponse() {
        // Query with txId=0x1111, response with txId=0x2222 — should NOT match
        val query = buildDnsQueryPacket("example.com", txId = 0x1111)
        PacketFlowTracker.processPacket(query, isUplink = true)

        val response = buildDnsResponsePacket("other.com", listOf("1.2.3.4"), txId = 0x2222)
        PacketFlowTracker.processPacket(response, isUplink = false)

        // other.com should be cached (parsed from response QNAME)
        assertEquals("other.com", DomainCache.getDomain("1.2.3.4"))
        // example.com should NOT be cached (no response yet)
        assertNull(DomainCache.getDomain("93.184.216.34"))
    }

    @Test
    fun testDnsDomainLowercase() {
        val query = buildDnsQueryPacket("Instagram.COM")
        PacketFlowTracker.processPacket(query, isUplink = true)

        val response = buildDnsResponsePacket("Instagram.COM", listOf("57.144.144.1"))
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("instagram.com", DomainCache.getDomain("57.144.144.1"))
    }

    @Test
    fun testDnsSubdomain() {
        val query = buildDnsQueryPacket("z-p42-gateway.instagram.com")
        PacketFlowTracker.processPacket(query, isUplink = true)

        val response = buildDnsResponsePacket("z-p42-gateway.instagram.com", listOf("57.144.100.192"))
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("z-p42-gateway.instagram.com", DomainCache.getDomain("57.144.100.192"))
    }

    @Test
    fun testDnsNoAnswersSkipped() {
        // Response with 0 answers — should not crash
        val dnsPayload = buildDnsResponsePayload("empty.com", emptyList(), 0xABCD)
        val response = buildUdpIpPacket("8.8.8.8", 53, "10.20.0.2", 12345, dnsPayload)
        PacketFlowTracker.processPacket(response, isUplink = false)

        // No crash, no cache entries
        assertNull(DomainCache.getDomain("empty.com"))
    }

    @Test
    fun testDnsShortPacketIgnored() {
        // Packet too short for DNS header
        val tiny = ByteArray(10)
        tiny[0] = 0x45.toByte()
        tiny[9] = 17 // UDP
        PacketFlowTracker.processPacket(tiny, isUplink = false)
        // No crash
    }

    @Test
    fun testDnsCacheUsedBySubsequentPackets() {
        // DNS response caches IP→domain
        val query = buildDnsQueryPacket("reddit.com")
        PacketFlowTracker.processPacket(query, isUplink = true)
        val response = buildDnsResponsePacket("reddit.com", listOf("151.101.1.140"))
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("reddit.com", DomainCache.getDomain("151.101.1.140"))

        // Now a TCP packet to that IP should get the domain from cache
        val tcpPacket = buildTcpSynPacket("10.20.0.2", "151.101.1.140", 443)
        PacketFlowTracker.processPacket(tcpPacket, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        val redditFlow = flows.find { it.server == "151.101.1.140" }
        assertNotNull(redditFlow)
        assertEquals("reddit.com", redditFlow!!.domain)
    }

    private fun buildTcpSynPacket(srcIp: String, dstIp: String, dstPort: Int): ByteArray {
        val ipHeader = ByteArray(20)
        ipHeader[0] = 0x45.toByte()
        val totalLen = 20 + 20 // IP + TCP (no payload)
        ipHeader[2] = ((totalLen shr 8) and 0xFF).toByte()
        ipHeader[3] = (totalLen and 0xFF).toByte()
        ipHeader[8] = 64
        ipHeader[9] = 6 // TCP
        val srcParts = srcIp.split(".")
        for (i in 0..3) ipHeader[12 + i] = srcParts[i].toInt().toByte()
        val dstParts = dstIp.split(".")
        for (i in 0..3) ipHeader[16 + i] = dstParts[i].toInt().toByte()

        val tcpHeader = ByteArray(20)
        tcpHeader[2] = ((44444 shr 8) and 0xFF).toByte()
        tcpHeader[3] = (44444 and 0xFF).toByte()
        tcpHeader[4] = ((dstPort shr 8) and 0xFF).toByte()
        tcpHeader[5] = (dstPort and 0xFF).toByte()
        tcpHeader[12] = 0x50.toByte() // data offset = 5 (20 bytes)
        tcpHeader[13] = 0x02.toByte() // SYN flag

        return ipHeader + tcpHeader
    }

    @Test
    fun testDnsPendingMapPurge() {
        // Fill pending map with many queries — should purge when >200
        for (i in 0 until 250) {
            val query = buildDnsQueryPacket("test$i.com", txId = i)
            PacketFlowTracker.processPacket(query, isUplink = true)
        }
        // No crash — pending map should have been purged
        // Verify DNS still works after purge
        val response = buildDnsResponsePacket("final.com", listOf("1.2.3.4"), txId = 0x9999)
        PacketFlowTracker.processPacket(response, isUplink = false)
        assertEquals("final.com", DomainCache.getDomain("1.2.3.4"))
    }

    @Test
    fun testDnsClearResetsState() {
        val query = buildDnsQueryPacket("test.com")
        PacketFlowTracker.processPacket(query, isUplink = true)
        val response = buildDnsResponsePacket("test.com", listOf("1.2.3.4"))
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals(1, PacketFlowTracker.dnsDomainsExtracted)
        assertNotNull(DomainCache.getDomain("1.2.3.4"))

        PacketFlowTracker.clear()

        assertEquals(0, PacketFlowTracker.dnsDomainsExtracted)
        assertNull(DomainCache.getDomain("1.2.3.4"))
    }

    @Test
    fun testNonDnsUdpPacketIgnored() {
        // UDP packet to port 443 (QUIC) — should not be parsed as DNS
        val quicPacket = buildUdpIpPacket("10.20.0.2", 12345, "142.251.12.100", 443, ByteArray(100))
        PacketFlowTracker.processPacket(quicPacket, isUplink = true)
        // No crash, no DNS entries
        assertEquals(0, PacketFlowTracker.dnsDomainsExtracted)
    }

    @Test
    fun testDnsQueryToPrivateIp() {
        // DNS to 10.0.2.3:53 (emulator private DNS)
        val query = buildDnsQueryPacket("android.com", dstIp = "10.0.2.3")
        PacketFlowTracker.processPacket(query, isUplink = true)

        val response = buildDnsResponsePacket("android.com", listOf("142.250.185.206"), srcIp = "10.0.2.3")
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("android.com", DomainCache.getDomain("142.250.185.206"))
    }

    @Test
    fun testDnsResponseOnSrcPort53() {
        // Response comes from src port 53 (not dst port 53)
        val dnsPayload = buildDnsResponsePayload("cloudflare.com", listOf("1.1.1.1"), 0xAAAA)
        val packet = buildUdpIpPacket("1.1.1.1", 53, "10.20.0.2", 54321, dnsPayload)
        PacketFlowTracker.processPacket(packet, isUplink = false)

        assertEquals("cloudflare.com", DomainCache.getDomain("1.1.1.1"))
    }
}

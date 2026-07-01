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

    // --- Additional edge case tests ---

    @Test
    fun testDnsResponseOverwritesExistingCache() {
        // First DNS maps 1.2.3.4 → old.com
        val q1 = buildDnsQueryPacket("old.com", txId = 0x1111)
        PacketFlowTracker.processPacket(q1, isUplink = true)
        val r1 = buildDnsResponsePacket("old.com", listOf("1.2.3.4"), txId = 0x1111)
        PacketFlowTracker.processPacket(r1, isUplink = false)
        assertEquals("old.com", DomainCache.getDomain("1.2.3.4"))

        // Second DNS maps same IP → new.com
        val q2 = buildDnsQueryPacket("new.com", txId = 0x2222)
        PacketFlowTracker.processPacket(q2, isUplink = true)
        val r2 = buildDnsResponsePacket("new.com", listOf("1.2.3.4"), txId = 0x2222)
        PacketFlowTracker.processPacket(r2, isUplink = false)
        assertEquals("new.com", DomainCache.getDomain("1.2.3.4"))
    }

    @Test
    fun testDnsMultipleDomainsCached() {
        // Multiple different domains → different IPs
        for ((domain, ip) in listOf(
            "google.com" to "142.250.185.78",
            "facebook.com" to "157.240.1.35",
            "instagram.com" to "57.144.144.1",
            "whatsapp.com" to "157.240.1.60",
            "youtube.com" to "142.250.185.174"
        )) {
            val q = buildDnsQueryPacket(domain, txId = domain.hashCode() and 0xFFFF)
            PacketFlowTracker.processPacket(q, isUplink = true)
            val r = buildDnsResponsePacket(domain, listOf(ip), txId = domain.hashCode() and 0xFFFF)
            PacketFlowTracker.processPacket(r, isUplink = false)
        }

        assertEquals("google.com", DomainCache.getDomain("142.250.185.78"))
        assertEquals("facebook.com", DomainCache.getDomain("157.240.1.35"))
        assertEquals("instagram.com", DomainCache.getDomain("57.144.144.1"))
        assertEquals("whatsapp.com", DomainCache.getDomain("157.240.1.60"))
        assertEquals("youtube.com", DomainCache.getDomain("142.250.185.174"))
        assertEquals(5, PacketFlowTracker.dnsDomainsExtracted)
    }

    @Test
    fun testDnsResponseWith5ARecords() {
        val query = buildDnsQueryPacket("cdn.example.com", txId = 0xBBBB)
        PacketFlowTracker.processPacket(query, isUplink = true)

        val ips = listOf("10.0.0.1", "10.0.0.2", "10.0.0.3", "10.0.0.4", "10.0.0.5")
        val response = buildDnsResponsePacket("cdn.example.com", ips, txId = 0xBBBB)
        PacketFlowTracker.processPacket(response, isUplink = false)

        for (ip in ips) {
            assertEquals("cdn.example.com", DomainCache.getDomain(ip))
        }
        assertEquals(5, PacketFlowTracker.dnsDomainsExtracted)
    }

    @Test
    fun testDnsResponsePrivateRfc1918() {
        // Response with RFC1918 addresses (e.g., internal service)
        val query = buildDnsQueryPacket("router.local", txId = 0xCCCC)
        PacketFlowTracker.processPacket(query, isUplink = true)
        val response = buildDnsResponsePacket("router.local", listOf("192.168.1.1"), txId = 0xCCCC)
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("router.local", DomainCache.getDomain("192.168.1.1"))
    }

    @Test
    fun testDnsLoopbackAddress() {
        val query = buildDnsQueryPacket("localhost", txId = 0xDDDD)
        PacketFlowTracker.processPacket(query, isUplink = true)
        val response = buildDnsResponsePacket("localhost", listOf("127.0.0.1"), txId = 0xDDDD)
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("localhost", DomainCache.getDomain("127.0.0.1"))
    }

    @Test
    fun testDnsIgnoresIpv6Packet() {
        // IPv6 packet — should be ignored (version != 4)
        val ipv6 = ByteArray(48)
        ipv6[0] = 0x60.toByte() // IPv6 version
        PacketFlowTracker.processPacket(ipv6, isUplink = true)
        // No crash, no DNS entries
        assertEquals(0, PacketFlowTracker.dnsDomainsExtracted)
    }

    @Test
    fun testDnsIgnoresTcpPacket() {
        // TCP packet on port 53 — should not be parsed as DNS
        val tcp = buildTcpSynPacket("10.20.0.2", "8.8.8.8", 53)
        PacketFlowTracker.processPacket(tcp, isUplink = true)
        // No crash, no DNS entries
        assertEquals(0, PacketFlowTracker.dnsDomainsExtracted)
    }

    @Test
    fun testDnsResponseWithZeroAnCount() {
        // Response with 0 answers (NXDOMAIN or similar)
        val dnsPayload = buildDnsResponsePayload("nonexistent.com", emptyList(), 0x1234)
        val packet = buildUdpIpPacket("8.8.8.8", 53, "10.20.0.2", 12345, dnsPayload)
        PacketFlowTracker.processPacket(packet, isUplink = false)
        // No crash, no entries
        assertNull(DomainCache.getDomain("nonexistent.com"))
    }

    @Test
    fun testDnsResponseTruncated() {
        // Response truncated mid-answer
        val dnsPayload = buildDnsResponsePayload("truncated.com", listOf("1.2.3.4"), 0xEEEE)
        val truncated = dnsPayload.copyOf(dnsPayload.size - 5) // cut off last 5 bytes
        val packet = buildUdpIpPacket("8.8.8.8", 53, "10.20.0.2", 12345, truncated)
        PacketFlowTracker.processPacket(packet, isUplink = false)
        // No crash — may or may not have partial results
    }

    @Test
    fun testDnsCacheSurvivesBetweenPackets() {
        // DNS response populates cache
        val q = buildDnsQueryPacket("persistent.com", txId = 0xFFFF)
        PacketFlowTracker.processPacket(q, isUplink = true)
        val r = buildDnsResponsePacket("persistent.com", listOf("5.6.7.8"), txId = 0xFFFF)
        PacketFlowTracker.processPacket(r, isUplink = false)

        // Process 100 non-DNS packets
        for (i in 0 until 100) {
            val tcp = buildTcpSynPacket("10.20.0.2", "93.184.216.$i", 443)
            PacketFlowTracker.processPacket(tcp, isUplink = true)
        }

        // Cache should still have the DNS entry
        assertEquals("persistent.com", DomainCache.getDomain("5.6.7.8"))
    }

    @Test
    fun testDnsWithNumericDomain() {
        val query = buildDnsQueryPacket("8.8.4.4.nip.io", txId = 0x1111)
        PacketFlowTracker.processPacket(query, isUplink = true)
        val response = buildDnsResponsePacket("8.8.4.4.nip.io", listOf("8.8.4.4"), txId = 0x1111)
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("8.8.4.4.nip.io", DomainCache.getDomain("8.8.4.4"))
    }

    @Test
    fun testDnsDomainWithHyphens() {
        val query = buildDnsQueryPacket("z-p42-gateway.instagram.com", txId = 0x2222)
        PacketFlowTracker.processPacket(query, isUplink = true)
        val response = buildDnsResponsePacket("z-p42-gateway.instagram.com", listOf("57.144.100.192"), txId = 0x2222)
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("z-p42-gateway.instagram.com", DomainCache.getDomain("57.144.100.192"))
    }

    @Test
    fun testDnsDomainWithNumbers() {
        val query = buildDnsQueryPacket("api2.v2.tiktokcdn.com", txId = 0x3333)
        PacketFlowTracker.processPacket(query, isUplink = true)
        val response = buildDnsResponsePacket("api2.v2.tiktokcdn.com", listOf("23.45.67.89"), txId = 0x3333)
        PacketFlowTracker.processPacket(response, isUplink = false)

        assertEquals("api2.v2.tiktokcdn.com", DomainCache.getDomain("23.45.67.89"))
    }

    @Test
    fun testDnsDebugStatsShowsDnsCount() {
        val q = buildDnsQueryPacket("stats-test.com", txId = 0x4444)
        PacketFlowTracker.processPacket(q, isUplink = true)
        val r = buildDnsResponsePacket("stats-test.com", listOf("9.8.7.6"), txId = 0x4444)
        PacketFlowTracker.processPacket(r, isUplink = false)

        val stats = PacketFlowTracker.getDebugStats()
        assertTrue("Debug stats should contain dns counter", stats.contains("dns=1"))
    }

    @Test
    fun testDnsFlowEntryGetsDomainFromCache() {
        // DNS response → cache → TCP flow to same IP gets domain
        val q = buildDnsQueryPacket("spotify.com", txId = 0x5555)
        PacketFlowTracker.processPacket(q, isUplink = true)
        val r = buildDnsResponsePacket("spotify.com", listOf("35.186.224.25"), txId = 0x5555)
        PacketFlowTracker.processPacket(r, isUplink = false)

        // TCP connection to the resolved IP
        val tcp = buildTcpSynPacket("10.20.0.2", "35.186.224.25", 443)
        PacketFlowTracker.processPacket(tcp, isUplink = true)

        val flows = PacketFlowTracker.getFlows()
        val spotifyFlow = flows.find { it.server == "35.186.224.25" }
        assertNotNull("Flow should exist", spotifyFlow)
        assertEquals("spotify.com", spotifyFlow!!.domain)
    }

    @Test
    fun testDnsResponseThenDownlinkTrafficShowsDomain() {
        // DNS resolves IP, then downlink traffic from that IP shows domain
        val q = buildDnsQueryPacket("netflix.com", txId = 0x6666)
        PacketFlowTracker.processPacket(q, isUplink = true)
        val r = buildDnsResponsePacket("netflix.com", listOf("52.2.128.100"), txId = 0x6666)
        PacketFlowTracker.processPacket(r, isUplink = false)

        // Downlink TCP from Netflix
        val downlinkPkt = buildTcpSynPacket("52.2.128.100", "10.20.0.2", 443)
        PacketFlowTracker.processPacket(downlinkPkt, isUplink = false)

        val flows = PacketFlowTracker.getFlows()
        val nf = flows.find { it.server == "52.2.128.100" }
        assertNotNull("Downlink flow should exist", nf)
        assertEquals("netflix.com", nf!!.domain)
    }

    @Test
    fun testDnsMaxDomainLength() {
        // 63-char label (max per DNS spec)
        val longLabel = "a".repeat(63)
        val domain = "$longLabel.example.com"
        val q = buildDnsQueryPacket(domain, txId = 0x7777)
        PacketFlowTracker.processPacket(q, isUplink = true)
        val r = buildDnsResponsePacket(domain, listOf("10.10.10.10"), txId = 0x7777)
        PacketFlowTracker.processPacket(r, isUplink = false)

        assertEquals(domain.lowercase(), DomainCache.getDomain("10.10.10.10"))
    }

    @Test
    fun testDnsConcurrentAccess() {
        // Simulate concurrent DNS processing from multiple threads
        val threads = mutableListOf<Thread>()
        for (i in 0 until 10) {
            threads.add(Thread {
                val q = buildDnsQueryPacket("concurrent$i.com", txId = i)
                PacketFlowTracker.processPacket(q, isUplink = true)
                val r = buildDnsResponsePacket("concurrent$i.com", listOf("10.0.0.$i"), txId = i)
                PacketFlowTracker.processPacket(r, isUplink = false)
            })
        }
        threads.forEach { it.start() }
        threads.forEach { it.join(5000) }

        // All 10 domains should be cached
        for (i in 0 until 10) {
            assertEquals("concurrent$i.com", DomainCache.getDomain("10.0.0.$i"))
        }
    }
}

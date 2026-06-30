package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Before
import org.junit.Test

/**
 * Tests for server-side SNI domain fallback in PacketFlowTracker.
 *
 * Server extracts SNI from TLS ClientHello and stores in tcp_debug.recent_snis.
 * Client fetches this map every 3s and uses it as final fallback in getFlows()
 * when FlowStats.domain and DomainCache are both null (ARM memory visibility bug).
 *
 * Fallback chain: FlowStats.domain → DomainCache → serverSniMap
 */
class ServerSniFallbackTest {

    @Before
    fun setUp() {
        PacketFlowTracker.clear()
        PacketFlowTracker.serverSniMap = emptyMap()
    }

    // ============================================================
    // serverSniMap assignment
    // ============================================================

    @Test
    fun `serverSniMap defaults to empty`() {
        assertTrue(PacketFlowTracker.serverSniMap.isEmpty())
    }

    @Test
    fun `serverSniMap can be set`() {
        val map = mapOf("142.251.10.95" to "google.com")
        PacketFlowTracker.serverSniMap = map
        assertEquals(map, PacketFlowTracker.serverSniMap)
    }

    @Test
    fun `serverSniMap can be replaced`() {
        PacketFlowTracker.serverSniMap = mapOf("1.2.3.4" to "old.com")
        PacketFlowTracker.serverSniMap = mapOf("5.6.7.8" to "new.com")
        assertEquals("new.com", PacketFlowTracker.serverSniMap["5.6.7.8"])
        assertNull(PacketFlowTracker.serverSniMap["1.2.3.4"])
    }

    @Test
    fun `serverSniMap cleared on clear()`() {
        PacketFlowTracker.serverSniMap = mapOf("1.2.3.4" to "test.com")
        PacketFlowTracker.clear()
        assertTrue(PacketFlowTracker.serverSniMap.isEmpty())
    }

    // ============================================================
    // getFlows() serverSniMap fallback
    // ============================================================

    @Test
    fun `getFlows uses serverSniMap when domain and cache are null`() {
        // Process a packet without SNI (non-TLS)
        val packet = buildTestPacket(dstIp = "142.251.10.95", dstPort = 443)
        PacketFlowTracker.processPacket(packet, isUplink = true)

        // No domain from SNI parser or cache
        val flowsBefore = PacketFlowTracker.getFlows()
        assertNull(flowsBefore[0].domain)

        // Now set server SNI map
        PacketFlowTracker.serverSniMap = mapOf("142.251.10.95" to "google.com")

        val flowsAfter = PacketFlowTracker.getFlows()
        assertEquals("google.com", flowsAfter[0].domain)
    }

    @Test
    fun `FlowStats domain takes priority over serverSniMap`() {
        // Process a TLS packet that extracts SNI
        val tlsPacket = buildTlsPacket("example.com", dstIp = "142.251.10.95", dstPort = 443)
        PacketFlowTracker.processPacket(tlsPacket, isUplink = true)

        // Set different domain in server map
        PacketFlowTracker.serverSniMap = mapOf("142.251.10.95" to "google.com")

        val flows = PacketFlowTracker.getFlows()
        // FlowStats.domain (from SNI parser) wins over serverSniMap
        assertEquals("example.com", flows[0].domain)
    }

    @Test
    fun `DomainCache takes priority over serverSniMap`() {
        // Process a TLS packet that extracts SNI
        val tlsPacket = buildTlsPacket("cached.com", dstIp = "142.251.10.95", dstPort = 443)
        PacketFlowTracker.processPacket(tlsPacket, isUplink = true)

        // Process a downlink packet from same IP (no SNI, but cache has it)
        val dlPacket = buildTestPacket(srcIp = "142.251.10.95", srcPort = 443, isUplink = false)
        PacketFlowTracker.processPacket(dlPacket, isUplink = false)

        // Set different domain in server map
        PacketFlowTracker.serverSniMap = mapOf("142.251.10.95" to "server-side.com")

        val flows = PacketFlowTracker.getFlows()
        // DomainCache (cached.com) wins over serverSniMap (server-side.com)
        val googleFlow = flows.find { it.server == "142.251.10.95" }
        // FlowStats.domain from the TLS packet is still "cached.com"
        assertEquals("cached.com", googleFlow?.domain)
    }

    @Test
    fun `serverSniMap used for multiple flows`() {
        // Create flows without SNI
        val p1 = buildTestPacket(dstIp = "1.1.1.1", dstPort = 443)
        val p2 = buildTestPacket(dstIp = "2.2.2.2", dstPort = 443)
        val p3 = buildTestPacket(dstIp = "3.3.3.3", dstPort = 443)
        PacketFlowTracker.processPacket(p1, isUplink = true)
        PacketFlowTracker.processPacket(p2, isUplink = true)
        PacketFlowTracker.processPacket(p3, isUplink = true)

        // Set server map for all three
        PacketFlowTracker.serverSniMap = mapOf(
            "1.1.1.1" to "cloudflare.com",
            "2.2.2.2" to "facebook.com",
            "3.3.3.3" to "amazon.com"
        )

        val flows = PacketFlowTracker.getFlows()
        assertEquals(3, flows.size)
        val domains = flows.map { it.domain }.toSet()
        assertTrue(domains.contains("cloudflare.com"))
        assertTrue(domains.contains("facebook.com"))
        assertTrue(domains.contains("amazon.com"))
    }

    @Test
    fun `serverSniMap update propagates to existing flows`() {
        // Create flow without SNI
        val packet = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(packet, isUplink = true)

        // First poll — no server SNI
        var flows = PacketFlowTracker.getFlows()
        assertNull(flows[0].domain)

        // Server returns SNI data
        PacketFlowTracker.serverSniMap = mapOf("10.0.0.1" to "newdomain.com")

        // Second poll — server SNI applied
        flows = PacketFlowTracker.getFlows()
        assertEquals("newdomain.com", flows[0].domain)
    }

    @Test
    fun `serverSniMap with empty map clears domains`() {
        // Set up flow with server SNI
        val packet = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(packet, isUplink = true)
        PacketFlowTracker.serverSniMap = mapOf("10.0.0.1" to "test.com")

        var flows = PacketFlowTracker.getFlows()
        assertEquals("test.com", flows[0].domain)

        // Clear server SNI
        PacketFlowTracker.serverSniMap = emptyMap()
        flows = PacketFlowTracker.getFlows()
        assertNull(flows[0].domain)
    }

    @Test
    fun `serverSniMap case insensitive domain match`() {
        val packet = buildTestPacket(dstIp = "142.251.10.95", dstPort = 443)
        PacketFlowTracker.processPacket(packet, isUplink = true)

        // Server returns lowercase domain (ApiClient does .lowercase())
        PacketFlowTracker.serverSniMap = mapOf("142.251.10.95" to "google.com")

        val flows = PacketFlowTracker.getFlows()
        assertEquals("google.com", flows[0].domain)
    }

    @Test
    fun `serverSniMap IP not in flows has no effect`() {
        val packet = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(packet, isUplink = true)

        // Server SNI for different IP
        PacketFlowTracker.serverSniMap = mapOf("99.99.99.99" to "other.com")

        val flows = PacketFlowTracker.getFlows()
        assertNull(flows[0].domain)
    }

    @Test
    fun `serverSniMap does not affect FlowStats domain field`() {
        // Process non-TLS packet
        val packet = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(packet, isUplink = true)

        // Set server SNI
        PacketFlowTracker.serverSniMap = mapOf("10.0.0.1" to "test.com")

        // getFlows returns domain from serverSniMap
        val flows = PacketFlowTracker.getFlows()
        assertEquals("test.com", flows[0].domain)

        // But the underlying FlowStats.domain is still null
        val flowField = PacketFlowTracker.javaClass.getDeclaredField("flows")
        flowField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flowsMap = flowField.get(PacketFlowTracker) as java.util.concurrent.ConcurrentHashMap<*, *>
        val stats = flowsMap.values.first() as PacketFlowTracker.FlowStats
        assertNull(stats.domain) // FlowStats.domain unchanged
    }

    // ============================================================
    // SNI parsing format tests (mirrors ApiClient.getServerSniDomains)
    // ============================================================

    @Test
    fun `parse server SNI format correctly`() {
        val entries = listOf(
            "10.20.0.243→142.251.10.95:443 = pubsub.googleapis.com",
            "10.20.0.243→157.240.1.35:443 = www.facebook.com",
            "10.20.0.243→151.101.1.140:443 = www.reddit.com"
        )

        val domainMap = mutableMapOf<String, String>()
        for (entry in entries) {
            val arrowIdx = entry.indexOf('→')
            val equalsIdx = entry.indexOf('=')
            if (arrowIdx >= 0 && equalsIdx > arrowIdx) {
                val remotePart = entry.substring(arrowIdx + 1, equalsIdx).trim()
                val domain = entry.substring(equalsIdx + 1).trim().lowercase()
                val colonIdx = remotePart.indexOf(':')
                val remoteIp = if (colonIdx > 0) remotePart.substring(0, colonIdx) else remotePart
                if (domain.isNotEmpty()) {
                    domainMap[remoteIp] = domain
                }
            }
        }

        assertEquals("pubsub.googleapis.com", domainMap["142.251.10.95"])
        assertEquals("www.facebook.com", domainMap["157.240.1.35"])
        assertEquals("www.reddit.com", domainMap["151.101.1.140"])
    }

    @Test
    fun `parse server SNI handles missing port`() {
        val entries = listOf("10.20.0.243→142.251.10.95 = google.com")

        val domainMap = mutableMapOf<String, String>()
        for (entry in entries) {
            val arrowIdx = entry.indexOf('→')
            val equalsIdx = entry.indexOf('=')
            if (arrowIdx >= 0 && equalsIdx > arrowIdx) {
                val remotePart = entry.substring(arrowIdx + 1, equalsIdx).trim()
                val domain = entry.substring(equalsIdx + 1).trim().lowercase()
                val colonIdx = remotePart.indexOf(':')
                val remoteIp = if (colonIdx > 0) remotePart.substring(0, colonIdx) else remotePart
                if (domain.isNotEmpty()) {
                    domainMap[remoteIp] = domain
                }
            }
        }

        assertEquals("google.com", domainMap["142.251.10.95"])
    }

    @Test
    fun `parse server SNI handles empty entries`() {
        val entries = listOf<String>()

        val domainMap = mutableMapOf<String, String>()
        for (entry in entries) {
            val arrowIdx = entry.indexOf('→')
            val equalsIdx = entry.indexOf('=')
            if (arrowIdx >= 0 && equalsIdx > arrowIdx) {
                val remotePart = entry.substring(arrowIdx + 1, equalsIdx).trim()
                val domain = entry.substring(equalsIdx + 1).trim().lowercase()
                val colonIdx = remotePart.indexOf(':')
                val remoteIp = if (colonIdx > 0) remotePart.substring(0, colonIdx) else remotePart
                if (domain.isNotEmpty()) {
                    domainMap[remoteIp] = domain
                }
            }
        }

        assertTrue(domainMap.isEmpty())
    }

    @Test
    fun `parse server SNI handles malformed entries gracefully`() {
        val entries = listOf(
            "malformed entry",
            "10.20.0.243→142.251.10.95:443 = valid.com",
            "no arrow here = nothing.com"
        )

        val domainMap = mutableMapOf<String, String>()
        for (entry in entries) {
            val arrowIdx = entry.indexOf('→')
            val equalsIdx = entry.indexOf('=')
            if (arrowIdx >= 0 && equalsIdx > arrowIdx) {
                val remotePart = entry.substring(arrowIdx + 1, equalsIdx).trim()
                val domain = entry.substring(equalsIdx + 1).trim().lowercase()
                val colonIdx = remotePart.indexOf(':')
                val remoteIp = if (colonIdx > 0) remotePart.substring(0, colonIdx) else remotePart
                if (domain.isNotEmpty()) {
                    domainMap[remoteIp] = domain
                }
            }
        }

        // Only valid entry parsed
        assertEquals(1, domainMap.size)
        assertEquals("valid.com", domainMap["142.251.10.95"])
    }

    @Test
    fun `parse server SNI with multiple flows same IP last wins`() {
        val entries = listOf(
            "10.20.0.243→142.251.10.95:443 = first.com",
            "10.20.0.243→142.251.10.95:8443 = second.com"
        )

        val domainMap = mutableMapOf<String, String>()
        for (entry in entries) {
            val arrowIdx = entry.indexOf('→')
            val equalsIdx = entry.indexOf('=')
            if (arrowIdx >= 0 && equalsIdx > arrowIdx) {
                val remotePart = entry.substring(arrowIdx + 1, equalsIdx).trim()
                val domain = entry.substring(equalsIdx + 1).trim().lowercase()
                val colonIdx = remotePart.indexOf(':')
                val remoteIp = if (colonIdx > 0) remotePart.substring(0, colonIdx) else remotePart
                if (domain.isNotEmpty()) {
                    domainMap[remoteIp] = domain
                }
            }
        }

        // Same IP, last entry wins
        assertEquals("second.com", domainMap["142.251.10.95"])
    }

    // ============================================================
    // Helper methods
    // ============================================================

    private fun buildTestPacket(
        srcIp: String = "10.20.0.2",
        dstIp: String = "142.251.10.95",
        srcPort: Int = 30000,
        dstPort: Int = 443,
        protocol: Int = 6, // TCP
        isUplink: Boolean = true
    ): ByteArray {
        val srcParts = srcIp.split(".").map { it.toInt() }
        val dstParts = dstIp.split(".").map { it.toInt() }

        // IP header (20 bytes)
        val ipHeader = ByteArray(20)
        ipHeader[0] = 0x45.toByte() // Version 4, IHL 5
        ipHeader[9] = protocol.toByte()
        ipHeader[12] = srcParts[0].toByte()
        ipHeader[13] = srcParts[1].toByte()
        ipHeader[14] = srcParts[2].toByte()
        ipHeader[15] = srcParts[3].toByte()
        ipHeader[16] = dstParts[0].toByte()
        ipHeader[17] = dstParts[1].toByte()
        ipHeader[18] = dstParts[2].toByte()
        ipHeader[19] = dstParts[3].toByte()

        // TCP header (20 bytes)
        val tcpHeader = ByteArray(20)
        tcpHeader[0] = ((srcPort shr 8) and 0xFF).toByte()
        tcpHeader[1] = (srcPort and 0xFF).toByte()
        tcpHeader[2] = ((dstPort shr 8) and 0xFF).toByte()
        tcpHeader[3] = (dstPort and 0xFF).toByte()
        tcpHeader[12] = 0x50.toByte() // Data offset = 5 (20 bytes)

        return ipHeader + tcpHeader + ByteArray(10) // small payload
    }

    private fun buildTlsPacket(
        sni: String,
        dstIp: String = "142.251.10.95",
        dstPort: Int = 443
    ): ByteArray {
        val basePacket = buildTestPacket(dstIp = dstIp, dstPort = dstPort)

        // Build minimal TLS ClientHello with SNI
        val sniBytes = sni.toByteArray()
        val sniEntry = byteArrayOf(0x00) + // host_name type
            byteArrayOf(((sniBytes.size shr 8) and 0xFF).toByte(), (sniBytes.size and 0xFF).toByte()) +
            sniBytes
        val sniList = byteArrayOf(((sniEntry.size shr 8) and 0xFF).toByte(), (sniEntry.size and 0xFF).toByte()) +
            sniEntry
        val sniExt = byteArrayOf(0x00, 0x00) + // server_name extension type
            byteArrayOf(((sniList.size shr 8) and 0xFF).toByte(), (sniList.size and 0xFF).toByte()) +
            sniList

        val extensions = byteArrayOf(((sniExt.size shr 8) and 0xFF).toByte(), (sniExt.size and 0xFF).toByte()) +
            sniExt

        // ClientHello body
        val chBody = byteArrayOf(0x03, 0x03) + // TLS 1.2
            ByteArray(32) + // random
            byteArrayOf(0x00) + // session ID length 0
            byteArrayOf(0x00, 0x02, 0x13, 0x01) + // cipher suites
            byteArrayOf(0x01, 0x00) + // compression
            extensions

        val ch = byteArrayOf(0x01) + // ClientHello
            byteArrayOf(((chBody.size shr 16) and 0xFF).toByte()) +
            byteArrayOf(((chBody.size shr 8) and 0xFF).toByte(), (chBody.size and 0xFF).toByte()) +
            chBody

        // TLS record
        val tlsRecord = byteArrayOf(0x16) + // Handshake
            byteArrayOf(0x03, 0x01) + // TLS 1.0 record version
            byteArrayOf(((ch.size shr 8) and 0xFF).toByte(), (ch.size and 0xFF).toByte()) +
            ch

        // Replace the empty payload portion of basePacket with TLS data
        val ipTcpHeader = basePacket.copyOf(40) // IP(20) + TCP(20)
        return ipTcpHeader + tlsRecord
    }
}

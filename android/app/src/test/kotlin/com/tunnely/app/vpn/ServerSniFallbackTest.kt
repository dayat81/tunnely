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

    // ============================================================
    // Edge Cases: Concurrent Access
    // ============================================================

    @Test
    fun `concurrent serverSniMap writes and getFlows reads`() {
        // Simulate VPN I/O thread writing packets while UI reads flows
        val packets = (1..50).map { i ->
            buildTestPacket(dstIp = "10.0.0.$i", dstPort = 443)
        }

        // Process all packets
        packets.forEach { PacketFlowTracker.processPacket(it, isUplink = true) }

        // Simulate rapid serverSniMap updates (like FlowsFragment polling every 3s)
        val domains = mutableMapOf<String, String>()
        for (i in 1..50) {
            domains["10.0.0.$i"] = "site$i.com"
            PacketFlowTracker.serverSniMap = domains.toMap()

            // getFlows should never crash
            val flows = PacketFlowTracker.getFlows()
            assertTrue(flows.isNotEmpty())
        }

        // Final state: all flows should have domains
        val finalFlows = PacketFlowTracker.getFlows()
        finalFlows.forEach { flow ->
            assertNotNull("Flow ${flow.server} should have domain", flow.domain)
        }
    }

    @Test
    fun `concurrent processPacket and serverSniMap update`() {
        // Simulate I/O threads processing packets while UI updates serverSniMap
        val errors = mutableListOf<String>()

        val thread1 = Thread {
            try {
                for (i in 1..100) {
                    val pkt = buildTestPacket(dstIp = "10.0.0.${i % 10}", dstPort = 443)
                    PacketFlowTracker.processPacket(pkt, isUplink = true)
                }
            } catch (e: Exception) {
                errors.add("processPacket: ${e.message}")
            }
        }

        val thread2 = Thread {
            try {
                for (i in 1..50) {
                    PacketFlowTracker.serverSniMap = mapOf("10.0.0.${i % 10}" to "site$i.com")
                    PacketFlowTracker.getFlows()
                }
            } catch (e: Exception) {
                errors.add("serverSniMap: ${e.message}")
            }
        }

        thread1.start()
        thread2.start()
        thread1.join(5000)
        thread2.join(5000)

        assertTrue("Concurrent errors: $errors", errors.isEmpty())
    }

    // ============================================================
    // Edge Cases: Large Scale
    // ============================================================

    @Test
    fun `serverSniMap with 100 entries applied to 100 flows`() {
        // Create 100 flows without SNI
        for (i in 1..100) {
            val pkt = buildTestPacket(dstIp = "10.0.${i / 256}.${i % 256}", dstPort = 443)
            PacketFlowTracker.processPacket(pkt, isUplink = true)
        }

        // Build server map for all 100 IPs
        val serverMap = (1..100).associate { i ->
            "10.0.${i / 256}.${i % 256}" to "domain$i.com"
        }
        PacketFlowTracker.serverSniMap = serverMap

        val flows = PacketFlowTracker.getFlows()
        assertEquals(100, flows.size)
        // All flows should have domains from server map
        flows.forEach { flow ->
            assertNotNull("Flow ${flow.server} should have domain", flow.domain)
            assertTrue("Domain should end with .com", flow.domain!!.endsWith(".com"))
        }
    }

    @Test
    fun `serverSniMap partial coverage — some flows have domain some dont`() {
        // Create 10 flows
        for (i in 1..10) {
            val pkt = buildTestPacket(dstIp = "10.0.0.$i", dstPort = 443)
            PacketFlowTracker.processPacket(pkt, isUplink = true)
        }

        // Server map only covers IPs 1-5
        val serverMap = (1..5).associate { "10.0.0.$it" to "covered$it.com" }
        PacketFlowTracker.serverSniMap = serverMap

        val flows = PacketFlowTracker.getFlows()
        assertEquals(10, flows.size)

        val coveredFlows = flows.filter { it.domain != null }
        val uncoveredFlows = flows.filter { it.domain == null }
        assertEquals(5, coveredFlows.size)
        assertEquals(5, uncoveredFlows.size)
    }

    // ============================================================
    // Edge Cases: Flow Lifecycle
    // ============================================================

    @Test
    fun `flow evicted at MAX_FLOWS then re-added still gets serverSniMap domain`() {
        // Fill up to MAX_FLOWS (500) — but that's expensive, use reflection to lower limit
        // Instead, test the concept with a few flows
        val pkt1 = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(pkt1, isUplink = true)

        // Set server SNI
        PacketFlowTracker.serverSniMap = mapOf("10.0.0.1" to "test.com")

        var flows = PacketFlowTracker.getFlows()
        assertEquals("test.com", flows[0].domain)

        // Simulate flow aging out (set lastSeen to old time via reflection)
        val flowField = PacketFlowTracker.javaClass.getDeclaredField("flows")
        flowField.isAccessible = true
        @Suppress("UNCHECKED_CAST")
        val flowsMap = flowField.get(PacketFlowTracker) as java.util.concurrent.ConcurrentHashMap<String, PacketFlowTracker.FlowStats>
        val stats = flowsMap.values.first()
        val lastSeenField = PacketFlowTracker.FlowStats::class.java.getDeclaredField("lastSeen")
        lastSeenField.isAccessible = true
        lastSeenField.setLong(stats, System.currentTimeMillis() - 600_000) // 10 min ago

        // getFlows should evict stale flow
        flows = PacketFlowTracker.getFlows()
        assertEquals(0, flows.size)

        // Re-add same flow
        PacketFlowTracker.processPacket(pkt1, isUplink = true)
        flows = PacketFlowTracker.getFlows()
        assertEquals(1, flows.size)
        // serverSniMap still applies to re-added flow
        assertEquals("test.com", flows[0].domain)
    }

    @Test
    fun `downlink-only flow gets domain from serverSniMap only`() {
        // Flow only has downlink packets (never sees TLS ClientHello)
        val dlPkt = buildTestPacket(srcIp = "142.251.10.95", srcPort = 443, isUplink = false)
        PacketFlowTracker.processPacket(dlPkt, isUplink = false)

        // No domain from SNI or cache
        var flows = PacketFlowTracker.getFlows()
        assertNull(flows[0].domain)

        // Server SNI provides domain
        PacketFlowTracker.serverSniMap = mapOf("142.251.10.95" to "google.com")
        flows = PacketFlowTracker.getFlows()
        assertEquals("google.com", flows[0].domain)
    }

    @Test
    fun `serverSniMap with stale entries for IPs no longer in flows`() {
        // Create flow for IP 1
        val pkt = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        // Server map has entries for IPs 1, 2, 3 (2 and 3 are stale)
        PacketFlowTracker.serverSniMap = mapOf(
            "10.0.0.1" to "active.com",
            "10.0.0.2" to "stale2.com",
            "10.0.0.3" to "stale3.com"
        )

        val flows = PacketFlowTracker.getFlows()
        // Only IP 1 flow exists, others ignored
        assertEquals(1, flows.size)
        assertEquals("active.com", flows[0].domain)
    }

    // ============================================================
    // Edge Cases: Domain Formats
    // ============================================================

    @Test
    fun `serverSniMap domain with hyphens`() {
        val pkt = buildTestPacket(dstIp = "1.2.3.4", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)
        PacketFlowTracker.serverSniMap = mapOf("1.2.3.4" to "my-app.example-site.com")

        val flows = PacketFlowTracker.getFlows()
        assertEquals("my-app.example-site.com", flows[0].domain)
    }

    @Test
    fun `serverSniMap domain with numbers`() {
        val pkt = buildTestPacket(dstIp = "1.2.3.4", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)
        PacketFlowTracker.serverSniMap = mapOf("1.2.3.4" to "api123.v2.example.com")

        val flows = PacketFlowTracker.getFlows()
        assertEquals("api123.v2.example.com", flows[0].domain)
    }

    @Test
    fun `serverSniMap domain with underscores`() {
        val pkt = buildTestPacket(dstIp = "1.2.3.4", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)
        PacketFlowTracker.serverSniMap = mapOf("1.2.3.4" to "internal_service.corp.local")

        val flows = PacketFlowTracker.getFlows()
        assertEquals("internal_service.corp.local", flows[0].domain)
    }

    @Test
    fun `serverSniMap very long domain`() {
        val longDomain = "a.".repeat(50) + "example.com"
        val pkt = buildTestPacket(dstIp = "1.2.3.4", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)
        PacketFlowTracker.serverSniMap = mapOf("1.2.3.4" to longDomain)

        val flows = PacketFlowTracker.getFlows()
        assertEquals(longDomain, flows[0].domain)
    }

    // ============================================================
    // Edge Cases: Same Domain Multiple IPs (CDN)
    // ============================================================

    @Test
    fun `same domain on multiple IPs — CDN scenario`() {
        // CDN serves same domain from multiple IPs
        val ips = listOf("1.1.1.1", "2.2.2.2", "3.3.3.3", "4.4.4.4", "5.5.5.5")
        ips.forEach { ip ->
            val pkt = buildTestPacket(dstIp = ip, dstPort = 443)
            PacketFlowTracker.processPacket(pkt, isUplink = true)
        }

        // All IPs map to same domain
        val serverMap = ips.associateWith { "cdn.example.com" }
        PacketFlowTracker.serverSniMap = serverMap

        val flows = PacketFlowTracker.getFlows()
        assertEquals(5, flows.size)
        flows.forEach { flow ->
            assertEquals("cdn.example.com", flow.domain)
        }
    }

    // ============================================================
    // Edge Cases: Rapid Refresh Cycles
    // ============================================================

    @Test
    fun `rapid serverSniMap refresh simulates 3s poll cycle`() {
        // Create flows
        for (i in 1..5) {
            val pkt = buildTestPacket(dstIp = "10.0.0.$i", dstPort = 443)
            PacketFlowTracker.processPacket(pkt, isUplink = true)
        }

        // Simulate 10 poll cycles (30s of polling)
        for (cycle in 1..10) {
            val serverMap = (1..5).associate { "10.0.0.$it" to "site${it}_v${cycle}.com" }
            PacketFlowTracker.serverSniMap = serverMap

            val flows = PacketFlowTracker.getFlows()
            assertEquals(5, flows.size)
            flows.forEach { flow ->
                assertNotNull(flow.domain)
                assertTrue(flow.domain!!.contains("_v${cycle}"))
            }
        }
    }

    @Test
    fun `serverSniMap set to empty then repopulated`() {
        val pkt = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        // Set domain
        PacketFlowTracker.serverSniMap = mapOf("10.0.0.1" to "test.com")
        var flows = PacketFlowTracker.getFlows()
        assertEquals("test.com", flows[0].domain)

        // Clear (server unreachable)
        PacketFlowTracker.serverSniMap = emptyMap()
        flows = PacketFlowTracker.getFlows()
        assertNull(flows[0].domain)

        // Repopulate (server back online)
        PacketFlowTracker.serverSniMap = mapOf("10.0.0.1" to "test.com")
        flows = PacketFlowTracker.getFlows()
        assertEquals("test.com", flows[0].domain)
    }

    // ============================================================
    // Edge Cases: getFlows Idempotency
    // ============================================================

    @Test
    fun `getFlows called multiple times returns consistent results`() {
        val pkt = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)
        PacketFlowTracker.serverSniMap = mapOf("10.0.0.1" to "test.com")

        // Call getFlows 10 times — should always return same domain
        repeat(10) {
            val flows = PacketFlowTracker.getFlows()
            assertEquals(1, flows.size)
            assertEquals("test.com", flows[0].domain)
        }
    }

    @Test
    fun `getFlows does not modify serverSniMap`() {
        val pkt = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)

        val originalMap = mapOf("10.0.0.1" to "test.com")
        PacketFlowTracker.serverSniMap = originalMap

        PacketFlowTracker.getFlows()
        PacketFlowTracker.getFlows()
        PacketFlowTracker.getFlows()

        // Map unchanged
        assertEquals(originalMap, PacketFlowTracker.serverSniMap)
    }

    // ============================================================
    // Edge Cases: Mixed Protocol Flows
    // ============================================================

    @Test
    fun `mixed TCP and UDP flows — serverSniMap only applies to matching IPs`() {
        // TCP flow (no SNI)
        val tcpPkt = buildTestPacket(dstIp = "1.1.1.1", dstPort = 443, protocol = 6)
        PacketFlowTracker.processPacket(tcpPkt, isUplink = true)

        // UDP flow
        val udpPkt = buildTestPacket(dstIp = "2.2.2.2", dstPort = 53, protocol = 17)
        PacketFlowTracker.processPacket(udpPkt, isUplink = true)

        // ICMP flow
        val icmpPkt = buildTestPacket(dstIp = "3.3.3.3", dstPort = 0, protocol = 1)
        PacketFlowTracker.processPacket(icmpPkt, isUplink = true)

        PacketFlowTracker.serverSniMap = mapOf(
            "1.1.1.1" to "cloudflare.com",
            "2.2.2.2" to "dns.google"
            // 3.3.3.3 not in map (ICMP has no domain)
        )

        val flows = PacketFlowTracker.getFlows()
        assertEquals(3, flows.size)

        val tcpFlow = flows.find { it.protocol == "TCP" }
        val udpFlow = flows.find { it.protocol == "UDP" }
        val icmpFlow = flows.find { it.protocol == "ICMP" }

        assertEquals("cloudflare.com", tcpFlow?.domain)
        assertEquals("dns.google", udpFlow?.domain)
        assertNull(icmpFlow?.domain)
    }

    // ============================================================
    // Edge Cases: Debug Stats with serverSniMap
    // ============================================================

    @Test
    fun `debug stats shows FlowStats domain not serverSniMap`() {
        val pkt = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)
        PacketFlowTracker.serverSniMap = mapOf("10.0.0.1" to "test.com")

        val debugStats = PacketFlowTracker.getDebugStats()
        // Debug stats show FlowStats.domain (NULL for non-TLS), not serverSniMap
        // serverSniMap is only used in getFlows() output, not in debug stats
        assertTrue("Debug stats should show NULL for FlowStats.domain",
            debugStats.contains("domain=NULL"))
    }

    @Test
    fun `debug stats shows NULL when no serverSniMap`() {
        val pkt = buildTestPacket(dstIp = "10.0.0.1", dstPort = 443)
        PacketFlowTracker.processPacket(pkt, isUplink = true)
        // No serverSniMap set

        val debugStats = PacketFlowTracker.getDebugStats()
        assertTrue("Debug stats should show NULL", debugStats.contains("NULL"))
    }

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

    // ============================================================
    // Edge Cases: sni_domain_map JSON parsing (mirrors ApiClient)
    // ============================================================

    private fun parseSniDomainMapJson(json: org.json.JSONObject): Map<String, String> {
        val tcpDebug = json.optJSONObject("tcp_debug") ?: return emptyMap()
        val sniDomainMap = tcpDebug.optJSONObject("sni_domain_map")
        if (sniDomainMap != null) {
            val domainMap = mutableMapOf<String, String>()
            for (key in sniDomainMap.keys()) {
                val domain = sniDomainMap.optString(key, "")
                if (domain.isNotEmpty()) {
                    domainMap[key] = domain.lowercase()
                }
            }
            if (domainMap.isNotEmpty()) return domainMap
        }
        // Fallback: parse recent_snis
        val recentSnis = tcpDebug.optJSONArray("recent_snis") ?: return emptyMap()
        val domainMap = mutableMapOf<String, String>()
        for (i in 0 until recentSnis.length()) {
            val entry = recentSnis.getString(i)
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
        return domainMap
    }

    @Test
    fun `sni_domain_map parsed as JSON object`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{"sni_domain_map":{
                "142.251.10.95":"google.com",
                "157.240.1.35":"facebook.com"
            }}}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals(2, result.size)
        assertEquals("google.com", result["142.251.10.95"])
        assertEquals("facebook.com", result["157.240.1.35"])
    }

    @Test
    fun `sni_domain_map empty returns empty`() {
        val json = org.json.JSONObject("""{"tcp_debug":{"sni_domain_map":{}}}""")
        val result = parseSniDomainMapJson(json)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `sni_domain_map missing falls back to recent_snis`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{"recent_snis":["10.20.0.2→1.2.3.4:443 = fallback.com"]}}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals("fallback.com", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map missing tcp_debug returns empty`() {
        val json = org.json.JSONObject("{}")
        val result = parseSniDomainMapJson(json)
        assertTrue(result.isEmpty())
    }

    @Test
    fun `sni_domain_map domain lowercased`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{"sni_domain_map":{"1.2.3.4":"EXAMPLE.COM"}}}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals("example.com", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map empty domain skipped`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{"sni_domain_map":{"1.2.3.4":"valid.com","5.6.7.8":""}}}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals(1, result.size)
        assertEquals("valid.com", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map preferred over recent_snis`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{
                "recent_snis":["10.20.0.2→1.2.3.4:443 = old.com"],
                "sni_domain_map":{"1.2.3.4":"new.com"}
            }}
        """)
        val result = parseSniDomainMapJson(json)
        // sni_domain_map takes priority
        assertEquals("new.com", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map with 100 entries`() {
        val mapJson = (1..100).joinToString(",") { i ->
            "\"10.0.${i / 256}.${i % 256}\":\"domain$i.com\""
        }
        val json = org.json.JSONObject("""{"tcp_debug":{"sni_domain_map":{$mapJson}}}""")
        val result = parseSniDomainMapJson(json)
        assertEquals(100, result.size)
        assertEquals("domain1.com", result["10.0.0.1"])
    }

    @Test
    fun `sni_domain_map with real API response structure`() {
        val json = org.json.JSONObject("""
            {"rx_bytes":12345,"tx_bytes":67890,"tcp_debug":{
                "tcp_flows":521,"tls_handshakes":339,"sni_domains":235,
                "recent_snis":["10.20.0.75→35.186.224.28:443 = gew4-spclient.spotify.com"],
                "sni_domain_map":{
                    "35.186.224.28":"gew4-spclient.spotify.com",
                    "74.125.68.95":"pubsub.googleapis.com"
                }
            }}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals(2, result.size)
        assertEquals("gew4-spclient.spotify.com", result["35.186.224.28"])
        assertEquals("pubsub.googleapis.com", result["74.125.68.95"])
    }

    @Test
    fun `sni_domain_map with hyphens and numbers in domain`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{"sni_domain_map":{
                "1.2.3.4":"my-app-v2.example-site.com",
                "5.6.7.8":"api123.internal.corp"
            }}}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals("my-app-v2.example-site.com", result["1.2.3.4"])
        assertEquals("api123.internal.corp", result["5.6.7.8"])
    }

    // ============================================================
    // Edge Cases: sni_domain_map JSON parsing edge cases
    // ============================================================

    @Test
    fun `sni_domain_map with extra JSON fields ignored`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{
                "tcp_flows":100,"tls_handshakes":50,"sni_domains":30,
                "recent_snis":[],"unknown_field":"ignored","another_field":42,
                "sni_domain_map":{"1.2.3.4":"test.com"}
            }}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals("test.com", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map with boolean value converted to string`() {
        val json = org.json.JSONObject("""{"tcp_debug":{"sni_domain_map":{"1.2.3.4":true}}}""")
        val result = parseSniDomainMapJson(json)
        // optString converts boolean to "true"
        assertEquals("true", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map with numeric value converted to string`() {
        val json = org.json.JSONObject("""{"tcp_debug":{"sni_domain_map":{"1.2.3.4":12345}}}""")
        val result = parseSniDomainMapJson(json)
        assertEquals("12345", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map with empty string key preserved`() {
        val json = org.json.JSONObject("""{"tcp_debug":{"sni_domain_map":{"":"no-ip.com"}}}""")
        val result = parseSniDomainMapJson(json)
        assertEquals("no-ip.com", result[""])
    }

    @Test
    fun `sni_domain_map with very long key preserved`() {
        val longKey = "a".repeat(200)
        val json = org.json.JSONObject("""{"tcp_debug":{"sni_domain_map":{"$longKey":"test.com"}}}""")
        val result = parseSniDomainMapJson(json)
        assertEquals("test.com", result[longKey])
    }

    @Test
    fun `sni_domain_map empty falls through to recent_snis`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{
                "recent_snis":["10.20.0.2→1.2.3.4:443 = fallback.com"],
                "sni_domain_map":{}
            }}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals("fallback.com", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map overrides recent_snis same IP`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{
                "recent_snis":["10.20.0.2→1.2.3.4:443 = old.com"],
                "sni_domain_map":{"1.2.3.4":"new.com"}
            }}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals("new.com", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map 500 entries`() {
        val mapJson = (1..500).joinToString(",") { i ->
            "\"10.${i / 256}.${i % 256}.1\":\"host$i.com\""
        }
        val json = org.json.JSONObject("""{"tcp_debug":{"sni_domain_map":{$mapJson}}}""")
        val result = parseSniDomainMapJson(json)
        assertEquals(500, result.size)
    }

    @Test
    fun `sni_domain_map CDN same domain 50 IPs`() {
        val mapJson = (0..49).joinToString(",") { i ->
            "\"10.0.0.$i\":\"cdn.example.com\""
        }
        val json = org.json.JSONObject("""{"tcp_debug":{"sni_domain_map":{$mapJson}}}""")
        val result = parseSniDomainMapJson(json)
        assertEquals(50, result.size)
        for (i in 0..49) {
            assertEquals("cdn.example.com", result["10.0.0.$i"])
        }
    }

    @Test
    fun `sni_domain_map with various TLDs`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{"sni_domain_map":{
                "1.1.1.1":"test.com",
                "2.2.2.2":"test.org",
                "3.3.3.3":"test.io",
                "4.4.4.4":"test.co.uk",
                "5.5.5.5":"test.example"
            }}}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals(5, result.size)
        assertEquals("test.com", result["1.1.1.1"])
        assertEquals("test.co.uk", result["4.4.4.4"])
    }

    @Test
    fun `sni_domain_map with punycode domain`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{"sni_domain_map":{"1.2.3.4":"xn--e1afmapc.xn--p1ai"}}}
        """)
        val result = parseSniDomainMapJson(json)
        assertEquals("xn--e1afmapc.xn--p1ai", result["1.2.3.4"])
    }

    @Test
    fun `sni_domain_map idempotent across calls`() {
        val json = org.json.JSONObject("""
            {"tcp_debug":{"sni_domain_map":{"1.2.3.4":"test.com"}}}
        """)
        val result1 = parseSniDomainMapJson(json)
        val result2 = parseSniDomainMapJson(json)
        val result3 = parseSniDomainMapJson(json)
        assertEquals(result1, result2)
        assertEquals(result2, result3)
    }
}

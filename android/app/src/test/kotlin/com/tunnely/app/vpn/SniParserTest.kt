package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

/**
 * Unit tests for SNI parser.
 * Tests TLS ClientHello parsing and domain extraction.
 */
class SniParserTest {

    // ── Helper: Build TLS ClientHello with SNI ────────────────────

    private fun buildClientHelloWithSni(domain: String): ByteArray {
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
        record.put(0x00) // Length placeholder (3 bytes)
        record.putShort(0)
        
        // Client Version
        record.putShort(0x0303.toShort()) // TLS 1.2
        
        // Random (32 bytes)
        for (i in 0 until 32) record.put(0x42)
        
        // Session ID (0 length)
        record.put(0x00)
        
        // Cipher Suites (2 suites)
        record.putShort(4.toShort()) // Length
        record.putShort(0x1301.toShort()) // TLS_AES_128_GCM_SHA256
        record.putShort(0x1302.toShort()) // TLS_AES_256_GCM_SHA384
        
        // Compression Methods (null only)
        record.put(0x01) // Length
        record.put(0x00) // null compression
        
        // Extensions
        val extStartPos = record.position()
        record.putShort(0) // Extensions length placeholder
        
        // SNI Extension
        val sniExtPos = record.position()
        record.putShort(0x0000.toShort()) // Extension type: SNI
        val sniExtLenPos = record.position()
        record.putShort(0) // Extension length placeholder
        
        // SNI List
        val sniListLenPos = record.position()
        record.putShort(0) // List length placeholder
        
        // Server Name
        record.put(0x00) // Name type: host_name
        record.putShort(domainBytes.size.toShort()) // Name length
        record.put(domainBytes) // Name
        
        // Update SNI list length
        val sniListLen = (domainBytes.size + 3).toShort()
        record.putShort(sniListLenPos, sniListLen)
        
        // Update SNI extension length
        val sniExtLen = (domainBytes.size + 5).toShort()
        record.putShort(sniExtLenPos, sniExtLen)
        
        // Update extensions length
        val extLen = (domainBytes.size + 7).toShort()
        record.putShort(extStartPos, extLen)
        
        // Update handshake length
        val handshakeLen = record.position() - handshakeLenPos - 3
        record.put(handshakeLenPos, ((handshakeLen shr 16) and 0xFF).toByte())
        record.put(handshakeLenPos + 1, ((handshakeLen shr 8) and 0xFF).toByte())
        record.put(handshakeLenPos + 2, (handshakeLen and 0xFF).toByte())
        
        // Update record length
        val recordLen = (record.position() - recordLenPos - 2).toShort()
        record.putShort(recordLenPos, recordLen)
        
        // Create IP packet wrapper
        val payload = ByteArray(record.position())
        record.position(0)
        record.get(payload)
        
        // Build IP packet
        val ipPacket = ByteBuffer.allocate(20 + 20 + payload.size) // IP + TCP + payload
        
        // IP Header
        ipPacket.put(0x45) // Version 4, IHL 5
        ipPacket.put(0x00) // DSCP
        ipPacket.putShort((20 + 20 + payload.size).toShort()) // Total length
        ipPacket.putInt(0) // ID, flags, fragment
        ipPacket.put(0x40.toByte()) // TTL
        ipPacket.put(0x06) // Protocol: TCP
        ipPacket.putShort(0) // Checksum (don't care)
        ipPacket.put(byteArrayOf(10, 0, 0, 2)) // Source IP
        ipPacket.put(byteArrayOf(140.toByte(), 82, 121, 6)) // Dest IP (GitHub)
        
        // TCP Header
        ipPacket.putShort(12345.toShort()) // Source port
        ipPacket.putShort(443.toShort()) // Dest port (HTTPS)
        ipPacket.putInt(0) // Sequence number
        ipPacket.putInt(0) // Ack number
        ipPacket.put(0x50.toByte()) // Data offset: 5 (20 bytes)
        ipPacket.put(0x02) // Flags: SYN
        ipPacket.putShort(65535.toShort()) // Window
        ipPacket.putShort(0) // Checksum
        ipPacket.putShort(0) // Urgent pointer
        
        // Payload
        ipPacket.put(payload)
        
        return ipPacket.array()
    }

    private fun buildNonTlsPacket(): ByteArray {
        val packet = ByteBuffer.allocate(100)
        
        // IP Header
        packet.put(0x45)
        packet.put(0x00)
        packet.putShort(100.toShort())
        packet.putInt(0)
        packet.put(0x40.toByte())
        packet.put(0x06) // TCP
        packet.putShort(0)
        packet.put(byteArrayOf(10, 0, 0, 2))
        packet.put(byteArrayOf(140.toByte(), 82, 121, 6))
        
        // TCP Header
        packet.putShort(12345.toShort())
        packet.putShort(80.toShort()) // HTTP port
        packet.putInt(0)
        packet.putInt(0)
        packet.put(0x50.toByte())
        packet.put(0x10) // ACK
        packet.putShort(65535.toShort())
        packet.putShort(0)
        packet.putShort(0)
        
        // Non-TLS payload
        packet.put("GET / HTTP/1.1\r\n".toByteArray())
        
        return packet.array()
    }

    private fun buildUdpPacket(): ByteArray {
        val packet = ByteBuffer.allocate(50)
        
        // IP Header
        packet.put(0x45)
        packet.put(0x00)
        packet.putShort(50.toShort())
        packet.putInt(0)
        packet.put(0x40.toByte())
        packet.put(0x11) // UDP
        packet.putShort(0)
        packet.put(byteArrayOf(10, 0, 0, 2))
        packet.put(byteArrayOf(8, 8, 8, 8))
        
        // UDP Header
        packet.putShort(12345.toShort())
        packet.putShort(53.toShort())
        packet.putShort(30.toShort())
        packet.putShort(0)
        
        return packet.array()
    }

    private fun buildTlsServerHello(): ByteArray {
        val packet = ByteBuffer.allocate(100)
        
        // IP Header
        packet.put(0x45)
        packet.put(0x00)
        packet.putShort(100.toShort())
        packet.putInt(0)
        packet.put(0x40.toByte())
        packet.put(0x06) // TCP
        packet.putShort(0)
        packet.put(byteArrayOf(140.toByte(), 82, 121, 6))
        packet.put(byteArrayOf(10, 0, 0, 2))
        
        // TCP Header
        packet.putShort(443.toShort())
        packet.putShort(12345.toShort())
        packet.putInt(0)
        packet.putInt(0)
        packet.put(0x50.toByte())
        packet.put(0x10) // ACK
        packet.putShort(65535.toShort())
        packet.putShort(0)
        packet.putShort(0)
        
        // TLS ServerHello (not ClientHello)
        packet.put(0x16) // Handshake
        packet.putShort(0x0303.toShort()) // TLS 1.2
        packet.putShort(50.toShort()) // Length
        packet.put(0x02) // ServerHello (not ClientHello)
        
        return packet.array()
    }

    private fun buildIcmpPacket(): ByteArray {
        val packet = ByteBuffer.allocate(40)
        
        // IP Header
        packet.put(0x45)
        packet.put(0x00)
        packet.putShort(40.toShort())
        packet.putInt(0)
        packet.put(0x40.toByte())
        packet.put(0x01) // ICMP
        packet.putShort(0)
        packet.put(byteArrayOf(10, 0, 0, 2))
        packet.put(byteArrayOf(8, 8, 8, 8))
        
        // ICMP Header
        packet.put(0x08) // Echo request
        packet.put(0x00)
        packet.putShort(0) // Checksum
        packet.putShort(0) // ID
        packet.putShort(0) // Sequence
        
        return packet.array()
    }

    // ── SNI Parser Tests ───────────────────────────────────────────

    @Test
    fun `extract SNI from TLS ClientHello`() {
        val packet = buildClientHelloWithSni("api.github.com")
        val domain = SniParser.extractSni(packet)
        assertEquals("api.github.com", domain)
    }

    @Test
    fun `extract SNI with subdomain`() {
        val packet = buildClientHelloWithSni("cdn.jsdelivr.net")
        val domain = SniParser.extractSni(packet)
        assertEquals("cdn.jsdelivr.net", domain)
    }

    @Test
    fun `extract SNI with deep subdomain`() {
        val packet = buildClientHelloWithSni("v1.api.example.com")
        val domain = SniParser.extractSni(packet)
        assertEquals("v1.api.example.com", domain)
    }

    @Test
    fun `non-TLS packet returns null`() {
        val packet = buildNonTlsPacket()
        val domain = SniParser.extractSni(packet)
        assertNull(domain)
    }

    @Test
    fun `UDP packet returns null`() {
        val packet = buildUdpPacket()
        val domain = SniParser.extractSni(packet)
        assertNull(domain)
    }

    @Test
    fun `ICMP packet returns null`() {
        val packet = buildIcmpPacket()
        val domain = SniParser.extractSni(packet)
        assertNull(domain)
    }

    @Test
    fun `too short packet returns null`() {
        val packet = ByteArray(5)
        val domain = SniParser.extractSni(packet)
        assertNull(domain)
    }

    @Test
    fun `empty packet returns null`() {
        val packet = ByteArray(0)
        val domain = SniParser.extractSni(packet)
        assertNull(domain)
    }

    @Test
    fun `IPv6 packet returns null`() {
        val packet = ByteArray(40)
        packet[0] = 0x60.toByte() // IPv6
        val domain = SniParser.extractSni(packet)
        assertNull(domain)
    }

    @Test
    fun `TLS ServerHello returns null`() {
        val packet = buildTlsServerHello()
        val domain = SniParser.extractSni(packet)
        assertNull(domain) // ServerHello has no SNI
    }

    @Test
    fun `domain with hyphen`() {
        val packet = buildClientHelloWithSni("my-app.example.com")
        val domain = SniParser.extractSni(packet)
        assertEquals("my-app.example.com", domain)
    }

    @Test
    fun `domain with numbers`() {
        val packet = buildClientHelloWithSni("api2.example.com")
        val domain = SniParser.extractSni(packet)
        assertEquals("api2.example.com", domain)
    }

    @Test
    fun `single label domain`() {
        val packet = buildClientHelloWithSni("localhost")
        val domain = SniParser.extractSni(packet)
        assertEquals("localhost", domain)
    }

    @Test
    fun `long domain name`() {
        val longDomain = "a".repeat(63) + ".example.com" // Max label 63 chars
        val packet = buildClientHelloWithSni(longDomain)
        val domain = SniParser.extractSni(packet)
        assertEquals(longDomain, domain)
    }

    @Test
    fun `domain with max length`() {
        // Max domain length is 253 chars
        val maxDomain = "a".repeat(60) + "." + "b".repeat(60) + "." + "c".repeat(60) + ".com"
        val packet = buildClientHelloWithSni(maxDomain)
        val domain = SniParser.extractSni(packet)
        assertEquals(maxDomain, domain)
    }

    @Test
    fun `multiple packets same domain`() {
        // Same domain should extract consistently
        val packet1 = buildClientHelloWithSni("api.example.com")
        val packet2 = buildClientHelloWithSni("api.example.com")
        assertEquals(SniParser.extractSni(packet1), SniParser.extractSni(packet2))
    }

    @Test
    fun `multiple packets different domains`() {
        val packet1 = buildClientHelloWithSni("api.example.com")
        val packet2 = buildClientHelloWithSni("cdn.example.com")
        assertNotEquals(SniParser.extractSni(packet1), SniParser.extractSni(packet2))
    }

    @Test
    fun `IHL 5 parses correctly`() {
        // IHL=5 means 20 byte IP header (standard)
        val packet = buildClientHelloWithSni("example.com")
        val ihl = (packet[0].toInt() and 0x0F) * 4
        assertEquals(20, ihl)
        assertEquals("example.com", SniParser.extractSni(packet))
    }

    @Test
    fun `TCP data offset 5 parses correctly`() {
        // Data offset=5 means 20 byte TCP header (standard)
        val packet = buildClientHelloWithSni("example.com")
        val tcpHeaderStart = 20 // After IP header
        val dataOffset = ((packet[tcpHeaderStart + 12].toInt() and 0xF0) shr 4) * 4
        assertEquals(20, dataOffset)
    }

    // ── DomainCache Tests ──────────────────────────────────────────

    @Test
    fun `cache stores and retrieves domain`() {
        DomainCache.clear()
        DomainCache.putDomain("140.82.121.6", "api.github.com")
        assertEquals("api.github.com", DomainCache.getDomain("140.82.121.6"))
    }

    @Test
    fun `cache returns null for unknown IP`() {
        DomainCache.clear()
        assertNull(DomainCache.getDomain("1.2.3.4"))
    }

    @Test
    fun `cache normalizes to lowercase`() {
        DomainCache.clear()
        DomainCache.putDomain("1.2.3.4", "API.Example.COM")
        assertEquals("api.example.com", DomainCache.getDomain("1.2.3.4"))
    }

    @Test
    fun `cache overwrites existing entry`() {
        DomainCache.clear()
        DomainCache.putDomain("1.2.3.4", "old.example.com")
        DomainCache.putDomain("1.2.3.4", "new.example.com")
        assertEquals("new.example.com", DomainCache.getDomain("1.2.3.4"))
    }

    @Test
    fun `cache clear removes all entries`() {
        DomainCache.clear()
        DomainCache.putDomain("1.2.3.4", "example.com")
        DomainCache.clear()
        assertNull(DomainCache.getDomain("1.2.3.4"))
    }

    @Test
    fun `cache size reports correctly`() {
        DomainCache.clear()
        assertEquals(0, DomainCache.size())
        DomainCache.putDomain("1.2.3.4", "a.com")
        DomainCache.putDomain("5.6.7.8", "b.com")
        assertEquals(2, DomainCache.size())
    }

    @Test
    fun `cache LRU eviction at 1000 entries`() {
        DomainCache.clear()
        // Fill cache to capacity
        for (i in 1..1000) {
            DomainCache.putDomain("10.0.0.$i", "host$i.example.com")
        }
        assertEquals(1000, DomainCache.size())

        // Adding one more should evict oldest
        DomainCache.putDomain("10.0.1.1", "new.example.com")
        assertEquals(1000, DomainCache.size())
        assertEquals("new.example.com", DomainCache.getDomain("10.0.1.1"))
    }

    @Test
    fun `cache LRU evicts least recently used`() {
        DomainCache.clear()
        // Fill to 999
        for (i in 1..999) {
            DomainCache.putDomain("10.0.0.$i", "host$i.example.com")
        }
        
        // Access first entry to make it recently used
        DomainCache.getDomain("10.0.0.1")
        
        // Add 2 more entries (total 1001, should evict 10.0.0.2)
        DomainCache.putDomain("10.0.1.1", "new1.example.com")
        DomainCache.putDomain("10.0.1.2", "new2.example.com")
        
        assertEquals(1000, DomainCache.size())
        // 10.0.0.1 should still exist (recently accessed)
        assertNotNull(DomainCache.getDomain("10.0.0.1"))
        // 10.0.0.2 should be evicted
        assertNull(DomainCache.getDomain("10.0.0.2"))
    }

    @Test
    fun `cache stores multiple IPs for different domains`() {
        DomainCache.clear()
        DomainCache.putDomain("1.1.1.1", "one.com")
        DomainCache.putDomain("2.2.2.2", "two.com")
        DomainCache.putDomain("3.3.3.3", "three.com")
        
        assertEquals("one.com", DomainCache.getDomain("1.1.1.1"))
        assertEquals("two.com", DomainCache.getDomain("2.2.2.2"))
        assertEquals("three.com", DomainCache.getDomain("3.3.3.3"))
    }

    @Test
    fun `cache handles empty domain string`() {
        DomainCache.clear()
        DomainCache.putDomain("1.2.3.4", "")
        assertEquals("", DomainCache.getDomain("1.2.3.4"))
    }

    @Test
    fun `cache handles localhost`() {
        DomainCache.clear()
        DomainCache.putDomain("127.0.0.1", "localhost")
        assertEquals("localhost", DomainCache.getDomain("127.0.0.1"))
    }

    @Test
    fun `cache handles private IPs`() {
        DomainCache.clear()
        DomainCache.putDomain("192.168.1.1", "router.local")
        DomainCache.putDomain("10.0.0.1", "gateway.local")
        assertEquals("router.local", DomainCache.getDomain("192.168.1.1"))
        assertEquals("gateway.local", DomainCache.getDomain("10.0.0.1"))
    }

    // ── FlowEntry Domain Tests ─────────────────────────────────────

    @Test
    fun `FlowEntry with domain shows domain`() {
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
    fun `FlowEntry without domain shows IP`() {
        val entry = FlowEntry(
            server = "140.82.121.6",
            domain = null,
            port = 443,
            protocol = "TCP",
            uplinkBytes = 1024,
            downlinkBytes = 4096
        )
        assertEquals("140.82.121.6:443", entry.displayServer)
        assertEquals("140.82.121.6:443", entry.displayServerWithPort)
    }

    @Test
    fun `FlowEntry domain with different ports`() {
        val entry443 = FlowEntry(server = "1.2.3.4", domain = "example.com", port = 443, protocol = "TCP", uplinkBytes = 0, downlinkBytes = 0)
        val entry8443 = FlowEntry(server = "1.2.3.4", domain = "example.com", port = 8443, protocol = "TCP", uplinkBytes = 0, downlinkBytes = 0)
        
        assertEquals("example.com:443", entry443.displayServerWithPort)
        assertEquals("example.com:8443", entry8443.displayServerWithPort)
    }

    @Test
    fun `FlowEntry with IP-only port 443`() {
        val entry = FlowEntry(
            server = "1.2.3.4",
            domain = null,
            port = 443,
            protocol = "TCP",
            uplinkBytes = 0,
            downlinkBytes = 0
        )
        assertEquals("1.2.3.4:443", entry.displayServer)
    }

    @Test
    fun `FlowEntry display server with domain hides port`() {
        val entry = FlowEntry(
            server = "1.2.3.4",
            domain = "api.example.com",
            port = 443,
            protocol = "TCP",
            uplinkBytes = 0,
            downlinkBytes = 0
        )
        // displayServer shows domain only (no port)
        assertEquals("api.example.com", entry.displayServer)
        // displayServerWithPort shows domain + port
        assertEquals("api.example.com:443", entry.displayServerWithPort)
    }

    @Test
    fun `FlowEntry display server with IP shows IP and port`() {
        val entry = FlowEntry(
            server = "1.2.3.4",
            domain = null,
            port = 8080,
            protocol = "TCP",
            uplinkBytes = 0,
            downlinkBytes = 0
        )
        // Both show IP:port when no domain
        assertEquals("1.2.3.4:8080", entry.displayServer)
        assertEquals("1.2.3.4:8080", entry.displayServerWithPort)
    }

    // ── Integration: PacketFlowTracker + SNI ───────────────────────

    @Test
    fun `PacketFlowTracker extracts domain from uplink TLS`() {
        DomainCache.clear()
        val tracker = PacketFlowTracker
        
        // Clear any existing flows
        tracker.clear()
        
        // Create TLS ClientHello packet
        val packet = buildClientHelloWithSni("api.github.com")
        
        // Process as uplink
        tracker.processPacket(packet, isUplink = true)
        
        // Check if domain was cached
        assertEquals("api.github.com", DomainCache.getDomain("140.82.121.6"))
    }

    @Test
    fun `PacketFlowTracker does not extract domain from downlink`() {
        DomainCache.clear()
        val tracker = PacketFlowTracker
        tracker.clear()
        
        // Create packet (downlink - server to client)
        val packet = buildClientHelloWithSni("api.github.com")
        
        // Process as downlink (should NOT extract SNI)
        tracker.processPacket(packet, isUplink = false)
        
        // Domain should NOT be cached (downlink packets don't have ClientHello)
        assertNull(DomainCache.getDomain("140.82.121.6"))
    }

    @Test
    fun `PacketFlowTracker uses cached domain for subsequent packets`() {
        DomainCache.clear()
        val tracker = PacketFlowTracker
        tracker.clear()
        
        // First packet: TLS ClientHello (uplink)
        val tlsPacket = buildClientHelloWithSni("api.github.com")
        tracker.processPacket(tlsPacket, isUplink = true)
        
        // Second packet: non-TLS (downlink) to same IP
        val nonTlsPacket = buildNonTlsPacket()
        tracker.processPacket(nonTlsPacket, isUplink = false)
        
        // Domain should be cached from first packet
        assertEquals("api.github.com", DomainCache.getDomain("140.82.121.6"))
    }

    @Test
    fun `PacketFlowTracker clear removes all state`() {
        DomainCache.clear()
        val tracker = PacketFlowTracker
        
        // Add some data
        val packet = buildClientHelloWithSni("api.github.com")
        tracker.processPacket(packet, isUplink = true)
        
        // Clear tracker
        tracker.clear()
        
        // Domain cache should still have the domain (separate from tracker)
        // But tracker flows should be empty
        val flows = tracker.getFlows()
        assertEquals(0, flows.size)
    }
}

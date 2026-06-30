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

    // ── Tests ──────────────────────────────────────────────────────

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
    fun `too short packet returns null`() {
        val packet = ByteArray(5)
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
}

package com.tunnely.app.vpn

/**
 * TLS SNI (Server Name Indication) parser.
 * Extracts domain names from TLS ClientHello packets without decryption.
 *
 * SNI is sent in plaintext during TLS handshake, so no CA cert or MITM needed.
 */
object SniParser {

    private const val TLS_HANDSHAKE: Byte = 0x16
    private const val CLIENT_HELLO: Byte = 0x01
    private const val SNI_EXTENSION: Int = 0x0000
    private const val SNI_HOST_NAME: Byte = 0x00

    /**
     * Extract SNI domain from a raw IP packet.
     * Returns null if not a TLS ClientHello or no SNI found.
     *
     * @param packet Raw IP packet (starts with IP header)
     * @return Domain name or null
     */
    fun extractSni(packet: ByteArray): String? {
        if (packet.size < 20) return null

        // Parse IP header
        val version = (packet[0].toInt() and 0xF0) shr 4
        if (version != 4) return null

        val ihl = (packet[0].toInt() and 0x0F) * 4
        if (ihl < 20 || packet.size < ihl) return null

        val protocol = packet[9].toInt() and 0xFF
        if (protocol != 6) return null // TCP only

        // Parse TCP header
        val dataOffset = if (packet.size >= ihl + 12) {
            ((packet[ihl + 12].toInt() and 0xF0) shr 4) * 4
        } else {
            return null
        }

        val payloadStart = ihl + dataOffset
        if (packet.size < payloadStart + 5) return null

        // Check TLS record header
        val tlsContentType = packet[payloadStart]
        if (tlsContentType != TLS_HANDSHAKE) return null

        // TLS version (2 bytes) + length (2 bytes) + handshake type (1 byte)
        val handshakeType = packet[payloadStart + 5]
        if (handshakeType != CLIENT_HELLO) return null

        // Parse ClientHello to find SNI extension
        return parseClientHello(packet, payloadStart + 5)
    }

    /**
     * Parse TLS ClientHello to extract SNI extension.
     */
    private fun parseClientHello(data: ByteArray, offset: Int): String? {
        if (data.size < offset + 34) return null // Minimum ClientHello size

        // Skip: handshake type (1) + length (3) + client version (2) + random (32)
        var pos = offset + 38

        // Session ID (1 byte length + variable)
        if (pos >= data.size) return null
        val sessionIdLen = data[pos].toInt() and 0xFF
        pos += 1 + sessionIdLen

        // Cipher Suites (2 byte length + variable)
        if (pos + 2 > data.size) return null
        val cipherSuitesLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2 + cipherSuitesLen

        // Compression Methods (1 byte length + variable)
        if (pos >= data.size) return null
        val compressionLen = data[pos].toInt() and 0xFF
        pos += 1 + compressionLen

        // Extensions (2 byte length + variable)
        if (pos + 2 > data.size) return null
        val extensionsLen = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
        pos += 2

        val extensionsEnd = pos + extensionsLen
        if (extensionsEnd > data.size) return null

        // Parse extensions looking for SNI (type 0x0000)
        while (pos + 4 <= extensionsEnd) {
            val extType = ((data[pos].toInt() and 0xFF) shl 8) or (data[pos + 1].toInt() and 0xFF)
            val extLen = ((data[pos + 2].toInt() and 0xFF) shl 8) or (data[pos + 3].toInt() and 0xFF)
            pos += 4

            if (extType == SNI_EXTENSION) {
                return parseSniExtension(data, pos, extLen)
            }

            pos += extLen
        }

        return null
    }

    /**
     * Parse SNI extension to extract hostname.
     */
    private fun parseSniExtension(data: ByteArray, offset: Int, length: Int): String? {
        if (offset + 2 > data.size) return null

        // SNI list length (2 bytes) + server name type (1 byte) + server name length (2 bytes)
        val end = offset + length
        var pos = offset + 2 // Skip SNI list length

        while (pos + 3 <= end) {
            val nameType = data[pos]
            val nameLen = ((data[pos + 1].toInt() and 0xFF) shl 8) or (data[pos + 2].toInt() and 0xFF)
            pos += 3

            if (nameType == SNI_HOST_NAME && pos + nameLen <= end) {
                return try {
                    String(data, pos, nameLen, Charsets.US_ASCII)
                } catch (e: Exception) {
                    null
                }
            }

            pos += nameLen
        }

        return null
    }
}

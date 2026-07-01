package com.tunnely.app.vpn

import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.InetAddress

/**
 * Minimal SNTP client (RFC 4330).
 * Sends one NTP request to a server, measures clock offset.
 *
 * NTP packet (48 bytes):
 *   [0]      LI + VN + Mode (0x1B = client, version 3)
 *   [1]      Stratum
 *   [2]      Poll
 *   [3]      Precision
 *   [4-7]    Root Delay
 *   [8-11]   Root Dispersion
 *   [12-15]  Reference ID
 *   [16-23]  Reference Timestamp
 *   [24-31]  Originate Timestamp (T1 — client send)
 *   [32-39]  Receive Timestamp   (T2 — server recv)
 *   [40-47]  Transmit Timestamp  (T3 — server send)
 *
 * Client computes after receiving:
 *   T4 = local receive time
 *   offset = ((T2 - T1) + (T3 - T4)) / 2
 *   delay  = (T4 - T1) - (T3 - T2)
 */
object SntpClient {
    private const val NTP_PORT = 123
    private const val NTP_PACKET_SIZE = 48
    private const val NTP_EPOCH_OFFSET = 2208988800L // seconds from 1900 to 1970
    private const val DEFAULT_TIMEOUT_MS = 3000

    data class NtpResult(
        val offsetMs: Long,      // clock offset in ms (positive = NTP server ahead / local behind)
        val roundTripMs: Long,   // NTP round-trip delay
        val stratum: Int,        // server stratum (1=GPS, 2=ref, etc.)
    )

    /**
     * Query NTP server and return clock offset.
     * @param server NTP server hostname (default: pool.ntp.org)
     * @param timeoutMs socket timeout in ms
     * @return NtpResult or null on failure
     */
    fun query(server: String = "pool.ntp.org", timeoutMs: Int = DEFAULT_TIMEOUT_MS): NtpResult? {
        return try {
            val address = InetAddress.getByName(server)
            val socket = DatagramSocket()
            socket.soTimeout = timeoutMs

            try {
                // Build NTP request
                val request = ByteArray(NTP_PACKET_SIZE)
                request[0] = 0x1B.toByte() // LI=0, VN=3, Mode=3 (client)

                // T1: local send time (NTP format: seconds since 1900)
                val t1Ms = System.currentTimeMillis()
                val t1Sec = t1Ms / 1000 + NTP_EPOCH_OFFSET
                val t1Frac = ((t1Ms % 1000) * 0x100000000L / 1000)
                // Write T1 into originate timestamp (bytes 24-31)
                writeTimestamp(request, 24, t1Sec, t1Frac)

                // Send
                val packet = DatagramPacket(request, NTP_PACKET_SIZE, address, NTP_PORT)
                socket.send(packet)

                // Receive
                val response = ByteArray(NTP_PACKET_SIZE)
                val recvPacket = DatagramPacket(response, NTP_PACKET_SIZE)
                socket.receive(recvPacket)

                // T4: local receive time
                val t4Ms = System.currentTimeMillis()

                // Parse server timestamps
                val t2Sec = readUnsignedInt(response, 32)
                val t2Frac = readUnsignedInt(response, 36)
                val t3Sec = readUnsignedInt(response, 40)
                val t3Frac = readUnsignedInt(response, 44)

                // Convert to ms
                val t2Ms = (t2Sec - NTP_EPOCH_OFFSET) * 1000 + t2Frac * 1000 / 0x100000000L
                val t3Ms = (t3Sec - NTP_EPOCH_OFFSET) * 1000 + t3Frac * 1000 / 0x100000000L

                // NTP offset: ((T2-T1) + (T3-T4)) / 2
                val offsetMs = ((t2Ms - t1Ms) + (t3Ms - t4Ms)) / 2
                val roundTripMs = (t4Ms - t1Ms) - (t3Ms - t2Ms)
                val stratum = response[1].toInt() and 0xFF

                NtpResult(
                    offsetMs = offsetMs,
                    roundTripMs = roundTripMs,
                    stratum = stratum
                )
            } finally {
                socket.close()
            }
        } catch (e: Exception) {
            null
        }
    }

    /**
     * Query multiple NTP servers and return median offset.
     * More robust than single-server query.
     */
    fun queryMultiple(
        servers: List<String> = listOf("0.pool.ntp.org", "1.pool.ntp.org", "2.pool.ntp.org"),
        timeoutMs: Int = DEFAULT_TIMEOUT_MS
    ): NtpResult? {
        val results = servers.mapNotNull { query(it, timeoutMs) }
        if (results.isEmpty()) return null

        // Median offset (robust against outliers)
        val sorted = results.sortedBy { it.offsetMs }
        val median = sorted[sorted.size / 2]
        return median
    }

    private fun writeTimestamp(buf: ByteArray, offset: Int, seconds: Long, fraction: Long) {
        buf[offset + 0] = (seconds shr 24).toByte()
        buf[offset + 1] = (seconds shr 16).toByte()
        buf[offset + 2] = (seconds shr 8).toByte()
        buf[offset + 3] = seconds.toByte()
        buf[offset + 4] = (fraction shr 24).toByte()
        buf[offset + 5] = (fraction shr 16).toByte()
        buf[offset + 6] = (fraction shr 8).toByte()
        buf[offset + 7] = fraction.toByte()
    }

    private fun readUnsignedInt(buf: ByteArray, offset: Int): Long {
        return ((buf[offset].toLong() and 0xFF) shl 24) or
               ((buf[offset + 1].toLong() and 0xFF) shl 16) or
               ((buf[offset + 2].toLong() and 0xFF) shl 8) or
               (buf[offset + 3].toLong() and 0xFF)
    }
}

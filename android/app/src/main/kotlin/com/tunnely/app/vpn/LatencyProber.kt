package com.tunnely.app.vpn

import java.nio.ByteBuffer

/**
 * Latency probe: client sends timestamped packets to server,
 * server echoes them back with its own receive timestamp.
 *
 * Wire format (24 bytes):
 *   [0-3]  Magic: 0x544C5450 ("TLTP")
 *   [4]    Type: 0x01=REQUEST, 0x02=RESPONSE
 *   [5]    Reserved
 *   [6-7]  Sequence (uint16)
 *   [8-15] Client send timestamp (microseconds)
 *   [16-23] Server receive timestamp (microseconds, 0 in request)
 */
object LatencyProber {
    const val MAGIC = 0x544C5450  // "TLTP"
    const val TYPE_REQUEST: Byte = 0x01
    const val TYPE_RESPONSE: Byte = 0x02
    const val PACKET_SIZE = 24
    const val PROBE_INTERVAL_MS = 5000L  // every 5 seconds

    data class ProbePacket(
        val type: Byte,
        val sequence: Int,
        val clientSendTs: Long,   // microseconds
        val serverRecvTs: Long,   // microseconds (0 in request)
    )

    fun encode(pkt: ProbePacket): ByteArray {
        val buf = ByteBuffer.allocate(PACKET_SIZE)
        buf.putInt(MAGIC)
        buf.put(pkt.type)
        buf.put(0x00)  // reserved
        buf.putShort(pkt.sequence.toShort())
        buf.putLong(pkt.clientSendTs)
        buf.putLong(pkt.serverRecvTs)
        return buf.array()
    }

    fun decode(data: ByteArray): ProbePacket? {
        if (data.size < PACKET_SIZE) return null
        val buf = ByteBuffer.wrap(data)
        val magic = buf.getInt()
        if (magic != MAGIC) return null
        val type = buf.get()
        buf.get()  // reserved
        val seq = buf.getShort().toInt() and 0xFFFF
        val clientTs = buf.getLong()
        val serverTs = buf.getLong()
        return ProbePacket(type, seq, clientTs, serverTs)
    }

    /** Current time in microseconds (wall clock, matches server time.time()). */
    fun nowMicros(): Long = System.currentTimeMillis() * 1000
}

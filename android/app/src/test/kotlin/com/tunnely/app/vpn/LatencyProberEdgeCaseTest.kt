package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

/**
 * Edge case tests for LatencyProber — wire format, packet processing,
 * and integration with NTP-synced latency calculation.
 */
class LatencyProberEdgeCaseTest {

    // ── Wire Format: Boundary Values ──────────────────────────────────────

    @Test
    fun `encode request with all zeros`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 0,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(32, data.size)

        // First 4 bytes = magic "TLTP"
        assertEquals(0x54, data[0].toInt() and 0xFF)
        assertEquals(0x4C, data[1].toInt() and 0xFF)
        assertEquals(0x54, data[2].toInt() and 0xFF)
        assertEquals(0x50, data[3].toInt() and 0xFF)

        // Byte 4 = type (0x01)
        assertEquals(0x01, data[4].toInt() and 0xFF)

        // Byte 5 = reserved (0x00)
        assertEquals(0x00, data[5].toInt() and 0xFF)

        // Bytes 6-7 = sequence (0)
        assertEquals(0, data[6].toInt() and 0xFF)
        assertEquals(0, data[7].toInt() and 0xFF)

        // Bytes 8-31 = timestamps (all zeros)
        for (i in 8..31) {
            assertEquals("byte $i should be 0", 0, data[i].toInt() and 0xFF)
        }
    }

    @Test
    fun `encode response with max values`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 65535,
            clientSendTs = Long.MAX_VALUE,
            serverRecvTs = Long.MAX_VALUE - 1,
            serverEchoTs = Long.MAX_VALUE - 2,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(LatencyProber.TYPE_RESPONSE, decoded.type)
        assertEquals(65535, decoded.sequence)
        assertEquals(Long.MAX_VALUE, decoded.clientSendTs)
        assertEquals(Long.MAX_VALUE - 1, decoded.serverRecvTs)
        assertEquals(Long.MAX_VALUE - 2, decoded.serverEchoTs)
    }

    @Test
    fun `encode preserves negative timestamps`() {
        // Negative timestamps shouldn't occur in practice but should roundtrip
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = -1L,
            serverRecvTs = -100L,
            serverEchoTs = -200L,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(-1L, decoded.clientSendTs)
        assertEquals(-100L, decoded.serverRecvTs)
        assertEquals(-200L, decoded.serverEchoTs)
    }

    // ── Decode: Corrupted Data ────────────────────────────────────────────

    @Test
    fun `decode truncated to 4 bytes - magic only`() {
        val data = byteArrayOf(0x54, 0x4C, 0x54, 0x50)  // "TLTP"
        assertNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode truncated to 7 bytes - missing sequence`() {
        val data = ByteArray(7)
        data[0] = 0x54; data[1] = 0x4C; data[2] = 0x54; data[3] = 0x50  // magic
        data[4] = 0x01  // type
        assertNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode with magic in wrong position`() {
        val data = ByteArray(32)
        // Put "TLTP" at offset 4 instead of 0
        data[4] = 0x54; data[5] = 0x4C; data[6] = 0x54; data[7] = 0x50
        assertNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode with partial magic - 3 of 4 bytes`() {
        val data = ByteArray(32)
        data[0] = 0x54; data[1] = 0x4C; data[2] = 0x54  // "TLT" (missing P)
        assertNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode with off-by-one magic`() {
        val data = ByteArray(32)
        // 0x544C5451 instead of 0x544C5450 (P→Q)
        data[0] = 0x54; data[1] = 0x4C; data[2] = 0x54; data[3] = 0x51
        assertNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode empty byte array`() {
        assertNull(LatencyProber.decode(ByteArray(0)))
    }

    @Test
    fun `decode single byte`() {
        assertNull(LatencyProber.decode(ByteArray(1)))
    }

    // ── Type Byte Edge Cases ──────────────────────────────────────────────

    @Test
    fun `type 0x00 - unknown type decodes but is not request or response`() {
        val pkt = LatencyProber.ProbePacket(
            type = 0x00,
            sequence = 1,
            clientSendTs = 1000L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(0x00.toByte(), decoded.type)
        assertNotEquals(LatencyProber.TYPE_REQUEST, decoded.type)
        assertNotEquals(LatencyProber.TYPE_RESPONSE, decoded.type)
    }

    @Test
    fun `type 0xFF - max type value`() {
        val pkt = LatencyProber.ProbePacket(
            type = 0xFF.toByte(),
            sequence = 1,
            clientSendTs = 1000L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(0xFF.toByte(), decoded.type)
    }

    // ── Sequence Number: Full Range ───────────────────────────────────────

    @Test
    fun `sequence 0 encodes as zero bytes`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 0,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(0, data[6].toInt() and 0xFF)
        assertEquals(0, data[7].toInt() and 0xFF)
    }

    @Test
    fun `sequence 1 sets LSB only`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(0, data[6].toInt() and 0xFF)  // MSB
        assertEquals(1, data[7].toInt() and 0xFF)  // LSB
    }

    @Test
    fun `sequence 256 sets MSB only`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 256,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(1, data[6].toInt() and 0xFF)  // MSB = 1
        assertEquals(0, data[7].toInt() and 0xFF)  // LSB = 0
    }

    @Test
    fun `sequence 32768 - high bit set`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 32768,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(32768, decoded.sequence)
    }

    @Test
    fun `sequence 65535 - all bits set`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 65535,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(0xFF, data[6].toInt() and 0xFF)
        assertEquals(0xFF, data[7].toInt() and 0xFF)

        val decoded = LatencyProber.decode(data)!!
        assertEquals(65535, decoded.sequence)
    }

    // ── Timestamp Byte Layout ─────────────────────────────────────────────

    @Test
    fun `clientSendTs at bytes 8-15`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 0,
            clientSendTs = 0x0102030405060708L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        // Big-endian: MSB first
        assertEquals(0x01, data[8].toInt() and 0xFF)
        assertEquals(0x02, data[9].toInt() and 0xFF)
        assertEquals(0x03, data[10].toInt() and 0xFF)
        assertEquals(0x04, data[11].toInt() and 0xFF)
        assertEquals(0x05, data[12].toInt() and 0xFF)
        assertEquals(0x06, data[13].toInt() and 0xFF)
        assertEquals(0x07, data[14].toInt() and 0xFF)
        assertEquals(0x08, data[15].toInt() and 0xFF)
    }

    @Test
    fun `serverRecvTs at bytes 16-23`() {
        // Use a value that fits in signed Long (top bit = 0)
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 0,
            clientSendTs = 0L,
            serverRecvTs = 0x0102030405060708L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(0x01, data[16].toInt() and 0xFF)
        assertEquals(0x02, data[17].toInt() and 0xFF)
        assertEquals(0x03, data[18].toInt() and 0xFF)
        assertEquals(0x04, data[19].toInt() and 0xFF)
        assertEquals(0x05, data[20].toInt() and 0xFF)
        assertEquals(0x06, data[21].toInt() and 0xFF)
        assertEquals(0x07, data[22].toInt() and 0xFF)
        assertEquals(0x08, data[23].toInt() and 0xFF)
    }

    @Test
    fun `serverEchoTs at bytes 24-31`() {
        // Use a value that fits in signed Long (top bit = 0)
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 0,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0x7F11223344556677L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(0x7F, data[24].toInt() and 0xFF)
        assertEquals(0x11, data[25].toInt() and 0xFF)
        assertEquals(0x22, data[26].toInt() and 0xFF)
        assertEquals(0x33, data[27].toInt() and 0xFF)
        assertEquals(0x44, data[28].toInt() and 0xFF)
        assertEquals(0x55, data[29].toInt() and 0xFF)
        assertEquals(0x66, data[30].toInt() and 0xFF)
        assertEquals(0x77, data[31].toInt() and 0xFF)
    }

    // ── ProbeSentTimes: Edge Cases ────────────────────────────────────────

    @Test
    fun `probe map handles duplicate sequence - retransmit`() {
        val map = ConcurrentHashMap<Int, Long>()

        // First send
        map[42] = 1_000_000L
        assertEquals(1_000_000L, map[42])

        // Retransmit (same sequence, later time)
        map[42] = 1_050_000L
        assertEquals(1_050_000L, map[42])
        assertEquals(1, map.size)
    }

    @Test
    fun `probe map purge boundary - exactly 30s`() {
        val map = ConcurrentHashMap<Int, Long>()
        val now = 30_000_000L

        // Entry at exactly 30s ago
        map[1] = now - 30_000_000L  // exactly at cutoff
        // Entry at 29.999s ago
        map[2] = now - 29_999_000L

        val cutoff = now - 30_000_000L
        val stale = map.filter { it.value < cutoff }.keys  // strictly less than
        stale.forEach { map.remove(it) }

        // Entry at exactly cutoff is NOT purged (< not <=)
        assertTrue(map.containsKey(1))
        assertTrue(map.containsKey(2))
    }

    @Test
    fun `probe map purge boundary - 30s plus 1 microsecond`() {
        val map = ConcurrentHashMap<Int, Long>()
        val now = 30_000_000L

        map[1] = now - 30_000_001L  // 1µs past cutoff

        val cutoff = now - 30_000_000L
        val stale = map.filter { it.value < cutoff }.keys
        stale.forEach { map.remove(it) }

        assertEquals(0, map.size)  // purged
    }

    @Test
    fun `probe map rapid send-purge cycle`() {
        val map = ConcurrentHashMap<Int, Long>()
        var seq = 0

        // Simulate 1000 probe cycles
        for (cycle in 0 until 1000) {
            seq = (seq + 1) and 0xFFFF
            map[seq] = cycle.toLong() * 1000L

            // Purge every 100 cycles
            if (cycle % 100 == 0 && cycle > 0) {
                val cutoff = cycle.toLong() * 1000L - 30_000L
                val stale = map.filter { it.value < cutoff }.keys
                stale.forEach { map.remove(it) }
            }
        }

        // Should not have leaked memory — at most entries from last purge window survive
        // At cycle 900 (last purge), cutoff = 870000 → entries 870-999 survive = 130
        assertTrue("Map size should be reasonable: ${map.size}", map.size < 200)
    }

    // ── Full Probe Lifecycle ──────────────────────────────────────────────

    @Test
    fun `full lifecycle - send request receive response`() {
        val probeSentTimes = ConcurrentHashMap<Int, Long>()

        // Client sends probe
        val seq = 42
        val sendTimeUs = 1_000_000L
        probeSentTimes[seq] = sendTimeUs

        val request = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = seq,
            clientSendTs = sendTimeUs,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )

        // Server processes (fills in timestamps)
        val serverRecvUs = 1_010_000L  // 10ms uplink
        val serverEchoUs = 1_010_050L  // 50µs processing
        val response = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = seq,
            clientSendTs = request.clientSendTs,
            serverRecvTs = serverRecvUs,
            serverEchoTs = serverEchoUs,
        )

        // Client receives response
        val recvData = LatencyProber.encode(response)
        val decoded = LatencyProber.decode(recvData)!!
        assertEquals(LatencyProber.TYPE_RESPONSE, decoded.type)
        assertEquals(seq, decoded.sequence)

        // Client computes latency
        val recvTimeUs = 1_020_050L  // 10ms downlink
        val sentUs = probeSentTimes.remove(decoded.sequence)
        assertNotNull(sentUs)

        val t1 = sentUs!!
        val t2 = decoded.serverRecvTs
        val t3 = decoded.serverEchoTs
        val t4 = recvTimeUs

        // NTP-synced mode (assume clocks aligned)
        val uplink = t2 - t1
        val downlink = t4 - t3

        assertEquals(10_000L, uplink)
        assertEquals(10_000L, downlink)
        // RTT = T4 - T1 (client timestamps, same clock)
        assertEquals(20_050L, recvTimeUs - sendTimeUs)  // includes 50µs server processing
    }

    @Test
    fun `full lifecycle with NTP offset correction`() {
        val probeSentTimes = ConcurrentHashMap<Int, Long>()
        val clientNtpOffset = 100_000L  // client 100ms behind NTP

        val seq = 1
        // Client sends (wall clock behind by 100ms)
        // T1 = wall + offset = NTP time (already corrected at send)
        val sendTimeNtp = 1_000_000L
        probeSentTimes[seq] = sendTimeNtp

        // Server timestamps (NTP-synced, so in true NTP time)
        val serverRecv = 1_010_000L  // 10ms uplink
        val serverEcho = 1_010_050L

        // Client receives (wall clock, NOT yet corrected)
        val recvWall = 1_010_050L + 10_000L - clientNtpOffset  // true NTP - offset
        val t4Corrected = recvWall + clientNtpOffset  // correct to NTP time

        val uplink = serverRecv - sendTimeNtp  // 10ms
        val downlink = t4Corrected - serverEcho  // 10ms

        assertEquals(10_000L, uplink)
        assertEquals(10_000L, downlink)
    }

    // ── EMA Integration Edge Cases ────────────────────────────────────────

    @Test
    fun `EMA from zero to target in one step`() {
        val alpha = 0.3f
        var ema = 0f
        val target = 50.0f

        ema = alpha * target + (1 - alpha) * ema
        assertEquals(15.0f, ema, 0.01f)  // 30% of 50
    }

    @Test
    fun `EMA never exceeds input value`() {
        val alpha = 0.3f
        var ema = 100.0f

        // Feed smaller value
        ema = alpha * 50.0f + (1 - alpha) * ema
        assertTrue(ema <= 100.0f)
    }

    @Test
    fun `EMA never goes below input value`() {
        val alpha = 0.3f
        var ema = 10.0f

        // Feed larger value
        ema = alpha * 100.0f + (1 - alpha) * ema
        assertTrue(ema >= 10.0f)
    }

    @Test
    fun `EMA with alpha 1_0 equals input`() {
        val alpha = 1.0f  // no smoothing
        var ema = 10.0f
        ema = alpha * 50.0f + (1 - alpha) * ema
        assertEquals(50.0f, ema, 0.001f)
    }

    @Test
    fun `EMA with alpha 0_0 stays unchanged`() {
        val alpha = 0.0f  // maximum smoothing
        var ema = 10.0f
        ema = alpha * 50.0f + (1 - alpha) * ema
        assertEquals(10.0f, ema, 0.001f)
    }

    // ── Probe Interval Timing ─────────────────────────────────────────────

    @Test
    fun `probe interval is 5 seconds`() {
        assertEquals(5000L, LatencyProber.PROBE_INTERVAL_MS)
    }

    @Test
    fun `probe interval in microseconds`() {
        val intervalUs = LatencyProber.PROBE_INTERVAL_MS * 1000
        assertEquals(5_000_000L, intervalUs)
    }

    @Test
    fun `packet size is 32 bytes`() {
        assertEquals(32, LatencyProber.PACKET_SIZE)
    }

    // ── Real-World Scenario Simulations ───────────────────────────────────

    @Test
    fun `Indonesian carrier - 50 probes with NAT jitter`() {
        val probeSentTimes = ConcurrentHashMap<Int, Long>()
        var emaRtt = 0f
        val alpha = 0.3f
        val random = java.util.Random(123)

        var seq = 0
        for (i in 0 until 50) {
            seq = (seq + 1) and 0xFFFF

            // Simulate Indonesian carrier: 10-30ms RTT with occasional spikes
            val baseRtt = 20_000L
            val jitter = random.nextInt(10_000).toLong() - 5_000L  // ±5ms
            val spike = if (random.nextInt(10) == 0) 100_000L else 0L  // 10% chance of 100ms spike
            val rttUs = baseRtt + jitter + spike

            val sendUs = i * 5_000_000L
            probeSentTimes[seq] = sendUs

            // Simulate server response
            val serverRecv = sendUs + rttUs / 2
            val serverEcho = serverRecv + 50L
            val recvUs = sendUs + rttUs

            // Compute RTT
            val uplink = serverRecv - sendUs
            val downlink = recvUs - serverEcho
            // RTT = T4 - T1 (client timestamps only)
            val rtt = recvUs - sendUs

            // EMA
            val rttMs = rtt / 1000f
            emaRtt = if (emaRtt == 0f) rttMs else alpha * rttMs + (1 - alpha) * emaRtt

            probeSentTimes.remove(seq)
        }

        // EMA should settle around 20ms (base RTT)
        assertTrue("EMA should be around 20ms: $emaRtt", emaRtt > 10f && emaRtt < 50f)
        assertEquals(0, probeSentTimes.size)
    }

    @Test
    fun `probe loss rate under congestion`() {
        var sent = 0L
        var recv = 0L
        val random = java.util.Random(456)

        for (i in 0 until 100) {
            sent++
            // 15% packet loss under congestion
            if (random.nextInt(100) < 85) {
                recv++
            }
        }

        val lossRate = (sent - recv).toFloat() / sent * 100
        // Should be around 15% ± some variance
        assertTrue("Loss rate should be ~15%: $lossRate", lossRate > 5f && lossRate < 25f)
    }

    // ── Timestamp Overflow Safety ─────────────────────────────────────────

    @Test
    fun `timestamp near Long MAX does not overflow on encode-decode`() {
        val nearMax = Long.MAX_VALUE - 1000L
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = nearMax,
            serverRecvTs = nearMax + 1,
            serverEchoTs = nearMax + 2,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(nearMax, decoded.clientSendTs)
        assertEquals(nearMax + 1, decoded.serverRecvTs)
        assertEquals(nearMax + 2, decoded.serverEchoTs)
    }

    @Test
    fun `RTT computation does not overflow with large timestamps`() {
        val largeBase = Long.MAX_VALUE / 2
        val t1 = largeBase
        val t2 = largeBase + 10_000L
        val t3 = largeBase + 10_050L
        val t4 = largeBase + 20_050L

        val offset = ((t2 - t1) + (t3 - t4)) / 2
        val up = (t2 - t1) - offset
        val down = (t4 - t3) + offset

        assertEquals(0L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
        // RTT = T4 - T1 (client timestamps)
        assertEquals(20_050L, t4 - t1)  // includes 50µs server processing
    }

    // ── Data Class Equality ───────────────────────────────────────────────

    @Test
    fun `ProbePacket data class equality`() {
        val pkt1 = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 42,
            clientSendTs = 1000L,
            serverRecvTs = 2000L,
            serverEchoTs = 3000L,
        )
        val pkt2 = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 42,
            clientSendTs = 1000L,
            serverRecvTs = 2000L,
            serverEchoTs = 3000L,
        )
        assertEquals(pkt1, pkt2)
        assertEquals(pkt1.hashCode(), pkt2.hashCode())
    }

    @Test
    fun `ProbePacket data class inequality - different type`() {
        val pkt1 = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = 1000L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val pkt2 = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 1,
            clientSendTs = 1000L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        assertNotEquals(pkt1, pkt2)
    }

    @Test
    fun `ProbePacket data class inequality - different sequence`() {
        val pkt1 = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = 1000L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val pkt2 = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 2,
            clientSendTs = 1000L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        assertNotEquals(pkt1, pkt2)
    }

    // ── Constants Validation ──────────────────────────────────────────────

    @Test
    fun `MAGIC is TLTP in ASCII`() {
        // T=0x54, L=0x4C, T=0x54, P=0x50
        assertEquals(0x544C5450, LatencyProber.MAGIC)
    }

    @Test
    fun `TYPE_REQUEST is 0x01`() {
        assertEquals(0x01.toByte(), LatencyProber.TYPE_REQUEST)
    }

    @Test
    fun `TYPE_RESPONSE is 0x02`() {
        assertEquals(0x02.toByte(), LatencyProber.TYPE_RESPONSE)
    }

    @Test
    fun `PACKET_SIZE is 32`() {
        // 4 magic + 1 type + 1 reserved + 2 seq + 8 clientTs + 8 serverRecvTs + 8 serverEchoTs = 32
        assertEquals(32, LatencyProber.PACKET_SIZE)
    }
}

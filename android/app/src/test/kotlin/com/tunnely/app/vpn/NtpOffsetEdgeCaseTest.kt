package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

class NtpOffsetEdgeCaseTest {

    private fun calcOneWay(t1: Long, t2: Long, t3: Long, t4: Long): Triple<Long, Long, Long> {
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        val uplink = (t2 - t1) - offset
        val downlink = (t4 - t3) + offset
        return Triple(offset, uplink, downlink)
    }

    // ── Clock Offset: Various Magnitudes ─────────────────────────────────

    @Test
    fun `1ms clock offset - typical LAN NTP`() {
        // offset = 1ms (1000µs), 10ms symmetric
        val t1 = 0L; val t2 = 11_000L; val t3 = 11_050L; val t4 = 20_050L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        // offset = ((11000) + (11050-20050)) / 2 = (11000 + -9000) / 2 = 1000
        assertEquals(1_000L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `100ms clock offset - cross-region`() {
        val t1 = 0L; val t2 = 110_000L; val t3 = 110_100L; val t4 = 20_100L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(100_000L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `500ms clock offset - cross-continent`() {
        val t1 = 0L; val t2 = 510_000L; val t3 = 510_100L; val t4 = 20_100L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(500_000L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `1000ms clock offset - worst case`() {
        val t1 = 0L; val t2 = 1_010_000L; val t3 = 1_010_100L; val t4 = 20_100L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(1_000_000L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `negative clock offset - server behind`() {
        val t1 = 0L; val t2 = -90_000L; val t3 = -89_900L; val t4 = 20_100L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(-100_000L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    // ── Network Latency: Various RTTs ────────────────────────────────────

    @Test
    fun `sub-millisecond - localhost`() {
        val t1 = 0L; val t2 = 100L; val t3 = 150L; val t4 = 250L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(100L, up)
        assertEquals(100L, down)
    }

    @Test
    fun `1ms RTT - same datacenter`() {
        val t1 = 0L; val t2 = 500L; val t3 = 600L; val t4 = 1_100L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(500L, up)
        assertEquals(500L, down)
    }

    @Test
    fun `10ms RTT - same country`() {
        val t1 = 0L; val t2 = 5_000L; val t3 = 5_100L; val t4 = 10_100L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(5_000L, up)
        assertEquals(5_000L, down)
    }

    @Test
    fun `100ms RTT - cross region`() {
        val t1 = 0L; val t2 = 50_000L; val t3 = 50_200L; val t4 = 100_200L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(50_000L, up)
        assertEquals(50_000L, down)
    }

    @Test
    fun `500ms RTT - satellite`() {
        val t1 = 0L; val t2 = 250_000L; val t3 = 250_500L; val t4 = 500_500L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(250_000L, up)
        assertEquals(250_000L, down)
    }

    @Test
    fun `1s RTT - extreme`() {
        val t1 = 0L; val t2 = 500_000L; val t3 = 500_500L; val t4 = 1_000_500L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(500_000L, up)
        assertEquals(500_000L, down)
    }

    // ── Server Processing Time ───────────────────────────────────────────

    @Test
    fun `zero server processing`() {
        val t1 = 0L; val t2 = 10_000L; val t3 = 10_000L; val t4 = 20_000L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `50us server processing`() {
        val t1 = 0L; val t2 = 10_000L; val t3 = 10_050L; val t4 = 20_050L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `1ms server processing - busy server`() {
        val t1 = 0L; val t2 = 10_000L; val t3 = 11_000L; val t4 = 21_000L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `10ms server processing - very busy`() {
        val t1 = 0L; val t2 = 10_000L; val t3 = 20_000L; val t4 = 30_000L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    // ── Combined: Clock Offset + Asymmetric + Processing ─────────────────

    @Test
    fun `50ms offset + 10ms up 30ms down + 200us proc`() {
        val clockOff = 50_000L; val upTrue = 10_000L; val downTrue = 30_000L; val proc = 200L
        val t1 = 0L
        val t2 = clockOff + upTrue                          // 60000
        val t3 = t2 + proc                                   // 60200
        val t4 = t3 + downTrue - clockOff                    // 40200

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        // offset = C + (U-D)/2 = 50000 + (10000-30000)/2 = 50000 - 10000 = 40000
        assertEquals(40_000L, offset)
        // up = (C+U) - offset = 60000 - 40000 = 20000 = (U+D)/2
        assertEquals(20_000L, up)
        // down = D + offset = 30000 + 40000 = 70000... wait
        // down = (T4-T3) + offset = (40200-60200) + 40000 = -20000 + 40000 = 20000
        assertEquals(20_000L, down)
        // Both show 20ms = (10+30)/2 — NTP averages asymmetry
        assertEquals(up, down)
    }

    @Test
    fun `200ms offset + 5ms up 5ms down + 50us proc - perfectly symmetric`() {
        val t1 = 0L; val t2 = 205_000L; val t3 = 205_050L; val t4 = 10_050L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(200_000L, offset)
        assertEquals(5_000L, up)
        assertEquals(5_000L, down)
    }

    @Test
    fun `-500ms offset + 50ms up 20ms down + 1ms proc`() {
        val clockOff = -500_000L; val upTrue = 50_000L; val downTrue = 20_000L; val proc = 1_000L
        val t1 = 0L
        val t2 = clockOff + upTrue            // -450000
        val t3 = t2 + proc                     // -449000
        val t4 = t3 + downTrue - clockOff      // 71000

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        // offset = ((-450000) + (-449000 - 71000)) / 2 = (-450000 + -520000) / 2 = -485000
        assertEquals(-485_000L, offset)
        // up = -450000 - (-485000) = 35000 = (50000+20000)/2
        assertEquals(35_000L, up)
        // down = (71000 - (-449000)) + (-485000) = 520000 - 485000 = 35000
        assertEquals(35_000L, down)
    }

    // ── RTT Correctness ──────────────────────────────────────────────────

    @Test
    fun `RTT always equals T4-T1 minus serverProc`() {
        // For any clock offset, uplink + downlink should equal network RTT
        val testCases = listOf(
            // (clockOffset, trueUplink, trueDownlink, serverProc)
            Triple(0L, 10_000L, 10_000L) to 100L,
            Triple(500_000L, 10_000L, 10_000L) to 100L,
            Triple(-200_000L, 5_000L, 20_000L) to 500L,
            Triple(1_000_000L, 50_000L, 50_000L) to 1_000L,
        )
        for ((params, proc) in testCases) {
            val (clockOff, upTrue, downTrue) = params
            val t1 = 0L
            val t2 = clockOff + upTrue
            val t3 = t2 + proc
            val t4 = t3 + downTrue - clockOff

            val (_, up, down) = calcOneWay(t1, t2, t3, t4)
            val expectedRtt = upTrue + downTrue
            val actualRtt = up + down

            // RTT should be preserved regardless of clock offset
            assertEquals(
                "RTT mismatch with offset=$clockOff",
                expectedRtt, actualRtt
            )
        }
    }

    @Test
    fun `RTT preserved with 997ms offset`() {
        val clockOff = 997_000L; val upTrue = 15_000L; val downTrue = 15_000L; val proc = 100L
        val t1 = 0L; val t2 = clockOff + upTrue; val t3 = t2 + proc; val t4 = t3 + downTrue - clockOff
        val (_, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(upTrue + downTrue, up + down)
    }

    @Test
    fun `RTT preserved with asymmetric + offset`() {
        val clockOff = 100_000L; val upTrue = 3_000L; val downTrue = 47_000L; val proc = 200L
        val t1 = 0L; val t2 = clockOff + upTrue; val t3 = t2 + proc; val t4 = t3 + downTrue - clockOff
        val (_, up, down) = calcOneWay(t1, t2, t3, t4)
        // RTT = 3000 + 47000 = 50000
        assertEquals(50_000L, up + down)
    }

    // ── EMA Smoothing ────────────────────────────────────────────────────

    @Test
    fun `EMA converges to stable value`() {
        val alpha = 0.3f
        var ema = 0f
        val target = 15.0f

        // Feed 100 identical samples
        repeat(100) {
            ema = alpha * target + (1 - alpha) * ema
        }

        // Should converge close to target
        assertEquals(target, ema, 0.01f)
    }

    @Test
    fun `EMA smooths spikes`() {
        val alpha = 0.3f
        var ema = 10.0f  // stable at 10ms

        // One spike to 100ms
        ema = alpha * 100.0f + (1 - alpha) * ema
        // Should be 37ms (0.3*100 + 0.7*10), not 100ms
        assertEquals(37.0f, ema, 0.1f)

        // Next normal reading — ema drops but not back to 10ms yet
        ema = alpha * 10.0f + (1 - alpha) * ema
        // 0.3*10 + 0.7*37 = 3 + 25.9 = 28.9
        assertTrue(ema < 30.0f)
        assertTrue(ema > 20.0f)  // still elevated from spike
    }

    @Test
    fun `EMA first value sets directly`() {
        val alpha = 0.3f
        var ema = 0f

        // First sample: special case (set directly, not blended)
        val first = 25.0f
        if (ema == 0f) {
            ema = first
        } else {
            ema = alpha * first + (1 - alpha) * ema
        }

        assertEquals(25.0f, ema, 0.001f)
    }

    @Test
    fun `EMA handles zero latency`() {
        val alpha = 0.3f
        var ema = 10.0f

        // Zero latency (loopback)
        ema = alpha * 0.0f + (1 - alpha) * ema
        assertEquals(7.0f, ema, 0.1f)
    }

    @Test
    fun `EMA handles very high latency`() {
        val alpha = 0.3f
        var ema = 10.0f

        // 5000ms spike (satellite)
        ema = alpha * 5000.0f + (1 - alpha) * ema
        assertEquals(1507.0f, ema, 1.0f)
    }

    // ── Sequence Number: Wraparound ──────────────────────────────────────

    @Test
    fun `sequence wraps at 65535`() {
        var seq = 65534
        val probeSentTimes = java.util.concurrent.ConcurrentHashMap<Int, Long>()

        // Send 3 probes: 65535, 0, 1
        repeat(3) {
            seq = (seq + 1) and 0xFFFF
            probeSentTimes[seq] = it * 1000L
        }

        assertTrue(probeSentTimes.containsKey(65535))
        assertTrue(probeSentTimes.containsKey(0))
        assertTrue(probeSentTimes.containsKey(1))
        assertEquals(3, probeSentTimes.size)
    }

    @Test
    fun `sequence 16-bit mask`() {
        val seq = 70000
        val masked = seq.toShort().toInt() and 0xFFFF
        assertEquals(70000 - 65536, masked)
    }

    // ── ProbeSentTimes: Stale Purge ──────────────────────────────────────

    @Test
    fun `purge entries older than 30s`() {
        val probeSentTimes = java.util.concurrent.ConcurrentHashMap<Int, Long>()
        val now = 1_000_000L

        // Add old and new entries
        probeSentTimes[1] = now - 31_000_000L  // 31s old → purge
        probeSentTimes[2] = now - 29_000_000L  // 29s old → keep
        probeSentTimes[3] = now - 10_000_000L  // 10s old → keep
        probeSentTimes[4] = now                 // 0s old → keep

        val cutoffUs = now - 30_000_000L
        val stale = probeSentTimes.filter { it.value < cutoffUs }.keys
        stale.forEach { probeSentTimes.remove(it) }

        assertEquals(3, probeSentTimes.size)
        assertFalse(probeSentTimes.containsKey(1))
        assertTrue(probeSentTimes.containsKey(2))
        assertTrue(probeSentTimes.containsKey(3))
        assertTrue(probeSentTimes.containsKey(4))
    }

    @Test
    fun `purge all when all stale`() {
        val probeSentTimes = java.util.concurrent.ConcurrentHashMap<Int, Long>()
        val now = 1_000_000L

        repeat(100) { probeSentTimes[it] = now - 60_000_000L }

        val cutoffUs = now - 30_000_000L
        val stale = probeSentTimes.filter { it.value < cutoffUs }.keys
        stale.forEach { probeSentTimes.remove(it) }

        assertEquals(0, probeSentTimes.size)
    }

    @Test
    fun `purge none when all fresh`() {
        val probeSentTimes = java.util.concurrent.ConcurrentHashMap<Int, Long>()
        val now = 1_000_000L

        repeat(100) { probeSentTimes[it] = now - it * 1000L }

        val cutoffUs = now - 30_000_000L
        val stale = probeSentTimes.filter { it.value < cutoffUs }.keys
        stale.forEach { probeSentTimes.remove(it) }

        assertEquals(100, probeSentTimes.size)
    }

    // ── Wire Format: Encode/Decode ───────────────────────────────────────

    @Test
    fun `encode request then decode matches`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 42,
            clientSendTs = 1234567890L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val encoded = LatencyProber.encode(pkt)
        assertEquals(32, encoded.size)

        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(LatencyProber.TYPE_REQUEST, decoded.type)
        assertEquals(42, decoded.sequence)
        assertEquals(1234567890L, decoded.clientSendTs)
        assertEquals(0L, decoded.serverRecvTs)
        assertEquals(0L, decoded.serverEchoTs)
    }

    @Test
    fun `encode response then decode matches`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 99,
            clientSendTs = 1000000L,
            serverRecvTs = 1050000L,
            serverEchoTs = 1050100L,
        )
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!

        assertEquals(LatencyProber.TYPE_RESPONSE, decoded.type)
        assertEquals(99, decoded.sequence)
        assertEquals(1000000L, decoded.clientSendTs)
        assertEquals(1050000L, decoded.serverRecvTs)
        assertEquals(1050100L, decoded.serverEchoTs)
    }

    @Test
    fun `decode rejects wrong magic`() {
        val data = ByteArray(32)
        java.nio.ByteBuffer.wrap(data).putInt(0x12345678)
        assertNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode rejects too short`() {
        assertNull(LatencyProber.decode(ByteArray(16)))
        assertNull(LatencyProber.decode(ByteArray(0)))
        assertNull(LatencyProber.decode(ByteArray(31)))
    }

    @Test
    fun `sequence preserves 16-bit unsigned`() {
        // seq=65535 → short = -1 → unsigned = 65535
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 65535,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(65535, decoded.sequence)
    }

    @Test
    fun `sequence 0 works`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 0,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(0, decoded.sequence)
    }

    @Test
    fun `timestamps preserve max long`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 1,
            clientSendTs = Long.MAX_VALUE,
            serverRecvTs = Long.MAX_VALUE,
            serverEchoTs = Long.MAX_VALUE,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(Long.MAX_VALUE, decoded.clientSendTs)
        assertEquals(Long.MAX_VALUE, decoded.serverRecvTs)
        assertEquals(Long.MAX_VALUE, decoded.serverEchoTs)
    }

    @Test
    fun `timestamps preserve zero`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(0L, decoded.clientSendTs)
        assertEquals(0L, decoded.serverRecvTs)
        assertEquals(0L, decoded.serverEchoTs)
    }

    // ── Full Pipeline: Probe → Server → Response → NTP ───────────────────

    @Test
    fun `full pipeline - client sends probe, server echoes, NTP calculates`() {
        // Simulate full round-trip
        val clientSendTime = 1_000_000_000L  // client clock
        val clockOffset = 250_000L            // server 250ms ahead
        val uplink = 12_000L                  // 12ms true uplink
        val downlink = 12_000L                // 12ms true downlink
        val serverProc = 150L                 // 150µs server processing

        // Client sends
        val request = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = clientSendTime,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )

        // Server receives and echoes
        val serverRecvTime = clientSendTime + clockOffset + uplink
        val serverEchoTime = serverRecvTime + serverProc
        val response = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 1,
            clientSendTs = clientSendTime,
            serverRecvTs = serverRecvTime,
            serverEchoTs = serverEchoTime,
        )

        // Client receives
        val clientRecvTime = serverEchoTime - clockOffset + downlink

        // NTP calculation
        val (offset, up, down) = calcOneWay(
            clientSendTime, serverRecvTime, serverEchoTime, clientRecvTime
        )

        // Should recover clock offset and true one-way delays
        assertEquals(clockOffset, offset)
        assertEquals(uplink, up)
        assertEquals(downlink, down)
        assertEquals(uplink + downlink, up + down)  // RTT preserved
    }

    @Test
    fun `full pipeline - encode-decode preserves timestamps for NTP`() {
        val t1 = 0L; val t2 = 100_000L; val t3 = 100_100L

        val response = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 5,
            clientSendTs = t1,
            serverRecvTs = t2,
            serverEchoTs = t3,
        )

        // Encode → decode (simulates wire transfer)
        val encoded = LatencyProber.encode(response)
        val decoded = LatencyProber.decode(encoded)!!

        // Simulate client receive (100ms return travel)
        val t4 = 200_100L

        val (offset, up, down) = calcOneWay(
            decoded.clientSendTs, decoded.serverRecvTs, decoded.serverEchoTs, t4
        )

        // offset = ((100000) + (100100-200100)) / 2 = (100000 + -100000) / 2 = 0
        assertEquals(0L, offset)
        assertEquals(100_000L, up)   // 100ms
        assertEquals(100_000L, down) // 100ms
    }
}

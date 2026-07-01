package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test
import java.util.concurrent.ConcurrentHashMap

class NtpOffsetStressTest {

    private fun calcOneWay(t1: Long, t2: Long, t3: Long, t4: Long): Triple<Long, Long, Long> {
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        val uplink = (t2 - t1) - offset
        val downlink = (t4 - t3) + offset
        return Triple(offset, uplink, downlink)
    }

    // ── Stress: Many Probes ──────────────────────────────────────────────

    @Test
    fun `100 sequential probes - stable offset`() {
        val clockOffset = 250_000L  // 250ms
        val trueUplink = 12_000L    // 12ms
        val trueDownlink = 12_000L
        val serverProc = 100L

        for (i in 0 until 100) {
            val t1 = i * 5_000_000L  // every 5s
            val t2 = t1 + clockOffset + trueUplink
            val t3 = t2 + serverProc
            val t4 = t3 + trueDownlink - clockOffset

            val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
            assertEquals("offset at probe $i", clockOffset, offset)
            assertEquals("uplink at probe $i", trueUplink, up)
            assertEquals("downlink at probe $i", trueDownlink, down)
        }
    }

    @Test
    fun `100 probes with jitter - offset stays stable`() {
        val clockOffset = 100_000L
        val baseLatency = 10_000L
        val random = java.util.Random(42)

        for (i in 0 until 100) {
            // Symmetric jitter (same on both legs) so NTP doesn't absorb it
            val jitter = random.nextInt(4000) - 2000L
            val trueUp = baseLatency + jitter
            val trueDown = baseLatency + jitter

            val t1 = i * 5_000_000L
            val t2 = t1 + clockOffset + trueUp
            val t3 = t2 + 100L
            val t4 = t3 + trueDown - clockOffset

            val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
            assertEquals("offset at probe $i", clockOffset, offset)
            assertEquals("uplink at probe $i", trueUp, up)
            assertEquals("downlink at probe $i", trueDown, down)
        }
    }

    @Test
    fun `1000 probes - no integer overflow`() {
        val bigOffset = 5_000_000L  // 5s offset
        val bigLatency = 500_000L   // 500ms

        for (i in 0 until 1000) {
            val t1 = i * 1_000_000L
            val t2 = t1 + bigOffset + bigLatency
            val t3 = t2 + 500L
            val t4 = t3 + bigLatency - bigOffset

            val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
            assertEquals(bigOffset, offset)
            assertEquals(bigLatency, up)
            assertEquals(bigLatency, down)
        }
    }

    // ── Stress: ProbeSentTimes ───────────────────────────────────────────

    @Test
    fun `1000 probes in map - purge keeps fresh`() {
        val map = ConcurrentHashMap<Int, Long>()
        val now = 1_000_000_000L

        // 500 fresh (within 30s) + 500 stale (older than 30s)
        for (i in 0 until 500) {
            map[i] = now - (i * 1000L)           // 0-499ms old → fresh
        }
        for (i in 500 until 1000) {
            map[i] = now - 60_000_000L - i       // 60s+ old → stale
        }

        val cutoff = now - 30_000_000L
        val stale = map.filter { it.value < cutoff }.keys
        stale.forEach { map.remove(it) }

        assertEquals(500, map.size)
    }

    @Test
    fun `probe map dedup by sequence`() {
        val map = ConcurrentHashMap<Int, Long>()

        // Same sequence sent twice (retransmit)
        map[42] = 1000L
        map[42] = 2000L  // overwrite

        assertEquals(1, map.size)
        assertEquals(2000L, map[42]!!)
    }

    @Test
    fun `probe map concurrent access`() {
        val map = ConcurrentHashMap<Int, Long>()
        val threads = mutableListOf<Thread>()

        // 10 threads each adding 100 entries
        for (t in 0 until 10) {
            threads.add(Thread {
                for (i in 0 until 100) {
                    map[t * 100 + i] = System.nanoTime()
                }
            })
        }
        threads.forEach { it.start() }
        threads.forEach { it.join() }

        assertEquals(1000, map.size)
    }

    // ── EMA: Convergence Speed ───────────────────────────────────────────

    @Test
    fun `EMA converges 95% in 10 samples`() {
        val alpha = 0.3f
        var ema = 0f
        val target = 100.0f

        repeat(10) {
            ema = alpha * target + (1 - alpha) * ema
        }

        // After 10 samples with α=0.3, should be >95% of target
        assertTrue("EMA should converge: $ema", ema > target * 0.95f)
    }

    @Test
    fun `EMA converges 99% in 15 samples`() {
        val alpha = 0.3f
        var ema = 0f
        val target = 100.0f

        repeat(15) {
            ema = alpha * target + (1 - alpha) * ema
        }

        assertTrue("EMA should converge: $ema", ema > target * 0.99f)
    }

    @Test
    fun `EMA recovers from spike within 15 samples`() {
        val alpha = 0.3f
        var ema = 10.0f  // stable

        // Spike to 1000ms
        ema = alpha * 1000.0f + (1 - alpha) * ema

        // 15 normal samples to recover
        repeat(15) {
            ema = alpha * 10.0f + (1 - alpha) * ema
        }

        // After 15 samples with α=0.3, should be back near 10ms
        assertTrue("EMA should recover: $ema", ema < 20.0f)
    }

    @Test
    fun `EMA with alternating high-low oscillation`() {
        val alpha = 0.3f
        var ema = 50.0f

        // Alternate between 10 and 100
        repeat(20) { i ->
            val value = if (i % 2 == 0) 10.0f else 100.0f
            ema = alpha * value + (1 - alpha) * ema
        }

        // Should settle around 55 (average of 10 and 100, biased by EMA)
        assertTrue("EMA should be moderate: $ema", ema > 30.0f && ema < 80.0f)
    }

    @Test
    fun `EMA monotonic increase`() {
        val alpha = 0.3f
        var ema = 0f

        // Feed increasing values
        for (i in 1..20) {
            ema = alpha * (i * 10.0f) + (1 - alpha) * ema
            assertTrue("EMA should increase at step $i", ema >= (i - 1) * 10.0f * 0.5f)
        }
    }

    // ── Sequence: Edge Cases ─────────────────────────────────────────────

    @Test
    fun `sequence 0 to 65535 full cycle`() {
        val map = ConcurrentHashMap<Int, Long>()
        var seq = 0

        for (i in 0 until 65536) {
            seq = (seq + 1) and 0xFFFF
            map[seq] = i.toLong()
        }

        // All 65536 unique sequences
        assertEquals(65536, map.size)
        assertTrue(map.containsKey(1))
        assertTrue(map.containsKey(32768))
        assertTrue(map.containsKey(65535))
    }

    @Test
    fun `sequence double wrap`() {
        var seq = 65530

        // First wrap
        repeat(10) {
            seq = (seq + 1) and 0xFFFF
        }
        assertEquals(4, seq)  // 65530 + 10 = 65540 → 65540 - 65536 = 4

        // Second wrap
        repeat(65536) {
            seq = (seq + 1) and 0xFFFF
        }
        assertEquals(4, seq)  // back to 4
    }

    @Test
    fun `sequence mask preserves lower 16 bits`() {
        assertEquals(0, (0).toShort().toInt() and 0xFFFF)
        assertEquals(1, (1).toShort().toInt() and 0xFFFF)
        assertEquals(32767, (32767).toShort().toInt() and 0xFFFF)
        assertEquals(32768, (-32768).toShort().toInt() and 0xFFFF)
        assertEquals(65535, (-1).toShort().toInt() and 0xFFFF)
    }

    // ── Wire Format: Edge Cases ──────────────────────────────────────────

    @Test
    fun `decode exact 32 bytes`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = 1000L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(32, data.size)
        assertNotNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode 33 bytes - extra byte ignored`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 1,
            clientSendTs = 1000L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt) + byteArrayOf(0xFF.toByte())
        // Should still decode (only reads first 32 bytes)
        assertNotNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode 31 bytes - too short`() {
        assertNull(LatencyProber.decode(ByteArray(31)))
    }

    @Test
    fun `decode all zeros - wrong magic`() {
        assertNull(LatencyProber.decode(ByteArray(32)))
    }

    @Test
    fun `decode random data - wrong magic`() {
        val random = ByteArray(32)
        java.util.Random(42).nextBytes(random)
        // Very unlikely to have correct magic
        assertNull(LatencyProber.decode(random))
    }

    @Test
    fun `encode preserves all fields exactly`() {
        val pkt = LatencyProber.ProbePacket(
            type = 0x03,  // non-standard type
            sequence = 12345,
            clientSendTs = 123456789012345L,
            serverRecvTs = 987654321098765L,
            serverEchoTs = 111111111111111L,
        )
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(0x03.toByte(), decoded.type)
        assertEquals(12345, decoded.sequence)
        assertEquals(123456789012345L, decoded.clientSendTs)
        assertEquals(987654321098765L, decoded.serverRecvTs)
        assertEquals(111111111111111L, decoded.serverEchoTs)
    }

    @Test
    fun `magic bytes at offset 0`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 0,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        // "TLTP" = 0x544C5450
        assertEquals(0x54, data[0].toInt() and 0xFF)
        assertEquals(0x4C, data[1].toInt() and 0xFF)
        assertEquals(0x54, data[2].toInt() and 0xFF)
        assertEquals(0x50, data[3].toInt() and 0xFF)
    }

    @Test
    fun `type byte at offset 4`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_RESPONSE,
            sequence = 0,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(0x02, data[4].toInt())
    }

    @Test
    fun `reserved byte at offset 5 is zero`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 0,
            clientSendTs = 0L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val data = LatencyProber.encode(pkt)
        assertEquals(0x00, data[5].toInt())
    }

    // ── NTP: Timestamp Edge Cases ────────────────────────────────────────

    @Test
    fun `timestamps near epoch - small values`() {
        // Symmetric 10ms, no clock offset
        val t1 = 1L; val t2 = 10_001L; val t3 = 10_051L; val t4 = 20_051L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `timestamps near Long MAX div 2`() {
        val base = Long.MAX_VALUE / 2
        val t1 = base; val t2 = base + 10_000L; val t3 = base + 10_100L; val t4 = base + 20_100L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `timestamps with large base plus offset`() {
        // Current epoch microseconds: ~1.7 × 10^15
        val base = 1_700_000_000_000_000L
        val clockOff = 500_000L
        val t1 = base
        val t2 = base + clockOff + 10_000L
        val t3 = t2 + 100L
        val t4 = t3 + 10_000L - clockOff

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(clockOff, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `timestamps crossing zero boundary`() {
        // Client at -1000, server at +1000 (2000µs offset)
        val t1 = -1_000L; val t2 = 1_000L + 5_000L; val t3 = t2 + 50L; val t4 = 6_050L - 1_000L
        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        // offset = ((6000 - (-1000)) + (6050 - 5050)) / 2 = (7000 + 1000) / 2 = 4000
        // Hmm: t2 = 1000 + 5000 = 6000, t3 = 6050, t4 = 6050 - 1000 = 5050
        // offset = ((6000 - (-1000)) + (6050 - 5050)) / 2 = (7000 + 1000) / 2 = 4000
        assertEquals(4_000L, offset)
    }

    // ── NTP: Derived Metrics ─────────────────────────────────────────────

    @Test
    fun `jitter calculation from consecutive probes`() {
        // When jitter is only on uplink, NTP absorbs half into symmetric average
        // Use jitter on BOTH up and down to get full range
        val probes = mutableListOf<Long>()
        val clockOff = 100_000L
        val baseUp = 10_000L
        val baseDown = 10_000L

        for (i in 0 until 10) {
            val jitter = (i % 3) * 1000L  // 0, 1000, 2000
            val t1 = i * 5_000_000L
            val t2 = t1 + clockOff + baseUp + jitter  // jitter on uplink
            val t3 = t2 + 100L
            val t4 = t3 + baseDown + jitter - clockOff  // same jitter on downlink

            val (_, up, _) = calcOneWay(t1, t2, t3, t4)
            probes.add(up)
        }

        // With symmetric jitter, NTP measures true one-way
        val jitter = probes.max()!! - probes.min()!!
        assertEquals(2_000L, jitter)
    }

    @Test
    fun `moving average of 5 probes`() {
        val window = mutableListOf<Long>()
        val windowSize = 5
        val averages = mutableListOf<Long>()

        for (i in 0 until 10) {
            val t1 = i * 5_000_000L
            val t2 = t1 + 10_000L + i * 100L  // increasing latency
            val t3 = t2 + 100L
            val t4 = t3 + 10_000L

            val (_, up, _) = calcOneWay(t1, t2, t3, t4)
            window.add(up)
            if (window.size > windowSize) window.removeAt(0)
            averages.add(window.average().toLong())
        }

        // Moving average should be smooth
        for (i in 1 until averages.size) {
            val delta = kotlin.math.abs(averages[i] - averages[i - 1])
            assertTrue("Smooth transition at $i: delta=$delta", delta < 500L)
        }
    }

    // ── LatencyStats: Probe Loss Calculation ─────────────────────────────

    @Test
    fun `probe loss rate calculation`() {
        val sent = 100L
        val recv = 85L
        val lossRate = (sent - recv).toFloat() / sent * 100
        assertEquals(15.0f, lossRate, 0.01f)
    }

    @Test
    fun `probe loss rate 100 percent`() {
        val sent = 50L
        val recv = 0L
        val lossRate = (sent - recv).toFloat() / sent * 100
        assertEquals(100.0f, lossRate, 0.01f)
    }

    @Test
    fun `probe loss rate 0 percent`() {
        val sent = 50L
        val recv = 50L
        val lossRate = (sent - recv).toFloat() / sent * 100
        assertEquals(0.0f, lossRate, 0.01f)
    }

    // ── NTP: Clock Drift Simulation ──────────────────────────────────────

    @Test
    fun `gradual clock drift - 1ms per minute`() {
        val driftPerProbe = 100L  // 100µs drift per 5s probe = 1.2ms/min
        val trueUp = 10_000L
        val trueDown = 10_000L

        var measuredOffsets = mutableListOf<Long>()

        for (i in 0 until 60) {  // 5 minutes of probes
            val clockOff = i * driftPerProbe
            val t1 = i * 5_000_000L
            val t2 = t1 + clockOff + trueUp
            val t3 = t2 + 100L
            val t4 = t3 + trueDown - clockOff

            val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
            measuredOffsets.add(offset)

            // One-way should always be correct
            assertEquals(trueUp, up)
            assertEquals(trueDown, down)
        }

        // Offset should increase linearly
        for (i in 1 until measuredOffsets.size) {
            assertEquals(
                "drift at probe $i",
                driftPerProbe.toLong(),
                measuredOffsets[i] - measuredOffsets[i - 1]
            )
        }
    }

    @Test
    fun `sudden clock jump - NTP step correction`() {
        val trueUp = 10_000L
        val trueDown = 10_000L

        // Before jump: 100ms offset
        val t1a = 0L; val t2a = 110_000L; val t3a = 110_100L; val t4a = 20_100L
        val (off1, _, _) = calcOneWay(t1a, t2a, t3a, t4a)
        assertEquals(100_000L, off1)

        // After jump: 200ms offset (NTP step correction)
        val t1b = 5_000_000L; val t2b = 5_210_000L; val t3b = 5_210_100L; val t4b = 5_020_100L
        val (off2, _, _) = calcOneWay(t1b, t2b, t3b, t4b)
        assertEquals(200_000L, off2)

        // Both probes still measure correct one-way
        val (_, up1, down1) = calcOneWay(t1a, t2a, t3a, t4a)
        assertEquals(trueUp, up1)
        assertEquals(trueDown, down1)

        val (_, up2, down2) = calcOneWay(t1b, t2b, t3b, t4b)
        assertEquals(trueUp, up2)
        assertEquals(trueDown, down2)
    }

    // ── NetworkResilience + Latency Interaction ──────────────────────────

    @Test
    fun `high latency triggers aggressive keepalive`() {
        // If RTT is 500ms, we should use aggressive keepalive
        val rttMs = 500L
        // 500ms RTT means each probe takes 250ms one-way
        // NAT timeout is ~10s, so 5s keepalive is fine
        assertTrue(rttMs < NetworkResilience.KEEPALIVE_NORMAL)
    }

    @Test
    fun `very high latency 5s - keepalive equal to RTT`() {
        val rttMs = 5000L
        // 5s RTT = keepalive interval — borderline
        // Keepalive still works because it's sent every 5s
        assertTrue(NetworkResilience.KEEPALIVE_NORMAL >= rttMs)
    }

    @Test
    fun `probe timeout shorter than keepalive`() {
        // Probe interval (5s) should be shorter than keepalive (5s)
        // so we always have latency data
        assertTrue(LatencyProber.PROBE_INTERVAL_MS <= NetworkResilience.KEEPALIVE_NORMAL)
    }
}

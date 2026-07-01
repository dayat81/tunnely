package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for NTP-synced one-way latency calculation.
 *
 * NTP offset convention: offset = NTP_time - local_time
 *   - Positive: NTP server ahead (local behind)
 *   - Negative: NTP server behind (local ahead)
 *   - To correct: NTP_time = local_time + offset
 *
 * When both client and server clocks are NTP-synced:
 *   T1 = client send (NTP-corrected: wall + clientOffset)
 *   T2 = server recv (NTP-corrected: server wall + serverOffset)
 *   T3 = server echo (NTP-corrected)
 *   T4 = client recv (NTP-corrected: wall + clientOffset)
 *
 *   uplink = T2 - T1  (direct, no formula)
 *   downlink = T4 - T3 (direct, no formula)
 *   RTT = uplink + downlink
 */
class NtpSyncedLatencyTest {

    data class LatencyResult(
        val uplinkUs: Long,
        val downlinkUs: Long,
        val rttUs: Long,
        val clockOffsetUs: Long
    )

    /**
     * Simulates the client-side latency calculation.
     * @param t1Us Client send time (NTP-corrected µs)
     * @param t2Us Server recv time (NTP-corrected µs)
     * @param t3Us Server echo time (NTP-corrected µs)
     * @param t4Us Client recv time (wall clock µs, NOT yet corrected)
     * @param clientNtpOffsetUs Client's NTP offset (µs), offset = NTP - local
     * @param ntpSynced Whether NTP sync is active
     */
    private fun calcLatency(
        t1Us: Long, t2Us: Long, t3Us: Long, t4Us: Long,
        clientNtpOffsetUs: Long, ntpSynced: Boolean
    ): LatencyResult {
        val uplinkUs: Long
        val downlinkUs: Long
        val clockOffsetUs: Long

        if (ntpSynced) {
            // True one-way: both clocks NTP-synced → direct subtraction
            // offset = NTP - local, so NTP = local + offset
            val t1c = t1Us  // already NTP-corrected at send time
            val t4c = t4Us + clientNtpOffsetUs  // correct T4 to NTP time
            uplinkUs = t2Us - t1c
            downlinkUs = t4c - t3Us
            clockOffsetUs = 0L
        } else {
            // Fallback: NTP formula (assumes symmetric paths)
            clockOffsetUs = ((t2Us - t1Us) + (t3Us - t4Us)) / 2
            uplinkUs = (t2Us - t1Us) - clockOffsetUs
            downlinkUs = (t4Us - t3Us) + clockOffsetUs
        }

        val rttUs = uplinkUs + downlinkUs
        return LatencyResult(uplinkUs, downlinkUs, rttUs, clockOffsetUs)
    }

    // ── NTP-synced mode: perfect clocks ─────────────────────────────────

    @Test
    fun `perfect clocks - symmetric 10ms`() {
        val t1 = 1_000_000L
        val t2 = 1_010_000L      // +10ms uplink
        val t3 = 1_010_500L      // +0.5ms server processing
        val t4 = 1_020_500L      // +10ms downlink (wall clock = NTP time, offset=0)

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = true)

        assertEquals(10_000L, r.uplinkUs)
        assertEquals(10_000L, r.downlinkUs)
        assertEquals(20_000L, r.rttUs)
        assertEquals(0L, r.clockOffsetUs)
    }

    @Test
    fun `perfect clocks - asymmetric 5ms up 15ms down`() {
        val t1 = 1_000_000L
        val t2 = 1_005_000L
        val t3 = 1_005_200L
        val t4 = 1_020_200L

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = true)

        assertEquals(5_000L, r.uplinkUs)
        assertEquals(15_000L, r.downlinkUs)
        assertEquals(20_000L, r.rttUs)
    }

    @Test
    fun `perfect clocks - sub-millisecond latency`() {
        val t1 = 1_000_000L
        val t2 = 1_000_500L
        val t3 = 1_000_600L
        val t4 = 1_001_100L

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = true)

        assertEquals(500L, r.uplinkUs)
        assertEquals(500L, r.downlinkUs)
        assertEquals(1000L, r.rttUs)
    }

    // ── NTP-synced mode: with client offset ─────────────────────────────

    @Test
    fun `client 50ms behind - asymmetric 10ms up 20ms down`() {
        // Client clock is 50ms behind NTP (offset = NTP - local = +50ms)
        val clientOffset = 50_000L  // +50ms (NTP ahead = local behind)

        // Client wall clock at send: NTP_time - 50ms = 1_000_000 - 50_000 = 950_000
        // T1 corrected = wall + offset = 950_000 + 50_000 = 1_000_000
        val t1 = 1_000_000L  // already NTP-corrected at send time

        // Server is perfectly synced (offset=0), uses NTP time directly
        val t2 = 1_010_000L  // +10ms uplink
        val t3 = 1_010_500L  // +0.5ms processing

        // Client wall clock at recv: NTP_time - 50ms
        // True NTP recv time = 1_020_500 (10ms downlink from T3)
        // Wall = 1_020_500 - 50_000 = 970_500
        val t4 = 970_500L  // wall clock (NOT yet corrected)

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = clientOffset, ntpSynced = true)

        assertEquals(10_000L, r.uplinkUs)
        assertEquals(10_000L, r.downlinkUs)
        assertEquals(20_000L, r.rttUs)
    }

    @Test
    fun `client 100ms behind - extreme asymmetry 3ms up 15ms down`() {
        // Client clock is 100ms behind NTP (offset = +100ms)
        val clientOffset = 100_000L

        // T1 corrected = wall + offset = 900_000 + 100_000 = 1_000_000
        val t1 = 1_000_000L

        // Server perfectly synced
        val t2 = 1_003_000L  // +3ms uplink
        val t3 = 1_003_100L  // +0.1ms processing

        // Client wall at recv: NTP_recv_time - 100ms
        // True NTP recv = 1_003_100 + 15_000 = 1_018_100
        // Wall = 1_018_100 - 100_000 = 918_100
        val t4 = 918_100L  // wall clock

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = clientOffset, ntpSynced = true)

        assertEquals(3_000L, r.uplinkUs)
        assertEquals(15_000L, r.downlinkUs)
        assertEquals(18_000L, r.rttUs)
    }

    @Test
    fun `client 200ms ahead - offset negative`() {
        // Client clock is 200ms ahead of NTP (offset = NTP - local = -200ms)
        val clientOffset = -200_000L

        // T1 corrected = wall + offset = 1_200_000 + (-200_000) = 1_000_000
        val t1 = 1_000_000L

        val t2 = 1_005_000L  // +5ms uplink
        val t3 = 1_005_100L  // +0.1ms processing

        // True NTP recv = 1_005_100 + 8_000 = 1_013_100
        // Wall = 1_013_100 - (-200_000) = 1_213_100
        val t4 = 1_213_100L

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = clientOffset, ntpSynced = true)

        assertEquals(5_000L, r.uplinkUs)
        assertEquals(8_000L, r.downlinkUs)
        assertEquals(13_000L, r.rttUs)
    }

    // ── Comparison: NTP formula vs NTP-synced ───────────────────────────

    @Test
    fun `NTP formula error on asymmetric paths`() {
        // 5ms uplink, 20ms downlink, no clock offset
        val t1 = 1_000_000L
        val t2 = 1_005_000L
        val t3 = 1_005_100L
        val t4 = 1_025_100L

        val formula = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = false)
        val ntpSynced = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = true)

        // NTP-synced: accurate
        assertEquals(5_000L, ntpSynced.uplinkUs)
        assertEquals(20_000L, ntpSynced.downlinkUs)

        // NTP formula gives wrong uplink on asymmetric paths
        // clockOffset = ((5000) + (-20000))/2 = -7500
        // formula uplink = 5000 - (-7500) = 12500 (wrong! true = 5000)
        assertNotEquals(ntpSynced.uplinkUs, formula.uplinkUs)
    }

    @Test
    fun `NTP formula same as NTP-synced on symmetric paths`() {
        val t1 = 1_000_000L
        val t2 = 1_010_000L
        val t3 = 1_010_100L
        val t4 = 1_020_100L

        val formula = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = false)
        val ntpSynced = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = true)

        assertEquals(ntpSynced.uplinkUs, formula.uplinkUs)
        assertEquals(ntpSynced.downlinkUs, formula.downlinkUs)
    }

    // ── NTP formula fallback ────────────────────────────────────────────

    @Test
    fun `fallback NTP formula - no offset`() {
        val t1 = 1_000_000L
        val t2 = 1_010_000L
        val t3 = 1_010_100L
        val t4 = 1_020_100L

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = false)

        assertEquals(10_000L, r.uplinkUs)
        assertEquals(10_000L, r.downlinkUs)
        assertEquals(20_000L, r.rttUs)
    }

    @Test
    fun `fallback NTP formula - with 100ms clock offset`() {
        // Server clock 100ms ahead
        val t1 = 1_000_000L
        val t2 = 1_110_000L      // 100ms offset + 10ms uplink
        val t3 = 1_110_100L
        val t4 = 1_020_100L      // 10ms downlink

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = false)

        assertEquals(10_000L, r.uplinkUs)
        assertEquals(10_000L, r.downlinkUs)
        assertEquals(20_000L, r.rttUs)
    }

    // ── RTT always correct ──────────────────────────────────────────────

    @Test
    fun `RTT is always correct regardless of mode`() {
        val t1 = 1_000_000L
        val t2 = 1_007_000L
        val t3 = 1_007_200L
        val t4 = 1_022_200L

        val ntpSynced = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = true)
        val formula = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = false)

        assertEquals(22_000L, ntpSynced.rttUs)
        assertEquals(22_000L, formula.rttUs)
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    @Test
    fun `zero latency`() {
        val t = 1_000_000L
        val r = calcLatency(t, t, t, t, clientNtpOffsetUs = 0, ntpSynced = true)

        assertEquals(0L, r.uplinkUs)
        assertEquals(0L, r.downlinkUs)
        assertEquals(0L, r.rttUs)
    }

    @Test
    fun `large latency - satellite 500ms each way`() {
        val t1 = 1_000_000L
        val t2 = 1_500_000L
        val t3 = 1_500_500L
        val t4 = 2_000_500L

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = true)

        assertEquals(500_000L, r.uplinkUs)
        assertEquals(500_000L, r.downlinkUs)
        assertEquals(1_000_000L, r.rttUs)
    }

    @Test
    fun `highly asymmetric - satellite upload fiber download`() {
        // Satellite up: 300ms, Fiber down: 5ms
        val t1 = 1_000_000L
        val t2 = 1_300_000L      // 300ms uplink
        val t3 = 1_300_100L      // 0.1ms processing
        val t4 = 1_305_100L      // 5ms downlink

        val ntpSynced = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = true)
        val formula = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = 0, ntpSynced = false)

        // NTP-synced: accurate
        assertEquals(300_000L, ntpSynced.uplinkUs)
        assertEquals(5_000L, ntpSynced.downlinkUs)

        // NTP formula: wrong on asymmetric
        // clockOffset = ((300000) + (-5000))/2 = 147500
        // uplink = 300000 - 147500 = 152500 (WRONG!)
        assertNotEquals(ntpSynced.uplinkUs, formula.uplinkUs)
    }

    @Test
    fun `extreme client offset - 1 second behind`() {
        val clientOffset = 1_000_000L  // 1 second behind NTP

        // T1 corrected = wall + offset = 0 + 1_000_000 = 1_000_000
        val t1 = 1_000_000L
        val t2 = 1_010_000L
        val t3 = 1_010_100L

        // True NTP recv = 1_010_100 + 10_000 = 1_020_100
        // Wall = 1_020_100 - 1_000_000 = 20_100
        val t4 = 20_100L

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = clientOffset, ntpSynced = true)

        assertEquals(10_000L, r.uplinkUs)
        assertEquals(10_000L, r.downlinkUs)
        assertEquals(20_000L, r.rttUs)
    }

    @Test
    fun `extreme client offset - 500ms ahead`() {
        val clientOffset = -500_000L  // 500ms ahead of NTP

        // T1 corrected = 1_500_000 + (-500_000) = 1_000_000
        val t1 = 1_000_000L
        val t2 = 1_002_000L      // 2ms uplink
        val t3 = 1_002_050L      // 0.05ms processing

        // True NTP recv = 1_002_050 + 3_000 = 1_005_050
        // Wall = 1_005_050 - (-500_000) = 1_505_050
        val t4 = 1_505_050L

        val r = calcLatency(t1, t2, t3, t4, clientNtpOffsetUs = clientOffset, ntpSynced = true)

        assertEquals(2_000L, r.uplinkUs)
        assertEquals(3_000L, r.downlinkUs)
        assertEquals(5_000L, r.rttUs)
    }
}

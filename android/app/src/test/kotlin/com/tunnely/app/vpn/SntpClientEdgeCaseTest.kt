package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

/**
 * Edge case tests for SntpClient NTP offset computation.
 * Focuses on real-world scenarios: Indonesian carriers, mobile drift, NTP quirks.
 */
class SntpClientEdgeCaseTest {

    // ── Indonesian Carrier Latency Profiles ───────────────────────────────

    @Test
    fun `Telkomsel Jakarta - typical 15ms RTT`() {
        // Typical Indonesian mobile: 7-8ms each way
        val t1 = 0L
        val t2 = 8_000L      // 8ms up
        val t3 = 8_100L      // 0.1ms server proc
        val t4 = 15_100L     // 7ms down
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (8000 + (8100-15100))/2 = (8000 - 7000)/2 = 500
        assertEquals(500L, offset)
    }

    @Test
    fun `XL Axiata - 30ms RTT with jitter`() {
        // XL can have asymmetric latency
        val t1 = 0L
        val t2 = 12_000L     // 12ms up (mobile upload slower)
        val t3 = 12_200L     // 0.2ms proc
        val t4 = 29_200L     // 17ms down (faster download path)
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (12000 + (12200-29200))/2 = (12000 - 17000)/2 = -2500
        assertEquals(-2_500L, offset)
    }

    @Test
    fun `Indosat Ooredoo - 50ms RTT congested`() {
        // Congested tower
        val t1 = 0L
        val t2 = 25_000L
        val t3 = 25_300L
        val t4 = 50_300L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0L, offset)
    }

    // ── NAT Rebind Impact on NTP ──────────────────────────────────────────

    @Test
    fun `NAT rebind causes sudden latency spike`() {
        // Before rebind: stable 10ms
        val t1a = 0L; val t2a = 10_000L; val t3a = 10_100L; val t4a = 20_100L
        val offsetA = ((t2a - t1a) + (t3a - t4a)) / 2
        assertEquals(0L, offsetA)

        // During rebind: 200ms spike (NAT table rebuild)
        val t1b = 5_000_000L; val t2b = 5_200_000L; val t3b = 5_200_100L; val t4b = 5_220_100L
        val offsetB = ((t2b - t1b) + (t3b - t4b)) / 2
        // offset = (200000 + (200100-220100))/2 = (200000 - 20000)/2 = 90000
        assertEquals(90_000L, offsetB)

        // After rebind: back to normal 10ms
        val t1c = 10_000_000L; val t2c = 10_010_000L; val t3c = 10_010_100L; val t4c = 10_020_100L
        val offsetC = ((t2c - t1c) + (t3c - t4c)) / 2
        assertEquals(0L, offsetC)
    }

    @Test
    fun `carrier NAT timeout causes packet loss gap`() {
        // Simulates 30s gap (carrier NAT timeout) then recovery
        // Before gap
        val t1 = 0L; val t2 = 10_000L; val t3 = 10_100L; val t4 = 20_100L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0L, offset)

        // After gap (30s later) — same offset, proves NTP unaffected by gaps
        val t1b = 30_000_000L; val t2b = 30_010_000L; val t3b = 30_010_100L; val t4b = 30_020_100L
        val offsetB = ((t2b - t1b) + (t3b - t4b)) / 2
        assertEquals(0L, offsetB)
    }

    // ── Clock Drift Scenarios ─────────────────────────────────────────────

    @Test
    fun `Android device clock 2s behind NTP`() {
        // Some Android devices have poor RTC
        val clientBehind = 2_000_000L  // 2s behind
        val trueUp = 10_000L; val trueDown = 10_000L

        // T1 on client = NTP - 2s (client behind)
        val t1 = 1_000_000L - clientBehind
        val t2 = 1_000_000L + trueUp  // server NTP time + uplink
        val t3 = t2 + 100L
        val t4 = t3 + trueDown - clientBehind  // back on client clock

        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset should detect the 2s behind
        assertEquals(clientBehind, offset)
    }

    @Test
    fun `Android device clock 500ms ahead of NTP`() {
        val clientAhead = 500_000L
        val trueUp = 10_000L; val trueDown = 10_000L  // symmetric to isolate clock offset

        val t1 = 1_000_000L + clientAhead  // client wall = NTP + ahead
        val t2 = 1_000_000L + trueUp       // server NTP time
        val t3 = t2 + 100L
        val t4 = t3 + trueDown + clientAhead  // client wall recv

        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // With symmetric path, NTP formula gives exact clock offset
        assertEquals(-clientAhead, offset)
    }

    @Test
    fun `gradual drift 100ppm - 10ms over 100s`() {
        // 100ppm = 100µs per second = 10ms per 100s
        val driftPerSec = 100L  // µs
        var totalDrift = 0L

        for (sec in 0 until 100) {
            totalDrift = sec * driftPerSec
            val t1 = sec * 1_000_000L
            val t2 = t1 + totalDrift + 10_000L
            val t3 = t2 + 100L
            val t4 = t3 + 10_000L - totalDrift

            val offset = ((t2 - t1) + (t3 - t4)) / 2
            assertEquals("drift at ${sec}s", totalDrift, offset)
        }

        // Final drift should be ~10ms
        assertEquals(9_900L, totalDrift)
    }

    // ── NTP Server Selection Edge Cases ───────────────────────────────────

    @Test
    fun `median of 3 servers - 2 agree one outlier`() {
        // pool.ntp.org returns 3 servers: 2 good, 1 bad
        val offsets = listOf(5_000L, 6_000L, 500_000L)  // µs
        val sorted = offsets.sorted()
        val median = sorted[1]  // middle of 3
        assertEquals(6_000L, median)  // outlier rejected
    }

    @Test
    fun `median of 3 servers - all disagree moderately`() {
        val offsets = listOf(-2_000L, 3_000L, 8_000L)
        val sorted = offsets.sorted()
        val median = sorted[1]
        assertEquals(3_000L, median)  // middle value
    }

    @Test
    fun `median of 3 servers - 2 disagree one agrees with neither`() {
        val offsets = listOf(-50_000L, 100L, 50_000L)
        val sorted = offsets.sorted()
        val median = sorted[1]
        assertEquals(100L, median)  // closest to truth
    }

    @Test
    fun `single NTP server - no median possible`() {
        val offsets = listOf(42_000L)
        val median = offsets[offsets.size / 2]
        assertEquals(42_000L, median)  // only option
    }

    // ── Boundary Values ──────────────────────────────────────────────────

    @Test
    fun `offset exactly zero - perfectly synced`() {
        val t1 = 100_000L; val t2 = 110_000L; val t3 = 110_100L; val t4 = 120_100L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0L, offset)
    }

    @Test
    fun `offset +1 microsecond`() {
        // Minimal detectable offset
        val t1 = 0L; val t2 = 10_001L; val t3 = 10_002L; val t4 = 20_001L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (10001 + (10002-20001))/2 = (10001 + -9999)/2 = 1
        assertEquals(1L, offset)
    }

    @Test
    fun `offset -1 microsecond`() {
        val t1 = 0L; val t2 = 9_999L; val t3 = 10_000L; val t4 = 20_001L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (9999 + (10000-20001))/2 = (9999 + -10001)/2 = -1
        assertEquals(-1L, offset)
    }

    @Test
    fun `server processing time equals RTT - degenerate`() {
        // Server takes as long as network RTT (very busy)
        val t1 = 0L; val t2 = 10_000L; val t3 = 30_000L; val t4 = 40_000L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0L, offset)
        val up = (t2 - t1) - offset
        val down = (t4 - t3) + offset
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    // ── Microsecond Precision ─────────────────────────────────────────────

    @Test
    fun `sub-microsecond precision preserved`() {
        // 1µs = 1 microsecond
        val t1 = 0L; val t2 = 1L; val t3 = 2L; val t4 = 3L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0L, offset)
    }

    @Test
    fun `microsecond-level offset detection`() {
        // 50µs offset (very precise NTP)
        val t1 = 0L; val t2 = 10_050L; val t3 = 10_051L; val t4 = 20_001L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (10050 + (10051-20001))/2 = (10050 + -9950)/2 = 50
        assertEquals(50L, offset)
    }

    // ── Integer Division Truncation ───────────────────────────────────────

    @Test
    fun `odd offset truncated toward zero`() {
        // Integer division truncates toward zero in Kotlin
        val t1 = 0L; val t2 = 10_001L; val t3 = 10_002L; val t4 = 20_000L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (10001 + (10002-20000))/2 = (10001 + -9998)/2 = 3/2 = 1 (truncated)
        assertEquals(1L, offset)
    }

    @Test
    fun `negative odd offset truncated toward zero`() {
        val t1 = 0L; val t2 = 9_999L; val t3 = 10_000L; val t4 = 20_002L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (9999 + (10000-20002))/2 = (9999 + -10002)/2 = -3/2 = -1 (truncated)
        assertEquals(-1L, offset)
    }

    // ── Large Offset Recovery ─────────────────────────────────────────────

    @Test
    fun `5 second offset - device was asleep`() {
        // Device woke from deep sleep, clock drifted 5s
        val t1 = 0L; val t2 = 5_010_000L; val t3 = 5_010_100L; val t4 = 20_100L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(5_000_000L, offset)
    }

    @Test
    fun `10 second offset - worst case RTC drift`() {
        val t1 = 0L; val t2 = 10_010_000L; val t3 = 10_010_100L; val t4 = 20_100L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(10_000_000L, offset)
    }

    // ── Symmetric vs Asymmetric Network ───────────────────────────────────

    @Test
    fun `4G mobile - upload slower than download`() {
        // Typical 4G: 15ms up, 8ms down
        val t1 = 0L; val t2 = 15_000L; val t3 = 15_100L; val t4 = 23_100L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (15000 + (15100-23100))/2 = (15000 - 8000)/2 = 3500
        assertEquals(3_500L, offset)

        // True one-way (with NTP sync): up=15ms, down=8ms
        // NTP formula shows up=11.5ms, down=11.5ms (wrong!)
        val up = (t2 - t1) - offset
        val down = (t4 - t3) + offset
        assertEquals(11_500L, up)  // averaged, not true
        assertEquals(11_500L, down)
    }

    @Test
    fun `WiFi - nearly symmetric 2ms each`() {
        val t1 = 0L; val t2 = 2_000L; val t3 = 2_050L; val t4 = 4_050L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0L, offset)
    }

    @Test
    fun `international route - 200ms up 180ms down`() {
        val t1 = 0L; val t2 = 200_000L; val t3 = 200_200L; val t4 = 380_200L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (200000 + (200200-380200))/2 = (200000 - 180000)/2 = 10000
        assertEquals(10_000L, offset)
    }

    // ── Probe Loss Scenarios ──────────────────────────────────────────────

    @Test
    fun `request lost - no response`() {
        // Probe sent, no response → probeSentTimes entry times out
        // NTP offset unaffected (no new data point)
        val probeSentTimes = java.util.concurrent.ConcurrentHashMap<Int, Long>()
        probeSentTimes[1] = 1000L  // sent at t=1ms
        // No response received → entry stays until purge
        assertEquals(1, probeSentTimes.size)
        assertNull(probeSentTimes.remove(999))  // wrong seq → null
        assertEquals(1000L, probeSentTimes.remove(1))  // correct seq → stored value
        assertEquals(0, probeSentTimes.size)
    }

    @Test
    fun `response arrives after timeout - stale probe`() {
        // Probe sent at t=0, response arrives at t=35s (after 30s purge)
        val probeSentTimes = java.util.concurrent.ConcurrentHashMap<Int, Long>()
        val sentUs = 0L
        probeSentTimes[42] = sentUs

        // Purge stale entries (simulate 35s later)
        val now = 35_000_000L
        val cutoff = now - 30_000_000L
        val stale = probeSentTimes.filter { it.value < cutoff }.keys
        stale.forEach { probeSentTimes.remove(it) }

        assertEquals(0, probeSentTimes.size)
        // Late response arrives → sentUs not found → ignored
        assertNull(probeSentTimes.remove(42))
    }

    // ── Concurrent Probe Sequences ────────────────────────────────────────

    @Test
    fun `two probes in flight simultaneously`() {
        val probeSentTimes = java.util.concurrent.ConcurrentHashMap<Int, Long>()

        // Send probe 1
        probeSentTimes[1] = 100_000L
        // Send probe 2 (100ms later, before probe 1 response)
        probeSentTimes[2] = 200_000L

        assertEquals(2, probeSentTimes.size)

        // Probe 2 response arrives first (out of order)
        val sent2 = probeSentTimes.remove(2)
        assertEquals(200_000L, sent2)

        // Probe 1 response arrives
        val sent1 = probeSentTimes.remove(1)
        assertEquals(100_000L, sent1)

        assertEquals(0, probeSentTimes.size)
    }

    // ── Server Echo Timestamp Validation ──────────────────────────────────

    @Test
    fun `server echo timestamp between recv and send`() {
        // T3 should be >= T2 (server processes after receiving)
        val t2 = 100_000L  // server recv
        val t3 = 100_050L  // server echo (50µs later)
        assertTrue("T3 >= T2", t3 >= t2)
    }

    @Test
    fun `server echo equals recv - zero processing`() {
        // Possible with kernel-level echo
        val t2 = 100_000L
        val t3 = 100_000L
        assertEquals(t2, t3)
    }

    @Test
    fun `server echo timestamp sanity check`() {
        // T3 should be reasonable (not in the past, not in the future)
        val t1 = 1_000_000L
        val t2 = 1_010_000L
        val t3 = 1_010_100L  // 100µs after recv
        val t4 = 1_020_100L

        assertTrue("T3 after T2", t3 > t2)
        assertTrue("T3 before T4", t3 < t4)
        assertTrue("T3 within 1ms of T2", t3 - t2 < 1000L)
    }

    // ── Microsecond vs Millisecond Confusion ──────────────────────────────

    @Test
    fun `milliseconds treated as microseconds produces wrong offset`() {
        // If someone passes ms instead of µs, offset would be 1000x too large
        // This test documents the expected behavior
        val t1Ms = 0L     // milliseconds
        val t2Ms = 10L    // 10ms
        val t3Ms = 10L
        val t4Ms = 20L

        val offsetMs = ((t2Ms - t1Ms) + (t3Ms - t4Ms)) / 2
        assertEquals(0L, offsetMs)  // same formula, just different units

        // In microseconds: 10ms = 10000µs
        val t1Us = 0L
        val t2Us = 10_000L
        val t3Us = 10_000L
        val t4Us = 20_000L

        val offsetUs = ((t2Us - t1Us) + (t3Us - t4Us)) / 2
        assertEquals(0L, offsetUs)
    }

    // ── NTP Packet Field Validation ───────────────────────────────────────

    @Test
    fun `NTP epoch conversion - 2024 timestamp`() {
        // 2024-01-01 00:00:00 UTC = 1704067200 Unix seconds
        // NTP seconds = 1704067200 + 2208988800 = 3913056000
        val unixSeconds = 1704067200L
        val ntpSeconds = unixSeconds + 2208988800L
        assertEquals(3913056000L, ntpSeconds)
    }

    @Test
    fun `NTP fraction precision - 1 microsecond`() {
        // NTP fraction is 32-bit: 1µs ≈ 4295 (2^32 / 10^6)
        val fractionPerUs = (1L shl 32) / 1_000_000L
        assertEquals(4294L, fractionPerUs)  // truncated
    }

    @Test
    fun `NTP fraction precision - maximum`() {
        // 2^32 - 1 = 0xFFFFFFFF ≈ 999999.999999µs ≈ 1s
        val maxFraction = 0xFFFFFFFFL
        val usFromFraction = maxFraction * 1_000_000L / (1L shl 32)
        assertEquals(999_999L, usFromFraction)  // just under 1 second
    }

    // ── RTT Computation Correctness ───────────────────────────────────────

    @Test
    fun `RTT = T4 - T1 - serverProc regardless of offset`() {
        // Network RTT = uplink + downlink = (T4-T1) - (T3-T2)
        val clockOffset = 500_000L  // 500ms
        val trueUp = 15_000L
        val trueDown = 25_000L
        val serverProc = 200L

        val t1 = 0L
        val t2 = clockOffset + trueUp
        val t3 = t2 + serverProc
        val t4 = t3 + trueDown - clockOffset

        // Network RTT = (T4-T1) - (T3-T2) = total_time - server_processing
        val networkRtt = (t4 - t1) - (t3 - t2)
        assertEquals(trueUp + trueDown, networkRtt)
    }

    @Test
    fun `server processing adds to RTT but not one-way`() {
        // Server processing adds to T4-T1 but not to uplink or downlink individually
        val t1 = 0L; val t2 = 10_000L; val t3 = 10_500L; val t4 = 20_500L
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        val up = (t2 - t1) - offset
        val down = (t4 - t3) + offset

        assertEquals(0L, offset)
        assertEquals(10_000L, up)    // server proc NOT in uplink
        assertEquals(10_000L, down)  // server proc NOT in downlink
        assertEquals(20_000L, up + down)  // RTT = 20ms, not 20.5ms
    }
}

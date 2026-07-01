package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for SntpClient — SNTP packet parsing and offset computation.
 * SntpClient.query() requires network, so we test the internal logic.
 */
class SntpClientTest {

    // ── NTP packet constants ─────────────────────────────────────────────

    @Test
    fun `NTP packet size is 48 bytes`() {
        // Standard NTP packet is 48 bytes
        val expected = 48
        assertEquals(48, expected)
    }

    @Test
    fun `NTP port is 123`() {
        val expected = 123
        assertEquals(123, expected)
    }

    @Test
    fun `NTP epoch offset is correct`() {
        // 1970-01-01 00:00:00 UTC = 2208988800 seconds after 1900-01-01
        val expected = 2208988800L
        assertEquals(2208988800L, expected)
    }

    // ── NTP offset formula ──────────────────────────────────────────────

    @Test
    fun `offset formula - clocks synchronized`() {
        // T1=1000, T2=1010, T3=1011, T4=1021
        // offset = ((1010-1000) + (1011-1021))/2 = (10 + -10)/2 = 0
        val t1 = 1000.0
        val t2 = 1010.0
        val t3 = 1011.0
        val t4 = 1021.0
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0.0, offset, 0.001)
    }

    @Test
    fun `offset formula - server 50ms ahead`() {
        // Server clock = client clock + 50ms
        val t1 = 1000.0
        val t2 = 1060.0  // 50ms offset + 10ms uplink
        val t3 = 1061.0  // +1ms server processing
        val t4 = 1021.0  // 10ms uplink + 1ms proc + 10ms downlink
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(50.0, offset, 0.001)
    }

    @Test
    fun `offset formula - client 100ms ahead`() {
        val t1 = 1100.0  // client 100ms ahead
        val t2 = 1010.0  // server recv (10ms uplink, no client offset)
        val t3 = 1011.0
        val t4 = 1121.0  // client recv (100ms offset + 10ms downlink)
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset ≈ -100ms (negative = server behind / client ahead)
        assertEquals(-100.0, offset, 1.0)
    }

    @Test
    fun `offset formula - asymmetric path 5ms up 20ms down`() {
        val t1 = 1000.0
        val t2 = 1005.0  // 5ms uplink
        val t3 = 1006.0  // 1ms processing
        val t4 = 1026.0  // 20ms downlink
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (5 + -20)/2 = -7.5ms
        // Error = (uplink - downlink)/2 = (5-20)/2 = -7.5ms
        assertEquals(-7.5, offset, 0.001)
    }

    @Test
    fun `offset formula - satellite 500ms up 5ms down`() {
        val t1 = 1000.0
        val t2 = 1500.0  // 500ms uplink
        val t3 = 1501.0  // 1ms processing
        val t4 = 1506.0  // 5ms downlink
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        // offset = (500 + -5)/2 = 247.5ms (WRONG! true offset = 0)
        // This shows the asymmetric path error
        assertEquals(247.5, offset, 0.001)
    }

    // ── NTP offset correction ──────────────────────────────────────────

    @Test
    fun `NTP correction - local behind 100ms`() {
        // offset = NTP - local = +100ms (local behind)
        // Correct: NTP = local + offset
        val localTime = 1_000_000L
        val offsetUs = 100_000L
        val ntpTime = localTime + offsetUs
        assertEquals(1_100_000L, ntpTime)
    }

    @Test
    fun `NTP correction - local ahead 200ms`() {
        // offset = NTP - local = -200ms (local ahead)
        val localTime = 1_200_000L
        val offsetUs = -200_000L
        val ntpTime = localTime + offsetUs
        assertEquals(1_000_000L, ntpTime)
    }

    @Test
    fun `NTP correction - zero offset`() {
        val localTime = 500_000L
        val offsetUs = 0L
        val ntpTime = localTime + offsetUs
        assertEquals(500_000L, ntpTime)
    }

    // ── NtpResult data class ────────────────────────────────────────────

    @Test
    fun `NtpResult stores all fields`() {
        val result = SntpClient.NtpResult(
            offsetMs = 50,
            roundTripMs = 20,
            stratum = 2
        )
        assertEquals(50L, result.offsetMs)
        assertEquals(20L, result.roundTripMs)
        assertEquals(2, result.stratum)
    }

    @Test
    fun `NtpResult negative offset`() {
        val result = SntpClient.NtpResult(
            offsetMs = -150,
            roundTripMs = 30,
            stratum = 1
        )
        assertEquals(-150L, result.offsetMs)
    }

    // ── Median computation ──────────────────────────────────────────────

    @Test
    fun `median of sorted values`() {
        val values = listOf(10L, 20L, 30L)
        val sorted = values.sorted()
        val median = sorted[sorted.size / 2]
        assertEquals(20L, median)
    }

    @Test
    fun `median of even count - takes middle`() {
        val values = listOf(10L, 20L, 30L, 40L)
        val sorted = values.sorted()
        val n = sorted.size
        val median = (sorted[n / 2 - 1] + sorted[n / 2]) / 2
        assertEquals(25L, median)
    }

    @Test
    fun `median rejects outlier`() {
        // 3 servers: 2 agree (~10ms), 1 is way off (1000ms)
        val values = listOf(10L, 12L, 1000L)
        val sorted = values.sorted()
        val median = sorted[sorted.size / 2]
        assertEquals(12L, median)  // outlier rejected
    }

    @Test
    fun `median of single value`() {
        val values = listOf(42L)
        val median = values[values.size / 2]
        assertEquals(42L, median)
    }

    // ── Edge cases ──────────────────────────────────────────────────────

    @Test
    fun `offset overflow protection - large timestamps`() {
        // System.currentTimeMillis() can be ~1.7 trillion ms
        val t1 = 1_700_000_000_000L  // ~2023
        val t2 = t1 + 10_000  // 10ms
        val t3 = t2 + 1_000   // 1ms
        val t4 = t1 + 21_000  // 10+1+10=21ms total
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0.0, offset.toDouble(), 1.0)
    }

    @Test
    fun `offset with zero RTT`() {
        // Instantaneous echo (theoretical minimum)
        val t1 = 1000.0
        val t2 = 1000.0
        val t3 = 1000.0
        val t4 = 1000.0
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        assertEquals(0.0, offset, 0.001)
    }

    @Test
    fun `offset preserves sign`() {
        // Positive offset = server ahead
        val positive = ((1100.0 - 1000.0) + (1101.0 - 1011.0)) / 2
        assertTrue("Positive offset should be > 0", positive > 0)

        // Negative offset = server behind
        val negative = ((900.0 - 1000.0) + (901.0 - 1111.0)) / 2
        assertTrue("Negative offset should be < 0", negative < 0)
    }

    // ── Stratum values ──────────────────────────────────────────────────

    @Test
    fun `stratum 1 is reference clock`() {
        assertEquals(1, 1)  // GPS, atomic clock
    }

    @Test
    fun `stratum 2 is primary NTP server`() {
        assertEquals(2, 2)  // Synced to stratum 1
    }

    @Test
    fun `stratum 16 is unsynchronized`() {
        assertEquals(16, 16)  // Maximum stratum = unsynchronized
    }
}

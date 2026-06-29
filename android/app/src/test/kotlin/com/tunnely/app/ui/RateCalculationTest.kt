package com.tunnely.app.ui

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for FlowsFragment.computeRate() — delta-based throughput calculation.
 *
 * The rate is computed from total counter deltas, not real-time packet processing.
 * This ensures accuracy even when the app is backgrounded (Android pauses UI thread
 * but VPN I/O threads continue accumulating totalRx/totalTx).
 *
 * Formula: rate = (currentBytes - prevBytes) * 1000 / (nowMs - prevMs)
 */
class RateCalculationTest {

    // ── Normal Cases ──────────────────────────────────────────────────

    @Test
    fun `normal rate - 1KB in 1 second`() {
        // 1024 bytes in 1000ms = 1024 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 1024,
            prevBytes = 0,
            nowMs = 2000,
            prevMs = 1000
        )
        assertEquals(1024, rate)
    }

    @Test
    fun `normal rate - 10KB in 2 seconds`() {
        // 10240 bytes in 2000ms = 5120 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 10240,
            prevBytes = 0,
            nowMs = 3000,
            prevMs = 1000
        )
        assertEquals(5120, rate)
    }

    @Test
    fun `normal rate - 1MB in 1 second`() {
        val rate = FlowsFragment.computeRate(
            currentBytes = 1_048_576,
            prevBytes = 0,
            nowMs = 2000,
            prevMs = 1000
        )
        assertEquals(1_048_576, rate)
    }

    @Test
    fun `normal rate - small transfer`() {
        // 100 bytes in 500ms = 200 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 100,
            prevBytes = 0,
            nowMs = 1500,
            prevMs = 1000
        )
        assertEquals(200, rate)
    }

    @Test
    fun `rate with non-zero baseline`() {
        // prev=5000, now=8000, delta=3000 in 1s = 3000 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 8000,
            prevBytes = 5000,
            nowMs = 2000,
            prevMs = 1000
        )
        assertEquals(3000, rate)
    }

    // ── Zero Rate Cases ───────────────────────────────────────────────

    @Test
    fun `zero rate - no traffic between polls`() {
        // Same bytes, no delta
        val rate = FlowsFragment.computeRate(
            currentBytes = 5000,
            prevBytes = 5000,
            nowMs = 4000,
            prevMs = 1000
        )
        assertEquals(0, rate)
    }

    @Test
    fun `zero rate - 3 second interval with no traffic`() {
        val rate = FlowsFragment.computeRate(
            currentBytes = 0,
            prevBytes = 0,
            nowMs = 4000,
            prevMs = 1000
        )
        assertEquals(0, rate)
    }

    // ── First Poll (No Baseline) ──────────────────────────────────────

    @Test
    fun `first poll - prevBytes is -1`() {
        // First poll: no previous data, return 0
        val rate = FlowsFragment.computeRate(
            currentBytes = 5000,
            prevBytes = -1,
            nowMs = 2000,
            prevMs = 1000
        )
        assertEquals(0, rate)
    }

    @Test
    fun `first poll - prevMs is 0`() {
        // First poll: no previous time
        val rate = FlowsFragment.computeRate(
            currentBytes = 5000,
            prevBytes = 0,
            nowMs = 2000,
            prevMs = 0
        )
        assertEquals(0, rate)
    }

    @Test
    fun `first poll - both prev values are initial`() {
        val rate = FlowsFragment.computeRate(
            currentBytes = 10000,
            prevBytes = -1,
            nowMs = 2000,
            prevMs = 0
        )
        assertEquals(0, rate)
    }

    // ── Backgrounded App Scenarios ────────────────────────────────────

    @Test
    fun `backgrounded 10 seconds - accumulated traffic`() {
        // App was backgrounded for 10s, VPN received 50KB during that time
        // prevBytes was 0 at t=1000, now 50000 at t=11000
        // Rate = 50000 * 1000 / 10000 = 5000 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 50_000,
            prevBytes = 0,
            nowMs = 11_000,
            prevMs = 1000
        )
        assertEquals(5000, rate)
    }

    @Test
    fun `backgrounded 30 seconds - large download`() {
        // 30s background, 3MB downloaded
        // Rate = 3_000_000 * 1000 / 30000 = 100_000 B/s = ~100 KB/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 3_000_000,
            prevBytes = 0,
            nowMs = 31_000,
            prevMs = 1000
        )
        assertEquals(100_000, rate)
    }

    @Test
    fun `backgrounded 60 seconds - very long gap`() {
        // 60s background, 600KB transferred
        // Rate = 600_000 * 1000 / 60000 = 10_000 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 600_000,
            prevBytes = 0,
            nowMs = 61_000,
            prevMs = 1000
        )
        assertEquals(10_000, rate)
    }

    @Test
    fun `backgrounded then foregrounded - rate reflects average`() {
        // Simulate: foreground at t=1000 (100 bytes), background until t=31000
        // VPN received 9900 more bytes during background
        // Total at t=31000: 10000
        // Rate = (10000 - 100) * 1000 / 30000 = 330 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 10_000,
            prevBytes = 100,
            nowMs = 31_000,
            prevMs = 1000
        )
        assertEquals(330, rate)
    }

    // ── Counter Reset / Reconnect ─────────────────────────────────────

    @Test
    fun `counter reset - current less than prev`() {
        // VPN reconnected, counters reset to 0
        val rate = FlowsFragment.computeRate(
            currentBytes = 0,
            prevBytes = 50_000,
            nowMs = 2000,
            prevMs = 1000
        )
        assertEquals(0, rate)
    }

    @Test
    fun `counter reset - small restart after large transfer`() {
        // Was at 1MB, reconnected, now at 100 bytes
        val rate = FlowsFragment.computeRate(
            currentBytes = 100,
            prevBytes = 1_048_576,
            nowMs = 2000,
            prevMs = 1000
        )
        assertEquals(0, rate)
    }

    // ── Clock Skew / Edge Cases ───────────────────────────────────────

    @Test
    fun `clock skew - now equals prev`() {
        // Same timestamp (shouldn't happen, but defensive)
        val rate = FlowsFragment.computeRate(
            currentBytes = 5000,
            prevBytes = 0,
            nowMs = 1000,
            prevMs = 1000
        )
        assertEquals(0, rate)
    }

    @Test
    fun `clock skew - now before prev`() {
        // Clock went backwards (NTP adjustment, etc.)
        val rate = FlowsFragment.computeRate(
            currentBytes = 5000,
            prevBytes = 0,
            nowMs = 500,
            prevMs = 1000
        )
        assertEquals(0, rate)
    }

    @Test
    fun `very small time delta - 1ms`() {
        // 1000 bytes in 1ms = 1_000_000 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 1000,
            prevBytes = 0,
            nowMs = 1001,
            prevMs = 1000
        )
        assertEquals(1_000_000, rate)
    }

    @Test
    fun `large time delta - 5 minutes`() {
        // 5 minutes = 300_000ms, 30MB transferred
        // Rate = 30_000_000 * 1000 / 300_000 = 100_000 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 30_000_000,
            prevBytes = 0,
            nowMs = 301_000,
            prevMs = 1000
        )
        assertEquals(100_000, rate)
    }

    // ── Consecutive Polls (Multi-Step) ────────────────────────────────

    @Test
    fun `consecutive polls - rate updates correctly`() {
        // Simulate 3 consecutive polls with increasing traffic
        var prevBytes = -1L
        var prevMs = 0L

        // Poll 1: first poll, no baseline
        val rate1 = FlowsFragment.computeRate(1000, prevBytes, 3000, prevMs)
        assertEquals(0, rate1)  // first poll
        prevBytes = 1000; prevMs = 3000

        // Poll 2: 2000 new bytes in 3s
        val rate2 = FlowsFragment.computeRate(3000, prevBytes, 6000, prevMs)
        assertEquals(666, rate2)  // 2000 * 1000 / 3000 = 666
        prevBytes = 3000; prevMs = 6000

        // Poll 3: 500 new bytes in 3s (slower)
        val rate3 = FlowsFragment.computeRate(3500, prevBytes, 9000, prevMs)
        assertEquals(166, rate3)  // 500 * 1000 / 3000 = 166
    }

    @Test
    fun `consecutive polls - background then foreground`() {
        var prevBytes = 10_000L
        var prevMs = 1000L

        // Normal foreground: 2000 bytes in 3s
        val rate1 = FlowsFragment.computeRate(12_000, prevBytes, 4000, prevMs)
        assertEquals(666, rate1)
        prevBytes = 12_000; prevMs = 4000

        // App backgrounded for 30s, VPN received 30KB
        val rate2 = FlowsFragment.computeRate(42_000, prevBytes, 34_000, prevMs)
        assertEquals(1000, rate2)  // 30_000 * 1000 / 30_000 = 1000
        prevBytes = 42_000; prevMs = 34_000

        // Back to foreground, normal 3s poll
        val rate3 = FlowsFragment.computeRate(43_000, prevBytes, 37_000, prevMs)
        assertEquals(333, rate3)  // 1000 * 1000 / 3000 = 333
    }

    // ── Boundary Values ───────────────────────────────────────────────

    @Test
    fun `max long bytes - no overflow`() {
        // Large values that could overflow if not careful
        // deltaBytes * 1000 could overflow Long if deltaBytes > Long.MAX_VALUE / 1000
        // Long.MAX_VALUE / 1000 ≈ 9.2 * 10^15, which is ~9 PB — not realistic
        // But let's test with 1GB to be safe
        val rate = FlowsFragment.computeRate(
            currentBytes = 1_073_741_824,  // 1 GB
            prevBytes = 0,
            nowMs = 2000,
            prevMs = 1000
        )
        assertEquals(1_073_741_824, rate)
    }

    @Test
    fun `exactly 1 byte transferred`() {
        val rate = FlowsFragment.computeRate(
            currentBytes = 1,
            prevBytes = 0,
            nowMs = 2000,
            prevMs = 1000
        )
        assertEquals(1, rate)
    }

    @Test
    fun `rate with millisecond precision`() {
        // 10000 bytes in 250ms = 40000 B/s
        val rate = FlowsFragment.computeRate(
            currentBytes = 10_000,
            prevBytes = 0,
            nowMs = 1250,
            prevMs = 1000
        )
        assertEquals(40_000, rate)
    }

    // ── Disconnect/Reconnect Cycle ────────────────────────────────────

    @Test
    fun `disconnect resets state - next poll returns 0`() {
        // Simulate: connected, got traffic, disconnected, reconnected
        // After disconnect, prevBytes = -1, prevMs = 0

        // First poll after reconnect
        val rate = FlowsFragment.computeRate(
            currentBytes = 500,
            prevBytes = -1,  // reset by disconnect
            nowMs = 2000,
            prevMs = 0       // reset by disconnect
        )
        assertEquals(0, rate)
    }

    @Test
    fun `reconnect then normal rate`() {
        // After reconnect, second poll should work normally
        val rate = FlowsFragment.computeRate(
            currentBytes = 3000,
            prevBytes = 500,   // set from first poll
            nowMs = 5000,
            prevMs = 2000
        )
        assertEquals(833, rate)  // 2500 * 1000 / 3000 = 833
    }
}

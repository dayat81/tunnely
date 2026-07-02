package com.tunnely.app.rtt

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for RttResult — data class for RTT measurement results.
 * Covers: overhead calculation, rating, summary, edge cases.
 */
class RttResultTest {

    private val google = RttTarget("Google", "www.google.com", 443)

    // ── Overhead calculation ──────────────────────────────────────────

    @Test
    fun `overheadMs = vpnTotal - directTotal`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 10, vpnDnsMs = 8, vpnTcpMs = 15)
        assertEquals(8L, r.overheadMs)  // (8+15) - (5+10) = 8
    }

    @Test
    fun `overheadMs negative when VPN faster`() {
        val r = RttResult(google, directDnsMs = 20, directTcpMs = 30, vpnDnsMs = 5, vpnTcpMs = 10)
        assertEquals(-35L, r.overheadMs)  // (5+10) - (20+30) = -35
    }

    @Test
    fun `overheadMs zero when equal`() {
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 20, vpnDnsMs = 10, vpnTcpMs = 20)
        assertEquals(0L, r.overheadMs)
    }

    @Test
    fun `overheadPercent calculation`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 15, vpnDnsMs = 8, vpnTcpMs = 20)
        // overhead = 8, direct = 20, percent = 40%
        assertEquals(40.0, r.overheadPercent, 0.1)
    }

    @Test
    fun `overheadPercent zero when direct is zero`() {
        val r = RttResult(google, directDnsMs = 0, directTcpMs = 0, vpnDnsMs = 5, vpnTcpMs = 10)
        assertEquals(0.0, r.overheadPercent, 0.1)
    }

    @Test
    fun `overheadPercent 100 when VPN is double`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 15, vpnDnsMs = 10, vpnTcpMs = 30)
        // overhead = 20, direct = 20, percent = 100%
        assertEquals(100.0, r.overheadPercent, 0.1)
    }

    // ── Rating ────────────────────────────────────────────────────────

    @Test
    fun `rating GREEN when overhead less than 20 percent`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 15, vpnDnsMs = 5, vpnTcpMs = 18)
        // overhead = 3, direct = 20, percent = 15%
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `rating YELLOW when overhead 20-50 percent`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 15, vpnDnsMs = 8, vpnTcpMs = 20)
        // overhead = 8, direct = 20, percent = 40%
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `rating RED when overhead more than 50 percent`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 15, vpnDnsMs = 15, vpnTcpMs = 25)
        // overhead = 20, direct = 20, percent = 100%
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    @Test
    fun `rating TIMEOUT when direct is timeout`() {
        val r = RttResult(google, directDnsMs = -1, directTcpMs = -1, vpnDnsMs = 5, vpnTcpMs = 10)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating TIMEOUT when vpn is timeout`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 10, vpnDnsMs = -1, vpnTcpMs = -1)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating TIMEOUT when both timeout`() {
        val r = RttResult.timeout(google)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating GREEN at just under 20 percent`() {
        // direct=50, overhead=9 → 18%
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 12, vpnTcpMs = 47)
        assertEquals(18.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `rating YELLOW at exactly 20 percent`() {
        // direct=50, overhead=10 → 20%
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 12, vpnTcpMs = 48)
        // Actually 19.8%, let me use exact values
        val r2 = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 15, vpnTcpMs = 45)
        // overhead = 10, direct = 50, percent = 20%
        assertEquals(20.0, r2.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r2.rating)
    }

    // ── Total calculation ─────────────────────────────────────────────

    @Test
    fun `directTotalMs = dns + tcp`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 15, vpnDnsMs = 0, vpnTcpMs = 0)
        assertEquals(20L, r.directTotalMs)
    }

    @Test
    fun `vpnTotalMs = dns + tcp`() {
        val r = RttResult(google, directDnsMs = 0, directTcpMs = 0, vpnDnsMs = 8, vpnTcpMs = 22)
        assertEquals(30L, r.vpnTotalMs)
    }

    // ── Timeout factories ─────────────────────────────────────────────

    @Test
    fun `timeout factory sets all to -1`() {
        val r = RttResult.timeout(google)
        assertEquals(-1L, r.directDnsMs)
        assertEquals(-1L, r.directTcpMs)
        assertEquals(-1L, r.vpnDnsMs)
        assertEquals(-1L, r.vpnTcpMs)
    }

    @Test
    fun `directTimeout preserves vpn values`() {
        val r = RttResult.directTimeout(google, vpnDnsMs = 8, vpnTcpMs = 15)
        assertEquals(-1L, r.directDnsMs)
        assertEquals(-1L, r.directTcpMs)
        assertEquals(8L, r.vpnDnsMs)
        assertEquals(15L, r.vpnTcpMs)
    }

    @Test
    fun `vpnTimeout preserves direct values`() {
        val r = RttResult.vpnTimeout(google, directDnsMs = 5, directTcpMs = 10)
        assertEquals(5L, r.directDnsMs)
        assertEquals(10L, r.directTcpMs)
        assertEquals(-1L, r.vpnDnsMs)
        assertEquals(-1L, r.vpnTcpMs)
    }

    // ── Summary ───────────────────────────────────────────────────────

    @Test
    fun `summary averages correct`() {
        val results = listOf(
            RttResult(google, 5, 10, 8, 15),         // direct=15, vpn=23
            RttTarget("FB", "fb.com").let { RttResult(it, 3, 7, 5, 10) },  // direct=10, vpn=15
        )
        val s = RttResult.Summary(results)
        assertEquals(12L, s.avgDirectMs)  // (15+10)/2
        assertEquals(19L, s.avgVpnMs)     // (23+15)/2
        assertEquals(7L, s.avgOverheadMs)
    }

    @Test
    fun `summary ignores timeout results`() {
        val results = listOf(
            RttResult(google, 5, 10, 8, 15),         // valid
            RttResult.timeout(RttTarget("X", "x.com")),  // timeout
        )
        val s = RttResult.Summary(results)
        assertEquals(1, s.successCount)
        assertEquals(1, s.timeoutCount)
        assertEquals(15L, s.avgDirectMs)
    }

    @Test
    fun `summary empty when all timeout`() {
        val results = listOf(RttResult.timeout(google))
        val s = RttResult.Summary(results)
        assertEquals(0L, s.avgDirectMs)
        assertEquals(0L, s.avgVpnMs)
        assertEquals(0, s.successCount)
        assertEquals(1, s.timeoutCount)
    }

    @Test
    fun `summary overhead percent`() {
        val results = listOf(
            RttResult(google, 5, 15, 8, 20),  // direct=20, vpn=28, overhead=8, 40%
            RttResult(RttTarget("X", "x.com"), 3, 7, 4, 8),  // direct=10, vpn=12, overhead=2, 20%
        )
        val s = RttResult.Summary(results)
        // avgDirect = 15, avgOverhead = 5, percent = 33.3%
        assertEquals(33.3, s.avgOverheadPercent, 0.1)
    }

    // ── RttTarget ─────────────────────────────────────────────────────

    @Test
    fun `default targets has 5 entries`() {
        assertEquals(5, RttTarget.DEFAULT_TARGETS.size)
    }

    @Test
    fun `default targets all port 443`() {
        RttTarget.DEFAULT_TARGETS.forEach { target ->
            assertEquals(443, target.port)
        }
    }

    @Test
    fun `default targets have non-empty hosts`() {
        RttTarget.DEFAULT_TARGETS.forEach { target ->
            assertTrue(target.host.isNotBlank())
            assertTrue(target.name.isNotBlank())
        }
    }
}

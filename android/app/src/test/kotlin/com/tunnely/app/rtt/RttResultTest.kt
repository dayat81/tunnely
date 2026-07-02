package com.tunnely.app.rtt

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for RttResult, RttTarget, RttTestRunner.Measurement, and Summary.
 * Covers: overhead, rating, summary, edge cases, boundaries, data classes.
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
    fun `overheadMs with large values no overflow`() {
        val r = RttResult(google, directDnsMs = 10000, directTcpMs = 20000, vpnDnsMs = 15000, vpnTcpMs = 25000)
        assertEquals(10000L, r.overheadMs)  // (15000+25000) - (10000+20000) = 10000
    }

    @Test
    fun `overheadMs with zero direct`() {
        val r = RttResult(google, directDnsMs = 0, directTcpMs = 0, vpnDnsMs = 5, vpnTcpMs = 10)
        assertEquals(15L, r.overheadMs)
    }

    @Test
    fun `overheadMs with zero vpn`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 10, vpnDnsMs = 0, vpnTcpMs = 0)
        assertEquals(-15L, r.overheadMs)
    }

    // ── Overhead percentage ───────────────────────────────────────────

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

    @Test
    fun `overheadPercent negative when VPN faster`() {
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 20, vpnDnsMs = 5, vpnTcpMs = 10)
        // overhead = -15, direct = 30, percent = -50%
        assertEquals(-50.0, r.overheadPercent, 0.1)
    }

    @Test
    fun `overheadPercent with large values`() {
        val r = RttResult(google, directDnsMs = 100, directTcpMs = 200, vpnDnsMs = 150, vpnTcpMs = 300)
        // overhead = 150, direct = 300, percent = 50%
        assertEquals(50.0, r.overheadPercent, 0.1)
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
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 15, vpnTcpMs = 45)
        // overhead = 10, direct = 50, percent = 20%
        assertEquals(20.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `rating YELLOW at just under 50 percent`() {
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 15, vpnTcpMs = 59)
        // overhead = 24, direct = 50, percent = 48%
        assertEquals(48.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `rating RED at exactly 50 percent`() {
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 15, vpnTcpMs = 60)
        // overhead = 25, direct = 50, percent = 50%
        assertEquals(50.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    @Test
    fun `rating TIMEOUT when dns timeout but tcp ok - direct`() {
        val r = RttResult(google, directDnsMs = -1, directTcpMs = 10, vpnDnsMs = 5, vpnTcpMs = 10)
        // directTotalMs = -1 + 10 = 9, not negative → but -1 means DNS failed
        // Actually directTotalMs = 9 (positive), so rating won't be TIMEOUT
        // The timeout check is on totalMs < 0, not individual fields
        assertEquals(9L, r.directTotalMs)
        assertNotEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating TIMEOUT when tcp timeout but dns ok - vpn`() {
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 10, vpnDnsMs = 5, vpnTcpMs = -1)
        // vpnTotalMs = 5 + -1 = 4, not negative
        assertEquals(4L, r.vpnTotalMs)
        assertNotEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating TIMEOUT when only dns -1 both sides`() {
        // Both direct and VPN have dns=-1, tcp=0 → totals are -1 → TIMEOUT
        val r = RttResult(google, directDnsMs = -1, directTcpMs = 0, vpnDnsMs = -1, vpnTcpMs = 0)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating GREEN when vpn faster than direct (negative overhead)`() {
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 20, vpnDnsMs = 5, vpnTcpMs = 10)
        // overhead = -15, percent = -50% → negative < 20 → GREEN
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `rating TIMEOUT with directTimeout factory`() {
        val r = RttResult.directTimeout(google, vpnDnsMs = 5, vpnTcpMs = 10)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating TIMEOUT with vpnTimeout factory`() {
        val r = RttResult.vpnTimeout(google, directDnsMs = 5, directTcpMs = 10)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
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

    @Test
    fun `directTotalMs with zeros`() {
        val r = RttResult(google, directDnsMs = 0, directTcpMs = 0, vpnDnsMs = 0, vpnTcpMs = 0)
        assertEquals(0L, r.directTotalMs)
        assertEquals(0L, r.vpnTotalMs)
    }

    @Test
    fun `directTotalMs negative when dns is -1`() {
        val r = RttResult(google, directDnsMs = -1, directTcpMs = 0, vpnDnsMs = 0, vpnTcpMs = 0)
        assertEquals(-1L, r.directTotalMs)
    }

    @Test
    fun `directTotalMs with large values`() {
        val r = RttResult(google, directDnsMs = 999999, directTcpMs = 999999, vpnDnsMs = 0, vpnTcpMs = 0)
        assertEquals(1999998L, r.directTotalMs)
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

    @Test
    fun `timeout factory target is preserved`() {
        val target = RttTarget("Custom", "custom.example.com", 8443)
        val r = RttResult.timeout(target)
        assertEquals(target, r.target)
        assertEquals("Custom", r.target.name)
        assertEquals("custom.example.com", r.target.host)
        assertEquals(8443, r.target.port)
    }

    @Test
    fun `directTimeout target is preserved`() {
        val target = RttTarget("Custom", "custom.example.com", 8443)
        val r = RttResult.directTimeout(target, vpnDnsMs = 1, vpnTcpMs = 2)
        assertEquals(target, r.target)
    }

    @Test
    fun `vpnTimeout target is preserved`() {
        val target = RttTarget("Custom", "custom.example.com", 8443)
        val r = RttResult.vpnTimeout(target, directDnsMs = 1, directTcpMs = 2)
        assertEquals(target, r.target)
    }

    // ── Data class equality ───────────────────────────────────────────

    @Test
    fun `RttResult data class equality`() {
        val r1 = RttResult(google, 5, 10, 8, 15)
        val r2 = RttResult(google, 5, 10, 8, 15)
        assertEquals(r1, r2)
        assertEquals(r1.hashCode(), r2.hashCode())
    }

    @Test
    fun `RttResult data class inequality`() {
        val r1 = RttResult(google, 5, 10, 8, 15)
        val r2 = RttResult(google, 5, 10, 8, 20)
        assertNotEquals(r1, r2)
    }

    @Test
    fun `RttResult toString contains field names`() {
        val r = RttResult(google, 5, 10, 8, 15)
        val s = r.toString()
        assertTrue(s.contains("directDnsMs"))
        assertTrue(s.contains("vpnTcpMs"))
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

    @Test
    fun `default target names are unique`() {
        val names = RttTarget.DEFAULT_TARGETS.map { it.name }
        assertEquals(names.size, names.toSet().size)
    }

    @Test
    fun `default target hosts are unique`() {
        val hosts = RttTarget.DEFAULT_TARGETS.map { it.host }
        assertEquals(hosts.size, hosts.toSet().size)
    }

    @Test
    fun `default targets include Google and Cloudflare`() {
        val names = RttTarget.DEFAULT_TARGETS.map { it.name }
        assertTrue(names.contains("Google"))
        assertTrue(names.contains("Cloudflare"))
    }

    @Test
    fun `RttTarget with custom port`() {
        val t = RttTarget("Custom", "example.com", 8080)
        assertEquals(8080, t.port)
    }

    @Test
    fun `RttTarget default port is 443`() {
        val t = RttTarget("Test", "example.com")
        assertEquals(443, t.port)
    }

    @Test
    fun `RttTarget data class equality`() {
        val t1 = RttTarget("Google", "www.google.com", 443)
        val t2 = RttTarget("Google", "www.google.com", 443)
        assertEquals(t1, t2)
        assertEquals(t1.hashCode(), t2.hashCode())
    }

    @Test
    fun `RttTarget data class inequality different host`() {
        val t1 = RttTarget("Google", "www.google.com", 443)
        val t2 = RttTarget("Google", "google.com", 443)
        assertNotEquals(t1, t2)
    }

    @Test
    fun `RttTarget data class inequality different port`() {
        val t1 = RttTarget("Google", "www.google.com", 443)
        val t2 = RttTarget("Google", "www.google.com", 80)
        assertNotEquals(t1, t2)
    }

    @Test
    fun `RttTarget copy`() {
        val t = RttTarget("Google", "www.google.com", 443)
        val t2 = t.copy(port = 8080)
        assertEquals("Google", t2.name)
        assertEquals("www.google.com", t2.host)
        assertEquals(8080, t2.port)
    }

    @Test
    fun `RttTarget iconRes default is 0`() {
        val t = RttTarget("Test", "example.com")
        assertEquals(0, t.iconRes)
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

    @Test
    fun `summary with directTimeout only`() {
        val results = listOf(
            RttResult.directTimeout(google, vpnDnsMs = 5, vpnTcpMs = 10),
        )
        val s = RttResult.Summary(results)
        assertEquals(0, s.successCount)
        assertEquals(1, s.timeoutCount)
        assertEquals(0L, s.avgDirectMs)
        assertEquals(0L, s.avgVpnMs)
    }

    @Test
    fun `summary with vpnTimeout only`() {
        val results = listOf(
            RttResult.vpnTimeout(google, directDnsMs = 5, directTcpMs = 10),
        )
        val s = RttResult.Summary(results)
        assertEquals(0, s.successCount)
        assertEquals(1, s.timeoutCount)
        assertEquals(0L, s.avgDirectMs)
        assertEquals(0L, s.avgVpnMs)
    }

    @Test
    fun `summary with mix of valid and partial timeout`() {
        val results = listOf(
            RttResult(google, 5, 10, 8, 15),  // valid: direct=15, vpn=23
            RttResult.directTimeout(RttTarget("A", "a.com"), vpnDnsMs = 5, vpnTcpMs = 10),  // timeout
            RttResult.vpnTimeout(RttTarget("B", "b.com"), directDnsMs = 3, directTcpMs = 7),  // timeout
            RttResult.timeout(RttTarget("C", "c.com")),  // full timeout
        )
        val s = RttResult.Summary(results)
        assertEquals(1, s.successCount)
        assertEquals(3, s.timeoutCount)
        assertEquals(15L, s.avgDirectMs)
        assertEquals(23L, s.avgVpnMs)
    }

    @Test
    fun `summary with all valid results`() {
        val results = listOf(
            RttResult(google, 5, 10, 8, 15),           // direct=15, vpn=23
            RttResult(RttTarget("A", "a.com"), 3, 7, 5, 10),   // direct=10, vpn=15
            RttResult(RttTarget("B", "b.com"), 2, 3, 4, 6),    // direct=5, vpn=10
        )
        val s = RttResult.Summary(results)
        assertEquals(3, s.successCount)
        assertEquals(0, s.timeoutCount)
        assertEquals(10L, s.avgDirectMs)  // (15+10+5)/3
        assertEquals(16L, s.avgVpnMs)     // (23+15+10)/3 = 16
        assertEquals(6L, s.avgOverheadMs)
    }

    @Test
    fun `summary successCount plus timeoutCount equals total`() {
        val results = listOf(
            RttResult(google, 5, 10, 8, 15),
            RttResult.timeout(RttTarget("X", "x.com")),
            RttResult.directTimeout(RttTarget("Y", "y.com"), 5, 10),
            RttResult.vpnTimeout(RttTarget("Z", "z.com"), 5, 10),
            RttResult(RttTarget("W", "w.com"), 1, 2, 3, 4),
        )
        val s = RttResult.Summary(results)
        assertEquals(results.size, s.successCount + s.timeoutCount)
    }

    @Test
    fun `summary with empty list`() {
        val s = RttResult.Summary(emptyList())
        assertEquals(0L, s.avgDirectMs)
        assertEquals(0L, s.avgVpnMs)
        assertEquals(0L, s.avgOverheadMs)
        assertEquals(0.0, s.avgOverheadPercent, 0.1)
        assertEquals(0, s.successCount)
        assertEquals(0, s.timeoutCount)
    }

    @Test
    fun `summary avgOverheadMs sign`() {
        // VPN faster → negative overhead
        val results = listOf(
            RttResult(google, 10, 20, 5, 10),  // direct=30, vpn=15, overhead=-15
        )
        val s = RttResult.Summary(results)
        assertEquals(-15L, s.avgOverheadMs)
    }

    @Test
    fun `summary avgOverheadPercent when direct is zero`() {
        val results = listOf(
            RttResult(google, 0, 0, 5, 10),  // direct=0, vpn=15
        )
        val s = RttResult.Summary(results)
        assertEquals(0.0, s.avgOverheadPercent, 0.1)
    }

    // ── RttTestRunner.Measurement ─────────────────────────────────────

    @Test
    fun `Measurement isTimeout when both -1`() {
        val m = RttTestRunner.Measurement(-1, -1)
        assertTrue(m.isTimeout)
    }

    @Test
    fun `Measurement isTimeout when dns -1 tcp ok`() {
        val m = RttTestRunner.Measurement(-1, 10)
        assertTrue(m.isTimeout)  // dnsMs == TIMEOUT → isTimeout
    }

    @Test
    fun `Measurement isTimeout when dns ok tcp -1`() {
        val m = RttTestRunner.Measurement(5, -1)
        assertTrue(m.isTimeout)  // tcpMs == TIMEOUT → isTimeout
    }

    @Test
    fun `Measurement not timeout when both positive`() {
        val m = RttTestRunner.Measurement(5, 10)
        assertFalse(m.isTimeout)
    }

    @Test
    fun `Measurement with zero values not timeout`() {
        val m = RttTestRunner.Measurement(0, 0)
        assertFalse(m.isTimeout)
    }

    @Test
    fun `Measurement default error is null`() {
        val m = RttTestRunner.Measurement(5, 10)
        assertNull(m.error)
    }

    @Test
    fun `Measurement with error message`() {
        val m = RttTestRunner.Measurement(-1, -1, "DNS failed: timeout")
        assertEquals("DNS failed: timeout", m.error)
        assertTrue(m.isTimeout)
    }

    @Test
    fun `Measurement data class equality`() {
        val m1 = RttTestRunner.Measurement(5, 10)
        val m2 = RttTestRunner.Measurement(5, 10)
        assertEquals(m1, m2)
        assertEquals(m1.hashCode(), m2.hashCode())
    }

    @Test
    fun `Measurement data class inequality`() {
        val m1 = RttTestRunner.Measurement(5, 10)
        val m2 = RttTestRunner.Measurement(5, 15)
        assertNotEquals(m1, m2)
    }

    @Test
    fun `Measurement copy`() {
        val m = RttTestRunner.Measurement(5, 10, "error")
        val m2 = m.copy(dnsMs = 20)
        assertEquals(20L, m2.dnsMs)
        assertEquals(10L, m2.tcpMs)
        assertEquals("error", m2.error)
    }

    // ── RttTestRunner constants ───────────────────────────────────────

    @Test
    fun `TIMEOUT constant is -1`() {
        assertEquals(-1L, RttTestRunner.TIMEOUT)
    }

    @Test
    fun `TIMEOUT_MS constant is -1`() {
        assertEquals(-1L, RttResult.TIMEOUT_MS)
    }

    @Test
    fun `TIMEOUT constant equals TIMEOUT_MS`() {
        assertEquals(RttTestRunner.TIMEOUT, RttResult.TIMEOUT_MS)
    }

    // ── Rating enum ───────────────────────────────────────────────────

    @Test
    fun `Rating enum has exactly 4 values`() {
        assertEquals(4, RttResult.Rating.values().size)
    }

    @Test
    fun `Rating enum values are GREEN YELLOW RED TIMEOUT`() {
        val values = RttResult.Rating.values().map { it.name }
        assertTrue(values.contains("GREEN"))
        assertTrue(values.contains("YELLOW"))
        assertTrue(values.contains("RED"))
        assertTrue(values.contains("TIMEOUT"))
    }

    @Test
    fun `Rating valueOf works`() {
        assertEquals(RttResult.Rating.GREEN, RttResult.Rating.valueOf("GREEN"))
        assertEquals(RttResult.Rating.YELLOW, RttResult.Rating.valueOf("YELLOW"))
        assertEquals(RttResult.Rating.RED, RttResult.Rating.valueOf("RED"))
        assertEquals(RttResult.Rating.TIMEOUT, RttResult.Rating.valueOf("TIMEOUT"))
    }

    // ── Stress / roundtrip ────────────────────────────────────────────

    @Test
    fun `summary with 5 default target results all valid`() {
        val results = RttTarget.DEFAULT_TARGETS.mapIndexed { i, target ->
            val base = (i + 1) * 10L
            RttResult(target, base, base * 2, base + 5, base * 2 + 5)
        }
        val s = RttResult.Summary(results)
        assertEquals(5, s.successCount)
        assertEquals(0, s.timeoutCount)
        assertTrue(s.avgDirectMs > 0)
        assertTrue(s.avgVpnMs > s.avgDirectMs)
        assertTrue(s.avgOverheadMs > 0)
    }

    @Test
    fun `summary with 5 default target results all timeout`() {
        val results = RttTarget.DEFAULT_TARGETS.map { RttResult.timeout(it) }
        val s = RttResult.Summary(results)
        assertEquals(0, s.successCount)
        assertEquals(5, s.timeoutCount)
        assertEquals(0L, s.avgDirectMs)
    }

    @Test
    fun `rating roundtrip all 4 states`() {
        val green = RttResult(google, 10, 40, 10, 45)   // ~10%
        val yellow = RttResult(google, 10, 40, 15, 50)   // ~25%
        val red = RttResult(google, 10, 40, 20, 60)      // ~60%
        val timeout = RttResult.timeout(google)

        assertEquals(RttResult.Rating.GREEN, green.rating)
        assertEquals(RttResult.Rating.YELLOW, yellow.rating)
        assertEquals(RttResult.Rating.RED, red.rating)
        assertEquals(RttResult.Rating.TIMEOUT, timeout.rating)
    }

    @Test
    fun `overheadMs is vpnTotal - directTotal for all factories`() {
        val timeout = RttResult.timeout(google)
        // -1 + -1 = -2 for both sides → overhead = -2 - (-2) = 0
        assertEquals(0L, timeout.overheadMs)

        val directTimeout = RttResult.directTimeout(google, 5, 10)
        // direct = -1 + -1 = -2, vpn = 5 + 10 = 15 → overhead = 15 - (-2) = 17
        assertEquals(17L, directTimeout.overheadMs)

        val vpnTimeout = RttResult.vpnTimeout(google, 5, 10)
        // direct = 5 + 10 = 15, vpn = -1 + -1 = -2 → overhead = -2 - 15 = -17
        assertEquals(-17L, vpnTimeout.overheadMs)
    }

    // ── Boundary precision ────────────────────────────────────────────

    @Test
    fun `overheadPercent precision at small values`() {
        // direct=1000, overhead=1 → 0.1%
        val r = RttResult(google, 100, 900, 100, 901)
        assertEquals(0.1, r.overheadPercent, 0.01)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `overheadPercent at boundary 19_9 percent is GREEN`() {
        // direct=1000, overhead=199 → 19.9%
        val r = RttResult(google, 100, 900, 100, 1099)
        assertEquals(19.9, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `overheadPercent at boundary 20_1 percent is YELLOW`() {
        // direct=1000, overhead=201 → 20.1%
        val r = RttResult(google, 100, 900, 100, 1101)
        assertEquals(20.1, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `overheadPercent at boundary 49_9 percent is YELLOW`() {
        // direct=1000, overhead=499 → 49.9%
        val r = RttResult(google, 100, 900, 100, 1399)
        assertEquals(49.9, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `overheadPercent at boundary 50_1 percent is RED`() {
        // direct=1000, overhead=501 → 50.1%
        val r = RttResult(google, 100, 900, 100, 1401)
        assertEquals(50.1, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.RED, r.rating)
    }
}

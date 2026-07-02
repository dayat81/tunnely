package com.tunnely.app.rtt

import org.junit.Assert.*
import org.junit.Test

/**
 * Edge case tests for RttResult, RttTarget, RttTestRunner.Measurement, and Summary.
 * Focuses on boundary conditions, partial failures, and unusual input.
 */
class RttResultEdgeCaseTest {

    private val google = RttTarget("Google", "www.google.com", 443)

    // ── Partial timeout scenarios ─────────────────────────────────────

    @Test
    fun `dns timeout but tcp success - direct`() {
        // DNS failed but TCP succeeded (cached DNS, retry, etc.)
        val r = RttResult(google, directDnsMs = -1, directTcpMs = 10, vpnDnsMs = 5, vpnTcpMs = 15)
        // directTotalMs = -1 + 10 = 9, not negative → NOT TIMEOUT
        assertEquals(9L, r.directTotalMs)
        assertNotEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `tcp timeout but dns success - vpn`() {
        // DNS worked but TCP timed out
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 10, vpnDnsMs = 8, vpnTcpMs = -1)
        // vpnTotalMs = 8 + -1 = 7, not negative → NOT TIMEOUT
        assertEquals(7L, r.vpnTotalMs)
        assertNotEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `dns timeout both sides`() {
        // Both direct and VPN DNS failed
        val r = RttResult(google, directDnsMs = -1, directTcpMs = 10, vpnDnsMs = -1, vpnTcpMs = 15)
        // directTotalMs = 9, vpnTotalMs = 14 → NOT TIMEOUT (totals are positive)
        assertEquals(9L, r.directTotalMs)
        assertEquals(14L, r.vpnTotalMs)
        assertNotEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `tcp timeout both sides`() {
        // Both direct and VPN TCP failed
        val r = RttResult(google, directDnsMs = 5, directTcpMs = -1, vpnDnsMs = 8, vpnTcpMs = -1)
        // directTotalMs = 4, vpnTotalMs = 7 → NOT TIMEOUT
        assertEquals(4L, r.directTotalMs)
        assertEquals(7L, r.vpnTotalMs)
    }

    @Test
    fun `direct dns timeout vpn tcp timeout`() {
        // Cross-failure: direct DNS failed, VPN TCP failed
        val r = RttResult(google, directDnsMs = -1, directTcpMs = 10, vpnDnsMs = 5, vpnTcpMs = -1)
        // directTotalMs = 9, vpnTotalMs = 4
        assertEquals(9L, r.directTotalMs)
        assertEquals(4L, r.vpnTotalMs)
        assertEquals(-5L, r.overheadMs)  // VPN faster
    }

    @Test
    fun `both totals negative triggers timeout`() {
        // directDnsMs=-1, directTcpMs=-1 → total=-2 → TIMEOUT
        val r = RttResult(google, directDnsMs = -1, directTcpMs = -1, vpnDnsMs = 5, vpnTcpMs = 10)
        assertTrue(r.directTotalMs < 0)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    // ── Overhead edge cases ───────────────────────────────────────────

    @Test
    fun `overheadMs 1ms difference`() {
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 10, vpnTcpMs = 41)
        assertEquals(1L, r.overheadMs)
    }

    @Test
    fun `overheadPercent very small`() {
        // direct=1000, overhead=1 → 0.1%
        val r = RttResult(google, directDnsMs = 100, directTcpMs = 900, vpnDnsMs = 100, vpnTcpMs = 901)
        assertEquals(0.1, r.overheadPercent, 0.01)
    }

    @Test
    fun `overheadPercent very large`() {
        // direct=1, overhead=999 → 99900%
        val r = RttResult(google, directDnsMs = 0, directTcpMs = 1, vpnDnsMs = 500, vpnTcpMs = 500)
        assertEquals(99900.0, r.overheadPercent, 1.0)
    }

    @Test
    fun `overheadPercent exactly 0`() {
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 20, vpnDnsMs = 10, vpnTcpMs = 20)
        assertEquals(0.0, r.overheadPercent, 0.0)
    }

    @Test
    fun `overheadPercent exactly 100`() {
        // direct=20, vpn=40, overhead=20 → 100%
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 10, vpnDnsMs = 20, vpnTcpMs = 20)
        assertEquals(100.0, r.overheadPercent, 0.0)
    }

    @Test
    fun `overheadMs with negative direct values`() {
        // directDnsMs=-1, directTcpMs=10 → directTotal=9
        val r = RttResult(google, directDnsMs = -1, directTcpMs = 10, vpnDnsMs = 5, vpnTcpMs = 15)
        // overhead = 20 - 9 = 11
        assertEquals(11L, r.overheadMs)
    }

    // ── Rating edge cases ─────────────────────────────────────────────

    @Test
    fun `rating GREEN at 0 percent overhead`() {
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 10, vpnTcpMs = 40)
        assertEquals(0.0, r.overheadPercent, 0.0)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `rating GREEN when VPN faster`() {
        // VPN is 50% faster → negative overhead → still GREEN
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 5, vpnTcpMs = 20)
        assertEquals(-50.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `rating RED at 200 percent overhead`() {
        // direct=20, vpn=60, overhead=40 → 200%
        val r = RttResult(google, directDnsMs = 10, directTcpMs = 10, vpnDnsMs = 30, vpnTcpMs = 30)
        assertEquals(200.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    @Test
    fun `rating RED at 1000 percent overhead`() {
        // direct=1, vpn=11, overhead=10 → 1000%
        val r = RttResult(google, directDnsMs = 0, directTcpMs = 1, vpnDnsMs = 5, vpnTcpMs = 6)
        assertEquals(1000.0, r.overheadPercent, 1.0)
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    @Test
    fun `rating with 1ms direct and 1ms overhead`() {
        // direct=1, overhead=1 → 100% → RED
        val r = RttResult(google, directDnsMs = 0, directTcpMs = 1, vpnDnsMs = 0, vpnTcpMs = 2)
        assertEquals(100.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    @Test
    fun `rating GREEN with very large direct and small overhead`() {
        // direct=10000, overhead=100 → 1% → GREEN
        val r = RttResult(google, directDnsMs = 5000, directTcpMs = 5000, vpnDnsMs = 5000, vpnTcpMs = 5100)
        assertEquals(1.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    // ── Summary edge cases ────────────────────────────────────────────

    @Test
    fun `summary single result`() {
        val results = listOf(RttResult(google, 5, 10, 8, 15))
        val s = RttResult.Summary(results)
        assertEquals(1, s.successCount)
        assertEquals(0, s.timeoutCount)
        assertEquals(15L, s.avgDirectMs)
        assertEquals(23L, s.avgVpnMs)
        assertEquals(8L, s.avgOverheadMs)
    }

    @Test
    fun `summary with only directTimeout results`() {
        val results = listOf(
            RttResult.directTimeout(RttTarget("A", "a.com"), vpnDnsMs = 5, vpnTcpMs = 10),
            RttResult.directTimeout(RttTarget("B", "b.com"), vpnDnsMs = 3, vpnTcpMs = 7),
        )
        val s = RttResult.Summary(results)
        assertEquals(0, s.successCount)
        assertEquals(2, s.timeoutCount)
        assertEquals(0L, s.avgDirectMs)
        assertEquals(0L, s.avgVpnMs)
    }

    @Test
    fun `summary with only vpnTimeout results`() {
        val results = listOf(
            RttResult.vpnTimeout(RttTarget("A", "a.com"), directDnsMs = 5, directTcpMs = 10),
            RttResult.vpnTimeout(RttTarget("B", "b.com"), directDnsMs = 3, directTcpMs = 7),
        )
        val s = RttResult.Summary(results)
        assertEquals(0, s.successCount)
        assertEquals(2, s.timeoutCount)
        assertEquals(0L, s.avgDirectMs)
        assertEquals(0L, s.avgVpnMs)
    }

    @Test
    fun `summary with all same values`() {
        val results = listOf(
            RttResult(google, 10, 20, 15, 25),
            RttResult(RttTarget("A", "a.com"), 10, 20, 15, 25),
            RttResult(RttTarget("B", "b.com"), 10, 20, 15, 25),
        )
        val s = RttResult.Summary(results)
        assertEquals(30L, s.avgDirectMs)
        assertEquals(40L, s.avgVpnMs)
        assertEquals(10L, s.avgOverheadMs)
    }

    @Test
    fun `summary negative overhead average`() {
        val results = listOf(
            RttResult(google, 10, 20, 5, 10),   // direct=30, vpn=15, overhead=-15
            RttResult(RttTarget("A", "a.com"), 10, 20, 5, 10),  // same
        )
        val s = RttResult.Summary(results)
        assertEquals(-15L, s.avgOverheadMs)
        assertEquals(-50.0, s.avgOverheadPercent, 0.1)
    }

    @Test
    fun `summary with 10 valid results`() {
        val results = (1..10).map { i ->
            RttResult(RttTarget("T$i", "t$i.com"), i * 1L, i * 2L, i * 1L + 5, i * 2L + 5)
        }
        val s = RttResult.Summary(results)
        assertEquals(10, s.successCount)
        assertEquals(0, s.timeoutCount)
        assertTrue(s.avgDirectMs > 0)
        assertTrue(s.avgVpnMs > s.avgDirectMs)
        assertTrue(s.avgOverheadMs > 0)
    }

    @Test
    fun `summary 1 valid among 4 timeouts`() {
        val results = listOf(
            RttResult.timeout(RttTarget("A", "a.com")),
            RttResult.timeout(RttTarget("B", "b.com")),
            RttResult(google, 5, 10, 8, 15),  // only valid
            RttResult.timeout(RttTarget("C", "c.com")),
            RttResult.timeout(RttTarget("D", "d.com")),
        )
        val s = RttResult.Summary(results)
        assertEquals(1, s.successCount)
        assertEquals(4, s.timeoutCount)
        assertEquals(15L, s.avgDirectMs)
        assertEquals(23L, s.avgVpnMs)
    }

    @Test
    fun `summary overhead percent with negative direct`() {
        // This shouldn't happen in practice, but test robustness
        // directTotalMs < 0 → TIMEOUT → filtered out
        val results = listOf(
            RttResult(google, -1, -1, 5, 10),  // TIMEOUT
        )
        val s = RttResult.Summary(results)
        assertEquals(0, s.successCount)
        assertEquals(1, s.timeoutCount)
    }

    // ── RttTarget edge cases ──────────────────────────────────────────

    @Test
    fun `RttTarget with IP address host`() {
        val t = RttTarget("Cloudflare", "1.1.1.1", 443)
        assertEquals("1.1.1.1", t.host)
        assertTrue(t.host.contains('.'))
    }

    @Test
    fun `RttTarget port boundary 0`() {
        val t = RttTarget("Test", "example.com", 0)
        assertEquals(0, t.port)
    }

    @Test
    fun `RttTarget port boundary 65535`() {
        val t = RttTarget("Test", "example.com", 65535)
        assertEquals(65535, t.port)
    }

    @Test
    fun `RttTarget same host different names`() {
        val t1 = RttTarget("Google", "www.google.com", 443)
        val t2 = RttTarget("Google Search", "www.google.com", 443)
        assertNotEquals(t1, t2)  // different names
        assertEquals(t1.host, t2.host)
    }

    @Test
    fun `RttTarget same name different hosts`() {
        val t1 = RttTarget("Google", "www.google.com", 443)
        val t2 = RttTarget("Google", "google.com", 443)
        assertNotEquals(t1, t2)  // different hosts
        assertEquals(t1.name, t2.name)
    }

    @Test
    fun `RttTarget copy changes name only`() {
        val t = RttTarget("Google", "www.google.com", 443)
        val t2 = t.copy(name = "G")
        assertEquals("G", t2.name)
        assertEquals("www.google.com", t2.host)
        assertEquals(443, t2.port)
    }

    @Test
    fun `RttTarget copy changes host only`() {
        val t = RttTarget("Google", "www.google.com", 443)
        val t2 = t.copy(host = "google.com")
        assertEquals("Google", t2.name)
        assertEquals("google.com", t2.host)
        assertEquals(443, t2.port)
    }

    @Test
    fun `RttTarget with empty name`() {
        val t = RttTarget("", "example.com", 443)
        assertEquals("", t.name)
        assertEquals("example.com", t.host)
    }

    @Test
    fun `RttTarget with long host`() {
        val longHost = "a".repeat(200) + ".example.com"
        val t = RttTarget("Long", longHost, 443)
        assertEquals(longHost, t.host)
    }

    @Test
    fun `RttTarget default targets include Indonesian services`() {
        val names = RttTarget.DEFAULT_TARGETS.map { it.name }
        assertTrue("Should include Tokopedia", names.contains("Tokopedia"))
        assertTrue("Should include WhatsApp", names.contains("WhatsApp"))
        assertTrue("Should include Instagram", names.contains("Instagram"))
    }

    @Test
    fun `RttTarget default targets all have valid hosts`() {
        RttTarget.DEFAULT_TARGETS.forEach { target ->
            assertTrue("Host should not be blank: ${target.name}", target.host.isNotBlank())
            assertTrue("Host should contain dot or be IP: ${target.host}",
                target.host.contains('.') || target.host.all { it.isDigit() || it == '.' })
        }
    }

    // ── Measurement edge cases ────────────────────────────────────────

    @Test
    fun `Measurement dnsMs=0 not timeout`() {
        val m = RttTestRunner.Measurement(0, 10)
        assertFalse(m.isTimeout)
    }

    @Test
    fun `Measurement tcpMs=0 not timeout`() {
        val m = RttTestRunner.Measurement(5, 0)
        assertFalse(m.isTimeout)
    }

    @Test
    fun `Measurement both 0 not timeout`() {
        val m = RttTestRunner.Measurement(0, 0)
        assertFalse(m.isTimeout)
    }

    @Test
    fun `Measurement dns=-1 tcp=0 is timeout`() {
        val m = RttTestRunner.Measurement(-1, 0)
        assertTrue(m.isTimeout)  // dnsMs == TIMEOUT
    }

    @Test
    fun `Measurement dns=0 tcp=-1 is timeout`() {
        val m = RttTestRunner.Measurement(0, -1)
        assertTrue(m.isTimeout)  // tcpMs == TIMEOUT
    }

    @Test
    fun `Measurement large values`() {
        val m = RttTestRunner.Measurement(999999, 999999)
        assertFalse(m.isTimeout)
        assertEquals(999999L, m.dnsMs)
        assertEquals(999999L, m.tcpMs)
    }

    @Test
    fun `Measurement error with empty string`() {
        val m = RttTestRunner.Measurement(5, 10, "")
        assertEquals("", m.error)
        assertFalse(m.isTimeout)
    }

    @Test
    fun `Measurement error with long message`() {
        val longError = "E".repeat(500)
        val m = RttTestRunner.Measurement(-1, -1, longError)
        assertEquals(longError, m.error)
        assertTrue(m.isTimeout)
    }

    @Test
    fun `Measurement toString contains fields`() {
        val m = RttTestRunner.Measurement(5, 10, "test")
        val s = m.toString()
        assertTrue(s.contains("dnsMs"))
        assertTrue(s.contains("tcpMs"))
        assertTrue(s.contains("error"))
    }

    // ── Multiple results same target ──────────────────────────────────

    @Test
    fun `multiple results with same target`() {
        val r1 = RttResult(google, 5, 10, 8, 15)
        val r2 = RttResult(google, 6, 12, 9, 18)
        // Same target, different measurements
        assertEquals(r1.target, r2.target)
        assertNotEquals(r1, r2)
    }

    @Test
    fun `summary with duplicate targets`() {
        val results = listOf(
            RttResult(google, 5, 10, 8, 15),
            RttResult(google, 6, 12, 9, 18),  // same target, different values
        )
        val s = RttResult.Summary(results)
        assertEquals(2, s.successCount)
        // avgDirect = (15 + 18) / 2 = 16
        assertEquals(16L, s.avgDirectMs)
    }

    // ── Rating with partial timeout fields ────────────────────────────

    @Test
    fun `rating not timeout when direct dns=-1 tcp=10`() {
        // directTotalMs = -1 + 10 = 9 (positive)
        val r = RttResult(google, directDnsMs = -1, directTcpMs = 10, vpnDnsMs = 5, vpnTcpMs = 15)
        // rating depends on overheadPercent, not individual fields
        assertNotEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating not timeout when vpn dns=5 tcp=-1`() {
        // vpnTotalMs = 5 + -1 = 4 (positive)
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 10, vpnDnsMs = 5, vpnTcpMs = -1)
        assertNotEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating timeout when direct total negative`() {
        // directDnsMs=-10, directTcpMs=-5 → total=-15
        val r = RttResult(google, directDnsMs = -10, directTcpMs = -5, vpnDnsMs = 5, vpnTcpMs = 10)
        assertTrue(r.directTotalMs < 0)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `rating timeout when vpn total negative`() {
        // vpnDnsMs=-10, vpnTcpMs=-5 → total=-15
        val r = RttResult(google, directDnsMs = 5, directTcpMs = 10, vpnDnsMs = -10, vpnTcpMs = -5)
        assertTrue(r.vpnTotalMs < 0)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    // ── Factory method edge cases ─────────────────────────────────────

    @Test
    fun `directTimeout with zero vpn values`() {
        val r = RttResult.directTimeout(google, vpnDnsMs = 0, vpnTcpMs = 0)
        assertEquals(-1L, r.directDnsMs)
        assertEquals(-1L, r.directTcpMs)
        assertEquals(0L, r.vpnDnsMs)
        assertEquals(0L, r.vpnTcpMs)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `vpnTimeout with zero direct values`() {
        val r = RttResult.vpnTimeout(google, directDnsMs = 0, directTcpMs = 0)
        assertEquals(0L, r.directDnsMs)
        assertEquals(0L, r.directTcpMs)
        assertEquals(-1L, r.vpnDnsMs)
        assertEquals(-1L, r.vpnTcpMs)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `directTimeout with large vpn values`() {
        val r = RttResult.directTimeout(google, vpnDnsMs = 999999, vpnTcpMs = 999999)
        assertEquals(999999L, r.vpnDnsMs)
        assertEquals(999999L, r.vpnTcpMs)
    }

    @Test
    fun `vpnTimeout with large direct values`() {
        val r = RttResult.vpnTimeout(google, directDnsMs = 999999, directTcpMs = 999999)
        assertEquals(999999L, r.directDnsMs)
        assertEquals(999999L, r.directTcpMs)
    }

    // ── Boundary precision ────────────────────────────────────────────

    @Test
    fun `overheadPercent at 19_99 percent is GREEN`() {
        // direct=10000, overhead=1999 → 19.99%
        val r = RttResult(google, directDnsMs = 1000, directTcpMs = 9000, vpnDnsMs = 1000, vpnTcpMs = 10999)
        assertEquals(19.99, r.overheadPercent, 0.01)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `overheadPercent at 20_01 percent is YELLOW`() {
        // direct=10000, overhead=2001 → 20.01%
        val r = RttResult(google, directDnsMs = 1000, directTcpMs = 9000, vpnDnsMs = 1000, vpnTcpMs = 11001)
        assertEquals(20.01, r.overheadPercent, 0.01)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `overheadPercent at 49_99 percent is YELLOW`() {
        // direct=10000, overhead=4999 → 49.99%
        val r = RttResult(google, directDnsMs = 1000, directTcpMs = 9000, vpnDnsMs = 1000, vpnTcpMs = 13999)
        assertEquals(49.99, r.overheadPercent, 0.01)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `overheadPercent at 50_01 percent is RED`() {
        // direct=10000, overhead=5001 → 50.01%
        val r = RttResult(google, directDnsMs = 1000, directTcpMs = 9000, vpnDnsMs = 1000, vpnTcpMs = 14001)
        assertEquals(50.01, r.overheadPercent, 0.01)
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    // ── Stress / roundtrip ────────────────────────────────────────────

    @Test
    fun `stress 100 results summary`() {
        val results = (1..100).map { i ->
            RttResult(RttTarget("T$i", "t$i.com"), i * 1L, i * 2L, i * 1L + 3, i * 2L + 3)
        }
        val s = RttResult.Summary(results)
        assertEquals(100, s.successCount)
        assertEquals(0, s.timeoutCount)
        assertTrue(s.avgDirectMs > 0)
        assertTrue(s.avgVpnMs > s.avgDirectMs)
        assertTrue(s.avgOverheadMs > 0)
    }

    @Test
    fun `stress 100 timeout results`() {
        val results = (1..100).map { i ->
            RttResult.timeout(RttTarget("T$i", "t$i.com"))
        }
        val s = RttResult.Summary(results)
        assertEquals(0, s.successCount)
        assertEquals(100, s.timeoutCount)
        assertEquals(0L, s.avgDirectMs)
    }

    @Test
    fun `stress 50 valid 50 timeout`() {
        val valid = (1..50).map { i ->
            RttResult(RttTarget("V$i", "v$i.com"), 5, 10, 8, 15)
        }
        val timeouts = (1..50).map { i ->
            RttResult.timeout(RttTarget("T$i", "t$i.com"))
        }
        val results = valid + timeouts
        val s = RttResult.Summary(results)
        assertEquals(50, s.successCount)
        assertEquals(50, s.timeoutCount)
        assertEquals(15L, s.avgDirectMs)
        assertEquals(23L, s.avgVpnMs)
    }

    @Test
    fun `all 5 default targets with realistic values`() {
        val results = RttTarget.DEFAULT_TARGETS.map { target ->
            RttResult(target, directDnsMs = 5, directTcpMs = 15, vpnDnsMs = 8, vpnTcpMs = 20)
        }
        val s = RttResult.Summary(results)
        assertEquals(5, s.successCount)
        assertEquals(20L, s.avgDirectMs)
        assertEquals(28L, s.avgVpnMs)
        assertEquals(8L, s.avgOverheadMs)
        assertEquals(40.0, s.avgOverheadPercent, 0.1)
    }

    @Test
    fun `all 5 default targets with varied overhead`() {
        val overheads = listOf(5L, 10L, 15L, 20L, 25L)
        val results = RttTarget.DEFAULT_TARGETS.zip(overheads).map { (target, overhead) ->
            RttResult(target, directDnsMs = 10, directTcpMs = 40, vpnDnsMs = 10, vpnTcpMs = 40 + overhead)
        }
        val s = RttResult.Summary(results)
        assertEquals(5, s.successCount)
        assertEquals(15L, s.avgOverheadMs)  // (5+10+15+20+25)/5
    }

    // ── Data class edge cases ─────────────────────────────────────────

    @Test
    fun `RttResult with all zeros`() {
        val r = RttResult(google, 0, 0, 0, 0)
        assertEquals(0L, r.directTotalMs)
        assertEquals(0L, r.vpnTotalMs)
        assertEquals(0L, r.overheadMs)
        assertEquals(0.0, r.overheadPercent, 0.0)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `RttResult with all -1`() {
        val r = RttResult(google, -1, -1, -1, -1)
        assertEquals(-2L, r.directTotalMs)
        assertEquals(-2L, r.vpnTotalMs)
        assertEquals(0L, r.overheadMs)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `RttResult hashCode consistent with equals`() {
        val r1 = RttResult(google, 5, 10, 8, 15)
        val r2 = RttResult(google, 5, 10, 8, 15)
        assertEquals(r1, r2)
        assertEquals(r1.hashCode(), r2.hashCode())
    }

    @Test
    fun `RttTarget hashCode consistent with equals`() {
        val t1 = RttTarget("Google", "www.google.com", 443)
        val t2 = RttTarget("Google", "www.google.com", 443)
        assertEquals(t1, t2)
        assertEquals(t1.hashCode(), t2.hashCode())
    }

    @Test
    fun `Measurement hashCode consistent with equals`() {
        val m1 = RttTestRunner.Measurement(5, 10, "error")
        val m2 = RttTestRunner.Measurement(5, 10, "error")
        assertEquals(m1, m2)
        assertEquals(m1.hashCode(), m2.hashCode())
    }
}

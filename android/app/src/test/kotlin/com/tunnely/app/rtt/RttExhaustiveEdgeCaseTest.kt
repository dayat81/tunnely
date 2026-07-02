package com.tunnely.app.rtt

import org.junit.Assert.*
import org.junit.Test

/**
 * Exhaustive edge case tests — gaps in RttResult, RttTarget, Measurement, Summary, AppRttTarget.
 * Covers: integer division precision, mixed timeout fields, dedup, sorting, boundary math.
 */
class RttExhaustiveEdgeCaseTest {

    // ── Integer division precision in Summary ──────────────────────────

    @Test
    fun `summary integer division truncation`() {
        // direct=[10,11] → avg=10 (21/2=10 truncated)
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 5, 5, 5, 5),   // direct=10
            RttResult(RttTarget("B", "b.com"), 5, 6, 5, 6),   // direct=11
        )
        val s = RttResult.Summary(results)
        assertEquals(10L, s.avgDirectMs)  // (10+11)/2 = 10 (integer division)
    }

    @Test
    fun `summary integer division for vpn`() {
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 5, 5, 6, 6),   // vpn=12
            RttResult(RttTarget("B", "b.com"), 5, 5, 6, 7),   // vpn=13
        )
        val s = RttResult.Summary(results)
        assertEquals(12L, s.avgVpnMs)  // (12+13)/2 = 12
    }

    @Test
    fun `summary overhead derived from truncated averages`() {
        // avgDirect=10, avgVpn=12 → avgOverhead=2
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 5, 5, 6, 6),   // direct=10, vpn=12
            RttResult(RttTarget("B", "b.com"), 5, 6, 6, 7),   // direct=11, vpn=13
        )
        val s = RttResult.Summary(results)
        assertEquals(10L, s.avgDirectMs)
        assertEquals(12L, s.avgVpnMs)
        assertEquals(2L, s.avgOverheadMs)
    }

    // ── RttResult with mixed timeout fields ───────────────────────────

    @Test
    fun `RttResult direct dns=-1 tcp=-1 vpn both positive`() {
        val r = RttResult(RttTarget("T", "t.com"), -1, -1, 5, 10)
        assertTrue(r.directTotalMs < 0)
        assertEquals(15L, r.vpnTotalMs)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `RttResult vpn dns=-1 tcp=-1 direct both positive`() {
        val r = RttResult(RttTarget("T", "t.com"), 5, 10, -1, -1)
        assertEquals(15L, r.directTotalMs)
        assertTrue(r.vpnTotalMs < 0)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    @Test
    fun `RttResult direct dns=-1 tcp=1 vpn dns=1 tcp=-1`() {
        // directTotal=0, vpnTotal=0 → not timeout, overhead=0
        val r = RttResult(RttTarget("T", "t.com"), -1, 1, 1, -1)
        assertEquals(0L, r.directTotalMs)
        assertEquals(0L, r.vpnTotalMs)
        assertEquals(0L, r.overheadMs)
        // Both totals are 0 → overheadPercent=0 → GREEN
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `RttResult direct dns=0 tcp=-1 vpn dns=-1 tcp=0`() {
        // directTotal=-1, vpnTotal=-1 → both negative → TIMEOUT
        val r = RttResult(RttTarget("T", "t.com"), 0, -1, -1, 0)
        assertTrue(r.directTotalMs < 0)
        assertTrue(r.vpnTotalMs < 0)
        assertEquals(RttResult.Rating.TIMEOUT, r.rating)
    }

    // ── Summary with mixed timeout types ──────────────────────────────

    @Test
    fun `summary 5 results - 2 valid 1 directTimeout 1 vpnTimeout 1 fullTimeout`() {
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 10, 20, 15, 25),  // valid: direct=30, vpn=40
            RttResult(RttTarget("B", "b.com"), 5, 10, 8, 12),    // valid: direct=15, vpn=20
            RttResult.directTimeout(RttTarget("C", "c.com"), 5, 10),  // timeout
            RttResult.vpnTimeout(RttTarget("D", "d.com"), 5, 10),    // timeout
            RttResult.timeout(RttTarget("E", "e.com")),               // timeout
        )
        val s = RttResult.Summary(results)
        assertEquals(2, s.successCount)
        assertEquals(3, s.timeoutCount)
        assertEquals(22L, s.avgDirectMs)  // (30+15)/2 = 22
        assertEquals(30L, s.avgVpnMs)     // (40+20)/2 = 30
        assertEquals(8L, s.avgOverheadMs)
    }

    @Test
    fun `summary with 1 valid 9 timeout`() {
        val valid = RttResult(RttTarget("V", "v.com"), 10, 20, 15, 25)  // direct=30, vpn=40
        val timeouts = (1..9).map { RttResult.timeout(RttTarget("T$it", "t$it.com")) }
        val s = RttResult.Summary(listOf(valid) + timeouts)
        assertEquals(1, s.successCount)
        assertEquals(9, s.timeoutCount)
        assertEquals(30L, s.avgDirectMs)
        assertEquals(40L, s.avgVpnMs)
    }

    // ── Rating with exact boundary math ───────────────────────────────

    @Test
    fun `rating GREEN when overhead is exactly 19_999 percent`() {
        // direct=1000, overhead=199 → 19.9%
        val r = RttResult(RttTarget("T", "t.com"), 200, 800, 200, 999)
        assertEquals(19.9, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `rating YELLOW when overhead is exactly 20 percent`() {
        // direct=100, overhead=20 → 20%
        val r = RttResult(RttTarget("T", "t.com"), 20, 80, 20, 100)
        assertEquals(20.0, r.overheadPercent, 0.01)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `rating YELLOW when overhead is exactly 49_999 percent`() {
        // direct=1000, overhead=499 → 49.9%
        val r = RttResult(RttTarget("T", "t.com"), 200, 800, 200, 1299)
        assertEquals(49.9, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `rating RED when overhead is exactly 50 percent`() {
        // direct=100, overhead=50 → 50%
        val r = RttResult(RttTarget("T", "t.com"), 20, 80, 20, 130)
        assertEquals(50.0, r.overheadPercent, 0.01)
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    @Test
    fun `rating GREEN when overhead negative 100 percent`() {
        // VPN is 2x faster → -100% overhead
        val r = RttResult(RttTarget("T", "t.com"), 10, 40, 5, 20)
        assertEquals(-50.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    // ── RttTarget.DEFAULT_TARGETS individual verification ─────────────

    @Test
    fun `default target 0 is Google`() {
        assertEquals("Google", RttTarget.DEFAULT_TARGETS[0].name)
        assertEquals("www.google.com", RttTarget.DEFAULT_TARGETS[0].host)
    }

    @Test
    fun `default target 1 is Tokopedia`() {
        assertEquals("Tokopedia", RttTarget.DEFAULT_TARGETS[1].name)
        assertEquals("www.tokopedia.com", RttTarget.DEFAULT_TARGETS[1].host)
    }

    @Test
    fun `default target 2 is Instagram`() {
        assertEquals("Instagram", RttTarget.DEFAULT_TARGETS[2].name)
        assertEquals("www.instagram.com", RttTarget.DEFAULT_TARGETS[2].host)
    }

    @Test
    fun `default target 3 is WhatsApp`() {
        assertEquals("WhatsApp", RttTarget.DEFAULT_TARGETS[3].name)
        assertEquals("web.whatsapp.com", RttTarget.DEFAULT_TARGETS[3].host)
    }

    @Test
    fun `default target 4 is Cloudflare`() {
        assertEquals("Cloudflare", RttTarget.DEFAULT_TARGETS[4].name)
        assertEquals("1.1.1.1", RttTarget.DEFAULT_TARGETS[4].host)
    }

    @Test
    fun `default targets Cloudflare uses IP not hostname`() {
        val cf = RttTarget.DEFAULT_TARGETS.first { it.name == "Cloudflare" }
        assertTrue(cf.host.all { it.isDigit() || it == '.' })
    }

    // ── inferHost edge cases ──────────────────────────────────────────

    @Test
    fun `inferHost two segments both skip`() {
        // "com.org" → both in skip set → null
        assertNull(AppRttTarget.inferHost("com.org"))
    }

    @Test
    fun `inferHost three segments all skip`() {
        assertNull(AppRttTarget.inferHost("com.org.net"))
    }

    @Test
    fun `inferHost with www prefix`() {
        // "www.example.app" → skips www → "example"
        assertEquals("www.example.com", AppRttTarget.inferHost("www.example.app"))
    }

    @Test
    fun `inferHost with io prefix`() {
        // "io.github.myapp" → skips io → "github"
        assertEquals("www.github.com", AppRttTarget.inferHost("io.github.myapp"))
    }

    @Test
    fun `inferHost with app prefix`() {
        // "app.mycompany.service" → skips app → "mycompany"
        assertEquals("www.mycompany.com", AppRttTarget.inferHost("app.mycompany.service"))
    }

    @Test
    fun `inferHost with id prefix`() {
        // "id.co.example" → skips id, co → "example"
        assertEquals("www.example.com", AppRttTarget.inferHost("id.co.example"))
    }

    // ── AppRttTarget KNOWN_APPS host uniqueness per category ──────────

    @Test
    fun `KNOWN_APPS Google hosts are google or youtube`() {
        val googlePkgs = listOf(
            "com.google.android.googlequicksearchbox",
            "com.google.android.gm",
            "com.google.android.apps.maps",
            "com.google.android.apps.photos",
            "com.google.android.apps.docs",
        )
        googlePkgs.forEach { pkg ->
            val host = AppRttTarget.KNOWN_APPS[pkg]!!.host
            assertTrue("Google app $pkg should use google host: $host", host.contains("google"))
        }
    }

    @Test
    fun `KNOWN_APPS YouTube hosts are youtube`() {
        val ytPkgs = listOf(
            "com.google.android.youtube",
            "com.google.android.apps.youtube.music",
        )
        ytPkgs.forEach { pkg ->
            val host = AppRttTarget.KNOWN_APPS[pkg]!!.host
            assertTrue("YouTube app $pkg should use youtube host: $host", host.contains("youtube"))
        }
    }

    @Test
    fun `KNOWN_APPS bank hosts match bank domains`() {
        val bankMap = mapOf(
            "id.co.bri.brimo" to "bri.co.id",
            "com.bca" to "bca.co.id",
            "id.co.bankmandiri.mandirionline" to "bankmandiri.co.id",
            "id.co.bni.bnimobilebanking" to "bni.co.id",
        )
        bankMap.forEach { (pkg, expectedDomain) ->
            val host = AppRttTarget.KNOWN_APPS[pkg]!!.host
            assertTrue("Bank app $pkg should contain $expectedDomain: $host",
                host.contains(expectedDomain))
        }
    }

    // ── Measurement with zero values ──────────────────────────────────

    @Test
    fun `Measurement dns=0 tcp=0 is valid`() {
        val m = RttTestRunner.Measurement(0, 0)
        assertFalse(m.isTimeout)
        assertNull(m.error)
    }

    @Test
    fun `Measurement dns=0 tcp=-1 is timeout`() {
        val m = RttTestRunner.Measurement(0, -1)
        assertTrue(m.isTimeout)
    }

    @Test
    fun `Measurement dns=-1 tcp=0 is timeout`() {
        val m = RttTestRunner.Measurement(-1, 0)
        assertTrue(m.isTimeout)
    }

    @Test
    fun `Measurement dns=1 tcp=0 is valid`() {
        val m = RttTestRunner.Measurement(1, 0)
        assertFalse(m.isTimeout)
    }

    @Test
    fun `Measurement dns=0 tcp=1 is valid`() {
        val m = RttTestRunner.Measurement(0, 1)
        assertFalse(m.isTimeout)
    }

    // ── RttResult with asymmetric DNS/TCP ─────────────────────────────

    @Test
    fun `RttResult high DNS low TCP`() {
        val r = RttResult(RttTarget("T", "t.com"), 100, 5, 120, 8)
        assertEquals(105L, r.directTotalMs)
        assertEquals(128L, r.vpnTotalMs)
        assertEquals(23L, r.overheadMs)
    }

    @Test
    fun `RttResult low DNS high TCP`() {
        val r = RttResult(RttTarget("T", "t.com"), 2, 200, 3, 250)
        assertEquals(202L, r.directTotalMs)
        assertEquals(253L, r.vpnTotalMs)
        assertEquals(51L, r.overheadMs)
    }

    @Test
    fun `RttResult DNS only overhead`() {
        // Same TCP, different DNS
        val r = RttResult(RttTarget("T", "t.com"), 10, 50, 30, 50)
        assertEquals(60L, r.directTotalMs)
        assertEquals(80L, r.vpnTotalMs)
        assertEquals(20L, r.overheadMs)
        // All overhead from DNS
    }

    @Test
    fun `RttResult TCP only overhead`() {
        // Same DNS, different TCP
        val r = RttResult(RttTarget("T", "t.com"), 10, 50, 10, 70)
        assertEquals(60L, r.directTotalMs)
        assertEquals(80L, r.vpnTotalMs)
        assertEquals(20L, r.overheadMs)
        // All overhead from TCP
    }

    // ── Summary with all valid same overhead ──────────────────────────

    @Test
    fun `summary all valid same overhead`() {
        val results = (1..5).map { i ->
            RttResult(RttTarget("T$i", "t$i.com"), 10, 40, 15, 45)  // overhead=10
        }
        val s = RttResult.Summary(results)
        assertEquals(5, s.successCount)
        assertEquals(0, s.timeoutCount)
        assertEquals(10L, s.avgOverheadMs)
        assertEquals(20.0, s.avgOverheadPercent, 0.1)
    }

    @Test
    fun `summary all valid zero overhead`() {
        val results = (1..5).map { i ->
            RttResult(RttTarget("T$i", "t$i.com"), 10, 40, 10, 40)  // overhead=0
        }
        val s = RttResult.Summary(results)
        assertEquals(0L, s.avgOverheadMs)
        assertEquals(0.0, s.avgOverheadPercent, 0.0)
    }

    // ── RttTarget copy variations ─────────────────────────────────────

    @Test
    fun `RttTarget copy all fields`() {
        val t = RttTarget("Original", "original.com", 443)
        val t2 = t.copy(name = "New", host = "new.com", port = 8080)
        assertEquals("New", t2.name)
        assertEquals("new.com", t2.host)
        assertEquals(8080, t2.port)
    }

    @Test
    fun `RttTarget copy preserves original`() {
        val t = RttTarget("Original", "original.com", 443)
        val t2 = t.copy(name = "New")
        assertEquals("Original", t.name)  // original unchanged
        assertEquals("New", t2.name)
    }

    // ── RttResult edge: both sides zero ───────────────────────────────

    @Test
    fun `RttResult both sides zero overhead zero percent`() {
        val r = RttResult(RttTarget("T", "t.com"), 0, 0, 0, 0)
        assertEquals(0L, r.overheadMs)
        assertEquals(0.0, r.overheadPercent, 0.0)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `RttResult direct=0 vpn=5 overhead infinite-like`() {
        // direct=0 → overheadPercent=0 (guard against div by zero)
        val r = RttResult(RttTarget("T", "t.com"), 0, 0, 2, 3)
        assertEquals(5L, r.overheadMs)
        assertEquals(0.0, r.overheadPercent, 0.0)  // guarded: direct=0
    }

    // ── KNOWN_APPS count verification ─────────────────────────────────

    @Test
    fun `KNOWN_APPS has at least 40 entries`() {
        assertTrue("Should have 40+ entries, got ${AppRttTarget.KNOWN_APPS.size}",
            AppRttTarget.KNOWN_APPS.size >= 40)
    }

    @Test
    fun `KNOWN_APPS has less than 60 entries`() {
        // Sanity: not too many
        assertTrue("Should have <60 entries, got ${AppRttTarget.KNOWN_APPS.size}",
            AppRttTarget.KNOWN_APPS.size < 60)
    }

    // ── RttResult hashCode stability ──────────────────────────────────

    @Test
    fun `RttResult hashCode stable across calls`() {
        val r = RttResult(RttTarget("T", "t.com"), 5, 10, 8, 15)
        val h1 = r.hashCode()
        val h2 = r.hashCode()
        assertEquals(h1, h2)
    }

    @Test
    fun `RttTarget hashCode stable across calls`() {
        val t = RttTarget("T", "t.com", 443)
        val h1 = t.hashCode()
        val h2 = t.hashCode()
        assertEquals(h1, h2)
    }

    @Test
    fun `Measurement hashCode stable across calls`() {
        val m = RttTestRunner.Measurement(5, 10, "err")
        val h1 = m.hashCode()
        val h2 = m.hashCode()
        assertEquals(h1, h2)
    }
}

package com.tunnely.app.rtt

import org.junit.Assert.*
import org.junit.Test

/**
 * Additional edge case tests for AppRttTarget, RttResult, RttTestRunner.Measurement.
 * Focuses on: mapping completeness, inference robustness, measurement combinations.
 */
class RttAdvancedEdgeCaseTest {

    // ── AppRttTarget mapping completeness ─────────────────────────────

    @Test
    fun `KNOWN_APPS package names are all unique`() {
        val packages = AppRttTarget.KNOWN_APPS.keys.toList()
        assertEquals(packages.size, packages.toSet().size)
    }

    @Test
    fun `KNOWN_APPS no empty package names`() {
        AppRttTarget.KNOWN_APPS.keys.forEach { pkg ->
            assertTrue("Package name should not be blank", pkg.isNotBlank())
        }
    }

    @Test
    fun `KNOWN_APPS no package names with spaces`() {
        AppRttTarget.KNOWN_APPS.keys.forEach { pkg ->
            assertFalse("Package should not contain spaces: $pkg", pkg.contains(' '))
        }
    }

    @Test
    fun `KNOWN_APPS all package names contain dots`() {
        AppRttTarget.KNOWN_APPS.keys.forEach { pkg ->
            assertTrue("Package should contain dots: $pkg", pkg.contains('.'))
        }
    }

    @Test
    fun `KNOWN_APPS covers e-commerce category`() {
        val ecommerce = listOf("com.tokopedia.tkpd", "com.shopee.id", "com.bukalapak.android", "com.lazada.android")
        ecommerce.forEach { pkg ->
            assertTrue("E-commerce app missing: $pkg", AppRttTarget.KNOWN_APPS.containsKey(pkg))
        }
    }

    @Test
    fun `KNOWN_APPS covers banking category`() {
        val banking = listOf("id.co.bri.brimo", "com.bca", "id.co.bankmandiri.mandirionline", "id.co.bni.bnimobilebanking")
        banking.forEach { pkg ->
            assertTrue("Banking app missing: $pkg", AppRttTarget.KNOWN_APPS.containsKey(pkg))
        }
    }

    @Test
    fun `KNOWN_APPS covers social category`() {
        val social = listOf("com.instagram.android", "com.facebook.katana", "com.whatsapp", "org.telegram.messenger")
        social.forEach { pkg ->
            assertTrue("Social app missing: $pkg", AppRttTarget.KNOWN_APPS.containsKey(pkg))
        }
    }

    @Test
    fun `KNOWN_APPS covers ride-hailing category`() {
        val rideHailing = listOf("com.grabtaxi.passenger", "com.gojek.app")
        rideHailing.forEach { pkg ->
            assertTrue("Ride-hailing app missing: $pkg", AppRttTarget.KNOWN_APPS.containsKey(pkg))
        }
    }

    @Test
    fun `KNOWN_APPS covers streaming category`() {
        val streaming = listOf("com.spotify.music", "com.netflix.mediaclient", "com.google.android.youtube")
        streaming.forEach { pkg ->
            assertTrue("Streaming app missing: $pkg", AppRttTarget.KNOWN_APPS.containsKey(pkg))
        }
    }

    @Test
    fun `KNOWN_APPS covers gaming category`() {
        val gaming = listOf("com.mobile.legends", "com.garena.game.kgid", "com.tencent.ig")
        gaming.forEach { pkg ->
            assertTrue("Gaming app missing: $pkg", AppRttTarget.KNOWN_APPS.containsKey(pkg))
        }
    }

    @Test
    fun `KNOWN_APPS all targets have port 443`() {
        AppRttTarget.KNOWN_APPS.forEach { (pkg, target) ->
            assertEquals("Port should be 443 for $pkg", 443, target.port)
        }
    }

    @Test
    fun `KNOWN_APPS all hosts end with valid TLD`() {
        val validTlds = listOf(".com", ".co.id", ".org", ".tv", ".me", ".id")
        AppRttTarget.KNOWN_APPS.forEach { (pkg, target) ->
            val hasValidTld = validTlds.any { target.host.endsWith(it) }
            assertTrue("Host should have valid TLD: ${target.host} ($pkg)", hasValidTld)
        }
    }

    @Test
    fun `KNOWN_APPS Google services all point to google domains`() {
        val googleApps = mapOf(
            "com.google.android.googlequicksearchbox" to "google",
            "com.google.android.youtube" to "youtube",
            "com.google.android.gm" to "google",
            "com.google.android.apps.maps" to "google",
            "com.google.android.apps.photos" to "google",
            "com.google.android.apps.youtube.music" to "youtube",
            "com.google.android.apps.docs" to "google",
        )
        googleApps.forEach { (pkg, domain) ->
            val target = AppRttTarget.KNOWN_APPS[pkg]
            assertNotNull("Google app missing: $pkg", target)
            assertTrue("Google app should point to $domain: ${target?.host}",
                target!!.host.contains(domain))
        }
    }

    @Test
    fun `KNOWN_APPS Meta services all point to meta domains`() {
        val metaApps = mapOf(
            "com.instagram.android" to "instagram.com",
            "com.facebook.katana" to "facebook.com",
            "com.facebook.orca" to "messenger.com",
            "com.whatsapp" to "whatsapp.com",
        )
        metaApps.forEach { (pkg, domain) ->
            val target = AppRttTarget.KNOWN_APPS[pkg]
            assertNotNull("Meta app missing: $pkg", target)
            assertTrue("Meta app should point to $domain: ${target?.host}",
                target!!.host.contains(domain))
        }
    }

    // ── Host inference edge cases ─────────────────────────────────────

    @Test
    fun `inferHost with deeply nested package`() {
        val host = AppRttTarget.inferHost("com.example.very.deep.nested.package")
        // skips: com → first non-skip = "example"
        assertEquals("www.example.com", host)
    }

    @Test
    fun `inferHost with numeric segment`() {
        val host = AppRttTarget.inferHost("com.123app.test")
        assertEquals("www.123app.com", host)
    }

    @Test
    fun `inferHost with mixed case`() {
        val host = AppRttTarget.inferHost("com.MyApp.test")
        assertEquals("www.MyApp.com", host)
    }

    @Test
    fun `inferHost with underscore`() {
        val host = AppRttTarget.inferHost("com.my_app.test")
        assertEquals("www.my_app.com", host)
    }

    @Test
    fun `inferHost with hyphen`() {
        val host = AppRttTarget.inferHost("com.my-app.test")
        assertEquals("www.my-app.com", host)
    }

    @Test
    fun `inferHost all skip prefixes`() {
        assertNull(AppRttTarget.inferHost("com.org.net.io"))
    }

    @Test
    fun `inferHost skip set includes common prefixes`() {
        val skip = setOf("com", "org", "net", "io", "id", "co", "app", "www")
        assertTrue(skip.contains("com"))
        assertTrue(skip.contains("org"))
        assertTrue(skip.contains("net"))
        assertTrue(skip.contains("io"))
        assertTrue(skip.contains("id"))
        assertTrue(skip.contains("co"))
        assertTrue(skip.contains("app"))
        assertTrue(skip.contains("www"))
    }

    @Test
    fun `inferHost with single char segment`() {
        val host = AppRttTarget.inferHost("com.x.app")
        assertEquals("www.x.com", host)
    }

    // ── AppRttTarget data class edge cases ────────────────────────────

    @Test
    fun `AppRttTarget with different targets not equal`() {
        val t1 = RttTarget("Google", "www.google.com", 443)
        val t2 = RttTarget("Facebook", "www.facebook.com", 443)
        val a1 = AppRttTarget("com.app", "App", null, t1)
        val a2 = AppRttTarget("com.app", "App", null, t2)
        assertNotEquals(a1, a2)
    }

    @Test
    fun `AppRttTarget with different package not equal`() {
        val t = RttTarget("Google", "www.google.com", 443)
        val a1 = AppRttTarget("com.app1", "App", null, t)
        val a2 = AppRttTarget("com.app2", "App", null, t)
        assertNotEquals(a1, a2)
    }

    @Test
    fun `AppRttTarget with different appName not equal`() {
        val t = RttTarget("Google", "www.google.com", 443)
        val a1 = AppRttTarget("com.app", "App1", null, t)
        val a2 = AppRttTarget("com.app", "App2", null, t)
        assertNotEquals(a1, a2)
    }

    @Test
    fun `AppRttTarget selected state mutable`() {
        val t = RttTarget("Test", "test.com", 443)
        val a = AppRttTarget("com.test", "Test", null, t, selected = false)
        assertFalse(a.selected)
        a.selected = true
        assertTrue(a.selected)
    }

    @Test
    fun `AppRttTarget toString contains package`() {
        val t = RttTarget("Test", "test.com", 443)
        val a = AppRttTarget("com.test.app", "Test App", null, t)
        assertTrue(a.toString().contains("com.test.app"))
    }

    @Test
    fun `AppRttTarget toString contains appName`() {
        val t = RttTarget("Test", "test.com", 443)
        val a = AppRttTarget("com.test", "My App", null, t)
        assertTrue(a.toString().contains("My App"))
    }

    // ── Measurement combinations ──────────────────────────────────────

    @Test
    fun `Measurement dns large tcp small`() {
        val m = RttTestRunner.Measurement(999999, 1)
        assertFalse(m.isTimeout)
        assertEquals(999999L, m.dnsMs)
        assertEquals(1L, m.tcpMs)
    }

    @Test
    fun `Measurement dns small tcp large`() {
        val m = RttTestRunner.Measurement(1, 999999)
        assertFalse(m.isTimeout)
        assertEquals(1L, m.dnsMs)
        assertEquals(999999L, m.tcpMs)
    }

    @Test
    fun `Measurement with error and valid times`() {
        val m = RttTestRunner.Measurement(5, 10, "warning: slow")
        assertFalse(m.isTimeout)
        assertEquals("warning: slow", m.error)
    }

    @Test
    fun `Measurement multiple instances independent`() {
        val m1 = RttTestRunner.Measurement(5, 10)
        val m2 = RttTestRunner.Measurement(20, 30)
        assertEquals(5L, m1.dnsMs)
        assertEquals(20L, m2.dnsMs)
    }

    @Test
    fun `Measurement with negative dns and positive tcp`() {
        val m = RttTestRunner.Measurement(-1, 100)
        assertTrue(m.isTimeout)  // dnsMs == TIMEOUT
    }

    @Test
    fun `Measurement with positive dns and negative tcp`() {
        val m = RttTestRunner.Measurement(100, -1)
        assertTrue(m.isTimeout)  // tcpMs == TIMEOUT
    }

    // ── TIMEOUT constant consistency ──────────────────────────────────

    @Test
    fun `TIMEOUT is -1 across all classes`() {
        assertEquals(-1L, RttTestRunner.TIMEOUT)
        assertEquals(-1L, RttResult.TIMEOUT_MS)
        assertEquals(RttTestRunner.TIMEOUT, RttResult.TIMEOUT_MS)
    }

    @Test
    fun `timeout factory uses TIMEOUT constant`() {
        val r = RttResult.timeout(RttTarget("T", "t.com"))
        assertEquals(RttResult.TIMEOUT_MS, r.directDnsMs)
        assertEquals(RttResult.TIMEOUT_MS, r.directTcpMs)
        assertEquals(RttResult.TIMEOUT_MS, r.vpnDnsMs)
        assertEquals(RttResult.TIMEOUT_MS, r.vpnTcpMs)
    }

    @Test
    fun `directTimeout uses TIMEOUT constant`() {
        val r = RttResult.directTimeout(RttTarget("T", "t.com"), 5, 10)
        assertEquals(RttResult.TIMEOUT_MS, r.directDnsMs)
        assertEquals(RttResult.TIMEOUT_MS, r.directTcpMs)
    }

    @Test
    fun `vpnTimeout uses TIMEOUT constant`() {
        val r = RttResult.vpnTimeout(RttTarget("T", "t.com"), 5, 10)
        assertEquals(RttResult.TIMEOUT_MS, r.vpnDnsMs)
        assertEquals(RttResult.TIMEOUT_MS, r.vpnTcpMs)
    }

    // ── RttResult with minimum non-zero direct ────────────────────────

    @Test
    fun `overheadPercent with direct=1`() {
        // direct=1ms, vpn=2ms → overhead=1 → 100%
        val r = RttResult(RttTarget("T", "t.com"), 0, 1, 0, 2)
        assertEquals(100.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    @Test
    fun `overheadPercent with direct=1 vpn=1`() {
        // direct=1ms, vpn=1ms → overhead=0 → 0%
        val r = RttResult(RttTarget("T", "t.com"), 0, 1, 0, 1)
        assertEquals(0.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `overheadPercent with direct=2 vpn=3`() {
        // direct=2ms, vpn=3ms → overhead=1 → 50%
        val r = RttResult(RttTarget("T", "t.com"), 0, 2, 0, 3)
        assertEquals(50.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.RED, r.rating)
    }

    @Test
    fun `overheadPercent with direct=5 vpn=6`() {
        // direct=5ms, vpn=6ms → overhead=1 → 20%
        val r = RttResult(RttTarget("T", "t.com"), 0, 5, 0, 6)
        assertEquals(20.0, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    // ── Summary with exactly 2 results ────────────────────────────────

    @Test
    fun `summary exactly 2 results`() {
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 5, 10, 8, 15),  // direct=15, vpn=23
            RttResult(RttTarget("B", "b.com"), 3, 7, 4, 8),    // direct=10, vpn=12
        )
        val s = RttResult.Summary(results)
        assertEquals(2, s.successCount)
        assertEquals(0, s.timeoutCount)
        assertEquals(12L, s.avgDirectMs)  // (15+10)/2 = 12 (integer division)
        assertEquals(17L, s.avgVpnMs)     // (23+12)/2 = 17 (integer division)
    }

    @Test
    fun `summary 3 results 1 timeout`() {
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 5, 10, 8, 15),  // valid
            RttResult.timeout(RttTarget("B", "b.com")),         // timeout
            RttResult(RttTarget("C", "c.com"), 3, 7, 4, 8),    // valid
        )
        val s = RttResult.Summary(results)
        assertEquals(2, s.successCount)
        assertEquals(1, s.timeoutCount)
        // valid: direct=[15,10], vpn=[23,12]
        assertEquals(12L, s.avgDirectMs)  // (15+10)/2
        assertEquals(17L, s.avgVpnMs)     // (23+12)/2
    }

    @Test
    fun `summary overhead percent with 2 valid results`() {
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 10, 40, 15, 55),  // direct=50, vpn=70, overhead=20, 40%
            RttResult(RttTarget("B", "b.com"), 5, 15, 5, 18),    // direct=20, vpn=23, overhead=3, 15%
        )
        val s = RttResult.Summary(results)
        // avgDirect = (50+20)/2 = 35, avgVpn = (70+23)/2 = 46, avgOverhead = 11
        assertEquals(35L, s.avgDirectMs)
        assertEquals(46L, s.avgVpnMs)
        assertEquals(11L, s.avgOverheadMs)
        // overheadPercent = 11/35 * 100 = 31.4%
        assertEquals(31.4, s.avgOverheadPercent, 0.1)
    }

    // ── RttTarget with various inputs ─────────────────────────────────

    @Test
    fun `RttTarget with IP address 8_8_8_8`() {
        val t = RttTarget("DNS", "8.8.8.8", 443)
        assertEquals("8.8.8.8", t.host)
    }

    @Test
    fun `RttTarget with IP address 1_1_1_1`() {
        val t = RttTarget("Cloudflare", "1.1.1.1", 443)
        assertEquals("1.1.1.1", t.host)
    }

    @Test
    fun `RttTarget with very long name`() {
        val longName = "A".repeat(200)
        val t = RttTarget(longName, "example.com", 443)
        assertEquals(longName, t.name)
    }

    @Test
    fun `RttTarget with very long host`() {
        val longHost = "sub." + "a".repeat(100) + ".example.com"
        val t = RttTarget("Long", longHost, 443)
        assertEquals(longHost, t.host)
    }

    @Test
    fun `RttTarget with unicode name`() {
        val t = RttTarget("日本語テスト", "example.com", 443)
        assertEquals("日本語テスト", t.name)
    }

    @Test
    fun `RttTarget with emoji name`() {
        val t = RttTarget("🎮 Gaming", "example.com", 443)
        assertEquals("🎮 Gaming", t.name)
    }

    @Test
    fun `RttTarget port 1`() {
        val t = RttTarget("Test", "example.com", 1)
        assertEquals(1, t.port)
    }

    @Test
    fun `RttTarget port 80`() {
        val t = RttTarget("HTTP", "example.com", 80)
        assertEquals(80, t.port)
    }

    @Test
    fun `RttTarget port 8080`() {
        val t = RttTarget("Alt HTTP", "example.com", 8080)
        assertEquals(8080, t.port)
    }

    @Test
    fun `RttTarget default targets are all RttTarget instances`() {
        RttTarget.DEFAULT_TARGETS.forEach { target ->
            assertTrue(target is RttTarget)
        }
    }

    @Test
    fun `RttTarget default targets can be used in RttResult`() {
        RttTarget.DEFAULT_TARGETS.forEach { target ->
            val r = RttResult(target, 5, 10, 8, 15)
            assertEquals(target, r.target)
        }
    }

    // ── RttResult with extreme values ─────────────────────────────────

    @Test
    fun `RttResult with max long values`() {
        val r = RttResult(RttTarget("T", "t.com"),
            Long.MAX_VALUE / 2, Long.MAX_VALUE / 2,
            Long.MAX_VALUE / 2, Long.MAX_VALUE / 2)
        assertEquals(Long.MAX_VALUE - 1, r.directTotalMs)
        assertEquals(Long.MAX_VALUE - 1, r.vpnTotalMs)
    }

    @Test
    fun `RttResult overhead with max values no overflow`() {
        val r = RttResult(RttTarget("T", "t.com"),
            0, 1000000, 0, 2000000)
        assertEquals(1000000L, r.overheadMs)
        assertEquals(100.0, r.overheadPercent, 0.1)
    }

    @Test
    fun `RttResult with dns=Long_MAX tcp=0`() {
        val r = RttResult(RttTarget("T", "t.com"),
            Long.MAX_VALUE, 0, 0, 0)
        assertEquals(Long.MAX_VALUE, r.directTotalMs)
    }

    // ── Summary edge cases ────────────────────────────────────────────

    @Test
    fun `summary with all different overheads`() {
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 10, 40, 10, 45),  // overhead=5, 10%
            RttResult(RttTarget("B", "b.com"), 10, 40, 15, 55),  // overhead=20, 40%
            RttResult(RttTarget("C", "c.com"), 10, 40, 20, 70),  // overhead=40, 80%
        )
        val s = RttResult.Summary(results)
        assertEquals(3, s.successCount)
        // avgDirect = 50, avgVpn = (55+70+90)/3 = 71, avgOverhead = 21
        // Actually: direct=[50,50,50], vpn=[55,70,90]
        // avgDirect = 50, avgVpn = 215/3 = 71, avgOverhead = 21
        assertEquals(50L, s.avgDirectMs)
        assertEquals(71L, s.avgVpnMs)
        assertEquals(21L, s.avgOverheadMs)
    }

    @Test
    fun `summary timeoutCount equals total minus successCount`() {
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 5, 10, 8, 15),
            RttResult.timeout(RttTarget("B", "b.com")),
            RttResult.directTimeout(RttTarget("C", "c.com"), 5, 10),
            RttResult.vpnTimeout(RttTarget("D", "d.com"), 5, 10),
            RttResult(RttTarget("E", "e.com"), 3, 7, 4, 8),
        )
        val s = RttResult.Summary(results)
        assertEquals(5, s.successCount + s.timeoutCount)
    }

    @Test
    fun `summary avgOverheadMs equals avgVpnMs minus avgDirectMs`() {
        val results = listOf(
            RttResult(RttTarget("A", "a.com"), 10, 20, 15, 30),
            RttResult(RttTarget("B", "b.com"), 5, 10, 8, 15),
        )
        val s = RttResult.Summary(results)
        assertEquals(s.avgVpnMs - s.avgDirectMs, s.avgOverheadMs)
    }

    // ── Rating boundary precision ─────────────────────────────────────

    @Test
    fun `rating at 19_5 percent is GREEN`() {
        // direct=200, overhead=39 → 19.5%
        val r = RttResult(RttTarget("T", "t.com"), 50, 150, 50, 189)
        assertEquals(19.5, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.GREEN, r.rating)
    }

    @Test
    fun `rating at 20_5 percent is YELLOW`() {
        // direct=200, overhead=41 → 20.5%
        val r = RttResult(RttTarget("T", "t.com"), 50, 150, 50, 191)
        assertEquals(20.5, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `rating at 49_5 percent is YELLOW`() {
        // direct=200, overhead=99 → 49.5%
        val r = RttResult(RttTarget("T", "t.com"), 50, 150, 50, 249)
        assertEquals(49.5, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.YELLOW, r.rating)
    }

    @Test
    fun `rating at 50_5 percent is RED`() {
        // direct=200, overhead=101 → 50.5%
        val r = RttResult(RttTarget("T", "t.com"), 50, 150, 50, 251)
        assertEquals(50.5, r.overheadPercent, 0.1)
        assertEquals(RttResult.Rating.RED, r.rating)
    }
}

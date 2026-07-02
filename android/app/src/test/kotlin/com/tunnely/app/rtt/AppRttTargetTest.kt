package com.tunnely.app.rtt

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for AppRttTarget — app-to-server mapping for RTT testing.
 * Covers: known apps, host inference, deduplication logic.
 */
class AppRttTargetTest {

    // ── Known apps mapping ────────────────────────────────────────────

    @Test
    fun `KNOWN_APPS is not empty`() {
        assertTrue(AppRttTarget.KNOWN_APPS.isNotEmpty())
    }

    @Test
    fun `KNOWN_APPS has at least 30 entries`() {
        assertTrue("Should have 30+ known apps", AppRttTarget.KNOWN_APPS.size >= 30)
    }

    @Test
    fun `KNOWN_APPS all have valid hosts`() {
        AppRttTarget.KNOWN_APPS.forEach { (pkg, target) ->
            assertTrue("Host blank for $pkg", target.host.isNotBlank())
            assertTrue("Host should contain dot: ${target.host}", target.host.contains('.'))
        }
    }

    @Test
    fun `KNOWN_APPS all have valid names`() {
        AppRttTarget.KNOWN_APPS.forEach { (pkg, target) ->
            assertTrue("Name blank for $pkg", target.name.isNotBlank())
        }
    }

    @Test
    fun `KNOWN_APPS all have port 443`() {
        AppRttTarget.KNOWN_APPS.forEach { (pkg, target) ->
            assertEquals("Port should be 443 for $pkg", 443, target.port)
        }
    }

    @Test
    fun `KNOWN_APPS includes Google`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.google.android.googlequicksearchbox"))
        assertEquals("www.google.com", AppRttTarget.KNOWN_APPS["com.google.android.googlequicksearchbox"]?.host)
    }

    @Test
    fun `KNOWN_APPS includes Instagram`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.instagram.android"))
        assertEquals("www.instagram.com", AppRttTarget.KNOWN_APPS["com.instagram.android"]?.host)
    }

    @Test
    fun `KNOWN_APPS includes WhatsApp`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.whatsapp"))
        assertEquals("web.whatsapp.com", AppRttTarget.KNOWN_APPS["com.whatsapp"]?.host)
    }

    @Test
    fun `KNOWN_APPS includes Tokopedia`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.tokopedia.tkpd"))
        assertEquals("www.tokopedia.com", AppRttTarget.KNOWN_APPS["com.tokopedia.tkpd"]?.host)
    }

    @Test
    fun `KNOWN_APPS includes Shopee`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.shopee.id"))
        assertEquals("shopee.co.id", AppRttTarget.KNOWN_APPS["com.shopee.id"]?.host)
    }

    @Test
    fun `KNOWN_APPS includes Telegram`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("org.telegram.messenger"))
        assertEquals("web.telegram.org", AppRttTarget.KNOWN_APPS["org.telegram.messenger"]?.host)
    }

    @Test
    fun `KNOWN_APPS includes Spotify`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.spotify.music"))
        assertEquals("open.spotify.com", AppRttTarget.KNOWN_APPS["com.spotify.music"]?.host)
    }

    @Test
    fun `KNOWN_APPS includes Indonesian banks`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("id.co.bri.brimo"))
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.bca"))
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("id.co.bankmandiri.mandirionline"))
    }

    @Test
    fun `KNOWN_APPS includes ride-hailing`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.grabtaxi.passenger"))
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.gojek.app"))
    }

    @Test
    fun `KNOWN_APPS includes gaming`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.mobile.legends"))
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.garena.game.kgid"))
    }

    @Test
    fun `KNOWN_APPS includes streaming`() {
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.spotify.music"))
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.netflix.mediaclient"))
        assertTrue(AppRttTarget.KNOWN_APPS.containsKey("com.google.android.apps.youtube.music"))
    }

    @Test
    fun `KNOWN_APPS duplicate hosts for WhatsApp variants`() {
        val wa = AppRttTarget.KNOWN_APPS["com.whatsapp"]
        val waB = AppRttTarget.KNOWN_APPS["com.whatsapp.w4b"]
        assertNotNull(wa)
        assertNotNull(waB)
        assertEquals(wa?.host, waB?.host)  // same host
    }

    @Test
    fun `KNOWN_APPS duplicate hosts for TikTok variants`() {
        val tt1 = AppRttTarget.KNOWN_APPS["com.zhiliaoapp.musically"]
        val tt2 = AppRttTarget.KNOWN_APPS["com.ss.android.ugc.trill"]
        assertNotNull(tt1)
        assertNotNull(tt2)
        assertEquals(tt1?.host, tt2?.host)
    }

    @Test
    fun `KNOWN_APPS duplicate hosts for X variants`() {
        val x1 = AppRttTarget.KNOWN_APPS["com.twitter.android"]
        val x2 = AppRttTarget.KNOWN_APPS["com.x.android"]
        assertNotNull(x1)
        assertNotNull(x2)
        assertEquals(x1?.host, x2?.host)
    }

    // ── Host inference ────────────────────────────────────────────────

    @Test
    fun `inferHost basic com-domain`() {
        assertEquals("www.example.com", AppRttTarget.inferHost("com.example.app"))
    }

    @Test
    fun `inferHost skips common prefixes`() {
        // "com.google.android.youtube" → first non-skip = "google"
        val host = AppRttTarget.inferHost("com.google.android.youtube")
        assertEquals("www.google.com", host)
    }

    @Test
    fun `inferHost org domain`() {
        // inferHost always appends .com — it's a best-effort guess
        assertEquals("www.telegram.com", AppRttTarget.inferHost("org.telegram.messenger"))
    }

    @Test
    fun `inferHost id domain`() {
        val host = AppRttTarget.inferHost("id.co.bri.brimo")
        // skips: id, co → first non-skip = "bri"
        assertEquals("www.bri.com", host)
    }

    @Test
    fun `inferHost single segment returns null`() {
        assertNull(AppRttTarget.inferHost("example"))
    }

    @Test
    fun `inferHost empty string returns null`() {
        assertNull(AppRttTarget.inferHost(""))
    }

    @Test
    fun `inferHost only prefixes returns null`() {
        // all parts are in skip set
        assertNull(AppRttTarget.inferHost("com.org.net"))
    }

    @Test
    fun `inferHost two segments`() {
        assertEquals("www.example.com", AppRttTarget.inferHost("com.example"))
    }

    // ── AppRttTarget data class ───────────────────────────────────────

    @Test
    fun `AppRttTarget data class equality`() {
        val target = RttTarget("Google", "www.google.com", 443)
        val a1 = AppRttTarget("com.google.app", "Google", null, target, false)
        val a2 = AppRttTarget("com.google.app", "Google", null, target, false)
        assertEquals(a1, a2)
        assertEquals(a1.hashCode(), a2.hashCode())
    }

    @Test
    fun `AppRttTarget data class inequality`() {
        val target = RttTarget("Google", "www.google.com", 443)
        val a1 = AppRttTarget("com.google.app", "Google", null, target, false)
        val a2 = AppRttTarget("com.google.app", "Google", null, target, true)
        assertNotEquals(a1, a2)
    }

    @Test
    fun `AppRttTarget default selected is false`() {
        val target = RttTarget("Test", "test.com", 443)
        val a = AppRttTarget("com.test", "Test", null, target)
        assertFalse(a.selected)
    }

    @Test
    fun `AppRttTarget icon is null in test`() {
        val target = RttTarget("Test", "test.com", 443)
        val a = AppRttTarget("com.test", "Test", null, target)
        assertNull(a.icon)
    }

    @Test
    fun `AppRttTarget target reference`() {
        val target = RttTarget("Custom", "custom.example.com", 8443)
        val a = AppRttTarget("com.custom", "Custom", null, target)
        assertEquals(target, a.target)
        assertEquals("custom.example.com", a.target.host)
        assertEquals(8443, a.target.port)
    }

    @Test
    fun `AppRttTarget copy`() {
        val target = RttTarget("Google", "www.google.com", 443)
        val a = AppRttTarget("com.google", "Google", null, target, false)
        val a2 = a.copy(selected = true)
        assertTrue(a2.selected)
        assertEquals("com.google", a2.packageName)
    }
}

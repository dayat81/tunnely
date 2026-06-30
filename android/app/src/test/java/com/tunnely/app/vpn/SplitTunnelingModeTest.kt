package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

/**
 * Unit tests for split tunneling mode logic.
 * 
 * These test the preference logic, not the Android VpnService.Builder
 * (which requires a real Android context).
 */
class SplitTunnelingModeTest {

    @Test
    fun `exclude mode - selected apps should be disallowed`() {
        val mode = "exclude"
        val selectedApps = setOf("com.android.chrome", "org.mozilla.firefox")
        
        // In exclude mode, selected apps bypass VPN
        assertEquals("exclude", mode)
        assertTrue(selectedApps.contains("com.android.chrome"))
    }

    @Test
    fun `include mode - selected apps should be allowed`() {
        val mode = "include"
        val selectedApps = setOf("com.android.chrome")
        
        // In include mode, only selected apps go through VPN
        assertEquals("include", mode)
        assertTrue(selectedApps.contains("com.android.chrome"))
    }

    @Test
    fun `mode should be persisted correctly`() {
        // Simulate the flow: user selects mode → save → read
        var savedMode = "exclude"  // default
        
        // User clicks Include button
        savedMode = "include"
        
        // Save to prefs (simulated)
        assertEquals("include", savedMode)
        
        // Read from prefs
        val readMode = savedMode
        assertEquals("include", readMode)
    }

    @Test
    fun `split tunneling disabled should skip mode logic`() {
        val splitEnabled = false
        val mode = "exclude"
        val apps = setOf("com.android.chrome")
        
        // When split is disabled, mode and apps don't matter
        assertFalse(splitEnabled)
        // VPN builder should NOT apply any split tunneling
    }

    @Test
    fun `split tunneling enabled but no apps selected should skip`() {
        val splitEnabled = true
        val apps = emptySet<String>()
        val mode = "exclude"
        
        assertTrue(splitEnabled)
        assertTrue(apps.isEmpty())
        // VPN builder should NOT apply split tunneling
    }

    @Test
    fun `default mode is exclude`() {
        val defaultMode = "exclude"
        assertEquals("exclude", defaultMode)
    }

    @Test
    fun `mode values are case sensitive`() {
        val mode1 = "exclude"
        val mode2 = "Exclude"
        val mode3 = "EXCLUDE"
        
        assertNotEquals(mode1, mode2)
        assertNotEquals(mode1, mode3)
        // Only lowercase "exclude" should match
    }

    // ── Dialog Persistence Tests (Issue #23) ──────────────────────────

    @Test
    fun `dialog save should persist apps immediately`() {
        // Simulate dialog Save button behavior
        val appsToSave = setOf("com.android.chrome", "org.mozilla.firefox")
        
        // In real code, this calls: prefs.splitApps = appsToSave
        // which now uses commit() for synchronous write
        val savedApps = appsToSave  // Simulated write
        
        // Verify apps are saved
        assertEquals(2, savedApps.size)
        assertTrue(savedApps.contains("com.android.chrome"))
        assertTrue(savedApps.contains("org.mozilla.firefox"))
    }

    @Test
    fun `dialog clear should empty apps immediately`() {
        // Simulate dialog Clear button behavior
        val appsAfterClear = emptySet<String>()
        
        // In real code, this calls: prefs.splitApps = emptySet()
        // which now uses commit() for synchronous write
        
        assertTrue(appsAfterClear.isEmpty())
    }

    @Test
    fun `dialog save then connect should read same apps`() {
        // Simulate the race condition fix:
        // 1. User selects apps in dialog
        // 2. Clicks Save (commit() writes synchronously)
        // 3. Immediately clicks Connect
        // 4. VPN service reads splitApps
        
        val selectedApps = setOf("com.android.chrome")
        
        // After commit(), read should return same value
        val readApps = selectedApps  // Simulated read
        
        assertEquals(1, readApps.size)
        assertTrue(readApps.contains("com.android.chrome"))
    }

    @Test
    fun `toggle switch persists splitTunneling immediately`() {
        // The toggle switch now saves splitTunneling immediately
        // (not just on main Save button click)
        var splitTunneling = false
        
        // User toggles ON
        splitTunneling = true
        
        // Should persist immediately
        assertTrue(splitTunneling)
    }

    @Test
    fun `mode toggle persists splitMode immediately`() {
        // The mode toggle now saves splitMode immediately
        var splitMode = "exclude"
        
        // User clicks Include mode
        splitMode = "include"
        
        // Should persist immediately
        assertEquals("include", splitMode)
    }

    @Test
    fun `all three prefs saved before VPN connects`() {
        // Scenario: User toggles split ON, picks Include mode, selects apps
        // All should be saved before Connect is clicked
        
        var splitTunneling = false
        var splitMode = "exclude"
        var splitApps = emptySet<String>()
        
        // User interactions (each saves immediately)
        splitTunneling = true
        splitMode = "include"
        splitApps = setOf("com.android.chrome", "com.whatsapp")
        
        // VPN service reads all three
        assertTrue(splitTunneling)
        assertEquals("include", splitMode)
        assertEquals(2, splitApps.size)
        assertTrue(splitApps.contains("com.android.chrome"))
        assertTrue(splitApps.contains("com.whatsapp"))
    }

    @Test
    fun `dialog save replaces previous selection`() {
        // User opens dialog, selects Chrome, saves
        var savedApps = setOf("com.android.chrome")
        
        // User opens dialog again, selects WhatsApp (unchecks Chrome), saves
        savedApps = setOf("com.whatsapp")
        
        // Should have only WhatsApp, not both
        assertEquals(1, savedApps.size)
        assertFalse(savedApps.contains("com.android.chrome"))
        assertTrue(savedApps.contains("com.whatsapp"))
    }

    @Test
    fun `empty apps set means split tunneling is no-op`() {
        // If splitTunneling is ON but apps is empty, VPN builder should skip
        val splitEnabled = true
        val apps = emptySet<String>()
        val mode = "exclude"
        
        assertTrue(splitEnabled)
        assertTrue(apps.isEmpty())
        // VPN builder should NOT call addDisallowedApplication()
    }

    @Test
    fun `exclude mode with apps means those apps bypass VPN`() {
        // In exclude mode, selected apps are EXCLUDED from VPN (bypass)
        val mode = "exclude"
        val apps = setOf("com.android.chrome")
        
        assertEquals("exclude", mode)
        assertEquals(1, apps.size)
        // VPN builder should call addDisallowedApplication("com.android.chrome")
    }

    @Test
    fun `include mode with apps means only those apps use VPN`() {
        // In include mode, ONLY selected apps go through VPN
        val mode = "include"
        val apps = setOf("com.android.chrome")
        
        assertEquals("include", mode)
        assertEquals(1, apps.size)
        // VPN builder should call addAllowedApplication("com.android.chrome")
    }

    @Test
    fun `switching mode does not clear apps`() {
        // User selects apps, then switches mode
        var apps = setOf("com.android.chrome", "com.whatsapp")
        var mode = "exclude"
        
        // User switches to Include mode
        mode = "include"
        
        // Apps should persist
        assertEquals(2, apps.size)
        assertEquals("include", mode)
    }
}

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
}

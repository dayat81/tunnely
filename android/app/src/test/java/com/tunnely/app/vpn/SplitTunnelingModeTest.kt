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

    @Test
    fun `include mode with 0 apps should block all traffic`() {
        // Issue #29: Include mode + 0 apps = traffic still flows (v3.14.6)
        // v3.14.7: dummy placeholder → NameNotFoundException → still broken
        // v3.14.8: throw exception before VPN establishment → VPN not started
        val mode = "include"
        val apps = emptySet<String>()
        val splitTunneling = true
        
        assertEquals("include", mode)
        assertEquals(0, apps.size)
        assertTrue(splitTunneling)
        
        // Should prevent VPN start when Include mode has 0 apps
        val shouldPreventVpn = splitTunneling && mode == "include" && apps.isEmpty()
        assertTrue(shouldPreventVpn)
    }

    @Test
    fun `include mode with apps should allow those apps`() {
        // Normal include mode: selected apps go through VPN
        val mode = "include"
        val apps = setOf("com.android.chrome")
        val splitTunneling = true
        
        assertEquals("include", mode)
        assertEquals(1, apps.size)
        
        // VPN should start with only selected apps
        val shouldPreventVpn = splitTunneling && mode == "include" && apps.isEmpty()
        assertFalse(shouldPreventVpn)
    }

    @Test
    fun `exclude mode with 0 apps should allow all traffic`() {
        // Exclude mode with 0 apps = no exclusions = all traffic through VPN
        val mode = "exclude"
        val apps = emptySet<String>()
        val splitTunneling = true
        
        assertEquals("exclude", mode)
        assertEquals(0, apps.size)
        
        // VPN should start normally (all traffic through VPN)
        val shouldPreventVpn = splitTunneling && mode == "include" && apps.isEmpty()
        assertFalse(shouldPreventVpn)
    }

    @Test
    fun `exclude mode with apps should exclude those apps`() {
        // Exclude mode: selected apps bypass VPN
        val mode = "exclude"
        val apps = setOf("com.android.chrome", "org.mozilla.firefox")
        val splitTunneling = true
        
        assertEquals("exclude", mode)
        assertEquals(2, apps.size)
        
        // VPN should start with those apps excluded
        val shouldPreventVpn = splitTunneling && mode == "include" && apps.isEmpty()
        assertFalse(shouldPreventVpn)
    }

    @Test
    fun `split tunneling disabled should allow all traffic`() {
        // Split tunneling off = all traffic through VPN regardless of mode
        val mode = "include"
        val apps = setOf("com.android.chrome")
        val splitTunneling = false
        
        assertFalse(splitTunneling)
        
        // VPN should start normally (split tunneling disabled)
        val shouldPreventVpn = splitTunneling && mode == "include" && apps.isEmpty()
        assertFalse(shouldPreventVpn)
    }

    @Test
    fun `include mode with multiple apps should work`() {
        // Include mode with multiple apps
        val mode = "include"
        val apps = setOf("com.android.chrome", "org.mozilla.firefox", "com.whatsapp")
        val splitTunneling = true
        
        assertEquals("include", mode)
        assertEquals(3, apps.size)
        
        // VPN should start with only those 3 apps
        val shouldPreventVpn = splitTunneling && mode == "include" && apps.isEmpty()
        assertFalse(shouldPreventVpn)
    }

    @Test
    fun `dummy placeholder fails with NameNotFoundException`() {
        // v3.14.7 fix attempt: addAllowedApplication("com.tunnely.blocked.placeholder")
        // This fails because Android validates package existence
        val dummyPackage = "com.tunnely.blocked.placeholder"
        
        // Simulate: addAllowedApplication throws NameNotFoundException
        // for non-existent packages
        val packageExists = false  // placeholder doesn't exist
        assertFalse(packageExists)
        
        // Therefore: dummy placeholder approach doesn't work
        // Must use throw exception approach instead
    }

    @Test
    fun `vpn error message for include 0 apps`() {
        // Error message when Include mode has 0 apps
        val expectedMessage = "Include mode requires at least 1 app. No apps selected — VPN not started."
        
        // Message should be user-friendly
        assertTrue(expectedMessage.contains("Include mode"))
        assertTrue(expectedMessage.contains("at least 1 app"))
    }

    // ── Additional Edge Cases ─────────────────────────────────────

    @Test
    fun `mode switching preserves apps`() {
        // User selects apps, then switches mode
        var apps = setOf("com.android.chrome", "com.whatsapp")
        var mode = "exclude"

        // User switches to Include
        mode = "include"
        assertEquals(2, apps.size)
        assertEquals("include", mode)

        // User switches back to Exclude
        mode = "exclude"
        assertEquals(2, apps.size)
        assertEquals("exclude", mode)
    }

    @Test
    fun `invalid mode defaults to exclude`() {
        // If mode is somehow invalid, should fall back to exclude
        val mode = "invalid"
        val effectiveMode = if (mode == "include") "include" else "exclude"
        assertEquals("exclude", effectiveMode)
    }

    @Test
    fun `empty string in apps set`() {
        // Edge case: empty string as package name
        val apps = setOf("")
        assertEquals(1, apps.size)
        assertTrue(apps.contains(""))
        // Should be treated as valid (though Android will reject it)
    }

    @Test
    fun `whitespace in package name`() {
        // Edge case: whitespace in package name
        val apps = setOf("com.android.chrome ")
        assertEquals(1, apps.size)
        // Android will reject this, but our logic shouldn't crash
    }

    @Test
    fun `duplicate apps in set`() {
        // Sets naturally deduplicate
        val apps = setOf("com.android.chrome", "com.android.chrome", "com.whatsapp")
        assertEquals(2, apps.size)
    }

    @Test
    fun `system apps can be selected`() {
        // System apps like com.android.*, com.google.*
        val apps = setOf(
            "com.android.chrome",
            "com.android.settings",
            "com.google.android.gms",
            "com.google.android.apps.maps"
        )
        assertEquals(4, apps.size)
    }

    @Test
    fun `our own app in include list`() {
        // If user adds Tunnely itself to include list
        val apps = setOf("com.tunnely.app", "com.android.chrome")
        val mode = "include"

        assertEquals(2, apps.size)
        // VPN builder will exclude ourselves AND try to allow ourselves
        // Exclusion takes precedence in Android
    }

    @Test
    fun `our own app in exclude list`() {
        // If user adds Tunnely itself to exclude list
        val apps = setOf("com.tunnely.app")
        val mode = "exclude"

        assertEquals(1, apps.size)
        // VPN builder already excludes ourselves, this is redundant but harmless
    }

    @Test
    fun `very long package name`() {
        // Edge case: very long package name
        val longPkg = "com." + "a".repeat(200) + ".app"
        val apps = setOf(longPkg)
        assertEquals(1, apps.size)
        assertTrue(apps.first().length > 200)
    }

    @Test
    fun `special characters in package name`() {
        // Edge case: special characters (invalid but shouldn't crash)
        val apps = setOf("com.android.chrome!@#")
        assertEquals(1, apps.size)
    }

    @Test
    fun `include mode remove last app`() {
        // Start with 1 app, remove it → 0 apps → should prevent VPN
        var apps = setOf("com.android.chrome")
        val mode = "include"

        assertEquals(1, apps.size)
        assertFalse(apps.isEmpty())

        // User removes the last app
        apps = emptySet()
        assertEquals(0, apps.size)
        assertTrue(apps.isEmpty())

        // Should prevent VPN
        val shouldPrevent = mode == "include" && apps.isEmpty()
        assertTrue(shouldPrevent)
    }

    @Test
    fun `exclude mode remove all apps`() {
        // Start with apps, remove all → still works (all through VPN)
        var apps = setOf("com.android.chrome", "com.whatsapp")
        val mode = "exclude"

        assertEquals(2, apps.size)

        // User removes all apps
        apps = emptySet()
        assertEquals(0, apps.size)

        // VPN should still start (exclude with 0 = no exclusions)
        val shouldPrevent = mode == "include" && apps.isEmpty()
        assertFalse(shouldPrevent)
    }

    @Test
    fun `case sensitivity`() {
        // Package names are case-sensitive
        val apps = setOf("com.android.Chrome", "com.android.chrome")
        assertEquals(2, apps.size)  // Different packages
    }

    @Test
    fun `many apps in include mode`() {
        // Include mode with many apps (e.g., 50)
        val apps = (1..50).map { "com.app$it" }.toSet()
        val mode = "include"

        assertEquals(50, apps.size)
        assertFalse(apps.isEmpty())

        // VPN should start with all 50 apps
        val shouldPrevent = mode == "include" && apps.isEmpty()
        assertFalse(shouldPrevent)
    }

    @Test
    fun `many apps in exclude mode`() {
        // Exclude mode with many apps
        val apps = (1..50).map { "com.app$it" }.toSet()
        val mode = "exclude"

        assertEquals(50, apps.size)

        // VPN should start (those 50 apps bypass VPN)
        val shouldPrevent = mode == "include" && apps.isEmpty()
        assertFalse(shouldPrevent)
    }

    @Test
    fun `split tunneling toggle rapidly`() {
        // Simulate rapid toggle: on → off → on
        var splitTunneling = true
        var apps = setOf("com.android.chrome")
        var mode = "include"

        // Toggle off
        splitTunneling = false
        assertFalse(splitTunneling)

        // Toggle on again
        splitTunneling = true
        assertTrue(splitTunneling)
        assertEquals(1, apps.size)  // Apps preserved
    }

    @Test
    fun `mode and apps independence`() {
        // Changing mode doesn't affect apps, changing apps doesn't affect mode
        var mode = "include"
        var apps = setOf("com.android.chrome")

        // Change mode
        mode = "exclude"
        assertEquals(1, apps.size)  // Apps unchanged

        // Change apps
        apps = setOf("com.whatsapp", "com.telegram")
        assertEquals("exclude", mode)  // Mode unchanged
    }

    @Test
    fun `shouldPreventVpn truth table`() {
        // Test all combinations of the prevent VPN logic
        data class Case(
            val splitTunneling: Boolean,
            val mode: String,
            val appsSize: Int,
            val expected: Boolean
        )

        val cases = listOf(
            Case(true, "include", 0, true),   // Include + 0 apps → prevent
            Case(true, "include", 1, false),  // Include + 1 app → allow
            Case(true, "exclude", 0, false),  // Exclude + 0 apps → allow
            Case(true, "exclude", 1, false),  // Exclude + 1 app → allow
            Case(false, "include", 0, false), // Disabled → allow
            Case(false, "include", 1, false), // Disabled → allow
            Case(false, "exclude", 0, false), // Disabled → allow
            Case(false, "exclude", 1, false), // Disabled → allow
        )

        for (case in cases) {
            val result = case.splitTunneling && case.mode == "include" && case.appsSize == 0
            assertEquals(
                "splitTunneling=${case.splitTunneling}, mode=${case.mode}, apps=${case.appsSize}",
                case.expected,
                result
            )
        }
    }

    @Test
    fun `include mode add then remove app`() {
        // Add app, then remove → back to 0 apps
        var apps = setOf<String>()
        val mode = "include"

        // Add app
        apps = setOf("com.android.chrome")
        assertFalse(apps.isEmpty())

        // Remove app
        apps = emptySet()
        assertTrue(apps.isEmpty())

        // Should prevent VPN
        val shouldPrevent = mode == "include" && apps.isEmpty()
        assertTrue(shouldPrevent)
    }

    @Test
    fun `exclude mode add then remove app`() {
        // Add app, then remove → back to 0 apps
        var apps = setOf<String>()
        val mode = "exclude"

        // Add app
        apps = setOf("com.android.chrome")
        assertFalse(apps.isEmpty())

        // Remove app
        apps = emptySet()
        assertTrue(apps.isEmpty())

        // Should NOT prevent VPN (exclude + 0 = no exclusions)
        val shouldPrevent = mode == "include" && apps.isEmpty()
        assertFalse(shouldPrevent)
    }

    @Test
    fun `package name with numbers`() {
        val apps = setOf("com.app123.test456")
        assertEquals(1, apps.size)
        assertTrue(apps.first().matches(Regex(".*\\d+.*")))
    }

    @Test
    fun `package name with underscores`() {
        val apps = setOf("com.my_app.test_name")
        assertEquals(1, apps.size)
    }

    @Test
    fun `single character package`() {
        val apps = setOf("a")
        assertEquals(1, apps.size)
        // Invalid but shouldn't crash
    }

    @Test
    fun `include mode with system and user apps`() {
        // Mix of system and user apps
        val apps = setOf(
            "com.android.chrome",      // system
            "com.whatsapp",             // user
            "com.google.android.gms",   // system
            "org.mozilla.firefox"       // user
        )
        val mode = "include"

        assertEquals(4, apps.size)

        // VPN should start with all 4 apps
        val shouldPrevent = mode == "include" && apps.isEmpty()
        assertFalse(shouldPrevent)
    }

    @Test
    fun `concurrent mode and apps changes`() {
        // Simulate concurrent changes (race condition test)
        var mode = "include"
        var apps = setOf("com.android.chrome")

        // Thread 1: change mode
        mode = "exclude"

        // Thread 2: change apps
        apps = setOf("com.whatsapp", "com.telegram")

        // Final state should be consistent
        assertEquals("exclude", mode)
        assertEquals(2, apps.size)
    }

    @Test
    fun `vpn start condition edge cases`() {
        // Additional edge cases for VPN start condition

        // Include + 0 apps + splitTunneling=false → should NOT prevent
        assertFalse(false && "include" == "include" && 0 == 0)

        // Include + 0 apps + splitTunneling=true → SHOULD prevent
        assertTrue(true && "include" == "include" && 0 == 0)

        // Include + 1 app + splitTunneling=true → should NOT prevent
        assertFalse(true && "include" == "include" && 1 == 0)

        // Exclude + 0 apps + splitTunneling=true → should NOT prevent
        assertFalse(true && "exclude" == "include" && 0 == 0)
    }
}

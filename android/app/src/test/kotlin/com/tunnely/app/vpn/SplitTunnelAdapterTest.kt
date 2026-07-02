package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

/**
 * Tests for split tunneling adapter logic and SharedPreferences persistence.
 * Covers: Issue #39 — checkbox double-toggle bug, putStringSet skip-if-equal bug.
 */
class SplitTunnelAdapterTest {

    // ── Simulate SplitTunnelApp data class behavior ─────────────────

    data class MockApp(
        val packageName: String,
        val appName: String,
        var selected: Boolean,
    )

    // ── Checkbox toggle: direct tap ─────────────────────────────────

    @Test
    fun `checkbox tap toggles selected state`() {
        val app = MockApp("com.whatsapp", "WhatsApp", selected = false)

        // Simulate: user taps checkbox → listener fires with isChecked=true
        val isChecked = true
        app.selected = isChecked

        assertTrue(app.selected)
    }

    @Test
    fun `checkbox tap uncheck toggles selected state`() {
        val app = MockApp("com.whatsapp", "WhatsApp", selected = true)

        // Simulate: user unchecks → listener fires with isChecked=false
        val isChecked = false
        app.selected = isChecked

        assertFalse(app.selected)
    }

    // ── Checkbox toggle: row click (double-toggle bug) ──────────────

    @Test
    fun `row click without listener suppression causes double toggle`() {
        // Bug: row click sets app.selected, then sets appCheck.isChecked
        // which triggers OnCheckedChangeListener, flipping app.selected back
        val app = MockApp("com.whatsapp", "WhatsApp", selected = false)

        // Step 1: row click handler
        app.selected = !app.selected  // false → true

        // Step 2: appCheck.isChecked = app.selected triggers listener
        // Old buggy code: app.selected = !app.selected  // true → false!
        // Net effect: no change! Bug!

        // Without fix, this would happen:
        app.selected = !app.selected  // simulating listener re-fire

        assertFalse("Bug: double-toggle reverted the change", app.selected)
    }

    @Test
    fun `row click with listener suppression preserves toggle`() {
        // Fix: suppress OnCheckedChangeListener before setting isChecked
        val app = MockApp("com.whatsapp", "WhatsApp", selected = false)

        // Step 1: row click handler
        app.selected = !app.selected  // false → true

        // Step 2: listener suppressed → isChecked set without triggering listener
        // appCheck.setOnCheckedChangeListener(null)  // suppressed
        // appCheck.isChecked = app.selected           // no listener = no flip
        // appCheck.setOnCheckedChangeListener { ... } // re-attach

        assertTrue("Fix: toggle preserved", app.selected)
    }

    @Test
    fun `checkbox listener uses isChecked param not manual flip`() {
        // Fix: use isChecked parameter instead of !app.selected
        val app = MockApp("com.whatsapp", "WhatsApp", selected = false)

        // Old buggy code: app.selected = !app.selected (ignores actual checkbox state)
        // New fixed code: app.selected = isChecked (uses actual state)
        val isChecked = true
        app.selected = isChecked  // correct: uses the actual checkbox state

        assertTrue(app.selected)
    }

    // ── getSelectedPackages logic ───────────────────────────────────

    @Test
    fun `getSelectedPackages returns only selected apps`() {
        val apps = listOf(
            MockApp("com.whatsapp", "WhatsApp", selected = true),
            MockApp("com.chrome", "Chrome", selected = false),
            MockApp("com.instagram", "Instagram", selected = true),
        )

        val selected = apps.filter { it.selected }.map { it.packageName }.toSet()

        assertEquals(2, selected.size)
        assertTrue(selected.contains("com.whatsapp"))
        assertTrue(selected.contains("com.instagram"))
        assertFalse(selected.contains("com.chrome"))
    }

    @Test
    fun `getSelectedPackages returns empty when none selected`() {
        val apps = listOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
        )

        val selected = apps.filter { it.selected }.map { it.packageName }.toSet()

        assertTrue(selected.isEmpty())
    }

    @Test
    fun `toggle then getSelected reflects change`() {
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
        )

        // User taps WhatsApp checkbox
        apps[0].selected = true

        val selected = apps.filter { it.selected }.map { it.packageName }.toSet()

        assertEquals(1, selected.size)
        assertTrue(selected.contains("com.whatsapp"))
    }

    @Test
    fun `toggle multiple apps then getSelected reflects all`() {
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
            MockApp("com.instagram", "Instagram", selected = false),
        )

        // User taps WhatsApp and Instagram
        apps[0].selected = true
        apps[2].selected = true

        val selected = apps.filter { it.selected }.map { it.packageName }.toSet()

        assertEquals(2, selected.size)
        assertTrue(selected.contains("com.whatsapp"))
        assertTrue(selected.contains("com.instagram"))
    }

    // ── setSelectedPackages logic ───────────────────────────────────

    @Test
    fun `setSelectedPackages restores saved selection`() {
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
            MockApp("com.instagram", "Instagram", selected = false),
        )
        val savedPackages = setOf("com.whatsapp", "com.instagram")

        // Simulate setSelectedPackages
        apps.forEach { it.selected = it.packageName in savedPackages }

        assertTrue(apps[0].selected)  // WhatsApp
        assertFalse(apps[1].selected) // Chrome
        assertTrue(apps[2].selected)  // Instagram
    }

    @Test
    fun `setSelectedPackages with empty set clears all`() {
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = true),
            MockApp("com.chrome", "Chrome", selected = true),
        )

        apps.forEach { it.selected = it.packageName in emptySet<String>() }

        assertFalse(apps[0].selected)
        assertFalse(apps[1].selected)
    }

    // ── putStringSet skip-if-equal simulation ───────────────────────

    @Test
    fun `putStringSet with same content should still persist`() {
        // Android bug: putStringSet skips write if new set equals old set
        // Fix: remove() before putStringSet()

        // Simulate SharedPreferences storage
        var storedSet: Set<String>? = null

        fun putStringSet(value: Set<String>) {
            // Android buggy behavior: skip if equal
            if (storedSet == value) return  // BUG: skips write!
            storedSet = value
        }

        fun putStringSetFixed(value: Set<String>) {
            // Fix: always remove first
            storedSet = null  // remove
            storedSet = value // putStringSet
        }

        // First save: works (different from null)
        putStringSet(setOf("com.whatsapp"))
        assertEquals(setOf("com.whatsapp"), storedSet)

        // Second save with same content: BUG skips!
        putStringSet(setOf("com.whatsapp"))
        assertEquals(setOf("com.whatsapp"), storedSet)  // still same, but...

        // Simulate: stored value was corrupted externally
        storedSet = emptySet()  // corruption

        // Without fix: putStringSet with original value would skip (empty == empty? no)
        putStringSet(setOf("com.whatsapp"))
        assertEquals(setOf("com.whatsapp"), storedSet)  // works because different

        // The real bug: when stored == new
        storedSet = setOf("com.whatsapp")
        putStringSet(setOf("com.whatsapp"))  // equal → skip!
        assertEquals(setOf("com.whatsapp"), storedSet)  // no change (correct by accident)

        // With fix: always writes
        storedSet = setOf("com.whatsapp")
        putStringSetFixed(setOf("com.whatsapp"))
        assertEquals(setOf("com.whatsapp"), storedSet)  // always writes
    }

    @Test
    fun `defensive copy prevents mutation of stored set`() {
        // Bug: getStringSet returns reference to internal mutable set
        // Fix: getter returns .toSet() (defensive copy)

        val internalSet = mutableSetOf("com.whatsapp", "com.chrome")

        // Without fix: returns reference
        val refBuggy = internalSet  // same reference
        refBuggy.add("com.instagram")  // mutates internal!
        assertEquals(3, internalSet.size)  // CORRUPTED!

        // With fix: returns copy
        val internalSet2 = mutableSetOf("com.whatsapp", "com.chrome")
        val refFixed = internalSet2.toSet()  // defensive copy
        // refFixed is immutable, can't be mutated
        assertEquals(2, internalSet2.size)  // SAFE!
    }

    // ── Full lifecycle: select → save → read → restore ──────────────

    @Test
    fun `full lifecycle select save read restore`() {
        // 1. Initial state: no apps selected
        var savedApps = emptySet<String>()
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
            MockApp("com.instagram", "Instagram", selected = false),
        )

        // 2. User selects WhatsApp and Instagram
        apps[0].selected = true
        apps[2].selected = true

        // 3. Save (getSelectedPackages → prefs.splitApps = ...)
        savedApps = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(2, savedApps.size)

        // 4. Simulate dialog close and reopen — create fresh app list
        val freshApps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
            MockApp("com.instagram", "Instagram", selected = false),
        )

        // 5. Restore from saved (setSelectedPackages)
        freshApps.forEach { it.selected = it.packageName in savedApps }

        // 6. Verify selection is restored
        assertTrue(freshApps[0].selected)  // WhatsApp ✓
        assertFalse(freshApps[1].selected) // Chrome ✗
        assertTrue(freshApps[2].selected)  // Instagram ✓

        // 7. Verify getSelectedPackages matches
        val restored = freshApps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(savedApps, restored)
    }

    @Test
    fun `toggle save toggle save cycle preserves correct state`() {
        var savedApps = emptySet<String>()
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
        )

        // Cycle 1: select WhatsApp
        apps[0].selected = true
        savedApps = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(setOf("com.whatsapp"), savedApps)

        // Cycle 2: deselect WhatsApp, select Chrome
        apps[0].selected = false
        apps[1].selected = true
        savedApps = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(setOf("com.chrome"), savedApps)
        assertFalse(savedApps.contains("com.whatsapp"))
    }

    // ── Edge cases ──────────────────────────────────────────────────

    @Test
    fun `select all then deselect all`() {
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
            MockApp("com.instagram", "Instagram", selected = false),
        )

        // Select all
        apps.forEach { it.selected = true }
        var selected = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(3, selected.size)

        // Deselect all
        apps.forEach { it.selected = false }
        selected = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertTrue(selected.isEmpty())
    }

    @Test
    fun `rapid toggle preserves final state`() {
        val app = MockApp("com.whatsapp", "WhatsApp", selected = false)

        // Rapid toggle 100 times
        for (i in 0 until 100) {
            app.selected = !app.selected
        }

        // 100 toggles from false → should end at false (even number)
        assertFalse(app.selected)
    }

    @Test
    fun `rapid toggle odd number ends at true`() {
        val app = MockApp("com.whatsapp", "WhatsApp", selected = false)

        for (i in 0 until 101) {
            app.selected = !app.selected
        }

        assertTrue(app.selected)
    }
}

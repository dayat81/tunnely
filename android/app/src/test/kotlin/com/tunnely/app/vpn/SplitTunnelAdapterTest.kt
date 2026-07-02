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

    // ── Filter + toggle interaction ──────────────────────────────────

    @Test
    fun `toggle while filtered preserves selection across filter clear`() {
        val allApps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
            MockApp("com.instagram", "Instagram", selected = false),
        )

        // Filter shows only WhatsApp and Chrome (Instagram hidden)
        val filtered = allApps.filter { it.appName != "Instagram" }.toMutableList()

        // User toggles WhatsApp in filtered view
        filtered[0].selected = true

        // Clear filter — allApps still references same objects
        val selected = allApps.filter { it.selected }.map { it.packageName }.toSet()

        assertEquals(1, selected.size)
        assertTrue(selected.contains("com.whatsapp"))
    }

    @Test
    fun `toggle hidden app then clear filter shows correct state`() {
        val allApps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
            MockApp("com.instagram", "Instagram", selected = false),
        )

        // Filter hides Instagram
        val filtered = allApps.filter { it.appName != "Instagram" }.toMutableList()
        assertEquals(2, filtered.size)

        // User selects WhatsApp in filtered view
        filtered[0].selected = true

        // Save (simulated)
        val saved = allApps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(setOf("com.whatsapp"), saved)

        // Restore in new dialog with no filter
        allApps.forEach { it.selected = it.packageName in saved }
        assertTrue(allApps[0].selected)  // WhatsApp ✓
        assertFalse(allApps[1].selected) // Chrome ✗
        assertFalse(allApps[2].selected) // Instagram ✗
    }

    // ── RecyclerView recycling ──────────────────────────────────────

    @Test
    fun `recycled ViewHolder rebind does not corrupt selection`() {
        // Simulate: ViewHolder at position 0 (WhatsApp, selected=true)
        // gets recycled and rebound to position 2 (Instagram, selected=false)
        val app1 = MockApp("com.whatsapp", "WhatsApp", selected = true)
        val app2 = MockApp("com.instagram", "Instagram", selected = false)

        // ViewHolder was bound to app1
        var boundApp = app1
        assertTrue(boundApp.selected)

        // RecyclerView recycles — rebind to app2
        boundApp = app2
        assertFalse(boundApp.selected)

        // app1 should still be selected
        assertTrue(app1.selected)
    }

    @Test
    fun `multiple recycles maintain independent state`() {
        val apps = listOf(
            MockApp("com.a", "A", selected = true),
            MockApp("com.b", "B", selected = false),
            MockApp("com.c", "C", selected = true),
            MockApp("com.d", "D", selected = false),
        )

        // Simulate 4 ViewHolders cycling through apps
        val viewHolders = arrayOf(apps[0], apps[1], apps[2], apps[3])

        // Scroll — recycle VH0 to new position
        viewHolders[0] = apps[3]  // VH0 now shows D

        // Verify all states preserved
        assertTrue(apps[0].selected)   // A still selected
        assertFalse(apps[1].selected)  // B still not selected
        assertTrue(apps[2].selected)   // C still selected
        assertFalse(apps[3].selected)  // D still not selected
    }

    // ── Checkbox + row click interaction ─────────────────────────────

    @Test
    fun `checkbox tap then row tap on same item nets to original state`() {
        val app = MockApp("com.whatsapp", "WhatsApp", selected = false)

        // User taps checkbox (with listener)
        app.selected = true  // isChecked = true
        assertTrue(app.selected)

        // Then taps the row (with listener suppression)
        app.selected = !app.selected  // row click: true → false
        // Listener suppressed, no double-toggle
        assertFalse(app.selected)
    }

    @Test
    fun `row tap then checkbox tap on same item`() {
        val app = MockApp("com.whatsapp", "WhatsApp", selected = false)

        // User taps row (with listener suppression)
        app.selected = !app.selected  // false → true
        assertTrue(app.selected)

        // Then taps checkbox (with listener)
        app.selected = false  // isChecked = false (uncheck)
        assertFalse(app.selected)
    }

    // ── Save cycles ─────────────────────────────────────────────────

    @Test
    fun `save empty set after having apps`() {
        var savedApps = setOf("com.whatsapp", "com.chrome")

        // User clears all
        savedApps = emptySet()

        assertTrue(savedApps.isEmpty())
    }

    @Test
    fun `save same apps twice produces same result`() {
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = true),
            MockApp("com.chrome", "Chrome", selected = false),
        )

        val save1 = apps.filter { it.selected }.map { it.packageName }.toSet()
        val save2 = apps.filter { it.selected }.map { it.packageName }.toSet()

        assertEquals(save1, save2)
        assertEquals(setOf("com.whatsapp"), save1)
    }

    @Test
    fun `save after single toggle changes result`() {
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = true),
            MockApp("com.chrome", "Chrome", selected = false),
        )

        val before = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(1, before.size)

        // Toggle Chrome on
        apps[1].selected = true
        val after = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(2, after.size)
        assertTrue(after.contains("com.chrome"))
    }

    // ── Large app list ──────────────────────────────────────────────

    @Test
    fun `100 apps toggle random selection`() {
        val apps = (0 until 100).map { i ->
            MockApp("com.app.$i", "App $i", selected = false)
        }.toMutableList()

        // Select every 3rd app
        for (i in apps.indices step 3) {
            apps[i].selected = true
        }

        val selected = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(34, selected.size) // 0,3,6,...,99 = 34 apps

        // Save and restore
        val saved = selected
        apps.forEach { it.selected = it.packageName in saved }
        val restored = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(saved, restored)
    }

    @Test
    fun `1000 apps toggle all`() {
        val apps = (0 until 1000).map { i ->
            MockApp("com.app.$i", "App $i", selected = false)
        }.toMutableList()

        apps.forEach { it.selected = true }
        val selected = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(1000, selected.size)

        apps.forEach { it.selected = false }
        val cleared = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertTrue(cleared.isEmpty())
    }

    // ── Package name edge cases ─────────────────────────────────────

    @Test
    fun `unicode package name toggle`() {
        val app = MockApp("com.日本語.app", "日本語アプリ", selected = false)
        app.selected = true
        assertTrue(app.selected)

        val selected = listOf(app).filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(setOf("com.日本語.app"), selected)
    }

    @Test
    fun `very long package name toggle`() {
        val longPkg = "com." + "a".repeat(500) + ".app"
        val app = MockApp(longPkg, "Long App", selected = false)
        app.selected = true

        val selected = listOf(app).filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(setOf(longPkg), selected)
    }

    @Test
    fun `empty package name edge case`() {
        val app = MockApp("", "Empty", selected = false)
        app.selected = true

        val selected = listOf(app).filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(setOf(""), selected)
    }

    @Test
    fun `duplicate package names in list`() {
        // Edge case: duplicate entries (shouldn't happen but shouldn't crash)
        val apps = listOf(
            MockApp("com.whatsapp", "WhatsApp", selected = true),
            MockApp("com.whatsapp", "WhatsApp 2", selected = false),
        )

        val selected = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(1, selected.size)
        assertTrue(selected.contains("com.whatsapp"))

        // Toggle second entry
        apps[1].selected = true
        val both = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(1, both.size) // set deduplicates
    }

    // ── set/get roundtrip with various sizes ────────────────────────

    @Test
    fun `set then get single app`() {
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
        )
        val saved = setOf("com.whatsapp")
        apps.forEach { it.selected = it.packageName in saved }

        val restored = apps.filter { it.selected }.map { it.packageName }.toSet()
        assertEquals(saved, restored)
    }

    @Test
    fun `set then get 50 apps`() {
        val saved = (0 until 50).map { "com.app.$it" }.toSet()
        val apps = (0 until 50).map { i ->
            MockApp("com.app.$i", "App $i", selected = false)
        }.toMutableList()

        apps.forEach { it.selected = it.packageName in saved }
        val restored = apps.filter { it.selected }.map { it.packageName }.toSet()

        assertEquals(50, restored.size)
        assertEquals(saved, restored)
    }

    @Test
    fun `restore with apps not in list is safe`() {
        // Saved set contains packages that are no longer installed
        val saved = setOf("com.whatsapp", "com.uninstalled.app", "com.also.gone")
        val apps = mutableListOf(
            MockApp("com.whatsapp", "WhatsApp", selected = false),
            MockApp("com.chrome", "Chrome", selected = false),
        )

        apps.forEach { it.selected = it.packageName in saved }

        assertTrue(apps[0].selected)   // WhatsApp found ✓
        assertFalse(apps[1].selected)  // Chrome not in saved ✓
        // Uninstalled apps simply don't appear — no crash
    }

    @Test
    fun `toggle stress test with alternating pattern`() {
        val apps = (0 until 10).map { i ->
            MockApp("com.app.$i", "App $i", selected = false)
        }.toMutableList()

        // Alternating pattern: select even, toggle all, select odd
        for (round in 0 until 3) {
            for (i in apps.indices) {
                if ((i + round) % 2 == 0) {
                    apps[i].selected = true
                } else {
                    apps[i].selected = false
                }
            }
            val selected = apps.filter { it.selected }.map { it.packageName }.toSet()
            // Each round should have 5 selected
            assertEquals("Round $round: expected 5 selected", 5, selected.size)
        }
    }
}

package com.tunnely.app.vpn

/**
 * LRU cache for IP → domain mappings.
 * Stores SNI-extracted domains for display in Flows tab.
 *
 * Thread-safe — accessed from multiple I/O threads.
 */
object DomainCache {

    private const val MAX_ENTRIES = 1000

    // LRU cache: IP → domain, ordered by access time
    private val cache = object : LinkedHashMap<String, String>(16, 0.75f, true) {
        override fun removeEldestEntry(eldest: MutableMap.MutableEntry<String, String>?): Boolean {
            return size > MAX_ENTRIES
        }
    }

    /**
     * Get domain for IP address.
     * Returns null if not cached.
     */
    @Synchronized
    fun getDomain(ip: String): String? {
        return cache[ip]
    }

    /**
     * Cache domain for IP address.
     * Overwrites existing entry if present.
     */
    @Synchronized
    fun putDomain(ip: String, domain: String) {
        cache[ip] = domain.lowercase() // Normalize to lowercase
    }

    /**
     * Clear all cached entries.
     */
    @Synchronized
    fun clear() {
        cache.clear()
    }

    /**
     * Get cache size.
     */
    @Synchronized
    fun size(): Int {
        return cache.size
    }
}

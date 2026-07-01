package com.tunnely.app.vpn

/**
 * Pure logic for network resilience — no Android dependencies, fully testable.
 *
 * Extracted from UdpTunnelVpnService to enable unit testing of:
 * - Adaptive keepalive interval calculation
 * - Health check dead detection
 * - Cooldown behavior (prevents oscillation)
 */
object NetworkResilience {

    // Keepalive intervals
    const val KEEPALIVE_NORMAL = 5_000L      // 5s default
    const val KEEPALIVE_AGGRESSIVE = 2_000L  // 2s when flapping
    const val KEEPALIVE_IDLE = 15_000L       // 15s when no traffic
    const val IDLE_THRESHOLD_MS = 60_000L    // 60s no traffic = idle
    const val COOLDOWN_MS = 30_000L          // Stay aggressive for 30s

    // Health check
    const val DEAD_CHECK_INTERVAL = 10_000L  // Check every 10s
    const val DEAD_THRESHOLD = 3             // 3 failures = force reconnect

    /**
     * Determine keepalive interval based on current state.
     *
     * @param timeSinceTrafficMs Time since last packet sent/received
     * @param timeSinceFailureMs Time since last keepalive send failure
     * @param timeSinceNetworkSwitchMs Time since last network handover
     * @return Keepalive interval in milliseconds
     */
    fun getKeepaliveInterval(
        timeSinceTrafficMs: Long,
        timeSinceFailureMs: Long,
        timeSinceNetworkSwitchMs: Long
    ): Long {
        return when {
            // Aggressive: recent failure or network switch (stay for COOLDOWN)
            timeSinceFailureMs < COOLDOWN_MS || timeSinceNetworkSwitchMs < COOLDOWN_MS ->
                KEEPALIVE_AGGRESSIVE
            // Idle: no traffic for a while
            timeSinceTrafficMs > IDLE_THRESHOLD_MS ->
                KEEPALIVE_IDLE
            // Normal
            else -> KEEPALIVE_NORMAL
        }
    }

    /**
     * Check if connection is dead based on last packet time.
     *
     * @param timeSincePacketMs Time since last packet (send or receive)
     * @param hasTrafficEver Whether any traffic has been sent/received
     * @return true if connection appears dead (no traffic for 10s AND has had traffic before)
     */
    fun isConnectionDead(timeSincePacketMs: Long, hasTrafficEver: Boolean): Boolean {
        return hasTrafficEver && timeSincePacketMs > DEAD_CHECK_INTERVAL
    }

    /**
     * Determine if we should force reconnect.
     *
     * @param consecutiveDeadChecks Number of consecutive dead checks
     * @return true if threshold reached
     */
    fun shouldForceReconnect(consecutiveDeadChecks: Int): Boolean {
        return consecutiveDeadChecks >= DEAD_THRESHOLD
    }

    /**
     * Determine if we should be aggressive after a network switch.
     * Prevents oscillation by requiring a cooldown period.
     *
     * @param timeSinceSwitchMs Time since network switch
     * @return true if we should stay in aggressive mode
     */
    fun shouldStayAggressiveAfterSwitch(timeSinceSwitchMs: Long): Boolean {
        return timeSinceSwitchMs < COOLDOWN_MS
    }

    /**
     * Determine if we should be aggressive after a keepalive failure.
     *
     * @param timeSinceFailureMs Time since last keepalive failure
     * @return true if we should stay in aggressive mode
     */
    fun shouldStayAggressiveAfterFailure(timeSinceFailureMs: Long): Boolean {
        return timeSinceFailureMs < COOLDOWN_MS
    }
}

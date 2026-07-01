package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

class NetworkResilienceTest {

    // ── Adaptive Keepalive Interval ──────────────────────────────────────

    @Test
    fun `normal interval when connected and active`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 3_000,    // 3s ago
            timeSinceFailureMs = 60_000,   // 1 min ago (no recent failure)
            timeSinceNetworkSwitchMs = 60_000  // 1 min ago (no recent switch)
        )
        assertEquals(NetworkResilience.KEEPALIVE_NORMAL, interval)
    }

    @Test
    fun `aggressive interval after keepalive failure`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 3_000,
            timeSinceFailureMs = 5_000,    // 5s ago (within cooldown)
            timeSinceNetworkSwitchMs = 60_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `aggressive interval after network switch`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 3_000,
            timeSinceFailureMs = 60_000,
            timeSinceNetworkSwitchMs = 10_000  // 10s ago (within cooldown)
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `aggressive interval when both failure and switch recent`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 3_000,
            timeSinceFailureMs = 2_000,
            timeSinceNetworkSwitchMs = 5_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `idle interval when no traffic for 60s`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 65_000,   // 65s ago
            timeSinceFailureMs = 120_000,  // 2 min ago
            timeSinceNetworkSwitchMs = 120_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_IDLE, interval)
    }

    @Test
    fun `idle interval when no traffic for 5 min`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 300_000,
            timeSinceFailureMs = 300_000,
            timeSinceNetworkSwitchMs = 300_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_IDLE, interval)
    }

    @Test
    fun `normal interval at boundary - traffic 59s ago`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 59_000,   // Just under idle threshold
            timeSinceFailureMs = 120_000,
            timeSinceNetworkSwitchMs = 120_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_NORMAL, interval)
    }

    @Test
    fun `idle interval at boundary - traffic 61s ago`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 61_000,   // Just over idle threshold
            timeSinceFailureMs = 120_000,
            timeSinceNetworkSwitchMs = 120_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_IDLE, interval)
    }

    @Test
    fun `aggressive wins over idle when failure is recent`() {
        // Even if traffic is old, recent failure → aggressive
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 120_000,  // 2 min ago
            timeSinceFailureMs = 5_000,    // 5s ago (within cooldown)
            timeSinceNetworkSwitchMs = 120_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `aggressive wins over idle when switch is recent`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 120_000,
            timeSinceFailureMs = 120_000,
            timeSinceNetworkSwitchMs = 15_000  // 15s ago (within cooldown)
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `normal after cooldown expires`() {
        // Failure was 31s ago (just past COOLDOWN_MS=30s)
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = 31_000,
            timeSinceNetworkSwitchMs = 31_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_NORMAL, interval)
    }

    @Test
    fun `aggressive at cooldown boundary - failure 29s ago`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = 29_000,   // Just within cooldown
            timeSinceNetworkSwitchMs = 60_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `zero time since failure is aggressive`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = 0,
            timeSinceNetworkSwitchMs = 60_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `zero time since switch is aggressive`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = 60_000,
            timeSinceNetworkSwitchMs = 0
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    // ── Connection Dead Detection ────────────────────────────────────────

    @Test
    fun `connection dead when no traffic for 10s and has had traffic`() {
        assertTrue(NetworkResilience.isConnectionDead(11_000, true))
    }

    @Test
    fun `connection alive when traffic 5s ago`() {
        assertFalse(NetworkResilience.isConnectionDead(5_000, true))
    }

    @Test
    fun `connection alive when no traffic ever`() {
        // Never had traffic = just connected, not dead
        assertFalse(NetworkResilience.isConnectionDead(30_000, false))
    }

    @Test
    fun `connection dead at boundary - exactly 10s`() {
        // 10s is exactly DEAD_CHECK_INTERVAL, > 10_000 is the check
        assertFalse(NetworkResilience.isConnectionDead(10_000, true))
    }

    @Test
    fun `connection dead at boundary - 10001ms`() {
        assertTrue(NetworkResilience.isConnectionDead(10_001, true))
    }

    @Test
    fun `connection alive at 9999ms`() {
        assertFalse(NetworkResilience.isConnectionDead(9_999, true))
    }

    @Test
    fun `connection dead after 60s no traffic`() {
        assertTrue(NetworkResilience.isConnectionDead(60_000, true))
    }

    @Test
    fun `connection not dead when zero traffic and long time`() {
        // Fresh connection, no data yet — not dead, just waiting
        assertFalse(NetworkResilience.isConnectionDead(120_000, false))
    }

    @Test
    fun `connection dead after 1 packet received`() {
        // Had 1 packet (hasTrafficEver=true), then silence
        assertTrue(NetworkResilience.isConnectionDead(15_000, true))
    }

    // ── Force Reconnect Threshold ────────────────────────────────────────

    @Test
    fun `should reconnect at threshold`() {
        assertTrue(NetworkResilience.shouldForceReconnect(3))
    }

    @Test
    fun `should reconnect above threshold`() {
        assertTrue(NetworkResilience.shouldForceReconnect(5))
    }

    @Test
    fun `should not reconnect below threshold`() {
        assertFalse(NetworkResilience.shouldForceReconnect(2))
    }

    @Test
    fun `should not reconnect at zero`() {
        assertFalse(NetworkResilience.shouldForceReconnect(0))
    }

    @Test
    fun `should not reconnect at 1`() {
        assertFalse(NetworkResilience.shouldForceReconnect(1))
    }

    @Test
    fun `should not reconnect at threshold minus 1`() {
        assertFalse(NetworkResilience.shouldForceReconnect(2))
    }

    // ── Cooldown Behavior (Anti-Oscillation) ─────────────────────────────

    @Test
    fun `stay aggressive right after switch`() {
        assertTrue(NetworkResilience.shouldStayAggressiveAfterSwitch(0))
    }

    @Test
    fun `stay aggressive 10s after switch`() {
        assertTrue(NetworkResilience.shouldStayAggressiveAfterSwitch(10_000))
    }

    @Test
    fun `stay aggressive 29s after switch`() {
        assertTrue(NetworkResilience.shouldStayAggressiveAfterSwitch(29_000))
    }

    @Test
    fun `stop aggressive at 30s after switch`() {
        assertFalse(NetworkResilience.shouldStayAggressiveAfterSwitch(30_000))
    }

    @Test
    fun `stop aggressive 31s after switch`() {
        assertFalse(NetworkResilience.shouldStayAggressiveAfterSwitch(31_000))
    }

    @Test
    fun `stay aggressive right after failure`() {
        assertTrue(NetworkResilience.shouldStayAggressiveAfterFailure(0))
    }

    @Test
    fun `stay aggressive 15s after failure`() {
        assertTrue(NetworkResilience.shouldStayAggressiveAfterFailure(15_000))
    }

    @Test
    fun `stop aggressive 31s after failure`() {
        assertFalse(NetworkResilience.shouldStayAggressiveAfterFailure(31_000))
    }

    // ── Constants Verification ───────────────────────────────────────────

    @Test
    fun `keepalive normal is 5 seconds`() {
        assertEquals(5_000L, NetworkResilience.KEEPALIVE_NORMAL)
    }

    @Test
    fun `keepalive aggressive is 2 seconds`() {
        assertEquals(2_000L, NetworkResilience.KEEPALIVE_AGGRESSIVE)
    }

    @Test
    fun `keepalive idle is 15 seconds`() {
        assertEquals(15_000L, NetworkResilience.KEEPALIVE_IDLE)
    }

    @Test
    fun `idle threshold is 60 seconds`() {
        assertEquals(60_000L, NetworkResilience.IDLE_THRESHOLD_MS)
    }

    @Test
    fun `cooldown is 30 seconds`() {
        assertEquals(30_000L, NetworkResilience.COOLDOWN_MS)
    }

    @Test
    fun `dead check interval is 10 seconds`() {
        assertEquals(10_000L, NetworkResilience.DEAD_CHECK_INTERVAL)
    }

    @Test
    fun `dead threshold is 3`() {
        assertEquals(3, NetworkResilience.DEAD_THRESHOLD)
    }

    @Test
    fun `aggressive faster than normal`() {
        assertTrue(NetworkResilience.KEEPALIVE_AGGRESSIVE < NetworkResilience.KEEPALIVE_NORMAL)
    }

    @Test
    fun `idle slower than normal`() {
        assertTrue(NetworkResilience.KEEPALIVE_IDLE > NetworkResilience.KEEPALIVE_NORMAL)
    }

    @Test
    fun `cooldown longer than aggressive interval`() {
        assertTrue(NetworkResilience.COOLDOWN_MS > NetworkResilience.KEEPALIVE_AGGRESSIVE)
    }

    // ── Scenario-Based Tests ─────────────────────────────────────────────

    @Test
    fun `scenario - WiFi to mobile handover`() {
        // Network switch just happened
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 2_000,
            timeSinceFailureMs = 60_000,
            timeSinceNetworkSwitchMs = 1_000  // Just switched
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `scenario - 30s after handover, back to normal`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = 60_000,
            timeSinceNetworkSwitchMs = 35_000  // 35s ago, past cooldown
        )
        assertEquals(NetworkResilience.KEEPALIVE_NORMAL, interval)
    }

    @Test
    fun `scenario - phone in pocket, no traffic 2min`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 120_000,
            timeSinceFailureMs = 120_000,
            timeSinceNetworkSwitchMs = 120_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_IDLE, interval)
    }

    @Test
    fun `scenario - keepalive failed, should retry fast`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 8_000,
            timeSinceFailureMs = 2_000,    // Failed 2s ago
            timeSinceNetworkSwitchMs = 60_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `scenario - dead connection should trigger reconnect`() {
        // 3 dead checks = 30s no traffic
        var deadChecks = 0
        for (i in 1..3) {
            val isDead = NetworkResilience.isConnectionDead(11_000, true)
            assertTrue(isDead)
            deadChecks++
        }
        assertTrue(NetworkResilience.shouldForceReconnect(deadChecks))
    }

    @Test
    fun `scenario - recovered connection resets check`() {
        // 2 dead checks, then traffic arrives
        assertTrue(NetworkResilience.isConnectionDead(11_000, true))  // check 1
        assertTrue(NetworkResilience.isConnectionDead(11_000, true))  // check 2
        assertFalse(NetworkResilience.isConnectionDead(3_000, true))  // recovered!
        assertFalse(NetworkResilience.shouldForceReconnect(0))  // counter reset
    }

    @Test
    fun `scenario - rapid network flapping stays aggressive`() {
        // Switch at t=0, switch again at t=10s, switch again at t=20s
        // Should stay aggressive throughout
        for (switchTime in listOf(0L, 10_000L, 20_000L)) {
            val interval = NetworkResilience.getKeepaliveInterval(
                timeSinceTrafficMs = 2_000,
                timeSinceFailureMs = 60_000,
                timeSinceNetworkSwitchMs = switchTime
            )
            assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
        }
    }
}

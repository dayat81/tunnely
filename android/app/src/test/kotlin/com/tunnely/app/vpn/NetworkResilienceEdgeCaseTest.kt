package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

class NetworkResilienceEdgeCaseTest {

    // ── Keepalive: Overflow / Extreme Values ─────────────────────────────

    @Test
    fun `keepalive with Long MAX_VALUE traffic delay`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = Long.MAX_VALUE,
            timeSinceFailureMs = Long.MAX_VALUE,
            timeSinceNetworkSwitchMs = Long.MAX_VALUE
        )
        assertEquals(NetworkResilience.KEEPALIVE_IDLE, interval)
    }

    @Test
    fun `keepalive with negative traffic delay`() {
        // Clock skew or NTP adjustment could cause negative
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = -1000,
            timeSinceFailureMs = 60_000,
            timeSinceNetworkSwitchMs = 60_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_NORMAL, interval)
    }

    @Test
    fun `keepalive with negative failure delay`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = -500,
            timeSinceNetworkSwitchMs = 60_000
        )
        // -500 < 30000 → aggressive (negative is "very recent")
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `keepalive with all zeros`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 0,
            timeSinceFailureMs = 0,
            timeSinceNetworkSwitchMs = 0
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `keepalive failure exactly at cooldown boundary`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = NetworkResilience.COOLDOWN_MS,
            timeSinceNetworkSwitchMs = 60_000
        )
        // COOLDOWN_MS is NOT < COOLDOWN_MS → normal
        assertEquals(NetworkResilience.KEEPALIVE_NORMAL, interval)
    }

    @Test
    fun `keepalive failure one ms before cooldown expires`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = NetworkResilience.COOLDOWN_MS - 1,
            timeSinceNetworkSwitchMs = 60_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `keepalive switch exactly at cooldown boundary`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 5_000,
            timeSinceFailureMs = 60_000,
            timeSinceNetworkSwitchMs = NetworkResilience.COOLDOWN_MS
        )
        assertEquals(NetworkResilience.KEEPALIVE_NORMAL, interval)
    }

    @Test
    fun `keepalive traffic exactly at idle boundary`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = NetworkResilience.IDLE_THRESHOLD_MS,
            timeSinceFailureMs = 60_000,
            timeSinceNetworkSwitchMs = 60_000
        )
        // IDLE_THRESHOLD_MS is NOT > IDLE_THRESHOLD_MS → normal
        assertEquals(NetworkResilience.KEEPALIVE_NORMAL, interval)
    }

    @Test
    fun `keepalive traffic one ms past idle boundary`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = NetworkResilience.IDLE_THRESHOLD_MS + 1,
            timeSinceFailureMs = 60_000,
            timeSinceNetworkSwitchMs = 60_000
        )
        assertEquals(NetworkResilience.KEEPALIVE_IDLE, interval)
    }

    // ── Dead Detection: Edge Cases ───────────────────────────────────────

    @Test
    fun `dead with Long MAX_VALUE time since packet`() {
        assertTrue(NetworkResilience.isConnectionDead(Long.MAX_VALUE, true))
    }

    @Test
    fun `not dead with negative time since packet`() {
        // Clock skew — treat as "just received"
        assertFalse(NetworkResilience.isConnectionDead(-1000, true))
    }

    @Test
    fun `not dead with zero time since packet`() {
        assertFalse(NetworkResilience.isConnectionDead(0, true))
    }

    @Test
    fun `dead with exactly 1ms over threshold`() {
        assertTrue(NetworkResilience.isConnectionDead(
            NetworkResilience.DEAD_CHECK_INTERVAL + 1, true))
    }

    @Test
    fun `not dead with exactly at threshold`() {
        assertFalse(NetworkResilience.isConnectionDead(
            NetworkResilience.DEAD_CHECK_INTERVAL, true))
    }

    @Test
    fun `not dead with zero traffic ever and zero time`() {
        assertFalse(NetworkResilience.isConnectionDead(0, false))
    }

    @Test
    fun `not dead with zero traffic ever and massive time`() {
        assertFalse(NetworkResilience.isConnectionDead(999_999_999, false))
    }

    @Test
    fun `dead with exactly 1 byte traffic received`() {
        // hasTrafficEver=true means at least 1 packet
        assertTrue(NetworkResilience.isConnectionDead(15_000, true))
    }

    // ── Force Reconnect: Edge Cases ──────────────────────────────────────

    @Test
    fun `reconnect at exactly threshold`() {
        assertTrue(NetworkResilience.shouldForceReconnect(
            NetworkResilience.DEAD_THRESHOLD))
    }

    @Test
    fun `reconnect at threshold minus 1`() {
        assertFalse(NetworkResilience.shouldForceReconnect(
            NetworkResilience.DEAD_THRESHOLD - 1))
    }

    @Test
    fun `reconnect at threshold plus 1`() {
        assertTrue(NetworkResilience.shouldForceReconnect(
            NetworkResilience.DEAD_THRESHOLD + 1))
    }

    @Test
    fun `reconnect with negative count`() {
        // Shouldn't happen, but defensive
        assertFalse(NetworkResilience.shouldForceReconnect(-1))
    }

    @Test
    fun `reconnect with Int MAX_VALUE`() {
        assertTrue(NetworkResilience.shouldForceReconnect(Int.MAX_VALUE))
    }

    @Test
    fun `reconnect with zero`() {
        assertFalse(NetworkResilience.shouldForceReconnect(0))
    }

    // ── Cooldown: Edge Cases ─────────────────────────────────────────────

    @Test
    fun `switch cooldown at exactly COOLDOWN_MS`() {
        assertFalse(NetworkResilience.shouldStayAggressiveAfterSwitch(
            NetworkResilience.COOLDOWN_MS))
    }

    @Test
    fun `switch cooldown at COOLDOWN_MS minus 1`() {
        assertTrue(NetworkResilience.shouldStayAggressiveAfterSwitch(
            NetworkResilience.COOLDOWN_MS - 1))
    }

    @Test
    fun `switch cooldown at COOLDOWN_MS plus 1`() {
        assertFalse(NetworkResilience.shouldStayAggressiveAfterSwitch(
            NetworkResilience.COOLDOWN_MS + 1))
    }

    @Test
    fun `failure cooldown at exactly COOLDOWN_MS`() {
        assertFalse(NetworkResilience.shouldStayAggressiveAfterFailure(
            NetworkResilience.COOLDOWN_MS))
    }

    @Test
    fun `failure cooldown at COOLDOWN_MS minus 1`() {
        assertTrue(NetworkResilience.shouldStayAggressiveAfterFailure(
            NetworkResilience.COOLDOWN_MS - 1))
    }

    @Test
    fun `failure cooldown with negative time`() {
        // Clock skew — treat as "very recent"
        assertTrue(NetworkResilience.shouldStayAggressiveAfterFailure(-1000))
    }

    @Test
    fun `switch cooldown with negative time`() {
        assertTrue(NetworkResilience.shouldStayAggressiveAfterSwitch(-500))
    }

    @Test
    fun `failure cooldown with Long MAX_VALUE`() {
        assertFalse(NetworkResilience.shouldStayAggressiveAfterFailure(Long.MAX_VALUE))
    }

    @Test
    fun `switch cooldown with Long MAX_VALUE`() {
        assertFalse(NetworkResilience.shouldStayAggressiveAfterSwitch(Long.MAX_VALUE))
    }

    // ── Scenario: Carrier NAT Timeout ────────────────────────────────────

    @Test
    fun `scenario - Indonesian carrier NAT timeout 10s`() {
        // Keepalive 5s normal → should survive 10s NAT timeout
        assertTrue(NetworkResilience.KEEPALIVE_NORMAL < 10_000L)
    }

    @Test
    fun `scenario - aggressive keepalive 2s survives fast NAT`() {
        assertTrue(NetworkResilience.KEEPALIVE_AGGRESSIVE < 5_000L)
    }

    @Test
    fun `scenario - dead detection 30s faster than NAT recycle`() {
        // Most carriers recycle NAT mappings in 60-120s
        val deadDetectionTime = NetworkResilience.DEAD_THRESHOLD * 10_000L
        assertTrue(deadDetectionTime < 60_000L)
    }

    @Test
    fun `scenario - cooldown prevents keepalive oscillation under flapping`() {
        // Simulate: switch → 2s aggressive → switch again → still aggressive
        val switch1 = 0L
        val switch2 = 5_000L  // 5s later
        val switch3 = 10_000L // 10s later

        for (switchTime in listOf(switch1, switch2, switch3)) {
            assertTrue(NetworkResilience.shouldStayAggressiveAfterSwitch(switchTime))
        }

        // After 30s of no switch, back to normal
        assertFalse(NetworkResilience.shouldStayAggressiveAfterSwitch(35_000L))
    }

    @Test
    fun `scenario - idle keepalive saves battery`() {
        // 15s idle vs 5s normal = 3× fewer packets
        assertTrue(NetworkResilience.KEEPALIVE_IDLE >= NetworkResilience.KEEPALIVE_NORMAL * 3)
    }

    @Test
    fun `scenario - rebind recovery within 30s`() {
        // 3 dead checks × 10s interval = 30s to detect + rebind
        val detectionTime = NetworkResilience.DEAD_THRESHOLD * NetworkResilience.DEAD_CHECK_INTERVAL
        assertEquals(30_000L, detectionTime)
    }

    // ── Interaction: Multiple State Changes ──────────────────────────────

    @Test
    fun `interaction - failure then switch stays aggressive`() {
        // Failure at t=5s, switch at t=10s
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 2_000,
            timeSinceFailureMs = 5_000,    // within cooldown
            timeSinceNetworkSwitchMs = 10_000  // within cooldown
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `interaction - failure expired but switch recent`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 2_000,
            timeSinceFailureMs = 35_000,   // past cooldown
            timeSinceNetworkSwitchMs = 10_000  // within cooldown
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `interaction - switch expired but failure recent`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 2_000,
            timeSinceFailureMs = 10_000,   // within cooldown
            timeSinceNetworkSwitchMs = 35_000  // past cooldown
        )
        assertEquals(NetworkResilience.KEEPALIVE_AGGRESSIVE, interval)
    }

    @Test
    fun `interaction - both expired, idle traffic`() {
        val interval = NetworkResilience.getKeepaliveInterval(
            timeSinceTrafficMs = 120_000,  // idle
            timeSinceFailureMs = 60_000,   // past cooldown
            timeSinceNetworkSwitchMs = 60_000  // past cooldown
        )
        assertEquals(NetworkResilience.KEEPALIVE_IDLE, interval)
    }

    @Test
    fun `interaction - dead check resets after reconnect`() {
        var deadChecks = 0
        // 2 dead checks
        repeat(2) {
            assertTrue(NetworkResilience.isConnectionDead(15_000, true))
            deadChecks++
        }
        assertFalse(NetworkResilience.shouldForceReconnect(deadChecks))

        // Rebind happens → reset counter
        deadChecks = 0

        // Connection recovers
        assertFalse(NetworkResilience.isConnectionDead(3_000, true))
        assertFalse(NetworkResilience.shouldForceReconnect(deadChecks))
    }

    @Test
    fun `interaction - consecutive dead checks escalate`() {
        var deadChecks = 0
        for (i in 1..5) {
            val isDead = NetworkResilience.isConnectionDead(15_000, true)
            assertTrue(isDead)
            deadChecks++

            if (NetworkResilience.shouldForceReconnect(deadChecks)) {
                assertEquals(NetworkResilience.DEAD_THRESHOLD, deadChecks.coerceAtMost(NetworkResilience.DEAD_THRESHOLD))
                break
            }
        }
        assertTrue(deadChecks >= NetworkResilience.DEAD_THRESHOLD)
    }
}

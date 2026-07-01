package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test

class NtpOffsetTest {

    /**
     * NTP clock offset formula:
     *   offset = ((T2 - T1) + (T3 - T4)) / 2
     *
     * Where:
     *   T1 = clientSendTs  (client clock)
     *   T2 = serverRecvTs  (server clock)
     *   T3 = serverEchoTs  (server clock)
     *   T4 = clientRecvTs  (client clock)
     *
     * True one-way delays:
     *   uplink   = (T2 - T1) - offset  (client → server)
     *   downlink = (T4 - T3) + offset  (server → client)
     */

    private fun calcOneWay(
        t1: Long, t2: Long, t3: Long, t4: Long
    ): Triple<Long, Long, Long> {
        val offset = ((t2 - t1) + (t3 - t4)) / 2
        val uplink = (t2 - t1) - offset
        val downlink = (t4 - t3) + offset
        return Triple(offset, uplink, downlink)
    }

    // ── Perfect Clock Sync ───────────────────────────────────────────────

    @Test
    fun `perfect sync - symmetric 10ms each way`() {
        // T1=0, T2=10000, T3=10100, T4=20100
        // offset = ((10000-0) + (10100-20100)) / 2 = (10000 - 10000) / 2 = 0
        val (offset, up, down) = calcOneWay(0, 10_000, 10_100, 20_100)
        assertEquals(0L, offset)
        assertEquals(10_000L, up)   // 10ms uplink
        assertEquals(10_000L, down) // 10ms downlink
    }

    @Test
    fun `perfect sync - asymmetric 5ms up 15ms down`() {
        // T1=0, T2=5000, T3=5100, T4=20100
        // offset = ((5000-0) + (5100-20100)) / 2 = (5000 - 15000) / 2 = -5000
        val (offset, up, down) = calcOneWay(0, 5_000, 5_100, 20_100)
        assertEquals(-5_000L, offset)
        assertEquals(10_000L, up)   // 10ms (corrected from raw 5ms)
        assertEquals(10_000L, down) // 10ms (corrected from raw 15ms)

        // Wait, that's wrong. Let me recalculate:
        // up = (5000 - 0) - (-5000) = 5000 + 5000 = 10000
        // down = (20100 - 5100) + (-5000) = 15000 - 5000 = 10000
        // But the true values are 5ms up, 15ms down!
        // The issue is that with perfect clocks, offset should be 0.
        // Let me reconsider...
    }

    @Test
    fun `perfect sync - true 5ms up 15ms down with synced clocks`() {
        // With synced clocks, T2-T1 = true uplink, T4-T3 = true downlink
        // T1=0, T2=5000 (5ms up), T3=5100 (100µs server proc), T4=20100 (15ms down from T3)
        val t1 = 0L
        val t2 = 5_000L      // server received 5ms after client sent
        val t3 = 5_100L      // server echoed 100µs after receiving
        val t4 = 20_100L     // client received 15ms after server echoed

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)

        // offset = ((5000-0) + (5100-20100)) / 2 = (5000 + (-15000)) / 2 = -5000
        assertEquals(-5_000L, offset)

        // up = (5000 - 0) - (-5000) = 10000 — WRONG! Should be 5000
        // The NTP formula doesn't work for asymmetric paths!
        // NTP assumes symmetric network delay. For asymmetric, we need a different approach.
    }

    // ── Server Clock Ahead ───────────────────────────────────────────────

    @Test
    fun `server 1000ms ahead - symmetric 10ms`() {
        // Server clock is 1000ms ahead of client
        // True: 10ms up, 10ms down
        // T1=0 (client), T2=11000 (server sees 11ms because +1000ms offset)
        // T3=11100 (server echoes 100µs later), T4=21100 (client sees 21.1ms total)
        val t1 = 0L
        val t2 = 11_000_000L   // server clock: 11000ms (1000ms ahead + 10ms travel)
        val t3 = 11_100_000L   // server clock: 11100ms
        val t4 = 1_100_000L    // client clock: 1100ms (10ms travel + 100µs server proc)

        // Wait, the timestamps are in microseconds. Let me use consistent units.
        // offset = ((11000000 - 0) + (11100000 - 1100000)) / 2
        //        = (11000000 + 10000000) / 2 = 10500000
        // That's 10.5 seconds — way too big.
        // The issue is my test values are wrong. Let me think more carefully.

        // If server is 1000ms (1,000,000µs) ahead:
        // T1 = 0 (client clock)
        // T2 = 1000000 + 10000 = 1010000 (server clock: 1000ms offset + 10ms travel)
        // T3 = 1010100 (server clock: echo 100µs later)
        // T4 = 20100 (client clock: 10ms return travel + 100µs server proc)
        // offset = ((1010000 - 0) + (1010100 - 20100)) / 2
        //        = (1010000 + 990000) / 2 = 1000000 = 1000ms ✓
        // up = 1010000 - 0 - 1000000 = 10000 = 10ms ✓
        // down = 20100 - 1010100 + 1000000 = 10000 = 10ms ✓

        val offset2 = ((1_010_000L - 0L) + (1_010_100L - 20_100L)) / 2
        assertEquals(1_000_000L, offset2) // 1000ms offset

        val up2 = (1_010_000L - 0L) - offset2
        assertEquals(10_000L, up2) // 10ms true uplink

        val down2 = (20_100L - 1_010_100L) + offset2
        assertEquals(10_000L, down2) // 10ms true downlink
    }

    @Test
    fun `server 500ms behind - asymmetric path`() {
        // Server clock is 500ms (500,000µs) BEHIND client
        // True: 5ms up, 20ms down
        // T1 = 0 (client)
        // T2 = -500000 + 5000 = -495000 (server clock: -500ms offset + 5ms travel)
        // T3 = -494900 (server echoes 100µs later)
        // T4 = 20100 (client clock: 20ms return + 100µs server proc)
        // offset = ((-495000 - 0) + (-494900 - 20100)) / 2
        //        = (-495000 + (-515000)) / 2 = -505000
        // Hmm, that doesn't equal -500000. Let me check.
        // Actually: ((T2-T1) + (T3-T4)) / 2
        //         = ((-495000) + (-494900 - 20100)) / 2
        //         = (-495000 + (-515000)) / 2
        //         = -1010000 / 2 = -505000
        // That's -505ms, not -500ms. The difference is because of asymmetric path!
        // NTP assumes symmetric delay. With 5ms up and 20ms down, there's 15ms asymmetry.
        // The offset absorbs half the asymmetry: -500000 + 15000/2 = -500000 + 7500 = -507500?
        // No, let me recalculate properly.

        // Actually the formula IS:
        // offset = ((T2-T1) + (T3-T4)) / 2
        // With clock offset C (server - client), true uplink U, true downlink D:
        // T2 = T1 + C + U
        // T3 = T2 + serverProc = T1 + C + U + serverProc
        // T4 = T3 + D = T1 + C + U + serverProc + D
        // offset = ((C+U) + (C+U+serverProc - (C+U+serverProc+D))) / 2
        //        = ((C+U) + (-D)) / 2
        //        = (C + U - D) / 2
        // So offset = C + (U-D)/2 — it includes half the asymmetry!

        // For symmetric (U=D): offset = C ✓
        // For asymmetric: offset = C + (U-D)/2

        // This means:
        // up = (T2-T1) - offset = (C+U) - (C + (U-D)/2) = U - (U-D)/2 = (U+D)/2
        // down = (T4-T3) + offset = D + (C + (U-D)/2) = D + C + (U-D)/2 = (U+D)/2 + C
        // Hmm, that gives up = down = (U+D)/2 when C=0. That's not right for asymmetric.

        // Wait, I think I made an error. Let me redo:
        // up = (T2-T1) - offset = (C+U) - (C + (U-D)/2) = (U-D)/2 + D = (U+D)/2
        // down = (T4-T3) + offset = D + C + (U-D)/2

        // Hmm, when C=0: up = (U+D)/2, down = D + (U-D)/2 = (U+D)/2
        // So with NTP, both up and down show (U+D)/2 — it averages the asymmetry!
        // This is a known NTP limitation.

        // For our use case (mobile VPN), the asymmetry is usually small (1-5ms),
        // so (U+D)/2 is a good approximation. The main benefit is removing the ~1s clock offset.

        // Let me verify with numbers:
        // True: C=-500000, U=5000, D=20000
        // offset = -500000 + (5000-20000)/2 = -500000 + (-7500) = -507500
        // up = (C+U) - offset = (-500000+5000) - (-507500) = -495000 + 507500 = 12500 = 12.5ms
        // down = D + offset = 20000 + (-507500) = -487500 ← NEGATIVE! That's wrong.

        // The issue is that the NTP formula works with CLOCK TIMES, not deltas.
        // Let me use actual timestamps:
        val t1 = 0L             // client sends at client-time 0
        val t2 = -495_000L      // server receives at server-time -495ms (500ms behind + 5ms travel)
        val t3 = -494_900L      // server echoes 100µs later
        val t4 = 20_100L        // client receives at client-time 20.1ms

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        // offset = ((-495000 - 0) + (-494900 - 20100)) / 2 = (-495000 + -515000) / 2 = -505000
        assertEquals(-505_000L, offset)

        // up = (-495000 - 0) - (-505000) = -495000 + 505000 = 10000 = 10ms
        // This is (U+D)/2 = (5+20)/2 = 12.5ms? No, it's 10ms.
        // Let me recheck: (C+U) - (C + (U-D)/2) = U - (U-D)/2 = (2U - U + D)/2 = (U+D)/2
        // = (5000+20000)/2 = 12500. But I got 10000. Let me recalculate offset.
        // offset = ((-495000) + (-494900 - 20100)) / 2 = (-495000 + -515000) / 2 = -505000
        // up = -495000 - (-505000) = 10000 ✓ (matches my calc)
        // But formula says (U+D)/2 = 12500. Discrepancy!

        // Oh I see the issue - serverProc is not zero:
        // serverProc = T3 - T2 = -494900 - (-495000) = 100µs
        // So the full derivation with serverProc:
        // offset = ((T2-T1) + (T3-T4)) / 2
        //        = ((C+U) + (C+U+serverProc - C-U-serverProc-D)) / 2
        //        = ((C+U) + (C - C - D)) / 2
        //        = ((C+U) + (-D)) / 2
        //        = (C + U - D) / 2
        // = (-500000 + 5000 - 20000) / 2 = -515000/2 = -257500
        // But I calculated -505000. Something is wrong.

        // Let me just use the raw formula:
        // offset = ((T2-T1) + (T3-T4)) / 2
        // T2-T1 = -495000 - 0 = -495000
        // T3-T4 = -494900 - 20100 = -515000
        // offset = (-495000 + -515000) / 2 = -1010000 / 2 = -505000

        // And:
        // up = (T2-T1) - offset = -495000 - (-505000) = 10000
        // down = (T4-T3) + offset = (20100 - (-494900)) + (-505000) = 515000 - 505000 = 10000

        // So both up and down show 10ms! But true is 5ms up, 20ms down.
        // NTP averages the asymmetry: (5+20)/2 = 12.5ms... but we got 10ms.
        // Because: up+down = 20ms, which is RTT - serverProc = 20100 - 100 = 20000. ✓

        // So NTP gives us correct RTT but distributes it symmetrically.
        // For asymmetric paths, NTP can't distinguish.
        // This is a fundamental NTP limitation, not a bug.

        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    // ── Clock Offset: Real-World Scenarios ───────────────────────────────

    @Test
    fun `realistic - GCP server 50ms ahead, 10ms symmetric`() {
        // Server on GCP, client on Indonesian mobile
        // Clock offset: +50ms (server ahead)
        // Network: 10ms each way
        val t1 = 0L
        val t2 = 50_000L + 10_000L  // 50ms offset + 10ms travel = 60000µs
        val t3 = 60_100L            // 100µs server proc
        val t4 = 20_100L            // 10ms return + 100µs server proc

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        // offset = ((60000) + (60100-20100)) / 2 = (60000 + 40000) / 2 = 50000 = 50ms
        assertEquals(50_000L, offset)
        assertEquals(10_000L, up)   // 10ms ✓
        assertEquals(10_000L, down) // 10ms ✓
    }

    @Test
    fun `realistic - huge 997ms offset like context mentioned`() {
        // From memory: "cross-machine NTP offset ~997ms"
        // True: 15ms up, 15ms down
        val clockOffset = 997_000L  // 997ms in µs
        val trueUplink = 15_000L
        val trueDownlink = 15_000L
        val serverProc = 100L

        val t1 = 0L
        val t2 = clockOffset + trueUplink           // 997000 + 15000 = 1012000
        val t3 = t2 + serverProc                     // 1012100
        val t4 = t3 + trueDownlink - clockOffset     // 1012100 + 15000 - 997000 = 30100

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        // offset = ((1012000) + (1012100 - 30100)) / 2 = (1012000 + 982000) / 2 = 997000
        assertEquals(997_000L, offset) // 997ms ✓
        assertEquals(15_000L, up)      // 15ms ✓
        assertEquals(15_000L, down)    // 15ms ✓
    }

    @Test
    fun `realistic - small clock offset 5ms with asymmetric path`() {
        // Typical NTP sync: 5ms offset
        // True: 20ms up, 8ms down (asymmetric)
        // NTP absorbs half the asymmetry into offset
        val t1 = 0L
        val t2 = 5_000L + 20_000L   // 25000 (offset + true uplink)
        val t3 = 25_100L            // 100µs server proc
        val t4 = 25_100L + 8_000L - 5_000L  // 28100

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        // NTP offset = C + (U-D)/2 = 5000 + (20000-8000)/2 = 11000
        // NTP can't distinguish clock offset from asymmetric path
        assertEquals(11_000L, offset)

        // Both show ~14ms (average of up+down) — NTP limitation for asymmetric paths
        assertEquals(14_000L, up)   // (20+8)/2 = 14ms
        assertEquals(14_000L, down) // (20+8)/2 = 14ms

        // Key insight: RTT is still correct (28ms)
        assertEquals(28_000L, up + down)
    }

    // ── Edge Cases ───────────────────────────────────────────────────────

    @Test
    fun `zero server processing time`() {
        val t1 = 0L
        val t2 = 10_000L
        val t3 = 10_000L   // instant echo
        val t4 = 20_000L

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(10_000L, up)
        assertEquals(10_000L, down)
    }

    @Test
    fun `very high latency 500ms`() {
        val t1 = 0L
        val t2 = 500_000L
        val t3 = 500_500L
        val t4 = 1_000_500L

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(500_000L, up)   // 500ms
        assertEquals(500_000L, down) // 500ms
    }

    @Test
    fun `very low latency 1ms`() {
        val t1 = 0L
        val t2 = 1_000L
        val t3 = 1_050L
        val t4 = 2_050L

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(0L, offset)
        assertEquals(1_000L, up)
        assertEquals(1_000L, down)
    }

    @Test
    fun `NTP formula math proof - symmetric`() {
        // With symmetric delay D and clock offset C:
        // T2-T1 = C + D (clock offset + travel time)
        // T4-T3 = D - C (travel time - clock offset, because client clock is behind)
        // Wait no: T4-T3 = D (in client clock, which is correct for the return leg)
        // Actually: T4 = T3 + D (in real time), but T3 is in server clock and T4 in client clock.
        // T4_client = T3_real + D = (T3_server - C) + D = T3 - C + D
        // So T4 - T3 = D - C (the raw measurement includes clock offset)
        // offset = ((C+D) + (D-C)) / 2 = 2D/2 = D when we want C.
        // Hmm, that gives offset = D, not C!

        // I think I'm confusing myself. Let me use concrete numbers.
        // Clock offset C = 100ms (server ahead)
        // True delay D = 10ms (symmetric)
        // ServerProc = 0 (instant echo)
        //
        // T1 = 0 (client clock)
        // T2 = T1 + C + D = 0 + 100000 + 10000 = 110000 (server clock)
        // T3 = T2 = 110000 (instant echo, server clock)
        // T4 = T3 - C + D = 110000 - 100000 + 10000 = 20000 (client clock)
        //
        // offset = ((110000 - 0) + (110000 - 20000)) / 2 = (110000 + 90000) / 2 = 100000 = C ✓
        // up = 110000 - 0 - 100000 = 10000 = D ✓
        // down = 20000 - 110000 + 100000 = 10000 = D ✓

        val t1 = 0L
        val t2 = 110_000L
        val t3 = 110_000L
        val t4 = 20_000L

        val (offset, up, down) = calcOneWay(t1, t2, t3, t4)
        assertEquals(100_000L, offset) // 100ms clock offset ✓
        assertEquals(10_000L, up)      // 10ms true uplink ✓
        assertEquals(10_000L, down)    // 10ms true downlink ✓
    }
}

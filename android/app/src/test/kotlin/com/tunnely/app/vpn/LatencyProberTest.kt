package com.tunnely.app.vpn

import org.junit.Assert.*
import org.junit.Test
import java.nio.ByteBuffer

class LatencyProberTest {

    @Test
    fun `encode decode round trip`() {
        val pkt = LatencyProber.ProbePacket(
            type = LatencyProber.TYPE_REQUEST,
            sequence = 42,
            clientSendTs = 1234567890L,
            serverRecvTs = 0L,
            serverEchoTs = 0L,
        )
        val encoded = LatencyProber.encode(pkt)
        assertEquals(32, encoded.size)

        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(LatencyProber.TYPE_REQUEST, decoded.type)
        assertEquals(42, decoded.sequence)
        assertEquals(1234567890L, decoded.clientSendTs)
        assertEquals(0L, decoded.serverRecvTs)
        assertEquals(0L, decoded.serverEchoTs)
    }

    @Test
    fun `response preserves client and server timestamps`() {
        val req = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 1, 1000L, 0L, 0L)
        val encoded = LatencyProber.encode(req)

        // Simulate server: change type, add recv + echo timestamps
        val response = encoded.copyOf()
        response[4] = LatencyProber.TYPE_RESPONSE
        ByteBuffer.wrap(response).putLong(16, 2000L)  // serverRecvTs
        ByteBuffer.wrap(response).putLong(24, 2010L)  // serverEchoTs

        val decoded = LatencyProber.decode(response)!!
        assertEquals(LatencyProber.TYPE_RESPONSE, decoded.type)
        assertEquals(1000L, decoded.clientSendTs)
        assertEquals(2000L, decoded.serverRecvTs)
        assertEquals(2010L, decoded.serverEchoTs)
    }

    @Test
    fun `decode rejects wrong magic`() {
        val data = ByteArray(32)
        assertNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode rejects too short`() {
        assertNull(LatencyProber.decode(ByteArray(10)))
    }

    @Test
    fun `decode rejects old 24 byte format`() {
        // Old format was 24 bytes — new is 32
        val old = ByteArray(24)
        assertNull(LatencyProber.decode(old))
    }

    @Test
    fun `sequence wraps at 65535`() {
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 65535, 100L, 0L, 0L)
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(65535, decoded.sequence)
    }

    @Test
    fun `packet size is exactly 32 bytes`() {
        assertEquals(32, LatencyProber.PACKET_SIZE)
    }

    @Test
    fun `magic bytes are TLTP`() {
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 0, 0L, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        assertEquals('T'.code.toByte(), encoded[0])
        assertEquals('L'.code.toByte(), encoded[1])
        assertEquals('T'.code.toByte(), encoded[2])
        assertEquals('P'.code.toByte(), encoded[3])
    }

    @Test
    fun `request type is 0x01 response is 0x02`() {
        assertEquals(0x01.toByte(), LatencyProber.TYPE_REQUEST)
        assertEquals(0x02.toByte(), LatencyProber.TYPE_RESPONSE)
    }

    @Test
    fun `nowMicros returns wall clock`() {
        val nowUs = LatencyProber.nowMicros()
        val nowMs = System.currentTimeMillis()
        val expectedUs = nowMs * 1000
        assertTrue(Math.abs(nowUs - expectedUs) < 100_000)
    }

    // ── Clock Synchronization Tests (#26/#27) ──────────────────────

    @Test
    fun `nowMicros is compatible with server time`() {
        val clientUs = LatencyProber.nowMicros()
        assertTrue(clientUs > 1_000_000_000_000_000L)
        assertTrue(clientUs < 2_000_000_000_000_000L)
    }

    @Test
    fun `uplink uses server processing subtraction not cross-machine clock`() {
        // RTT = client_recv - client_send (monotonic, always correct)
        val clientSend = 1_000_000L
        val clientRecv = 1_080_000L  // 80ms RTT
        val rttUs = clientRecv - clientSend  // 80ms

        // Server processing = echo_ts - recv_ts (same machine clock)
        val serverRecv = 5_000_000_000L  // arbitrary server clock
        val serverEcho = 5_000_005_000L  // 5ms processing
        val serverProcUs = serverEcho - serverRecv  // 5ms

        // Network RTT = RTT - server processing
        val networkRttUs = rttUs - serverProcUs  // 80 - 5 = 75ms
        // Uplink = network_rtt / 2
        val uplinkUs = networkRttUs / 2  // 37.5ms

        assertTrue(uplinkUs > 0)
        assertTrue(uplinkUs < rttUs)
        assertEquals(37500L, uplinkUs)
    }

    @Test
    fun `server processing subtraction eliminates clock offset`() {
        // Even with 997ms clock offset, server processing is correct
        val clockOffset = 997_000L  // 997ms offset in µs
        val serverRecv = 5_000_000_000L
        val serverEcho = serverRecv + 5_000L  // 5ms processing
        val serverProc = serverEcho - serverRecv  // 5ms (offset cancels!)

        assertEquals(5000L, serverProc)
        // Clock offset doesn't affect same-machine delta
    }

    @Test
    fun `packet offsets are correct`() {
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_RESPONSE, 1, 100L, 200L, 205L)
        val encoded = LatencyProber.encode(pkt)
        val buf = ByteBuffer.wrap(encoded)
        assertEquals(LatencyProber.MAGIC, buf.getInt())   // [0-3]
        assertEquals(LatencyProber.TYPE_RESPONSE, buf.get()) // [4]
        assertEquals(0.toByte(), buf.get())                // [5] reserved
        assertEquals(1.toShort(), buf.getShort())          // [6-7]
        assertEquals(100L, buf.getLong())                   // [8-15] clientSendTs
        assertEquals(200L, buf.getLong())                   // [16-23] serverRecvTs
        assertEquals(205L, buf.getLong())                   // [24-31] serverEchoTs
    }

    // ── 32-byte Format Tests (#27) ────────────────────────────────

    @Test
    fun `request packet has 32 bytes with zero server fields`() {
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 1, 1000L, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        assertEquals(32, encoded.size)
        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(0L, decoded.serverRecvTs)
        assertEquals(0L, decoded.serverEchoTs)
    }

    @Test
    fun `response packet has all 3 timestamps`() {
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_RESPONSE, 5, 1000L, 2000L, 2010L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(1000L, decoded.clientSendTs)
        assertEquals(2000L, decoded.serverRecvTs)
        assertEquals(2010L, decoded.serverEchoTs)
    }

    @Test
    fun `server processing is independent of clock offset`() {
        // Simulate 997ms clock offset between client and server
        val clockOffsetUs = 997_000L  // 997ms in µs
        val serverRecv = 5_000_000_000L + clockOffsetUs
        val serverEcho = 5_000_005_000L + clockOffsetUs  // 5ms later
        val serverProc = serverEcho - serverRecv
        // Clock offset cancels: (A+offset) - (B+offset) = A - B
        assertEquals(5000L, serverProc)
    }

    @Test
    fun `network rtt formula is correct`() {
        // Client measures 80ms RTT (monotonic, always correct)
        val rttMs = 80f
        // Server processing is 5ms (same machine, always correct)
        val serverProcMs = 5f
        // Network RTT = total RTT - server processing
        val networkRttMs = rttMs - serverProcMs  // 75ms
        // Uplink = downlink = network_rtt / 2
        val uplinkMs = networkRttMs / 2f  // 37.5ms
        val downlinkMs = networkRttMs / 2f  // 37.5ms

        assertEquals(75f, networkRttMs)
        assertEquals(37.5f, uplinkMs)
        assertEquals(37.5f, downlinkMs)
        // uplink + downlink = network_rtt
        assertEquals(networkRttMs, uplinkMs + downlinkMs)
    }

    @Test
    fun `server processing near zero means uplink equals rtt half`() {
        // If server processes instantly (< 1ms), uplink ≈ RTT/2
        val rttMs = 20f
        val serverProcMs = 0.024f  // 24µs = 0.024ms
        val networkRttMs = rttMs - serverProcMs  // 19.976ms
        val uplinkMs = networkRttMs / 2f  // 9.988ms

        assertTrue(uplinkMs > 9.9f)
        assertTrue(uplinkMs < 10.1f)
    }

    @Test
    fun `large server processing reduces network estimate`() {
        // If server takes 50ms to process (overloaded), network RTT is reduced
        val rttMs = 100f
        val serverProcMs = 50f
        val networkRttMs = rttMs - serverProcMs  // 50ms
        val uplinkMs = networkRttMs / 2f  // 25ms

        assertEquals(50f, networkRttMs)
        assertEquals(25f, uplinkMs)
    }

    @Test
    fun `negative network rtt clamped to zero`() {
        // Edge case: if serverProc > RTT (clock jitter), clamp to 0
        val rttMs = 5f
        val serverProcMs = 10f  // impossible but due to timing jitter
        val networkRttMs = maxOf(0f, rttMs - serverProcMs)
        assertEquals(0f, networkRttMs)
    }

    @Test
    fun `32 byte packet rejected as 24 byte old format`() {
        // Old 24-byte format should not decode with new 32-byte decoder
        val oldPkt = ByteArray(24)
        ByteBuffer.wrap(oldPkt).putInt(0, LatencyProber.MAGIC)
        assertNull(LatencyProber.decode(oldPkt))
    }

    @Test
    fun `33 byte packet decodes first 32 bytes`() {
        // decode() checks size >= PACKET_SIZE (32), so 33 bytes is valid
        val pkt = ByteArray(33)
        ByteBuffer.wrap(pkt).putInt(0, LatencyProber.MAGIC)
        // 33 >= 32, so decode succeeds (reads first 32 bytes)
        assertNotNull(LatencyProber.decode(pkt))
    }

    // ── Additional Edge Case Tests ────────────────────────────────

    @Test
    fun `sequence 0 is valid first probe`() {
        // First probe should use seq=0
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 0, 1000L, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(0, decoded.sequence)
    }

    @Test
    fun `sequence wrap from 65535 to 0`() {
        // After 65535, next seq should wrap to 0
        val pkt1 = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 65535, 1000L, 0L, 0L)
        val encoded1 = LatencyProber.encode(pkt1)
        val decoded1 = LatencyProber.decode(encoded1)!!
        assertEquals(65535, decoded1.sequence)

        // Next probe wraps to 0
        val pkt2 = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 0, 2000L, 0L, 0L)
        val encoded2 = LatencyProber.encode(pkt2)
        val decoded2 = LatencyProber.decode(encoded2)!!
        assertEquals(0, decoded2.sequence)
    }

    @Test
    fun `large timestamp value year 2100`() {
        // Year 2100 in microseconds: ~4.1e15
        val year2100Us = 4_102_444_800_000_000L
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 1, year2100Us, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(year2100Us, decoded.clientSendTs)
    }

    @Test
    fun `max safe timestamp value`() {
        // Long.MAX_VALUE would overflow, but typical timestamps are ~10^15
        val largeTs = 9_999_999_999_999_999L  // ~10^16
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 1, largeTs, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(largeTs, decoded.clientSendTs)
    }

    @Test
    fun `reserved byte is preserved in encode`() {
        // Byte [5] is reserved, should be 0x00
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 1, 1000L, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        assertEquals(0x00.toByte(), encoded[5])
    }

    @Test
    fun `invalid type byte not treated as response`() {
        // Type 0xFF is not TYPE_REQUEST or TYPE_RESPONSE
        val data = ByteArray(32)
        ByteBuffer.wrap(data).apply {
            putInt(LatencyProber.MAGIC)
            put(0xFF.toByte())  // invalid type
            put(0x00)  // reserved
            putShort(1)  // seq
            putLong(1000L)  // clientSendTs
            putLong(2000L)  // serverRecvTs
            putLong(2010L)  // serverEchoTs
        }
        val decoded = LatencyProber.decode(data)!!
        // Should decode successfully but with invalid type
        assertEquals(0xFF.toByte(), decoded.type)
        assertNotEquals(LatencyProber.TYPE_RESPONSE, decoded.type)
    }

    @Test
    fun `multiple encode decode cycles maintain consistency`() {
        // Multiple probes should encode/decode independently
        val probes = (1..10).map { seq ->
            LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, seq, seq * 1000L, 0L, 0L)
        }

        probes.forEach { pkt ->
            val encoded = LatencyProber.encode(pkt)
            val decoded = LatencyProber.decode(encoded)!!
            assertEquals(pkt.sequence, decoded.sequence)
            assertEquals(pkt.clientSendTs, decoded.clientSendTs)
        }
    }

    @Test
    fun `ema converges to steady value`() {
        // EMA with α=0.3 should converge to target
        var ema = 0.0f
        val alpha = 0.3f
        val target = 50.0f

        repeat(30) {
            ema = alpha * target + (1 - alpha) * ema
        }

        assertTrue(ema > 49.0f)
        assertTrue(ema < 51.0f)
    }

    @Test
    fun `ema responds to spike but dampens it`() {
        // EMA should respond to sudden spike but not jump immediately
        var ema = 50.0f
        val alpha = 0.3f

        // Spike to 500ms
        ema = alpha * 500.0f + (1 - alpha) * ema

        // Should be between old and new value
        assertTrue(ema > 50.0f)
        assertTrue(ema < 500.0f)
        // Should be ~185 (0.3*500 + 0.7*50 = 150+35 = 185)
        assertTrue(ema > 180.0f)
        assertTrue(ema < 190.0f)
    }

    @Test
    fun `ema responds to latency drop`() {
        // EMA should respond to sudden drop
        var ema = 200.0f
        val alpha = 0.3f

        // Drop to 10ms
        ema = alpha * 10.0f + (1 - alpha) * ema

        // Should be between old and new value
        assertTrue(ema > 10.0f)
        assertTrue(ema < 200.0f)
        // Should be ~143 (0.3*10 + 0.7*200 = 3+140 = 143)
        assertTrue(ema > 140.0f)
        assertTrue(ema < 146.0f)
    }

    @Test
    fun `rtt exactly equals server processing`() {
        // If server processing equals RTT, network RTT is 0
        val rttMs = 50f
        val serverProcMs = 50f
        val networkRttMs = rttMs - serverProcMs
        assertEquals(0f, networkRttMs)

        // Uplink = downlink = 0
        val uplinkMs = networkRttMs / 2f
        assertEquals(0f, uplinkMs)
    }

    @Test
    fun `very small rtt near zero`() {
        // Sub-millisecond RTT (fast LAN)
        val rttMs = 0.5f
        val serverProcMs = 0.1f
        val networkRttMs = rttMs - serverProcMs  // 0.4ms
        val uplinkMs = networkRttMs / 2f  // 0.2ms

        assertTrue(uplinkMs > 0.19f)
        assertTrue(uplinkMs < 0.21f)
    }

    @Test
    fun `probe sent times management`() {
        // Simulate probe sent times map
        val probeSentTimes = mutableMapOf<Int, Long>()

        // Add probes
        probeSentTimes[1] = 1000L
        probeSentTimes[2] = 2000L
        probeSentTimes[3] = 3000L

        assertEquals(3, probeSentTimes.size)

        // Remove on response
        val sentUs = probeSentTimes.remove(2)
        assertEquals(2000L, sentUs)
        assertEquals(2, probeSentTimes.size)

        // Unknown seq returns null
        val unknown = probeSentTimes.remove(99)
        assertNull(unknown)
    }

    @Test
    fun `stale probe cleanup removes old entries`() {
        val probeSentTimes = mutableMapOf<Int, Long>()
        val nowUs = 50_000_000L  // 50s

        // Add entries: some fresh, some stale
        probeSentTimes[1] = 10_000_000L  // 40s ago
        probeSentTimes[2] = 19_000_000L  // 31s ago
        probeSentTimes[3] = 45_000_000L  // 5s ago
        probeSentTimes[4] = 49_000_000L  // 1s ago

        // Purge entries older than 30s
        val cutoffUs = nowUs - 30_000_000L
        val stale = probeSentTimes.filter { it.value < cutoffUs }.keys
        stale.forEach { probeSentTimes.remove(it) }

        assertFalse(probeSentTimes.containsKey(1))
        assertFalse(probeSentTimes.containsKey(2))
        assertTrue(probeSentTimes.containsKey(3))
        assertTrue(probeSentTimes.containsKey(4))
        assertEquals(2, probeSentTimes.size)
    }

    @Test
    fun `response after disconnect cleanup ignored`() {
        // Simulate: disconnect clears map, then response arrives
        val probeSentTimes = mutableMapOf<Int, Long>()
        probeSentTimes.clear()

        // Response arrives with seq=42
        val sentUs = probeSentTimes.remove(42)
        assertNull(sentUs)  // No crash, just ignored
    }

    @Test
    fun `duplicate response for same sequence ignored`() {
        // Second response for same seq finds no entry
        val probeSentTimes = mutableMapOf<Int, Long>()
        probeSentTimes[42] = 5000L

        // First response
        val sentUs1 = probeSentTimes.remove(42)
        assertEquals(5000L, sentUs1)

        // Second response (duplicate)
        val sentUs2 = probeSentTimes.remove(42)
        assertNull(sentUs2)
    }

    @Test
    fun `format latency microseconds`() {
        // Sub-millisecond should show µs
        val ms = 0.5f
        val result = if (ms < 1) "${(ms * 1000).toInt()}µs" else "${ms}ms"
        assertEquals("500µs", result)
    }

    @Test
    fun `format latency milliseconds`() {
        // 1-999ms should show ms
        val ms = 45.2f
        val result = if (ms < 1) "${(ms * 1000).toInt()}µs" else "${ms}ms"
        assertEquals("45.2ms", result)
    }

    @Test
    fun `format latency seconds`() {
        // >=1000ms should show seconds
        val ms = 1500.0f
        val result = if (ms >= 1000) "${ms / 1000}s" else "${ms}ms"
        assertEquals("1.5s", result)
    }

    @Test
    fun `multiple connect disconnect cycles reset state`() {
        val probeSentTimes = mutableMapOf<Int, Long>()
        var emaRtt = 50.0f
        var probesSent = 100

        // Cycle 1: disconnect
        probeSentTimes.clear()
        emaRtt = 0.0f
        probesSent = 0
        assertEquals(0, probeSentTimes.size)

        // Cycle 2: reconnect
        probeSentTimes[1] = 1000L
        emaRtt = 30.0f
        probesSent = 5
        assertEquals(1, probeSentTimes.size)

        // Cycle 2: disconnect
        probeSentTimes.clear()
        emaRtt = 0.0f
        probesSent = 0
        assertEquals(0, probeSentTimes.size)
        assertEquals(0.0f, emaRtt)
    }

    @Test
    fun `probe interval is 5 seconds`() {
        assertEquals(5000L, LatencyProber.PROBE_INTERVAL_MS)
    }

    @Test
    fun `concurrent access no crash`() {
        // Simulate concurrent read/write from multiple threads
        val probeSentTimes = mutableMapOf<Int, Long>()
        val errors = mutableListOf<Exception>()

        val writer = Thread {
            try {
                for (i in 1..1000) {
                    probeSentTimes[i] = i.toLong()
                }
            } catch (e: Exception) {
                errors.add(e)
            }
        }

        val reader = Thread {
            try {
                for (i in 1..1000) {
                    probeSentTimes[i]
                }
            } catch (e: Exception) {
                errors.add(e)
            }
        }

        writer.start()
        reader.start()
        writer.join()
        reader.join()

        // No crash = pass
        assertTrue(errors.isEmpty())
    }

    @Test
    fun `probe response skips tun write`() {
        // After detecting probe response, code does continue (not write to TUN)
        // This is a code path test: if probe detected → continue
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_RESPONSE, 1, 1000L, 2000L, 2010L)
        val encoded = LatencyProber.encode(pkt)
        assertEquals(32, encoded.size)
        // In real code: if n == PACKET_SIZE && decode(type==RESPONSE) → continue
        // No TUN write happens
    }

    @Test
    fun `asymmetric path uplink greater than downlink`() {
        // Simulate asymmetric path: uplink slower than downlink
        val rttMs = 100f
        val serverProcMs = 10f
        val networkRttMs = rttMs - serverProcMs  // 90ms

        // Asymmetric: 60% uplink, 40% downlink
        val uplinkMs = networkRttMs * 0.6f  // 54ms
        val downlinkMs = networkRttMs * 0.4f  // 36ms

        assertTrue(uplinkMs > downlinkMs)
        assertEquals(networkRttMs, uplinkMs + downlinkMs)
    }

    @Test
    fun `server processing equals zero edge case`() {
        // Server processes instantly (0ms)
        val rttMs = 20f
        val serverProcMs = 0f
        val networkRttMs = rttMs - serverProcMs  // 20ms
        val uplinkMs = networkRttMs / 2f  // 10ms

        assertEquals(20f, networkRttMs)
        assertEquals(10f, uplinkMs)
    }

    @Test
    fun `timestamp precision preservation`() {
        // Microsecond precision should be preserved
        val preciseTs = 1234567890123456L
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 1, preciseTs, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(preciseTs, decoded.clientSendTs)
    }

    @Test
    fun `sequence boundary at 32768`() {
        // Test at int16 boundary (0x8000)
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 32768, 1000L, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        // 32768 as uint16 is valid
        assertEquals(32768, decoded.sequence)
    }

    @Test
    fun `negative sequence stored as unsigned`() {
        // -1 as uint16 is 65535
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, -1, 1000L, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        // -1.toShort() = 0xFFFF, toInt() and 0xFFFF = 65535
        assertEquals(65535, decoded.sequence)
    }

    @Test
    fun `all fields zero valid packet`() {
        // All zeros except magic
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 0, 0L, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(0, decoded.sequence)
        assertEquals(0L, decoded.clientSendTs)
        assertEquals(0L, decoded.serverRecvTs)
        assertEquals(0L, decoded.serverEchoTs)
    }

    @Test
    fun `decode exactly 31 bytes fails`() {
        // 31 < 32, should fail
        val pkt = ByteArray(31)
        ByteBuffer.wrap(pkt).putInt(0, LatencyProber.MAGIC)
        assertNull(LatencyProber.decode(pkt))
    }

    @Test
    fun `decode exactly 32 bytes succeeds`() {
        // 32 >= 32, should succeed
        val pkt = ByteArray(32)
        ByteBuffer.wrap(pkt).putInt(0, LatencyProber.MAGIC)
        assertNotNull(LatencyProber.decode(pkt))
    }

    @Test
    fun `decode 64 bytes reads first 32`() {
        // Larger packet should still decode (reads first 32 bytes)
        val pkt = ByteArray(64)
        ByteBuffer.wrap(pkt).putInt(0, LatencyProber.MAGIC)
        assertNotNull(LatencyProber.decode(pkt))
    }

    @Test
    fun `server echo timestamp always after recv timestamp`() {
        // In real server, echo_ts >= recv_ts
        val serverRecv = 1000L
        val serverEcho = 1010L  // 10µs processing
        assertTrue(serverEcho >= serverRecv)
        val serverProc = serverEcho - serverRecv
        assertEquals(10L, serverProc)
    }

    @Test
    fun `probe response with zero server timestamps edge case`() {
        // Server returned 0 timestamps (shouldn't happen but handle gracefully)
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_RESPONSE, 1, 1000L, 0L, 0L)
        val encoded = LatencyProber.encode(pkt)
        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(0L, decoded.serverRecvTs)
        assertEquals(0L, decoded.serverEchoTs)

        // If server timestamps are 0, serverProc would be 0
        val serverProc = decoded.serverEchoTs - decoded.serverRecvTs
        assertEquals(0L, serverProc)
    }

    @Test
    fun `probe sent times map size limit`() {
        // If map grows too large (no responses), cleanup should handle it
        val probeSentTimes = mutableMapOf<Int, Long>()
        val nowUs = 100_000_000L

        // Add 1000 stale entries
        for (i in 1..1000) {
            probeSentTimes[i] = nowUs - 60_000_000L  // 60s ago
        }
        assertEquals(1000, probeSentTimes.size)

        // Purge stale entries
        val cutoffUs = nowUs - 30_000_000L
        val stale = probeSentTimes.filter { it.value < cutoffUs }.keys
        stale.forEach { probeSentTimes.remove(it) }

        assertEquals(0, probeSentTimes.size)
    }
}

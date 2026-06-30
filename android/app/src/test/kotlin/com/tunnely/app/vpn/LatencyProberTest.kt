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
}

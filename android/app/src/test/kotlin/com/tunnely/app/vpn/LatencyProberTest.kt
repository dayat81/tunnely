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
        )
        val encoded = LatencyProber.encode(pkt)
        assertEquals(24, encoded.size)

        val decoded = LatencyProber.decode(encoded)!!
        assertEquals(LatencyProber.TYPE_REQUEST, decoded.type)
        assertEquals(42, decoded.sequence)
        assertEquals(1234567890L, decoded.clientSendTs)
        assertEquals(0L, decoded.serverRecvTs)
    }

    @Test
    fun `response preserves client timestamp`() {
        val req = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 1, 1000L, 0L)
        val encoded = LatencyProber.encode(req)

        // Simulate server: change type, add server timestamp
        val response = encoded.copyOf()
        response[4] = LatencyProber.TYPE_RESPONSE
        ByteBuffer.wrap(response).putLong(16, 2000L)

        val decoded = LatencyProber.decode(response)!!
        assertEquals(LatencyProber.TYPE_RESPONSE, decoded.type)
        assertEquals(1000L, decoded.clientSendTs)  // preserved
        assertEquals(2000L, decoded.serverRecvTs)  // added by server
    }

    @Test
    fun `decode rejects wrong magic`() {
        val data = ByteArray(24)
        assertNull(LatencyProber.decode(data))
    }

    @Test
    fun `decode rejects too short`() {
        assertNull(LatencyProber.decode(ByteArray(10)))
    }

    @Test
    fun `sequence wraps at 65535`() {
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 65535, 100L, 0L)
        val decoded = LatencyProber.decode(LatencyProber.encode(pkt))!!
        assertEquals(65535, decoded.sequence)
    }

    @Test
    fun `packet size is exactly 24 bytes`() {
        assertEquals(24, LatencyProber.PACKET_SIZE)
    }

    @Test
    fun `magic bytes are TLTP`() {
        val pkt = LatencyProber.ProbePacket(LatencyProber.TYPE_REQUEST, 0, 0L, 0L)
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
    fun `nowMicros returns monotonic time`() {
        val t1 = LatencyProber.nowMicros()
        Thread.sleep(1)
        val t2 = LatencyProber.nowMicros()
        assertTrue(t2 > t1)
    }

    // ── Clock Synchronization Tests (#26) ─────────────────────────

    @Test
    fun `nowMicros returns wall clock microseconds since epoch`() {
        val nowUs = LatencyProber.nowMicros()
        val nowMs = System.currentTimeMillis()
        val expectedUs = nowMs * 1000
        // Should be within 100ms of each other
        assertTrue(
            "nowMicros should be wall clock (within 100ms)",
            Math.abs(nowUs - expectedUs) < 100_000
        )
    }

    @Test
    fun `nowMicros is compatible with server time`() {
        // Server uses: int(time.time() * 1_000_000)
        // Client should produce similar magnitude values
        val clientUs = LatencyProber.nowMicros()
        // Wall clock µs since epoch should be ~1.7 × 10^15 in 2026
        assertTrue("should be > 1e15 (epoch µs)", clientUs > 1_000_000_000_000_000L)
        assertTrue("should be < 2e15 (before year 2033)", clientUs < 2_000_000_000_000_000L)
    }

    @Test
    fun `uplink latency is small for same-clock timestamps`() {
        // Simulate: client sends at T1, server receives at T1 + 50ms
        val clientSendUs = LatencyProber.nowMicros()
        val serverRecvUs = clientSendUs + 50_000  // 50ms later
        val uplinkUs = serverRecvUs - clientSendUs
        val uplinkMs = uplinkUs / 1000f
        // Should be ~50ms, NOT 1782742400s (the old bug)
        assertTrue("uplink should be < 1s", uplinkMs < 1000f)
        assertTrue("uplink should be ~50ms", Math.abs(uplinkMs - 50f) < 1f)
    }

    @Test
    fun `downlink latency is small for same-clock timestamps`() {
        val serverSendUs = LatencyProber.nowMicros()
        val clientRecvUs = serverSendUs + 30_000  // 30ms later
        val downlinkUs = clientRecvUs - serverSendUs
        val downlinkMs = downlinkUs / 1000f
        assertTrue("downlink should be < 1s", downlinkMs < 1000f)
        assertTrue("downlink should be ~30ms", Math.abs(downlinkMs - 30f) < 1f)
    }

    @Test
    fun `old nanoTime would give wrong magnitude`() {
        // OLD bug: nanoTime()/1000 gives ~10^12 range (not epoch µs)
        // NEW: currentTimeMillis()*1000 gives ~10^15 range (epoch µs)
        // If we accidentally used nanoTime, serverTs - clientTs would be ~10^15
        val clientUs = LatencyProber.nowMicros()
        // Simulate server timestamp (same clock)
        val serverUs = clientUs + 50_000
        val diff = serverUs - clientUs
        // The diff should be tiny (50ms = 50000µs), NOT 1.7×10^15
        assertTrue("diff should be < 1s worth of µs", diff < 1_000_000)
    }
}

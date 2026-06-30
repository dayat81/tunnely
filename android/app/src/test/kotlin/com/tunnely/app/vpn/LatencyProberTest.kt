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
}

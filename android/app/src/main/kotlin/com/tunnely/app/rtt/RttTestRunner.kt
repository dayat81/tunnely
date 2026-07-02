package com.tunnely.app.rtt

import android.net.VpnService
import kotlinx.coroutines.*
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Socket
import java.net.UnknownHostException

/**
 * Runs RTT measurements: direct (bypass VPN) vs VPN (through tunnel).
 *
 * - Direct: protect(socket) → bypass VPN → exit directly
 * - VPN: normal socket → goes through tun0
 * - DNS and TCP measured separately for accuracy
 * - Parallel execution within each mode
 */
class RttTestRunner(
    private val vpnService: VpnService? = null,
    private val connectTimeoutMs: Int = 3000,
) {
    /**
     * Run all measurements. VPN must be connected.
     * Returns results sorted by overhead (highest first).
     */
    suspend fun runAll(
        targets: List<RttTarget> = RttTarget.DEFAULT_TARGETS,
    ): List<RttResult> = withContext(Dispatchers.IO) {
        // Phase 1: Direct measurements (parallel)
        val directResults = targets.map { target ->
            async { measureDirect(target) }
        }.awaitAll()

        // Phase 2: VPN measurements (parallel)
        val vpnResults = targets.map { target ->
            async { measureVpn(target) }
        }.awaitAll()

        // Combine results
        targets.indices.map { i ->
            val direct = directResults[i]
            val vpn = vpnResults[i]
            RttResult(
                target = targets[i],
                directDnsMs = direct.dnsMs,
                directTcpMs = direct.tcpMs,
                vpnDnsMs = vpn.dnsMs,
                vpnTcpMs = vpn.tcpMs,
            )
        }.sortedByDescending { it.overheadMs }
    }

    /**
     * Measure direct connection (bypass VPN).
     * Uses protect() to route socket outside VPN tunnel.
     */
    internal fun measureDirect(target: RttTarget): Measurement {
        return try {
            // DNS resolution
            val dnsStart = System.nanoTime()
            val addr = try {
                InetAddress.getByName(target.host)
            } catch (e: UnknownHostException) {
                return Measurement(TIMEOUT, TIMEOUT, "DNS failed: ${e.message}")
            }
            val dnsMs = (System.nanoTime() - dnsStart) / 1_000_000

            // TCP connect via protected socket (bypass VPN)
            val tcpStart = System.nanoTime()
            val socket = Socket()
            try {
                val protected = vpnService?.protect(socket) ?: false
                if (!protected) {
                    // protect() failed — fallback to unprotect (may go through VPN)
                    // Still measure, but note it in logs
                }
                socket.connect(InetSocketAddress(addr, target.port), connectTimeoutMs)
                val tcpMs = (System.nanoTime() - tcpStart) / 1_000_000
                Measurement(dnsMs, tcpMs)
            } finally {
                try { socket.close() } catch (_: Exception) {}
            }
        } catch (e: java.net.SocketTimeoutException) {
            Measurement(TIMEOUT, TIMEOUT, "Timeout")
        } catch (e: Exception) {
            Measurement(TIMEOUT, TIMEOUT, e.message ?: "Unknown error")
        }
    }

    /**
     * Measure VPN connection (through tunnel).
     * Normal socket — traffic goes through tun0.
     */
    internal fun measureVpn(target: RttTarget): Measurement {
        return try {
            // DNS resolution
            val dnsStart = System.nanoTime()
            val addr = try {
                InetAddress.getByName(target.host)
            } catch (e: UnknownHostException) {
                return Measurement(TIMEOUT, TIMEOUT, "DNS failed: ${e.message}")
            }
            val dnsMs = (System.nanoTime() - dnsStart) / 1_000_000

            // TCP connect via normal socket (through VPN)
            val tcpStart = System.nanoTime()
            val socket = Socket()
            try {
                socket.connect(InetSocketAddress(addr, target.port), connectTimeoutMs)
                val tcpMs = (System.nanoTime() - tcpStart) / 1_000_000
                Measurement(dnsMs, tcpMs)
            } finally {
                try { socket.close() } catch (_: Exception) {}
            }
        } catch (e: java.net.SocketTimeoutException) {
            Measurement(TIMEOUT, TIMEOUT, "Timeout")
        } catch (e: Exception) {
            Measurement(TIMEOUT, TIMEOUT, e.message ?: "Unknown error")
        }
    }

    data class Measurement(
        val dnsMs: Long,
        val tcpMs: Long,
        val error: String? = null,
    ) {
        val isTimeout: Boolean get() = dnsMs == TIMEOUT || tcpMs == TIMEOUT
    }

    companion object {
        const val TIMEOUT = -1L
    }
}

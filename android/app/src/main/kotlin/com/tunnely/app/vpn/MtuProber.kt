package com.tunnely.app.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress

/**
 * ICMP MTU discovery using binary search.
 * Runs `ping -M do -s <size>` to find the maximum path MTU,
 * then subtracts WireGuard overhead (60 bytes) to get the tunnel MTU.
 */
object MtuProber {

    private const val WG_OVERHEAD = 60  // 20 IP + 8 UDP + 32 WireGuard
    private const val MAX_MTU = 1500
    private const val MIN_MTU = 68
    private const val PROBE_TIMEOUT_MS = 2000

    /**
     * Discover the optimal MTU for the given host using ICMP probes.
     * Returns the WireGuard tunnel MTU (path MTU - WG_OVERHEAD).
     */
    suspend fun discover(host: String): Int = withContext(Dispatchers.IO) {
        try {
            // Resolve the host to get IP address
            val address = InetAddress.getByName(host)

            var low = MIN_MTU
            var high = MAX_MTU
            var bestMtu = MIN_MTU

            // Binary search for the maximum working MTU
            while (low <= high) {
                val mid = (low + high) / 2

                if (probeMtu(address.hostAddress ?: host, mid)) {
                    bestMtu = mid
                    low = mid + 1
                } else {
                    high = mid - 1
                }
            }

            // Subtract WireGuard overhead
            val wgMtu = bestMtu - WG_OVERHEAD
            wgMtu.coerceIn(576, 1420)
        } catch (e: Exception) {
            // Default MTU if probing fails
            1420
        }
    }

    /**
     * Probe whether the given MTU size works to the target host.
     * Uses ICMP ping with Don't Fragment flag set.
     */
    private fun probeMtu(host: String, size: Int): Boolean {
        return try {
            // ICMP data size = total - 20 (IP header) - 8 (ICMP header)
            val icmpSize = size - 28
            if (icmpSize <= 0) return false

            val process = Runtime.getRuntime().exec(
                arrayOf(
                    "/system/bin/ping",
                    "-c", "1",
                    "-W", "2",
                    "-M", "do",
                    "-s", icmpSize.toString(),
                    host
                )
            )

            val exitCode = process.waitFor()
            exitCode == 0
        } catch (e: Exception) {
            false
        }
    }
}

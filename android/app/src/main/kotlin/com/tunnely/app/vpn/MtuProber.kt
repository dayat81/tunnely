package com.tunnely.app.vpn

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import java.net.InetAddress

/**
 * ICMP MTU discovery using binary search.
 * Runs `ping -M do -s <size>` to find the maximum path MTU,
 * then subtracts UDP tunnel overhead (28 bytes) to get the tunnel MTU.
 */
object MtuProber {

    private const val UDP_OVERHEAD = 28  // 20 IP + 8 UDP (UDP tunnel, not WireGuard)
    private const val MAX_MTU = 1500
    private const val MIN_MTU = 68
    private const val PROBE_TIMEOUT_MS = 2000

    /**
     * Discover the optimal MTU for the given host using ICMP probes.
     * Returns the UDP tunnel MTU (path MTU - UDP_OVERHEAD).
     */
    suspend fun discover(host: String): Int = withContext(Dispatchers.IO) {
        try {
            val address = InetAddress.getByName(host)

            var low = MIN_MTU
            var high = MAX_MTU
            var bestMtu = MIN_MTU

            while (low <= high) {
                val mid = (low + high) / 2

                if (probeMtu(address.hostAddress ?: host, mid)) {
                    bestMtu = mid
                    low = mid + 1
                } else {
                    high = mid - 1
                }
            }

            // Subtract UDP tunnel overhead (not WireGuard)
            val tunnelMtu = bestMtu - UDP_OVERHEAD
            tunnelMtu.coerceIn(576, 1400)  // cap at 1400 to match server TUN MTU
        } catch (e: Exception) {
            1400  // safe default matching server TUN MTU
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

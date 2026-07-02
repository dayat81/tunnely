package com.tunnely.app.rtt

/**
 * Result of RTT measurement for a single target.
 * DNS and TCP are measured separately for accuracy.
 */
data class RttResult(
    val target: RttTarget,
    val directDnsMs: Long,
    val directTcpMs: Long,
    val vpnDnsMs: Long,
    val vpnTcpMs: Long,
) {
    /** Total direct latency (DNS + TCP) */
    val directTotalMs: Long get() = directDnsMs + directTcpMs

    /** Total VPN latency (DNS + TCP) */
    val vpnTotalMs: Long get() = vpnDnsMs + vpnTcpMs

    /** Overhead: VPN total - Direct total */
    val overheadMs: Long get() = vpnTotalMs - directTotalMs

    /** Overhead as percentage of direct latency */
    val overheadPercent: Double get() = if (directTotalMs > 0) {
        (overheadMs.toDouble() / directTotalMs) * 100.0
    } else 0.0

    /**
     * Color rating based on overhead percentage:
     * - GREEN: <20% overhead
     * - YELLOW: 20-50% overhead
     * - RED: >50% overhead
     * - TIMEOUT: measurement failed
     */
    val rating: Rating get() = when {
        directTotalMs < 0 || vpnTotalMs < 0 -> Rating.TIMEOUT
        overheadPercent < 20 -> Rating.GREEN
        overheadPercent < 50 -> Rating.YELLOW
        else -> Rating.RED
    }

    enum class Rating { GREEN, YELLOW, RED, TIMEOUT }

    companion object {
        const val TIMEOUT_MS = -1L

        fun timeout(target: RttTarget) = RttResult(
            target = target,
            directDnsMs = TIMEOUT_MS,
            directTcpMs = TIMEOUT_MS,
            vpnDnsMs = TIMEOUT_MS,
            vpnTcpMs = TIMEOUT_MS,
        )

        fun directTimeout(target: RttTarget, vpnDnsMs: Long, vpnTcpMs: Long) = RttResult(
            target = target,
            directDnsMs = TIMEOUT_MS,
            directTcpMs = TIMEOUT_MS,
            vpnDnsMs = vpnDnsMs,
            vpnTcpMs = vpnTcpMs,
        )

        fun vpnTimeout(target: RttTarget, directDnsMs: Long, directTcpMs: Long) = RttResult(
            target = target,
            directDnsMs = directDnsMs,
            directTcpMs = directTcpMs,
            vpnDnsMs = TIMEOUT_MS,
            vpnTcpMs = TIMEOUT_MS,
        )
    }

    /** Summary across multiple results */
    data class Summary(
        val results: List<RttResult>,
    ) {
        private val valid = results.filter { it.rating != Rating.TIMEOUT }

        val avgDirectMs: Long = if (valid.isNotEmpty()) {
            valid.sumOf { it.directTotalMs } / valid.size
        } else 0

        val avgVpnMs: Long = if (valid.isNotEmpty()) {
            valid.sumOf { it.vpnTotalMs } / valid.size
        } else 0

        val avgOverheadMs: Long = avgVpnMs - avgDirectMs

        val avgOverheadPercent: Double = if (avgDirectMs > 0) {
            (avgOverheadMs.toDouble() / avgDirectMs) * 100.0
        } else 0.0

        val successCount: Int get() = valid.size
        val timeoutCount: Int get() = results.size - valid.size
    }
}

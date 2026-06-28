package com.tunnely.app.vpn

/**
 * Reads /proc/net/tcp, /proc/net/udp etc. for local connection visibility.
 * On Android 10+ this only shows the app's own connections unless running as system/root.
 * Used as a supplement to server-side conntrack data.
 */
object LocalFlowReader {

    data class LocalFlow(
        val protocol: String,
        val localAddr: String,
        val localPort: Int,
        val remoteAddr: String,
        val remotePort: Int,
        val state: String
    )

    private val TCP_STATES = mapOf(
        "01" to "ESTABLISHED",
        "02" to "SYN_SENT",
        "03" to "SYN_RECV",
        "04" to "FIN_WAIT1",
        "05" to "FIN_WAIT2",
        "06" to "TIME_WAIT",
        "07" to "CLOSE",
        "08" to "CLOSE_WAIT",
        "09" to "LAST_ACK",
        "0A" to "LISTEN",
        "0B" to "CLOSING"
    )

    /**
     * Try to read local connections. Returns empty list if not accessible.
     */
    fun getActiveConnections(): List<FlowEntry> {
        return try {
            val flows = mutableListOf<LocalFlow>()
            flows.addAll(parseProcNet("/proc/net/tcp", "TCP"))
            flows.addAll(parseProcNet("/proc/net/udp", "UDP"))
            flows.addAll(parseProcNet("/proc/net/tcp6", "TCP6"))
            flows.addAll(parseProcNet("/proc/net/udp6", "UDP6"))

            // Filter out loopback and LISTEN, convert to FlowEntry
            flows.filter { f ->
                f.state != "LISTEN" &&
                f.remoteAddr !in listOf("00000000", "00000000000000000000000000000000") &&
                !f.remoteAddr.startsWith("0100007F") && // 127.x
                f.remoteAddr != "0000000000000000FFFF0000" + "0100007F" // ::1 mapped
            }.map { f ->
                val ip = hexToIp(f.remoteAddr)
                FlowEntry(
                    server = ip,
                    port = f.remotePort,
                    protocol = f.protocol,
                    uplinkBytes = 0,  // /proc/net doesn't have per-connection byte counters
                    downlinkBytes = 0
                )
            }.distinctBy { "${it.server}:${it.port}" }
             .sortedBy { it.server }
        } catch (_: Exception) {
            emptyList()
        }
    }

    private fun parseProcNet(path: String, protocol: String): List<LocalFlow> {
        val flows = mutableListOf<LocalFlow>()
        try {
            val lines = java.io.File(path).readLines()
            for (i in 1 until lines.size) {
                val parts = lines[i].trim().split(Regex("\\s+"))
                if (parts.size < 4) continue
                try {
                    val localParts = parts[1].split(":")
                    val remoteParts = parts[2].split(":")
                    if (localParts.size < 2 || remoteParts.size < 2) continue

                    val state = if (protocol.startsWith("TCP")) {
                        TCP_STATES[parts[3]] ?: parts[3]
                    } else "ACTIVE"

                    flows.add(LocalFlow(
                        protocol = protocol,
                        localAddr = localParts[0],
                        localPort = localParts[1].toInt(16),
                        remoteAddr = remoteParts[0],
                        remotePort = remoteParts[1].toInt(16),
                        state = state
                    ))
                } catch (_: Exception) {}
            }
        } catch (_: Exception) {}
        return flows
    }

    private fun hexToIp(hex: String): String {
        return try {
            if (hex.length == 8) {
                hex.chunked(2).reversed().map { it.toInt(16) }.joinToString(".")
            } else if (hex.length == 32) {
                // IPv6 - try mapped IPv4
                val v4part = hex.substring(24)
                if (hex.startsWith("0000000000000000FFFF0000")) {
                    v4part.chunked(2).reversed().map { it.toInt(16) }.joinToString(".")
                } else {
                    hex.chunked(4).joinToString(":")
                }
            } else hex
        } catch (_: Exception) { hex }
    }
}

package com.tunnely.app.api

import android.util.Log
import com.tunnely.app.vpn.FlowEntry
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody.Companion.toRequestBody
import org.json.JSONArray
import org.json.JSONObject
import java.util.concurrent.TimeUnit

data class VpnRegistration(
    val serverPublicKey: String,
    val tunnelAddress: String,
    val endpoint: String
)

class ApiClient(
    private val serverAddress: String = "tunnely.site",
    private val serverPort: Int = 51820
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    // Registration API is on tunnely.site
    private val baseUrl = "https://tunnely.site"

    /**
     * Register client with the VPN server and get configuration.
     * POST /api/vpn/register with client public key.
     */
    suspend fun registerClient(clientPublicKey: String): VpnRegistration =
        withContext(Dispatchers.IO) {
            val url = "$baseUrl/api/vpn/register"
            Log.i("ApiClient", "📡 POST $url")
            Log.i("ApiClient", "  public_key=$clientPublicKey")
            val json = JSONObject().apply {
                put("public_key", clientPublicKey)
            }

            val request = Request.Builder()
                .url(url)
                .post(json.toString().toRequestBody("application/json".toMediaType()))
                .build()

            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: throw Exception("Empty response")
            Log.i("ApiClient", "  Response: ${response.code} ${body.take(200)}")

            if (!response.isSuccessful) {
                Log.e("ApiClient", "  ❌ Registration failed: ${response.code}")
                throw Exception("Registration failed: ${response.code} - $body")
            }

            val data = JSONObject(body)
            // API returns "assigned_ip" (e.g. "10.10.0.45"), app needs "tunnel_address" with CIDR (e.g. "10.10.0.45/32")
            val assignedIp = data.optString("assigned_ip", "")
            val tunnelAddress = if (assignedIp.isNotBlank()) {
                if (assignedIp.contains("/")) assignedIp else "$assignedIp/32"
            } else {
                data.optString("tunnel_address", "")
            }
            val reg = VpnRegistration(
                serverPublicKey = data.getString("server_public_key"),
                tunnelAddress = tunnelAddress,
                endpoint = "$serverAddress:$serverPort"
            )
            Log.i("ApiClient", "  ✅ Registered: tunnel=${reg.tunnelAddress}, server_key=${reg.serverPublicKey}")
            reg
        }

    /**
     * Get traffic data for a specific tunnel IP.
     * GET /api/vpn/traffic/client/{ip}
     */
    suspend fun getTrafficData(tunnelIp: String): List<FlowEntry> =
        withContext(Dispatchers.IO) {
            val request = Request.Builder()
                .url("$baseUrl/api/vpn/traffic/client/$tunnelIp")
                .get()
                .build()

            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: "{}"

            if (!response.isSuccessful) {
                return@withContext emptyList()
            }

            val json = JSONObject(body)
            val array = json.optJSONArray("flows_detail") ?: return@withContext emptyList()
            val flows = mutableListOf<FlowEntry>()

            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                flows.add(
                    FlowEntry(
                        server = obj.optString("server_ip", obj.optString("server", "unknown")),
                        port = obj.optInt("server_port", obj.optInt("port", 0)),
                        protocol = obj.optString("proto", obj.optString("protocol", "UDP")),
                        uplinkBytes = obj.optLong("uplink", obj.optLong("tx_bytes", 0)),
                        downlinkBytes = obj.optLong("downlink", obj.optLong("rx_bytes", 0))
                    )
                )
            }

            flows
        }

    /**
     * Get raw traffic stats JSON for a specific tunnel IP.
     * Returns the full JSON response with peer stats, rates, flows count.
     */
    suspend fun getTrafficStatsRaw(tunnelIp: String): JSONObject? =
        withContext(Dispatchers.IO) {
            try {
                val request = Request.Builder()
                    .url("$baseUrl/api/vpn/traffic/client/$tunnelIp")
                    .get()
                    .build()

                val response = client.newCall(request).execute()
                val body = response.body?.string() ?: return@withContext null

                if (!response.isSuccessful) return@withContext null
                JSONObject(body)
            } catch (_: Exception) {
                null
            }
        }

    /**
     * Get server-side SNI domain map from /api/vpn/stats.
     * Returns map of "remote_ip" -> "domain" extracted from TLS ClientHello.
     * Server tracks ALL SNI domains in tcp_debug.sni_domain_map.
     */
    suspend fun getServerSniDomains(): Map<String, String> =
        withContext(Dispatchers.IO) {
            try {
                val request = Request.Builder()
                    .url("$baseUrl/api/vpn/stats")
                    .get()
                    .build()

                val response = client.newCall(request).execute()
                val body = response.body?.string() ?: return@withContext emptyMap()

                if (!response.isSuccessful) return@withContext emptyMap()

                val json = JSONObject(body)
                val tcpDebug = json.optJSONObject("tcp_debug") ?: return@withContext emptyMap()

                // Try new sni_domain_map first (comprehensive, all IPs)
                val sniDomainMap = tcpDebug.optJSONObject("sni_domain_map")
                if (sniDomainMap != null) {
                    val domainMap = mutableMapOf<String, String>()
                    for (key in sniDomainMap.keys()) {
                        val domain = sniDomainMap.optString(key, "")
                        if (domain.isNotEmpty()) {
                            domainMap[key] = domain.lowercase()
                        }
                    }
                    if (domainMap.isNotEmpty()) return@withContext domainMap
                }

                // Fallback: parse recent_snis array (last 10 only)
                val recentSnis = tcpDebug.optJSONArray("recent_snis") ?: return@withContext emptyMap()

                val domainMap = mutableMapOf<String, String>()
                for (i in 0 until recentSnis.length()) {
                    val entry = recentSnis.getString(i)
                    // Format: "client_ip→remote_ip:port = domain"
                    // e.g. "10.20.0.243→142.251.10.95:443 = pubsub.googleapis.com"
                    val arrowIdx = entry.indexOf('→')
                    val equalsIdx = entry.indexOf('=')
                    if (arrowIdx >= 0 && equalsIdx > arrowIdx) {
                        val remotePart = entry.substring(arrowIdx + 1, equalsIdx).trim()
                        val domain = entry.substring(equalsIdx + 1).trim().lowercase()
                        // remotePart = "142.251.10.95:443" — extract just IP
                        val colonIdx = remotePart.indexOf(':')
                        val remoteIp = if (colonIdx > 0) remotePart.substring(0, colonIdx) else remotePart
                        if (domain.isNotEmpty()) {
                            domainMap[remoteIp] = domain
                        }
                    }
                }
                domainMap
            } catch (_: Exception) {
                emptyMap()
            }
        }
}

package com.tunnely.app.api

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
    private val serverAddress: String = "osig.aksa.ai",
    private val serverPort: Int = 51820
) {
    private val client = OkHttpClient.Builder()
        .connectTimeout(10, TimeUnit.SECONDS)
        .readTimeout(10, TimeUnit.SECONDS)
        .build()

    private val baseUrl = "https://$serverAddress"

    /**
     * Register client with the VPN server and get configuration.
     * POST /api/vpn/register with client public key.
     */
    suspend fun registerClient(clientPublicKey: String): VpnRegistration =
        withContext(Dispatchers.IO) {
            val json = JSONObject().apply {
                put("public_key", clientPublicKey)
            }

            val request = Request.Builder()
                .url("$baseUrl/api/vpn/register")
                .post(json.toString().toRequestBody("application/json".toMediaType()))
                .build()

            val response = client.newCall(request).execute()
            val body = response.body?.string() ?: throw Exception("Empty response")

            if (!response.isSuccessful) {
                throw Exception("Registration failed: ${response.code} - $body")
            }

            val data = JSONObject(body)
            VpnRegistration(
                serverPublicKey = data.getString("server_public_key"),
                tunnelAddress = data.getString("tunnel_address"),
                endpoint = "$serverAddress:$serverPort"
            )
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
            val body = response.body?.string() ?: "[]"

            if (!response.isSuccessful) {
                return@withContext emptyList()
            }

            val array = JSONArray(body)
            val flows = mutableListOf<FlowEntry>()

            for (i in 0 until array.length()) {
                val obj = array.getJSONObject(i)
                flows.add(
                    FlowEntry(
                        server = obj.optString("server", "unknown"),
                        port = obj.optInt("port", 0),
                        protocol = obj.optString("protocol", "UDP"),
                        uplinkBytes = obj.optLong("uplink", 0),
                        downlinkBytes = obj.optLong("downlink", 0)
                    )
                )
            }

            flows
        }
}

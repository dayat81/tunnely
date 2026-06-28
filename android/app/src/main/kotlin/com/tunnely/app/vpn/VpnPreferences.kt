package com.tunnely.app.vpn

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64

class VpnPreferences(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("tunnely_prefs", Context.MODE_PRIVATE)

    var serverAddress: String
        get() = prefs.getString("server_address", "osig.aksa.ai") ?: "osig.aksa.ai"
        set(value) = prefs.edit().putString("server_address", value).apply()

    var serverPort: Int
        get() = prefs.getInt("server_port", 51820)
        set(value) = prefs.edit().putInt("server_port", value).apply()

    var dnsServers: String
        get() = prefs.getString("dns_servers", "1.1.1.1, 1.0.0.1") ?: "1.1.1.1, 1.0.0.1"
        set(value) = prefs.edit().putString("dns_servers", value).apply()

    var privateKey: String
        get() {
            var key = prefs.getString("private_key", null)
            if (key == null) {
                val kp = Curve25519.generateKeyPair()
                key = kp.privateKeyBase64
                prefs.edit()
                    .putString("private_key", key)
                    .putString("public_key", kp.publicKeyBase64)
                    .apply()
            }
            return key
        }
        set(value) = prefs.edit().putString("private_key", value).apply()

    var publicKey: String
        get() {
            // Ensure key pair is generated
            prefs.getString("private_key", null) ?: run { privateKey = privateKey }
            return prefs.getString("public_key", "") ?: ""
        }
        set(value) = prefs.edit().putString("public_key", value).apply()

    var serverPublicKey: String
        get() = prefs.getString("server_public_key", DEFAULT_SERVER_PUBKEY) ?: DEFAULT_SERVER_PUBKEY
        set(value) = prefs.edit().putString("server_public_key", value).apply()

    var tunnelAddress: String
        get() = prefs.getString("tunnel_address", DEFAULT_TUNNEL_ADDRESS) ?: DEFAULT_TUNNEL_ADDRESS
        set(value) = prefs.edit().putString("tunnel_address", value).apply()

    var mtu: Int
        get() = prefs.getInt("mtu", 1420)
        set(value) = prefs.edit().putInt("mtu", value).apply()

    var autoMtu: Boolean
        get() = prefs.getBoolean("auto_mtu", true)
        set(value) = prefs.edit().putBoolean("auto_mtu", value).apply()

    var allowedIps: String
        get() = prefs.getString("allowed_ips", "0.0.0.0/0") ?: "0.0.0.0/0"
        set(value) = prefs.edit().putString("allowed_ips", value).apply()

    var splitTunneling: Boolean
        get() = prefs.getBoolean("split_tunneling", false)
        set(value) = prefs.edit().putBoolean("split_tunneling", value).apply()

    var splitApps: Set<String>
        get() = prefs.getStringSet("split_apps", emptySet()) ?: emptySet()
        set(value) = prefs.edit().putStringSet("split_apps", value).apply()

    fun regenerateKeys(): String {
        val kp = Curve25519.generateKeyPair()
        prefs.edit()
            .putString("private_key", kp.privateKeyBase64)
            .putString("public_key", kp.publicKeyBase64)
            .apply()
        return kp.publicKeyBase64
    }

    fun decodePrivateKey(): ByteArray {
        return Base64.decode(privateKey, Base64.NO_WRAP)
    }

    fun decodeServerPublicKey(): ByteArray {
        return Base64.decode(serverPublicKey, Base64.NO_WRAP)
    }

    companion object {
        const val DEFAULT_SERVER_PUBKEY = "LD7xNAw6Sn7Q0dIhJ211y24Il/oTeCXgGyEaOGIwZSE="
        const val DEFAULT_TUNNEL_ADDRESS = "10.10.0.45/32"
    }
}

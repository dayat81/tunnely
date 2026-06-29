package com.tunnely.app.vpn

import android.content.Context
import android.content.SharedPreferences
import android.util.Base64

class VpnPreferences(context: Context) {

    private val prefs: SharedPreferences =
        context.getSharedPreferences("tunnely_prefs", Context.MODE_PRIVATE)

    var serverAddress: String
        get() = prefs.getString("server_address", "tunnely.site") ?: "tunnely.site"
        set(value) = prefs.edit().putString("server_address", value).apply()

    var serverPort: Int
        get() = prefs.getInt("server_port", 51820)
        set(value) = prefs.edit().putInt("server_port", value).apply()

    var dnsServers: String
        get() = prefs.getString("dns_servers", "1.1.1.1, 1.0.0.1") ?: "1.1.1.1, 1.0.0.1"
        set(value) = prefs.edit().putString("dns_servers", value).apply()

    var privateKey: String
        get() = prefs.getString("private_key", "") ?: ""
        set(value) = prefs.edit().putString("private_key", value).apply()

    var publicKey: String
        get() = prefs.getString("public_key", "") ?: ""
        set(value) = prefs.edit().putString("public_key", value).apply()

    var serverPublicKey: String
        get() = prefs.getString("server_public_key", DEFAULT_SERVER_PUBKEY) ?: DEFAULT_SERVER_PUBKEY
        set(value) = prefs.edit().putString("server_public_key", value).apply()

    var tunnelAddress: String
        get() = prefs.getString("tunnel_address", "") ?: ""
        set(value) = prefs.edit().putString("tunnel_address", value).apply()

    var mtu: Int
        get() = prefs.getInt("mtu", 1400)
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

    var remoteLogging: Boolean
        get() = prefs.getBoolean("remote_logging", false)
        set(value) = prefs.edit().putBoolean("remote_logging", value).apply()

    /** Check if we have a valid VPN config (like netprobe AnalysisPreferences.hasConfig) */
    fun hasConfig(): Boolean {
        return privateKey.isNotBlank() &&
            publicKey.isNotBlank() &&
            serverPublicKey.isNotBlank() &&
            tunnelAddress.isNotBlank()
    }

    /**
     * Generate a new WireGuard keypair (like netprobe AnalysisVpnService.generateKeyPair).
     * Uses the same BigInteger Curve25519 that netprobe uses.
     * Returns the public key base64 string.
     */
    fun generateKeyPair(): String {
        val privBytes = ByteArray(32)
        java.security.SecureRandom().nextBytes(privBytes)
        // Clamp per Curve25519 / WireGuard spec
        privBytes[0] = (privBytes[0].toInt() and 248).toByte()
        privBytes[31] = (privBytes[31].toInt() and 127).toByte()
        privBytes[31] = (privBytes[31].toInt() or 64).toByte()

        val pubBytes = Curve25519.scalarMultBase(privBytes)

        privateKey = Base64.encodeToString(privBytes, Base64.NO_WRAP)
        publicKey = Base64.encodeToString(pubBytes, Base64.NO_WRAP)
        return publicKey
    }

    /**
     * Derive public key from existing private key (like netprobe displayClientPublicKey).
     */
    fun derivePublicKey(): String {
        if (privateKey.isBlank()) return ""
        return try {
            val privBytes = Base64.decode(privateKey, Base64.NO_WRAP)
            val pubBytes = Curve25519.scalarMultBase(privBytes)
            Base64.encodeToString(pubBytes, Base64.NO_WRAP)
        } catch (_: Exception) {
            ""
        }
    }

    fun decodePrivateKey(): ByteArray {
        return Base64.decode(privateKey, Base64.NO_WRAP)
    }

    fun decodeServerPublicKey(): ByteArray {
        return Base64.decode(serverPublicKey, Base64.NO_WRAP)
    }

    /** Return private key as base64 string for Config.Builder.parsePrivateKey() */
    fun decodePrivateKeyBase64(): String = privateKey

    /** Return server public key as base64 string for Config.Builder.parsePublicKey() */
    fun decodeServerPublicKeyBase64(): String = serverPublicKey

    companion object {
        const val DEFAULT_SERVER_PUBKEY = "LD7xNAw6Sn7Q0dIhJ211y24Il/oTeCXgGyEaOGIwZSE="
    }
}

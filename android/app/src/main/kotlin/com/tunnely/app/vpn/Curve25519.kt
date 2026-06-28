package com.tunnely.app.vpn

import android.util.Base64
import java.security.SecureRandom

/**
 * Curve25519 scalar-basepoint multiplication (RFC 7748).
 * Used for WireGuard public key derivation from private key.
 * Uses Java's built-in BigInteger for field arithmetic.
 * (Copied from netprobe AnalysisVpnService — proven working)
 */
object Curve25519 {

    private val P = java.math.BigInteger(
        "57896044618658097711785492504343953926634992332820282019728792003956564819949",
    )
    private val A24 = java.math.BigInteger("121666")
    private val BASE = java.math.BigInteger("9")

    data class KeyPair(
        val privateKey: ByteArray,
        val publicKey: ByteArray
    ) {
        val privateKeyBase64: String
            get() = Base64.encodeToString(privateKey, Base64.NO_WRAP)
        val publicKeyBase64: String
            get() = Base64.encodeToString(publicKey, Base64.NO_WRAP)
    }

    fun generateKeyPair(): KeyPair {
        val privateKey = ByteArray(32)
        SecureRandom().nextBytes(privateKey)
        // Clamp per Curve25519 / WireGuard spec
        privateKey[0] = (privateKey[0].toInt() and 248).toByte()
        privateKey[31] = (privateKey[31].toInt() and 127).toByte()
        privateKey[31] = (privateKey[31].toInt() or 64).toByte()

        val publicKey = scalarMultBase(privateKey)
        return KeyPair(privateKey, publicKey)
    }

    fun scalarMultBase(scalar: ByteArray): ByteArray {
        // Clamp the scalar per RFC 7748
        val clamped = scalar.clone()
        clamped[0] = (clamped[0].toInt() and 248).toByte()
        clamped[31] = (clamped[31].toInt() and 127).toByte()
        clamped[31] = (clamped[31].toInt() or 64).toByte()

        val s = bytesToLittleEndian(clamped)
        var x1 = BASE
        var x2 = java.math.BigInteger.ONE
        var z2 = java.math.BigInteger.ZERO
        var x3 = BASE
        var z3 = java.math.BigInteger.ONE
        var swap = 0

        for (t in 254 downTo 0) {
            val kt = s.testBit(t)
            val b = if (kt) 1 else 0
            swap = swap xor b
            if (swap == 1) {
                val tx = x2; x2 = x3; x3 = tx
                val tz = z2; z2 = z3; z3 = tz
            }
            swap = b

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b2 = x2.subtract(z2).mod(P)
            val bb = b2.multiply(b2).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b2).mod(P)
            x3 = da.add(cb).mod(P)
            x3 = x3.multiply(x3).mod(P)
            z3 = da.subtract(cb).mod(P)
            z3 = z3.multiply(z3).mod(P)
            z3 = z3.multiply(x1).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e).mod(P)).mod(P)).mod(P)
        }

        if (swap == 1) {
            val tx = x2; x2 = x3; x3 = tx
            val tz = z2; z2 = z3; z3 = tz
        }

        val invZ = z2.modPow(P.subtract(java.math.BigInteger("2")), P)
        val result = x2.multiply(invZ).mod(P)
        return littleEndianToBytes(result, 32)
    }

    private fun bytesToLittleEndian(bytes: ByteArray): java.math.BigInteger {
        var result = java.math.BigInteger.ZERO
        for (i in bytes.indices) {
            result = result.or(
                java.math.BigInteger.valueOf((bytes[i].toLong() and 0xFF)).shiftLeft(i * 8),
            )
        }
        return result
    }

    private fun littleEndianToBytes(value: java.math.BigInteger, length: Int): ByteArray {
        val result = ByteArray(length)
        var v = value
        for (i in 0 until length) {
            result[i] = (v.and(java.math.BigInteger.valueOf(0xFF))).toByte()
            v = v.shiftRight(8)
        }
        return result
    }
}

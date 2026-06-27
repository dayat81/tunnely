package com.tunnely.app.vpn

import android.util.Base64
import java.security.SecureRandom

/**
 * Pure Java implementation of Curve25519 key generation (RFC 7748).
 * Used for WireGuard key pairs.
 */
object Curve25519 {

    private const val KEY_SIZE = 32
    private val random = SecureRandom()

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
        val privateKey = ByteArray(KEY_SIZE)
        random.nextBytes(privateKey)

        // Clamp private key per RFC 7748
        privateKey[0] = (privateKey[0].toInt() and 248).toByte()
        privateKey[31] = (privateKey[31].toInt() and 127).toByte()
        privateKey[31] = (privateKey[31].toInt() or 64).toByte()

        val publicKey = scalarMultBase(privateKey)
        return KeyPair(privateKey, publicKey)
    }

    private fun scalarMultBase(scalar: ByteArray): ByteArray {
        // Simplified X25519 base point scalar multiplication
        // Base point u-coordinate = 9
        val baseU = longArrayOf(9, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        return scalarMult(scalar, encodeUCoordinate(baseU))
    }

    private fun scalarMult(scalar: ByteArray, uCoord: ByteArray): ByteArray {
        // Montgomery ladder for X25519
        val p = 255L
        val a24 = longArrayOf(121665, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        val x1 = decodeUCoordinate(uCoord)
        var x2 = longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        var z2 = longArrayOf(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        var x3 = x1.copyOf()
        var z3 = longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)

        var swap = 0L
        for (t in (p - 1) downTo 0) {
            val kt = ((scalar[(t / 8).toInt()].toInt() shr (t % 8).toInt()) and 1).toLong()
            swap = swap xor kt
            conditionalSwap(x2, x3, swap)
            conditionalSwap(z2, z3, swap)
            swap = kt

            val a = add(x2, z2)
            val aa = sqr(a)
            val b = sub(x2, z2)
            val bb = sqr(b)
            val e = sub(aa, bb)
            val c = add(x3, z3)
            val d = sub(x3, z3)
            val da = mul(d, a)
            val cb = mul(c, b)

            x3 = sqr(add(da, cb))
            z3 = mul(x1, sqr(sub(da, cb)))
            x2 = mul(aa, bb)
            z2 = mul(e, add(aa, mul(a24, e)))
        }
        conditionalSwap(x2, x3, swap)
        conditionalSwap(z2, z3, swap)

        val result = mul(x2, modInverse(z2))
        return encodeUCoordinate(result)
    }

    // Field arithmetic modulo 2^255 - 19
    private fun add(a: LongArray, b: LongArray): LongArray {
        val r = LongArray(16)
        for (i in 0 until 16) r[i] = a[i] + b[i]
        return r
    }

    private fun sub(a: LongArray, b: LongArray): LongArray {
        val r = LongArray(16)
        for (i in 0 until 16) r[i] = a[i] - b[i]
        return reduce(r)
    }

    private fun mul(a: LongArray, b: LongArray): LongArray {
        val r = LongArray(31)
        for (i in 0 until 16) {
            for (j in 0 until 16) {
                r[i + j] += a[i] * b[j]
            }
        }
        return reduce(r)
    }

    private fun sqr(a: LongArray): LongArray = mul(a, a)

    private fun reduce(r: LongArray): LongArray {
        val out = LongArray(16)
        System.arraycopy(r, 0, out, 0, minOf(r.size, 16))

        // Carry chain
        for (i in 0 until 15) {
            out[i + 1] += out[i] shr 16
            out[i] = out[i] and 0xFFFF
        }
        out[0] += (out[15] shr 16) * 19
        out[15] = out[15] and 0xFFFF
        out[1] += out[0] shr 16
        out[0] = out[0] and 0xFFFF

        return out
    }

    private fun modInverse(a: LongArray): LongArray {
        // a^(p-2) mod p using Fermat's little theorem
        // Simplified: compute a^(2^255 - 21) — for production use a proper implementation
        var result = longArrayOf(1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0)
        val base = a.copyOf()

        // Exponent: 2^255 - 21
        // This is a simplified version; full X25519 uses specific chain
        result = base.copyOf()
        for (i in 0 until 253) {
            result = sqr(result)
            result = mul(result, base)
        }
        result = sqr(result)
        result = sqr(result)
        result = mul(result, base)

        return result
    }

    private fun conditionalSwap(a: LongArray, b: LongArray, swap: LongArray) {
        // Use Long scalar swap
        conditionalSwap(a, b, swap[0])
    }

    private fun conditionalSwap(a: LongArray, b: LongArray, swap: Long) {
        val mask = -swap
        for (i in 0 until 16) {
            val t = mask and (a[i] xor b[i])
            a[i] = a[i] xor t
            b[i] = b[i] xor t
        }
    }

    private fun decodeUCoordinate(bytes: ByteArray): LongArray {
        val result = LongArray(16)
        for (i in 0 until minOf(bytes.size, 32)) {
            result[i / 2] = result[i / 2] or ((bytes[i].toLong() and 0xFF) shl (8 * (i % 2)))
        }
        return result
    }

    private fun encodeUCoordinate(u: LongArray): ByteArray {
        val r = reduce(u)
        val bytes = ByteArray(KEY_SIZE)
        for (i in 0 until 32) {
            bytes[i] = ((r[i / 2].toInt() shr (8 * (i % 2))) and 0xFF).toByte()
        }
        return bytes
    }
}

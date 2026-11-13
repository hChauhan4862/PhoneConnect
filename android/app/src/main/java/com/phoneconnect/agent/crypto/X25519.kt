package com.phoneconnect.agent.crypto

import java.math.BigInteger

/**
 * X25519 (RFC 7748) scalar multiplication.
 *
 * The agent needs exactly one operation — `X25519(static_secret, pinned_public)` — to agree
 * on session keys with the hub, so this is the Montgomery ladder over GF(2^255-19) written
 * against the RFC's definition. It uses [BigInteger] on purpose: one agreement per session
 * costs microseconds either way, and the short, obviously-correct form is worth more than a
 * limb implementation nobody on this team can audit.
 *
 * Verified against the RFC 7748 §6.1 vectors and against public keys produced by the Rust
 * `x25519-dalek` build in `crates/transport`.
 */
object X25519 {
    const val KEY_SIZE: Int = 32

    private val P: BigInteger = BigInteger.ONE.shiftLeft(255).subtract(BigInteger.valueOf(19))
    private val A24: BigInteger = BigInteger.valueOf(121_665)
    private val ZERO: BigInteger = BigInteger.ZERO
    private val ONE: BigInteger = BigInteger.ONE

    /** The public key for [secret]: `X25519(secret, 9)`. */
    fun publicKey(secret: ByteArray): ByteArray = scalarMultiply(secret, byteArrayOf(9) + ByteArray(31))

    /**
     * `X25519(scalar, u)`. [scalar] is clamped as the RFC requires, [u] has its top bit
     * masked, and the result is 32 little-endian bytes.
     */
    fun scalarMultiply(scalar: ByteArray, u: ByteArray): ByteArray {
        require(scalar.size == KEY_SIZE) { "X25519 scalar must be $KEY_SIZE bytes, was ${scalar.size}" }
        require(u.size == KEY_SIZE) { "X25519 coordinate must be $KEY_SIZE bytes, was ${u.size}" }

        val k = decodeScalar(scalar)
        val x1 = decodeCoordinate(u)
        var x2 = ONE
        var z2 = ZERO
        var x3 = x1
        var z3 = ONE
        var swap = 0

        for (bit in 254 downTo 0) {
            val current = k.shiftRight(bit).and(ONE).toInt()
            swap = swap xor current
            if (swap == 1) {
                val x = x2; x2 = x3; x3 = x
                val z = z2; z2 = z3; z3 = z
            }
            swap = current

            val a = x2.add(z2).mod(P)
            val aa = a.multiply(a).mod(P)
            val b = x2.subtract(z2).mod(P)
            val bb = b.multiply(b).mod(P)
            val e = aa.subtract(bb).mod(P)
            val c = x3.add(z3).mod(P)
            val d = x3.subtract(z3).mod(P)
            val da = d.multiply(a).mod(P)
            val cb = c.multiply(b).mod(P)

            val daPlusCb = da.add(cb).mod(P)
            x3 = daPlusCb.multiply(daPlusCb).mod(P)
            val daMinusCb = da.subtract(cb).mod(P)
            z3 = x1.multiply(daMinusCb.multiply(daMinusCb).mod(P)).mod(P)
            x2 = aa.multiply(bb).mod(P)
            z2 = e.multiply(aa.add(A24.multiply(e)).mod(P)).mod(P)
        }

        if (swap == 1) {
            val x = x2; x2 = x3; x3 = x
            val z = z2; z2 = z3; z3 = z
        }

        // x2 * z2^(p-2), i.e. the affine x-coordinate; z2 == 0 yields the all-zero point.
        val inverse = z2.modPow(P.subtract(BigInteger.valueOf(2)), P)
        return encodeLittleEndian(x2.multiply(inverse).mod(P))
    }

    /** True when the agreed secret is the degenerate point both peers must refuse. */
    fun isWeak(shared: ByteArray): Boolean = shared.all { it == 0.toByte() }

    private fun decodeScalar(scalar: ByteArray): BigInteger {
        val clamped = scalar.copyOf()
        clamped[0] = (clamped[0].toInt() and 248).toByte()
        clamped[31] = (clamped[31].toInt() and 127 or 64).toByte()
        return fromLittleEndian(clamped)
    }

    private fun decodeCoordinate(coordinate: ByteArray): BigInteger {
        val masked = coordinate.copyOf()
        masked[31] = (masked[31].toInt() and 127).toByte()
        return fromLittleEndian(masked).mod(P)
    }

    private fun fromLittleEndian(bytes: ByteArray): BigInteger {
        val bigEndian = ByteArray(bytes.size)
        for (index in bytes.indices) {
            bigEndian[index] = bytes[bytes.size - 1 - index]
        }
        return BigInteger(1, bigEndian)
    }

    private fun encodeLittleEndian(value: BigInteger): ByteArray {
        val bigEndian = value.mod(P).toByteArray()
        val unsigned = if (bigEndian.size > KEY_SIZE) bigEndian.copyOfRange(bigEndian.size - KEY_SIZE, bigEndian.size) else bigEndian
        val output = ByteArray(KEY_SIZE)
        for (index in unsigned.indices) {
            output[index] = unsigned[unsigned.size - 1 - index]
        }
        return output
    }
}

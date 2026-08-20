package xyz.heavenlydev.p256account.crypto

import java.math.BigInteger

/** A P-256 public key as the on-chain owner representation `(x, y)`. */
data class PublicKeyP256(val x: BigInteger, val y: BigInteger) {
    init {
        require(x.signum() > 0 && x < P256.P) { "x out of field range (0, p)" }
        require(y.signum() > 0 && y < P256.P) { "y out of field range (0, p)" }
        require(P256.isOnCurve(x, y)) { "public key is not on the P-256 curve — would brick the account" }
    }
}

/**
 * P-256 / secp256r1 domain parameters plus the two transforms the SDK needs:
 * DER → raw `r‖s`, and strict low-S normalisation. The contract mandates
 * `s ∈ (0, n/2]` (see sdk/SPEC.md); hardware signers do not normalise, so we do.
 */
object P256 {
    /** Field prime p. */
    @JvmField
    val P = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF", 16)
    /** Group order n. */
    @JvmField
    val N = BigInteger("FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 16)
    /** floor(n/2): strict low-S boundary. */
    @JvmField
    val HALF_N = N.shiftRight(1)
    private val A = BigInteger("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC", 16) // -3 mod p
    private val B = BigInteger("5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B", 16)

    @JvmStatic
    fun isOnCurve(x: BigInteger, y: BigInteger): Boolean {
        // y^2 ≡ x^3 + a·x + b (mod p)
        val lhs = y.modPow(BigInteger.TWO, P)
        val rhs = x.modPow(BigInteger.valueOf(3), P).add(A.multiply(x)).add(B).mod(P)
        return lhs == rhs
    }

    /**
     * Convert a DER `SEQUENCE { INTEGER r, INTEGER s }` (what Android's
     * `SHA256withECDSA` emits) into a canonical 64-byte `r‖s` with low-S applied.
     */
    @JvmStatic
    fun derToRawLowS(der: ByteArray): ByteArray {
        val (r, sRaw) = decodeDer(der)
        require(r.signum() > 0 && r < N) { "r out of range (0, n)" }
        require(sRaw.signum() > 0 && sRaw < N) { "s out of range (0, n)" }
        val s = if (sRaw > HALF_N) N.subtract(sRaw) else sRaw
        val out = ByteArray(64)
        Numeric.toUint256(r).copyInto(out, 0)
        Numeric.toUint256(s).copyInto(out, 32)
        return out
    }

    /** Minimal ASN.1 DER decoder for an ECDSA signature. */
    private fun decodeDer(der: ByteArray): Pair<BigInteger, BigInteger> {
        var i = 0
        require(der[i++].toInt() and 0xff == 0x30) { "expected DER SEQUENCE" }
        // SEQUENCE length (short or long form); value not needed beyond bounds.
        i = skipLength(der, i)
        require(der[i++].toInt() and 0xff == 0x02) { "expected INTEGER r" }
        val rLen = der[i++].toInt() and 0xff
        val r = BigInteger(1, der.copyOfRange(i, i + rLen)); i += rLen
        require(der[i++].toInt() and 0xff == 0x02) { "expected INTEGER s" }
        val sLen = der[i++].toInt() and 0xff
        val s = BigInteger(1, der.copyOfRange(i, i + sLen))
        return r to s
    }

    private fun skipLength(der: ByteArray, start: Int): Int {
        var i = start
        val first = der[i++].toInt() and 0xff
        if (first and 0x80 != 0) i += (first and 0x7f) // long form: skip length-of-length bytes
        return i
    }
}

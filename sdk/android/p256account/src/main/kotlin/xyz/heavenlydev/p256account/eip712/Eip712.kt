package xyz.heavenlydev.p256account.eip712

import xyz.heavenlydev.p256account.crypto.Keccak256
import xyz.heavenlydev.p256account.crypto.Numeric
import java.math.BigInteger

/**
 * EIP-712 digest construction matching `P256Account` exactly. The typehash
 * constants below were verified against the contract (see sdk/SPEC.md §2) — do
 * not edit without re-deriving from the contract.
 */
object Eip712 {
    private val DOMAIN_TYPEHASH =
        Numeric.hexToBytes("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f")
    private val NAME_HASH =
        Numeric.hexToBytes("0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d")
    private val VERSION_HASH =
        Numeric.hexToBytes("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6")
    private val EXECUTE_TYPEHASH =
        Numeric.hexToBytes("5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c")
    private val ROTATE_TYPEHASH =
        Numeric.hexToBytes("8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a")

    fun domainSeparator(chainId: Long, account: String): ByteArray =
        Keccak256.digest(
            concat(
                DOMAIN_TYPEHASH,
                NAME_HASH,
                VERSION_HASH,
                Numeric.toUint256(BigInteger.valueOf(chainId)),
                Numeric.addressWord(account),
            )
        )

    /** Digest for `execute(to, value, data, nonce)`. */
    fun executeDigest(
        chainId: Long,
        account: String,
        to: String,
        value: BigInteger,
        data: ByteArray,
        nonce: BigInteger,
    ): ByteArray {
        val structHash = Keccak256.digest(
            concat(
                EXECUTE_TYPEHASH,
                Numeric.addressWord(to),
                Numeric.toUint256(value),
                Keccak256.digest(data),
                Numeric.toUint256(nonce),
            )
        )
        return envelope(chainId, account, structHash)
    }

    /** Digest for `rotateOwner(newX, newY, nonce)`. */
    fun rotateDigest(
        chainId: Long,
        account: String,
        newX: BigInteger,
        newY: BigInteger,
        nonce: BigInteger,
    ): ByteArray {
        val structHash = Keccak256.digest(
            concat(
                ROTATE_TYPEHASH,
                Numeric.toUint256(newX),
                Numeric.toUint256(newY),
                Numeric.toUint256(nonce),
            )
        )
        return envelope(chainId, account, structHash)
    }

    private fun envelope(chainId: Long, account: String, structHash: ByteArray): ByteArray {
        val sep = domainSeparator(chainId, account)
        val buf = ByteArray(2 + 32 + 32)
        buf[0] = 0x19
        buf[1] = 0x01
        sep.copyInto(buf, 2)
        structHash.copyInto(buf, 34)
        return Keccak256.digest(buf)
    }

    private fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArray(parts.sumOf { it.size })
        var off = 0
        for (p in parts) { p.copyInto(out, off); off += p.size }
        return out
    }
}

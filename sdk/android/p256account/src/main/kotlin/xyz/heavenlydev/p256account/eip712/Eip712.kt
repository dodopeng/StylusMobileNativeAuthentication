package xyz.heavenlydev.p256account.eip712

import xyz.heavenlydev.p256account.account.Call
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

    @JvmStatic
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
    @JvmStatic
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

    /** keccak256("BatchExecute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)") */
    private val BATCH_TYPEHASH =
        Numeric.hexToBytes("e4c4e9c11a8826c10f239085bcd6b1f837ac8891ef69510451fb4e86df1ff4fb")

    /** keccak256("PersonalSign(bytes32 hash)") — the EIP-1271 challenge wrapper. */
    private val PERSONAL_SIGN_TYPEHASH =
        Numeric.hexToBytes("2431bd832cbb131f8882ef79f68ed6ae065cca9270f5bce0f2e4f75a9cd814b7")

    /** keccak256("Call(address to,uint256 value,bytes data)") */
    private val CALL_TYPEHASH =
        Numeric.hexToBytes("9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483")

    /**
     * Digest for `executeBatch` — one signature authorising an ordered list of
     * calls under a single nonce. Order is part of the hash, so a relayer
     * cannot reorder a signed batch.
     */
    @JvmStatic
    fun batchDigest(
        chainId: Long,
        account: String,
        calls: List<Call>,
        nonce: BigInteger,
    ): ByteArray {
        val concatenated = java.io.ByteArrayOutputStream()
        for (call in calls) {
            val callHash = Keccak256.digest(
                CALL_TYPEHASH +
                    Numeric.addressWord(call.to) +
                    Numeric.toUint256(call.value) +
                    Keccak256.digest(call.data),
            )
            concatenated.write(callHash)
        }
        val callsHash = Keccak256.digest(concatenated.toByteArray())
        val structHash = Keccak256.digest(
            BATCH_TYPEHASH + callsHash + Numeric.toUint256(nonce),
        )
        return envelope(chainId, account, structHash)
    }

    /**
     * Digest for an EIP-1271 challenge: `PersonalSign(bytes32 hash)`.
     *
     * The 1271 path MUST NOT sign the raw hash. An `Execute` digest is itself a
     * 32-byte hash an attacker can compute from public inputs; presented as a
     * "login challenge" and signed raw, the result is a valid transfer
     * authorisation. Wrapping puts the two in disjoint typed domains.
     */
    @JvmStatic
    fun personalSignDigest(chainId: Long, account: String, hash: ByteArray): ByteArray {
        require(hash.size == 32) { "EIP-1271 hash must be exactly 32 bytes, got ${hash.size}" }
        val structHash = Keccak256.digest(PERSONAL_SIGN_TYPEHASH + hash)
        return envelope(chainId, account, structHash)
    }

    /** Digest for `rotateOwner(newX, newY, nonce)`. */
    @JvmStatic
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

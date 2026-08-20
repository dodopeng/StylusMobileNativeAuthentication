package xyz.heavenlydev.p256account.abi

import xyz.heavenlydev.p256account.crypto.Keccak256
import xyz.heavenlydev.p256account.crypto.Numeric
import java.math.BigInteger

/** A single ABI argument. Enough types to encode every call this SDK makes. */
sealed interface AbiValue {
    data class Address(val value: String) : AbiValue
    data class Uint(val value: BigInteger) : AbiValue
    data class DynBytes(val value: ByteArray) : AbiValue
    /** Fixed `address[]` for swap paths etc. */
    data class AddressArray(val values: List<String>) : AbiValue
    /** `bool`, encoded as a right-aligned 0/1 word (ERC-721 `setApprovalForAll`). */
    data class Bool(val value: Boolean) : AbiValue
    /** `uint256[]` — batch call values. */
    data class UintArray(val values: List<BigInteger>) : AbiValue
    /** `bytes[]` — batch calldata. Doubly dynamic: an offset table into
     *  individually length-prefixed, right-padded elements. */
    data class BytesArray(val values: List<ByteArray>) : AbiValue
}

/**
 * Minimal Solidity ABI encoder (head/tail layout) and 4-byte selectors. Covers
 * static `address`/`uint256` and dynamic `bytes`/`address[]`, which is all the
 * P256Account methods and action templates need.
 */
object Abi {
    /** `bytes4(keccak256(signature))`, e.g. `selector("transfer(address,uint256)")`. */
    @JvmStatic
    fun selector(signature: String): ByteArray =
        Keccak256.digest(signature.toByteArray(Charsets.US_ASCII)).copyOfRange(0, 4)

    @JvmStatic
    fun encodeWithSelector(signature: String, args: List<AbiValue>): ByteArray =
        encode(selector(signature), args)

    @JvmStatic
    fun encode(selector: ByteArray, args: List<AbiValue>): ByteArray {
        val head = ArrayList<ByteArray>(args.size)
        val tail = ArrayList<ByteArray>()
        val headSize = args.size * 32
        var tailOffset = headSize

        for (arg in args) {
            when (arg) {
                is AbiValue.Address -> head.add(Numeric.addressWord(arg.value))
                is AbiValue.Uint -> head.add(Numeric.toUint256(arg.value))
                is AbiValue.Bool -> head.add(
                    Numeric.toUint256(if (arg.value) BigInteger.ONE else BigInteger.ZERO),
                )
                is AbiValue.DynBytes -> {
                    head.add(Numeric.toUint256(BigInteger.valueOf(tailOffset.toLong())))
                    val enc = encodeDynBytes(arg.value)
                    tail.add(enc); tailOffset += enc.size
                }
                is AbiValue.AddressArray -> {
                    head.add(Numeric.toUint256(BigInteger.valueOf(tailOffset.toLong())))
                    val enc = encodeAddressArray(arg.values)
                    tail.add(enc); tailOffset += enc.size
                }
                is AbiValue.UintArray -> {
                    head.add(Numeric.toUint256(BigInteger.valueOf(tailOffset.toLong())))
                    val enc = encodeUintArray(arg.values)
                    tail.add(enc); tailOffset += enc.size
                }
                is AbiValue.BytesArray -> {
                    head.add(Numeric.toUint256(BigInteger.valueOf(tailOffset.toLong())))
                    val enc = encodeBytesArray(arg.values)
                    tail.add(enc); tailOffset += enc.size
                }
            }
        }

        val total = ByteArray(4 + headSize + tail.sumOf { it.size })
        selector.copyInto(total, 0)
        var off = 4
        for (h in head) { h.copyInto(total, off); off += 32 }
        for (t in tail) { t.copyInto(total, off); off += t.size }
        return total
    }

    private fun encodeDynBytes(value: ByteArray): ByteArray {
        val padded = ((value.size + 31) / 32) * 32
        val out = ByteArray(32 + padded)
        Numeric.toUint256(BigInteger.valueOf(value.size.toLong())).copyInto(out, 0)
        value.copyInto(out, 32)
        return out
    }

    private fun encodeUintArray(values: List<BigInteger>): ByteArray {
        val out = ByteArray(32 + values.size * 32)
        Numeric.toUint256(BigInteger.valueOf(values.size.toLong())).copyInto(out, 0)
        var off = 32
        for (v in values) { Numeric.toUint256(v).copyInto(out, off); off += 32 }
        return out
    }

    /**
     * `bytes[]`: count, then a word-offset per element (relative to the start of
     * the offset table), then each element length-prefixed and right-padded.
     */
    private fun encodeBytesArray(values: List<ByteArray>): ByteArray {
        val bodies = values.map { encodeDynBytes(it) }
        val offsetTable = values.size * 32
        val out = java.io.ByteArrayOutputStream()
        out.write(Numeric.toUint256(BigInteger.valueOf(values.size.toLong())))
        var cursor = offsetTable
        for (b in bodies) {
            out.write(Numeric.toUint256(BigInteger.valueOf(cursor.toLong())))
            cursor += b.size
        }
        for (b in bodies) out.write(b)
        return out.toByteArray()
    }

    private fun encodeAddressArray(values: List<String>): ByteArray {
        val out = ByteArray(32 + values.size * 32)
        Numeric.toUint256(BigInteger.valueOf(values.size.toLong())).copyInto(out, 0)
        var off = 32
        for (a in values) { Numeric.addressWord(a).copyInto(out, off); off += 32 }
        return out
    }
}

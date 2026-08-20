package xyz.heavenlydev.p256account.crypto

import java.math.BigInteger

/** Hex / 32-byte word helpers shared by the ABI encoder and EIP-712 hashing. */
object Numeric {
    @JvmStatic
    fun hexToBytes(hex: String): ByteArray {
        val s = hex.removePrefix("0x").removePrefix("0X")
        val clean = if (s.length % 2 == 1) "0$s" else s
        val out = ByteArray(clean.length / 2)
        for (i in out.indices) {
            out[i] = ((hexDigit(clean[i * 2]) shl 4) or hexDigit(clean[i * 2 + 1])).toByte()
        }
        return out
    }

    @JvmStatic
    @JvmOverloads
    fun bytesToHex(bytes: ByteArray, prefix: Boolean = true): String {
        val sb = StringBuilder(bytes.size * 2 + 2)
        if (prefix) sb.append("0x")
        for (b in bytes) {
            sb.append(HEX[(b.toInt() ushr 4) and 0xf])
            sb.append(HEX[b.toInt() and 0xf])
        }
        return sb.toString()
    }

    /** Left-pad an unsigned big-endian value to a 32-byte EVM word. */
    @JvmStatic
    fun toUint256(value: BigInteger): ByteArray {
        require(value.signum() >= 0) { "uint256 must be non-negative" }
        val raw = value.toByteArray() // may have a leading 0x00 sign byte
        val trimmed = if (raw.size > 1 && raw[0].toInt() == 0) raw.copyOfRange(1, raw.size) else raw
        require(trimmed.size <= 32) { "value exceeds uint256" }
        val out = ByteArray(32)
        trimmed.copyInto(out, 32 - trimmed.size)
        return out
    }

    /** Encode an address as a left-padded 32-byte word. */
    @JvmStatic
    fun addressWord(address: String): ByteArray {
        val bytes = hexToBytes(address)
        require(bytes.size == 20) { "address must be 20 bytes: $address" }
        val out = ByteArray(32)
        bytes.copyInto(out, 12)
        return out
    }

    @JvmStatic
    fun toBigInteger(word: ByteArray): BigInteger = BigInteger(1, word)

    private val HEX = "0123456789abcdef".toCharArray()
    private fun hexDigit(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("bad hex char: $c")
    }
}

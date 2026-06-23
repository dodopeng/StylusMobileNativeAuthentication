package xyz.heavenlydev.p256account.crypto

/**
 * Keccak-256 (the Ethereum variant: 0x01 domain padding, 136-byte rate) in pure
 * Kotlin so the SDK has no native-crypto or BouncyCastle dependency for hashing.
 *
 * This is a faithful port of the reference implementation that was verified
 * byte-for-byte against `cast keccak` for the empty string, "abc", and the
 * contract's EIP-712 type strings. See sdk/SPEC.md.
 */
object Keccak256 {
    private val RHO = intArrayOf(
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44
    )
    private val PI = intArrayOf(
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1
    )
    private val RC = longArrayOf(
        0x0000000000000001uL.toLong(), 0x0000000000008082uL.toLong(),
        0x800000000000808auL.toLong(), 0x8000000080008000uL.toLong(),
        0x000000000000808buL.toLong(), 0x0000000080000001uL.toLong(),
        0x8000000080008081uL.toLong(), 0x8000000000008009uL.toLong(),
        0x000000000000008auL.toLong(), 0x0000000000000088uL.toLong(),
        0x0000000080008009uL.toLong(), 0x000000008000000auL.toLong(),
        0x000000008000808buL.toLong(), 0x800000000000008buL.toLong(),
        0x8000000000008089uL.toLong(), 0x8000000000008003uL.toLong(),
        0x8000000000008002uL.toLong(), 0x8000000000000080uL.toLong(),
        0x000000000000800auL.toLong(), 0x800000008000000auL.toLong(),
        0x8000000080008081uL.toLong(), 0x8000000000008080uL.toLong(),
        0x0000000080000001uL.toLong(), 0x8000000080008008uL.toLong()
    )
    private const val RATE = 136 // bytes (1088 bits)

    fun digest(input: ByteArray): ByteArray {
        val state = LongArray(25)
        // pad10*1 with Keccak's 0x01 first byte (not SHA3's 0x06)
        val padLen = RATE - (input.size % RATE)
        val padded = ByteArray(input.size + padLen)
        input.copyInto(padded)
        padded[input.size] = 0x01
        padded[padded.size - 1] = (padded[padded.size - 1].toInt() or 0x80).toByte()

        var off = 0
        while (off < padded.size) {
            for (i in 0 until RATE / 8) {
                state[i] = state[i] xor leLong(padded, off + i * 8)
            }
            keccakF(state)
            off += RATE
        }

        val out = ByteArray(32)
        for (i in 0 until 4) leBytes(state[i], out, i * 8)
        return out
    }

    private fun keccakF(a: LongArray) {
        val c = LongArray(5)
        val d = LongArray(5)
        for (round in 0 until 24) {
            for (x in 0 until 5) c[x] = a[x] xor a[x + 5] xor a[x + 10] xor a[x + 15] xor a[x + 20]
            for (x in 0 until 5) d[x] = c[(x + 4) % 5] xor java.lang.Long.rotateLeft(c[(x + 1) % 5], 1)
            for (x in 0 until 5) {
                var y = 0
                while (y < 25) {
                    a[x + y] = a[x + y] xor d[x]
                    y += 5
                }
            }
            // rho + pi
            var t = a[1]
            for (i in 0 until 24) {
                val j = PI[i]
                val tmp = a[j]
                a[j] = java.lang.Long.rotateLeft(t, RHO[i])
                t = tmp
            }
            // chi
            var y = 0
            while (y < 25) {
                val r0 = a[y]; val r1 = a[y + 1]; val r2 = a[y + 2]; val r3 = a[y + 3]; val r4 = a[y + 4]
                a[y] = r0 xor (r1.inv() and r2)
                a[y + 1] = r1 xor (r2.inv() and r3)
                a[y + 2] = r2 xor (r3.inv() and r4)
                a[y + 3] = r3 xor (r4.inv() and r0)
                a[y + 4] = r4 xor (r0.inv() and r1)
                y += 5
            }
            a[0] = a[0] xor RC[round]
        }
    }

    private fun leLong(b: ByteArray, off: Int): Long {
        var v = 0L
        for (i in 0 until 8) v = v or ((b[off + i].toLong() and 0xff) shl (8 * i))
        return v
    }

    private fun leBytes(v: Long, out: ByteArray, off: Int) {
        for (i in 0 until 8) out[off + i] = ((v ushr (8 * i)) and 0xff).toByte()
    }
}

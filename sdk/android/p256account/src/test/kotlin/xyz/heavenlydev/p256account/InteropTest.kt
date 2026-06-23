package xyz.heavenlydev.p256account

import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test
import xyz.heavenlydev.p256account.abi.Abi
import xyz.heavenlydev.p256account.account.ExecutedEvent
import xyz.heavenlydev.p256account.action.Erc20
import xyz.heavenlydev.p256account.crypto.Keccak256
import xyz.heavenlydev.p256account.crypto.Numeric
import xyz.heavenlydev.p256account.crypto.P256
import xyz.heavenlydev.p256account.eip712.Eip712
import java.math.BigInteger

/**
 * Pure-JVM interop tests (no Android). Golden values were computed with the
 * Keccak reference that was verified against `cast` and against the contract's
 * own EIP-712 type strings — so a regression here means the SDK would produce
 * signatures the on-chain `execute` rejects.
 */
class InteropTest {
    @Test fun keccakKnownVectors() {
        assertEquals(
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470",
            Numeric.bytesToHex(Keccak256.digest(ByteArray(0)), prefix = false),
        )
        assertEquals(
            "0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d",
            Numeric.bytesToHex(Keccak256.digest("P256Account".toByteArray()), prefix = false),
        )
    }

    @Test fun executeDigestMatchesContract() {
        val digest = Eip712.executeDigest(
            chainId = 42161,
            account = "0x1111111111111111111111111111111111111111",
            to = "0x2222222222222222222222222222222222222222",
            value = BigInteger.valueOf(1000),
            data = "hello".toByteArray(),
            nonce = BigInteger.ZERO,
        )
        assertEquals(
            "4e71705df943b3848269d8a661320fca963cd2392a7cc0ee2e9028ff7983f854",
            Numeric.bytesToHex(digest, prefix = false),
        )
    }

    @Test fun erc20TransferEncoding() {
        val call = Erc20.transfer(
            token = "0x000000000000000000000000000000000000dead",
            to = "0x2222222222222222222222222222222222222222",
            amount = BigInteger.valueOf(1_000_000),
        )
        assertEquals(
            "0xa9059cbb0000000000000000000000002222222222222222222222222222222222222222" +
                "00000000000000000000000000000000000000000000000000000000000f4240",
            Numeric.bytesToHex(call.data),
        )
        assertEquals("0x000000000000000000000000000000000000dead", call.to)
    }

    @Test fun selectorsMatchAbi() {
        assertEquals("0xd2c88a7c", Numeric.bytesToHex(Abi.selector("execute(address,uint256,bytes,uint256,bytes)")))
        assertEquals("0x82bed5b3", Numeric.bytesToHex(Abi.selector("rotateOwner(uint256,uint256,uint256,bytes)")))
        assertEquals("0xaffed0e0", Numeric.bytesToHex(Abi.selector("nonce()")))
    }

    @Test fun lowSNormalisationCanonicalises() {
        // A DER sig with s in the upper half must be flipped to n - s.
        val r = BigInteger.valueOf(0x1234)
        val highS = P256.N.subtract(BigInteger.valueOf(0x5678)) // > n/2
        val der = der(r, highS)
        val raw = P256.derToRawLowS(der)
        val s = Numeric.toBigInteger(raw.copyOfRange(32, 64))
        assertTrue("s must be low-S", s <= P256.HALF_N)
        assertEquals(BigInteger.valueOf(0x5678), s) // n - (n - 0x5678)
    }

    @Test fun executedDecodeSuccessWithReturnData() {
        // value‖nonce‖success(=1)‖offset(0x80)‖len(2)‖returnData(0xcafe padded)
        val data = ByteArray(192)
        data[95] = 1                 // success = true
        data[127] = 0x80.toByte()    // offset to returnData
        data[159] = 2                // returnData length
        data[160] = 0xca.toByte()
        data[161] = 0xfe.toByte()
        val r = ExecutedEvent.decodeData(data)
        assertTrue(r.success)
        assertEquals("0xcafe", Numeric.bytesToHex(r.returnData))
    }

    @Test fun executedDecodeRevertedInnerCall() {
        // The dangerous case: tx succeeds but the inner call reverted.
        val data = ByteArray(160) // success word all-zero, empty returnData
        val r = ExecutedEvent.decodeData(data)
        assertTrue(!r.success)
        assertEquals(0, r.returnData.size)
    }

    private fun der(r: BigInteger, s: BigInteger): ByteArray {
        fun int(v: BigInteger): ByteArray {
            var b = v.toByteArray() // already big-endian, with sign byte if high bit set
            return byteArrayOf(0x02, b.size.toByte()) + b
        }
        val body = int(r) + int(s)
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}

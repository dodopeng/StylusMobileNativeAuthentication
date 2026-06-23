package xyz.heavenlydev.p256account

import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertTrue
import org.junit.Test
import xyz.heavenlydev.p256account.crypto.P256
import xyz.heavenlydev.p256account.eip712.Eip712
import xyz.heavenlydev.p256account.keystore.SoftwareP256Signer
import java.math.BigInteger
import java.security.AlgorithmParameters
import java.security.KeyFactory
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import java.security.spec.ECParameterSpec
import java.security.spec.ECPoint
import java.security.spec.ECPublicKeySpec

/**
 * Proves the Android signing path on the JVM (no Android framework, no device):
 * [SoftwareP256Signer] uses the same `NONEwithECDSA` raw operation as the
 * hardware [xyz.heavenlydev.p256account.keystore.StrongBoxP256Signer], so a
 * signature it produces over an EIP-712 digest verifies over that digest
 * directly — exactly what the RIP-7212 precompile checks — and is low-S.
 *
 * This de-risks the Android algorithm; the only hardware-specific unknown that
 * remains is whether a given StrongBox/TEE supports `DIGEST_NONE` keys.
 */
class SoftwareSignerTest {

    @Test fun softwareSignerProducesContractValidLowSSignature() = runTest {
        val signer = SoftwareP256Signer()
        val pub = signer.publicKey()

        val digest = Eip712.executeDigest(
            chainId = 412346,
            account = "0x00000000000000000000000000000000000000aa",
            to = "0x1111111111111111111111111111111111111111",
            value = BigInteger.valueOf(1000),
            data = ByteArray(0),
            nonce = BigInteger.ZERO,
        )

        val sig = signer.sign(digest, null) // 64-byte r‖s
        assertTrue("signature must be 64 bytes", sig.size == 64)

        // low-S
        val s = BigInteger(1, sig.copyOfRange(32, 64))
        assertTrue("signature must be low-S", s <= P256.HALF_N)

        // Verify over the RAW digest (e = digest) with NONEwithECDSA — the same
        // semantics as RIP-7212. Reconstruct the EC public key from (x, y).
        val verifier = Signature.getInstance("NONEwithECDSA").apply {
            initVerify(ecPublicKey(pub.x, pub.y))
            update(digest)
        }
        assertTrue("raw-digest signature must verify", verifier.verify(rawToDer(sig)))
    }

    private fun ecPublicKey(x: BigInteger, y: BigInteger): ECPublicKey {
        val params = AlgorithmParameters.getInstance("EC").apply {
            init(ECGenParameterSpec("secp256r1"))
        }.getParameterSpec(ECParameterSpec::class.java)
        val spec = ECPublicKeySpec(ECPoint(x, y), params)
        return KeyFactory.getInstance("EC").generatePublic(spec) as ECPublicKey
    }

    /** 64-byte `r‖s` → DER `SEQUENCE { INTEGER r, INTEGER s }` for JCA verify. */
    private fun rawToDer(sig: ByteArray): ByteArray {
        fun der(int: BigInteger): ByteArray {
            val b = int.toByteArray() // already big-endian, with sign byte if needed
            return byteArrayOf(0x02, b.size.toByte()) + b
        }
        val r = der(BigInteger(1, sig.copyOfRange(0, 32)))
        val s = der(BigInteger(1, sig.copyOfRange(32, 64)))
        val body = r + s
        return byteArrayOf(0x30, body.size.toByte()) + body
    }
}

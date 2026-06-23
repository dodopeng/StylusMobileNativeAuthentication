package xyz.heavenlydev.p256account.keystore

import xyz.heavenlydev.p256account.account.BiometricAuth
import xyz.heavenlydev.p256account.account.SignProvider
import xyz.heavenlydev.p256account.crypto.P256
import xyz.heavenlydev.p256account.crypto.PublicKeyP256
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec

/**
 * **Testing / development only — NOT hardware-backed.**
 *
 * A drop-in [SignProvider] that behaves exactly like [StrongBoxP256Signer] but
 * with a *software* P-256 key (plain JCA, no Android Keystore, no biometric).
 * It uses the **identical** signing operation — `NONEwithECDSA`, which signs the
 * supplied 32-byte digest as the ECDSA message hash `e` directly — so signatures
 * are byte-compatible with the hardware signer and verify the same way on-chain
 * via RIP-7212.
 *
 * Use it to run the SDK on the emulator / in JVM unit tests (it depends only on
 * `java.security`, not the Android framework). Swap in [StrongBoxP256Signer] for
 * production. The key lives only in memory and is never persisted.
 */
class SoftwareP256Signer private constructor(private val keyPair: KeyPair) : SignProvider {

    constructor() : this(generate())

    override fun publicKey(): PublicKeyP256 {
        val ec = keyPair.public as ECPublicKey
        val w = ec.w
        return PublicKeyP256(w.affineX, w.affineY)
    }

    /** [auth] is ignored — this signer does not gate on biometrics. */
    override suspend fun sign(digest: ByteArray, auth: BiometricAuth?): ByteArray {
        require(digest.size == 32) { "digest must be 32 bytes" }
        val sig = Signature.getInstance("NONEwithECDSA").apply {
            initSign(keyPair.private)
            update(digest) // NONEwithECDSA: input is the ECDSA hash `e`, no SHA-256
        }
        return P256.derToRawLowS(sig.sign())
    }

    private companion object {
        fun generate(): KeyPair =
            KeyPairGenerator.getInstance("EC").apply {
                initialize(ECGenParameterSpec("secp256r1"))
            }.generateKeyPair()
    }
}

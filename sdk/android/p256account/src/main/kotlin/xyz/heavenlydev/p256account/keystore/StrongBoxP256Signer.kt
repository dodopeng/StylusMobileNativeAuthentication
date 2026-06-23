package xyz.heavenlydev.p256account.keystore

import android.os.Build
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import androidx.biometric.BiometricPrompt
import xyz.heavenlydev.p256account.account.BiometricAuth
import xyz.heavenlydev.p256account.account.SignProvider
import xyz.heavenlydev.p256account.crypto.P256
import xyz.heavenlydev.p256account.crypto.PublicKeyP256
import java.security.KeyPairGenerator
import java.security.KeyStore
import java.security.Signature
import java.security.interfaces.ECPublicKey
import java.security.spec.ECGenParameterSpec
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException
import kotlinx.coroutines.suspendCancellableCoroutine

/**
 * Hardware-backed P-256 signer using the Android Keystore. Keys are generated
 * non-exportable inside StrongBox (Titan-M / secure element) when available,
 * else the TEE, and every signature is gated behind a [BiometricPrompt].
 *
 * The private key never leaves hardware. We only ever read the public key
 * `(x, y)` out — which is what becomes the on-chain account owner.
 */
class StrongBoxP256Signer(
    private val alias: String,
    private val requireBiometric: Boolean = true,
) : SignProvider {

    private val keyStore: KeyStore = KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }

    fun exists(): Boolean = keyStore.containsAlias(alias)

    /**
     * Generate a new hardware key. Returns the public key to register on-chain
     * (constructor args, or a rotation target). [strongBox] requests the secure
     * element; if the device lacks one, callers should retry with `false`.
     */
    fun create(strongBox: Boolean = true): PublicKeyP256 {
        val purposes = KeyProperties.PURPOSE_SIGN
        val builder = KeyGenParameterSpec.Builder(alias, purposes)
            .setAlgorithmParameterSpec(ECGenParameterSpec("secp256r1"))
            // DIGEST_NONE → raw ECDSA over the 32-byte digest we supply. The
            // RIP-7212 precompile treats its input as the message hash `e`
            // directly, so the signer must NOT apply its own SHA-256.
            .setDigests(KeyProperties.DIGEST_NONE)
            .setUserAuthenticationRequired(requireBiometric)
        if (requireBiometric) {
            // Auth valid only for the single signing operation it gates. The
            // modern API is 30+; on 29 the equivalent is a validity duration of
            // -1, which means "authenticate for every use via a CryptoObject".
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
                builder.setUserAuthenticationParameters(0, KeyProperties.AUTH_BIOMETRIC_STRONG)
            } else {
                @Suppress("DEPRECATION")
                builder.setUserAuthenticationValidityDurationSeconds(-1)
            }
        }
        if (strongBox) builder.setIsStrongBoxBacked(true)

        val gen = KeyPairGenerator.getInstance(KeyProperties.KEY_ALGORITHM_EC, ANDROID_KEYSTORE)
        gen.initialize(builder.build())
        gen.generateKeyPair()
        return publicKey()
    }

    override fun publicKey(): PublicKeyP256 {
        val cert = keyStore.getCertificate(alias)
            ?: throw IllegalStateException("no key for alias '$alias'; call create() first")
        val ec = cert.publicKey as ECPublicKey
        val w = ec.w
        // affineX/affineY are non-negative BigIntegers — exactly the on-chain (x,y).
        return PublicKeyP256(w.affineX, w.affineY)
    }

    /**
     * Sign a 32-byte EIP-712 [digest] and return canonical 64-byte `r‖s`
     * (low-S applied).
     *
     * When [requireBiometric] is set, [auth] MUST be supplied: signing drives a
     * [BiometricPrompt] bound to the operation via [BiometricPrompt.CryptoObject],
     * so the key is only usable for this one digest after a successful biometric.
     *
     * Signed with NONEwithECDSA so the 32-byte [digest] is the ECDSA message
     * hash `e` verbatim — exactly what the RIP-7212 precompile verifies. We do
     * NOT pre-hash, and the key is DIGEST_NONE so the hardware does not either
     * (see sdk/SPEC.md §2).
     */
    override suspend fun sign(digest: ByteArray, auth: BiometricAuth?): ByteArray {
        require(digest.size == 32) { "digest must be 32 bytes" }
        val signature = newSignSession()

        if (!requireBiometric) {
            signature.update(digest)
            return P256.derToRawLowS(signature.sign())
        }

        val auth = requireNotNull(auth) {
            "this signer requires a biometric; pass BiometricAuth(activity, promptInfo) to execute()/rotateOwner()"
        }
        val authed = suspendCancellableCoroutine<Signature> { cont ->
            val executor = androidx.core.content.ContextCompat.getMainExecutor(auth.activity)
            val prompt = BiometricPrompt(auth.activity, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    val s = result.cryptoObject?.signature
                    if (s == null) cont.resumeWithException(IllegalStateException("no Signature in CryptoObject"))
                    else cont.resume(s)
                }
                override fun onAuthenticationError(code: Int, msg: CharSequence) {
                    cont.resumeWithException(BiometricSignException(code, msg.toString()))
                }
            })
            prompt.authenticate(auth.promptInfo, BiometricPrompt.CryptoObject(signature))
        }
        authed.update(digest)
        return P256.derToRawLowS(authed.sign())
    }

    private fun newSignSession(): Signature {
        val entry = keyStore.getEntry(alias, null) as? KeyStore.PrivateKeyEntry
            ?: throw IllegalStateException("no private key for alias '$alias'")
        // NONEwithECDSA: the bytes passed to update() are used as the ECDSA
        // message hash `e` directly (no SHA-256), matching the RIP-7212 input.
        return Signature.getInstance("NONEwithECDSA").apply { initSign(entry.privateKey) }
    }

    companion object {
        private const val ANDROID_KEYSTORE = "AndroidKeyStore"
    }
}

class BiometricSignException(val code: Int, message: String) : Exception(message)

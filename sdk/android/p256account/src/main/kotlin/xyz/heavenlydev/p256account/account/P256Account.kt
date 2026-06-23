package xyz.heavenlydev.p256account.account

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.delay
import xyz.heavenlydev.p256account.abi.Abi
import xyz.heavenlydev.p256account.abi.AbiValue
import xyz.heavenlydev.p256account.crypto.PublicKeyP256
import xyz.heavenlydev.p256account.eip712.Eip712
import xyz.heavenlydev.p256account.rpc.JsonRpcClient
import xyz.heavenlydev.p256account.rpc.RpcException
import xyz.heavenlydev.p256account.rpc.SignedAction
import xyz.heavenlydev.p256account.rpc.TransactionRelay
import java.math.BigInteger

/**
 * The biometric context needed to satisfy a hardware signature at call time:
 * the host activity to attach the prompt to, and the prompt copy. Mirrors the
 * `LAContext` the iOS SDK threads through `execute`. Pass `null` only for a
 * non-biometric signer (e.g. integration tests).
 */
class BiometricAuth(
    val activity: FragmentActivity,
    val promptInfo: BiometricPrompt.PromptInfo,
)

/** Produces a canonical 64-byte `r‖s` (low-S) signature over a 32-byte digest. */
interface SignProvider {
    fun publicKey(): PublicKeyP256
    /**
     * Sign [digest]. [auth] carries the biometric prompt context; a signer that
     * gates on biometrics requires it to be non-null, one that does not ignores it.
     */
    suspend fun sign(digest: ByteArray, auth: BiometricAuth?): ByteArray
}

/** An outbound call to perform via the account: `account.execute(to, value, data)`. */
data class Call(
    val to: String,
    val value: BigInteger = BigInteger.ZERO,
    val data: ByteArray = ByteArray(0),
)

/**
 * High-level handle to a deployed P256Account contract. Reads its state over
 * JSON-RPC, builds the EIP-712 digest, asks the hardware [signer] for a
 * signature, ABI-encodes the call, and hands it to the [relay] to broadcast.
 *
 * Deployment of the account contract itself is done out-of-band via
 * `cargo stylus deploy --constructor-args <x> <y>` (the public key comes from
 * [SignProvider.publicKey]); this class operates an already-deployed account.
 */
class P256Account(
    val address: String,
    private val rpc: JsonRpcClient,
    private val relay: TransactionRelay,
    private val signer: SignProvider,
    chainId: Long? = null,
) {
    private var cachedChainId: Long? = chainId

    suspend fun chainId(): Long = cachedChainId ?: rpc.chainId().also { cachedChainId = it }

    /**
     * Poll for the receipt of a relayed [txHash] and decode the account's
     * `Executed` event. A successful transaction with `result.success == false`
     * means the inner call reverted (nonce still consumed) — the bare tx hash
     * from [execute] does NOT prove the action worked, so call this to confirm.
     * Throws if the transaction itself reverted, has no `Executed` log, or the
     * receipt does not arrive within [attempts] × [delayMs].
     */
    suspend fun awaitExecuted(txHash: String, attempts: Int = 30, delayMs: Long = 1_000): ExecutionResult {
        repeat(attempts) {
            val receipt = rpc.getTransactionReceipt(txHash)
            if (receipt != null) {
                if (receipt.optString("status").equals("0x0", ignoreCase = true)) {
                    throw RpcException(-1, "transaction $txHash reverted (status 0x0)")
                }
                return ExecutedEvent.decode(receipt, address)
                    ?: throw RpcException(-1, "no Executed event from $address in receipt $txHash")
            }
            delay(delayMs)
        }
        throw RpcException(-1, "timed out waiting for receipt $txHash")
    }

    suspend fun nonce(): BigInteger = rpc.callUint(address, Abi.encodeWithSelector("nonce()", emptyList()))
    suspend fun ownerX(): BigInteger = rpc.callUint(address, Abi.encodeWithSelector("ownerX()", emptyList()))
    suspend fun ownerY(): BigInteger = rpc.callUint(address, Abi.encodeWithSelector("ownerY()", emptyList()))

    /** Sign and relay an `execute`. Returns the broadcast transaction hash. */
    suspend fun execute(call: Call, auth: BiometricAuth? = null): String {
        val chainId = chainId()
        val nonce = nonce()
        val digest = Eip712.executeDigest(chainId, address, call.to, call.value, call.data, nonce)
        val signature = signer.sign(digest, auth)
        val callData = Abi.encodeWithSelector(
            "execute(address,uint256,bytes,uint256,bytes)",
            listOf(
                AbiValue.Address(call.to),
                AbiValue.Uint(call.value),
                AbiValue.DynBytes(call.data),
                AbiValue.Uint(nonce),
                AbiValue.DynBytes(signature),
            ),
        )
        return relay.send(SignedAction(address, callData, nonce))
    }

    suspend fun execute(
        to: String,
        value: BigInteger = BigInteger.ZERO,
        data: ByteArray = ByteArray(0),
        auth: BiometricAuth? = null,
    ): String = execute(Call(to, value, data), auth)

    /** Sign and relay an owner-key rotation. [newOwner] must be a real hardware key. */
    suspend fun rotateOwner(newOwner: PublicKeyP256, auth: BiometricAuth? = null): String {
        val chainId = chainId()
        val nonce = nonce()
        val digest = Eip712.rotateDigest(chainId, address, newOwner.x, newOwner.y, nonce)
        val signature = signer.sign(digest, auth)
        val callData = Abi.encodeWithSelector(
            "rotateOwner(uint256,uint256,uint256,bytes)",
            listOf(
                AbiValue.Uint(newOwner.x),
                AbiValue.Uint(newOwner.y),
                AbiValue.Uint(nonce),
                AbiValue.DynBytes(signature),
            ),
        )
        return relay.send(SignedAction(address, callData, nonce))
    }
}

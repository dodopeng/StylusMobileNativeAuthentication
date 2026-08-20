package xyz.heavenlydev.p256account.account

import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import kotlinx.coroutines.delay
import xyz.heavenlydev.p256account.abi.Abi
import xyz.heavenlydev.p256account.abi.AbiValue
import xyz.heavenlydev.p256account.crypto.PublicKeyP256
import xyz.heavenlydev.p256account.eip712.Eip712
import xyz.heavenlydev.p256account.rpc.AccountRpc
import xyz.heavenlydev.p256account.rpc.RpcException
import xyz.heavenlydev.p256account.rpc.SignedAction
import xyz.heavenlydev.p256account.rpc.TransactionRelay
import kotlinx.coroutines.sync.withLock
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
/**
 * Low-level signing primitive.
 *
 * **Never pass a hash you did not construct.** [sign] puts the hardware key over
 * the given 32 bytes verbatim, with no domain separation. An `Execute` digest is
 * itself a 32-byte hash whose inputs are all public, so signing caller-supplied
 * bytes here reproduces exactly the EIP-1271 vulnerability that `PersonalSign`
 * wrapping was added to close: an attacker hands you an
 * `execute(to = attacker, value = 1 ETH)` digest as a "challenge" and the result
 * is a valid transfer authorisation.
 *
 * For EIP-1271 challenges use [P256Account.signHash], which applies the
 * `PersonalSign(bytes32 hash)` wrapper. Use this interface directly only for
 * digests the SDK itself built.
 */
interface SignProvider {
    fun publicKey(): PublicKeyP256
    /**
     * Sign [digest]. [auth] carries the biometric prompt context; a signer that
     * gates on biometrics requires it to be non-null, one that does not ignores it.
     */
    suspend fun sign(digest: ByteArray, auth: BiometricAuth?): ByteArray
}

/** Contract-enforced cap on calls per `executeBatch`. */
const val MAX_BATCH_CALLS: Int = 32

/** How long a local nonce reservation survives without the chain catching up. */
const val RESERVATION_TTL_MILLIS: Long = 120_000

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
    private val rpc: AccountRpc,
    private val relay: TransactionRelay,
    private val signer: SignProvider,
    chainId: Long? = null,
    /**
     * Overridable so the staleness fallback is testable without waiting out
     * the real TTL. Defaults to [RESERVATION_TTL_MILLIS].
     */
    private val reservationTtlMillis: Long = RESERVATION_TTL_MILLIS,
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

    /**
     * Serialises signing+relay and tracks a locally-reserved nonce.
     *
     * `nonce()` reads the chain at *latest*, which only advances once a relayed
     * transaction is mined. Two calls started before the first confirms would
     * otherwise both read the same value, sign against it, and the second would
     * revert with `NonceMismatch`. `executeBatch` removes the need for
     * back-to-back calls in the common approve→swap case, but it does not fix
     * two genuinely independent actions — this does.
     *
     * Scope and limits, stated plainly: this serialises calls made through
     * **this client instance**. Two instances, two devices, or a process restart
     * mid-flight still race, because the authoritative nonce lives on-chain and
     * only moves on confirmation. Reserved values are released if signing or
     * relaying throws, and the reservation resets whenever the chain catches up.
     */
    private val nonceMutex = kotlinx.coroutines.sync.Mutex()
    private var reservedNonce: BigInteger? = null
    private var reservedAtMillis: Long = 0

    private suspend fun <T> withReservedNonce(block: suspend (BigInteger) -> T): T =
        nonceMutex.withLock {
            val onChain = nonce()
            val reserved = reservedNonce
            val next = when {
                reserved == null -> onChain
                // Chain caught up or overtook: the reservation is spent.
                onChain > reserved -> onChain
                // Stale reservation — a broadcast transaction was probably
                // dropped or replaced. Without this the client would sign an
                // unreachable nonce forever and every call would fail
                // NonceMismatch until the object was recreated.
                System.currentTimeMillis() - reservedAtMillis > reservationTtlMillis -> {
                    resetNonce()
                    onChain
                }
                else -> reserved
            }
            // The reservation is only advanced on the success path below; if
            // `block` throws, nothing was broadcast and the nonce is untouched.
            val result = block(next)
            reservedNonce = next + BigInteger.ONE
            reservedAtMillis = System.currentTimeMillis()
            result
        }

    /**
     * Drop the local nonce reservation and resynchronise with the chain on the
     * next call. Call after a transaction is known to have been dropped or
     * replaced, or to recover from repeated `NonceMismatch` failures.
     */
    fun resetNonce() {
        reservedNonce = null
        reservedAtMillis = 0
    }

    /** Sign and relay an `execute`. Returns the broadcast transaction hash. */
    suspend fun execute(call: Call, auth: BiometricAuth? = null): String = withReservedNonce { nonce ->
        val chainId = chainId()
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
        relay.send(SignedAction(address, callData, nonce))
    }

    suspend fun execute(
        to: String,
        value: BigInteger = BigInteger.ZERO,
        data: ByteArray = ByteArray(0),
        auth: BiometricAuth? = null,
    ): String = execute(Call(to, value, data), auth)

    /**
     * Sign and relay a **batch** of calls under one signature and one nonce.
     *
     * The correct way to run approve → swap. Two separate [execute] calls means
     * two biometric prompts and, because [nonce] reads at *latest*, both get
     * signed against the same nonce so the second reverts unless the user waits
     * for the first to confirm. A batch has one nonce, so the race cannot happen.
     *
     * All-or-nothing: the contract reverts the whole batch if any call fails,
     * so the nonce is not consumed and no partial state (a dangling approval)
     * is left behind.
     */
    @JvmOverloads
    suspend fun executeBatch(calls: List<Call>, auth: BiometricAuth? = null): String {
        require(calls.isNotEmpty()) { "executeBatch requires at least one call" }
        require(calls.size <= MAX_BATCH_CALLS) {
            "executeBatch accepts at most $MAX_BATCH_CALLS calls, got ${calls.size}"
        }
        return withReservedNonce { nonce ->
            val chainId = chainId()
            val digest = Eip712.batchDigest(chainId, address, calls, nonce)
            val signature = signer.sign(digest, auth)
            val callData = Abi.encodeWithSelector(
                "executeBatch(address[],uint256[],bytes[],uint256,bytes)",
                listOf(
                    AbiValue.AddressArray(calls.map { it.to }),
                    AbiValue.UintArray(calls.map { it.value }),
                    AbiValue.BytesArray(calls.map { it.data }),
                    AbiValue.Uint(nonce),
                    AbiValue.DynBytes(signature),
                ),
            )
            relay.send(SignedAction(address, callData, nonce))
        }
    }

    /**
     * Produce a signature over an arbitrary 32-byte hash, verifiable on-chain
     * through this account's EIP-1271 `isValidSignature`.
     *
     * The signing half of EIP-1271. The contract has always exposed the
     * verifying half, but without this an integrator had to reach past this
     * class to [SignProvider] to sign an off-chain order (Permit2, Seaport, a
     * login challenge) — so "dApps can verify signatures from this account"
     * only worked in one direction.
     *
     * The hash is wrapped in `PersonalSign(bytes32 hash)` before signing, which
     * is what `isValidSignature` verifies against.
     *
     * It must NOT be signed raw. An `Execute` digest is itself a 32-byte hash
     * computable from public inputs, so a raw-signing 1271 path lets an attacker
     * present `execute(to = attacker, value = 1 ETH)` as a login challenge and
     * receive a valid transfer authorisation from the biometric prompt.
     */
    @JvmOverloads
    suspend fun signHash(hash: ByteArray, auth: BiometricAuth? = null): ByteArray {
        require(hash.size == 32) { "EIP-1271 hash must be exactly 32 bytes, got ${hash.size}" }
        val wrapped = Eip712.personalSignDigest(chainId(), address, hash)
        return signer.sign(wrapped, auth)
    }

    /**
     * Sign and relay an owner-key rotation, authorised by the *current* owner.
     *
     * `newOwner` must be a real hardware key: the contract verifies curve
     * membership, but a key that is on-curve yet not backed by the enclave is
     * still an unrecoverable loss of control.
     *
     * Shares the monotonic nonce with [execute] and [executeBatch] — on-chain
     * *and* in this client's reservation, so it goes through
     * [withReservedNonce] (which also holds [nonceMutex]), never a raw [nonce].
     */
    suspend fun rotateOwner(newOwner: PublicKeyP256, auth: BiometricAuth? = null): String =
        withReservedNonce { nonce ->
            val chainId = chainId()
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
            relay.send(SignedAction(address, callData, nonce))
        }
}

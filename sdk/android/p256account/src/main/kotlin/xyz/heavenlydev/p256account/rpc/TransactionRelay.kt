package xyz.heavenlydev.p256account.rpc

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONObject
import xyz.heavenlydev.p256account.crypto.Numeric
import java.math.BigInteger

/**
 * A signed, ready-to-broadcast account action. `callData` is the full
 * `execute(...)` / `rotateOwner(...)` calldata addressed to the account
 * contract; the relayer just needs to send an EVM tx `{to: account, data:
 * callData, value: 0}`.
 */
data class SignedAction(
    val account: String,
    val callData: ByteArray,
    val nonce: BigInteger,
)

/** Strategy for getting a signed action on-chain. See sdk/SPEC.md §4. */
interface TransactionRelay {
    /** Returns the broadcast transaction hash. */
    suspend fun send(action: SignedAction): String
}

/**
 * POSTs the signed action to a relay service that pays gas and broadcasts.
 * The default production path — no on-device ETH required.
 *
 * Wire format (JSON): `{ "account", "data", "nonce" }`; response: `{ "txHash" }`.
 */
class HttpRelay(private val url: String) : TransactionRelay {
    override suspend fun send(action: SignedAction): String = withContext(Dispatchers.IO) {
        val body = JSONObject().apply {
            put("account", action.account)
            put("data", Numeric.bytesToHex(action.callData))
            put("nonce", action.nonce.toString())
        }.toString()
        val response = Http.postJson(url, body)
        val json = Http.parse(response, url)
        Http.errorMessage(json)?.let { throw RpcException(-1, "relayer rejected the action: $it") }
        if (!json.has("txHash") || json.isNull("txHash")) {
            throw RpcException(-1, "relayer response has no txHash: '${response.body.take(200)}'")
        }
        json.getString("txHash")
    }
}

/**
 * Self-relay path: the integrator supplies a [Broadcaster] (typically a funded
 * secp256k1 dev EOA) that signs and sends the raw EVM transaction. Keeps the
 * SDK free of a secp256k1 dependency while still supporting tests / self-hosting.
 */
fun interface Broadcaster {
    /** Sign & send an EVM tx to [to] with [data]; return the tx hash. */
    suspend fun sendTransaction(to: String, data: ByteArray): String
}

class BroadcasterRelay(private val broadcaster: Broadcaster) : TransactionRelay {
    override suspend fun send(action: SignedAction): String =
        broadcaster.sendTransaction(action.account, action.callData)
}

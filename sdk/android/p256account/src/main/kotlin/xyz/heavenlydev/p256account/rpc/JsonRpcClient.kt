package xyz.heavenlydev.p256account.rpc

import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import org.json.JSONArray
import org.json.JSONObject
import xyz.heavenlydev.p256account.crypto.Numeric
import java.math.BigInteger
import java.net.HttpURLConnection
import java.net.URL

/**
 * Tiny Ethereum JSON-RPC client over `HttpURLConnection` (org.json ships with
 * Android, so no networking/JSON dependency is forced on consumers). Only the
 * read paths the SDK needs are implemented: `eth_call`, `eth_chainId`,
 * `eth_sendRawTransaction`, `eth_getTransactionReceipt`.
 */
/**
 * The RPC surface [xyz.heavenlydev.p256account.account.P256Account] depends on.
 *
 * Extracted so the nonce-reservation logic is testable: a fake can hold the
 * chain nonce still across several `execute` calls, which is precisely the
 * state a real chain is in between broadcast and confirmation. [JsonRpcClient]
 * is the production implementation. Mirrors `AccountRPC` in the iOS SDK.
 */
interface AccountRpc {
    suspend fun chainId(): Long
    suspend fun callUint(to: String, data: ByteArray): BigInteger
    suspend fun getTransactionReceipt(txHash: String): JSONObject?
}

class JsonRpcClient(private val endpoint: String) : AccountRpc {

    override suspend fun chainId(): Long = withContext(Dispatchers.IO) {
        val hex = rpc("eth_chainId", JSONArray())
        val id = try {
            BigInteger(hex.removePrefix("0x"), 16).toLong()
        } catch (e: NumberFormatException) {
            throw RpcException(-1, "eth_chainId returned an unparseable value: '$hex'")
        }
        // A wrong/zero chainId silently corrupts the EIP-712 domain and the
        // signature would be rejected on-chain with no clear cause — fail loud.
        if (id == 0L) throw RpcException(-1, "eth_chainId returned 0")
        id
    }

    /** `eth_call` with `latest` block; returns the raw return bytes. */
    suspend fun call(to: String, data: ByteArray): ByteArray = withContext(Dispatchers.IO) {
        val params = JSONArray().apply {
            put(JSONObject().apply {
                put("to", to)
                put("data", Numeric.bytesToHex(data))
            })
            put("latest")
        }
        Numeric.hexToBytes(rpc("eth_call", params))
    }

    suspend fun sendRawTransaction(rawTx: ByteArray): String = withContext(Dispatchers.IO) {
        rpc("eth_sendRawTransaction", JSONArray().put(Numeric.bytesToHex(rawTx)))
    }

    /** Fetches a transaction receipt, or `null` if the tx is not yet mined. */
    override suspend fun getTransactionReceipt(txHash: String): JSONObject? = withContext(Dispatchers.IO) {
        val result = request("eth_getTransactionReceipt", JSONArray().put(txHash))
        result as? JSONObject
    }

    /** Reads a single uint256 return value (nonce / ownerX / ownerY). */
    override suspend fun callUint(to: String, data: ByteArray): BigInteger {
        val ret = call(to, data)
        require(ret.size >= 32) { "expected uint256 return, got ${ret.size} bytes" }
        return Numeric.toBigInteger(ret.copyOfRange(ret.size - 32, ret.size))
    }

    private fun rpc(method: String, params: JSONArray): String =
        request(method, params) as? String ?: throw RpcException(-1, "$method: null result")

    /** Raw request returning the `result` field (String, JSONObject, or null). */
    private fun request(method: String, params: JSONArray): Any? {
        val body = JSONObject().apply {
            put("jsonrpc", "2.0")
            put("id", 1)
            put("method", method)
            put("params", params)
        }.toString()

        val response = Http.postJson(endpoint, body)
        val json = Http.parse(response, endpoint)
        Http.rpcError(json)?.let { (code, message) -> throw RpcException(code, message) }
        return if (json.isNull("result")) null else json.get("result")
    }
}

/**
 * Shared HTTP plumbing for the two clients.
 *
 * Two problems this fixes:
 *  - `HttpURLConnection` was never `disconnect()`ed, so sockets were held until
 *    the finaliser ran.
 *  - a non-JSON error body (an HTML 502 from a proxy, a plain-text gateway
 *    error) threw a raw `JSONException` straight through a typed error surface.
 *    Callers catching `RpcException` never saw it.
 */
internal object Http {
    /** An HTTP response body together with the status that produced it. */
    data class Response(val status: Int, val body: String)

    fun postJson(url: String, body: String, connectTimeoutMs: Int = 15_000, readTimeoutMs: Int = 30_000): Response {
        val conn = (URL(url).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            connectTimeout = connectTimeoutMs
            readTimeout = readTimeoutMs
        }
        try {
            conn.outputStream.use { it.write(body.toByteArray()) }
            val code = conn.responseCode
            val stream = if (code in 200..299) conn.inputStream else conn.errorStream
            return Response(code, stream?.bufferedReader()?.use { it.readText() } ?: "")
        } catch (e: RpcException) {
            throw e
        } catch (e: Exception) {
            throw RpcException(-1, "HTTP request to $url failed: ${e.message}")
        } finally {
            conn.disconnect()
        }
    }

    /**
     * Parse a response body, converting malformed payloads into [RpcException].
     * The HTTP status goes in the message: with an empty body it is the only
     * thing separating a dead gateway from a truncated response.
     */
    fun parse(response: Response, url: String): JSONObject =
        try {
            JSONObject(response.body)
        } catch (e: Exception) {
            val preview = response.body.take(200).replace(Regex("\\s+"), " ")
            throw RpcException(
                -1,
                "non-JSON response from $url (HTTP ${response.status}): '$preview'",
            )
        }

    /**
     * Render an `error` member that may be an object (`{code, message}`), a
     * string, or absent. `getString` on an object threw.
     */
    fun errorMessage(json: JSONObject): String? = rpcError(json)?.second

    /**
     * Extract `(code, message)`. The code is preserved rather than folded into
     * the message so [RpcException.code] carries the real JSON-RPC code — it was
     * always -1, which made programmatic handling (e.g. distinguishing -32000
     * "insufficient funds" from a nonce error) impossible.
     */
    fun rpcError(json: JSONObject): Pair<Int, String>? {
        if (!json.has("error") || json.isNull("error")) return null
        json.optJSONObject("error")?.let { obj ->
            return obj.optInt("code", -1) to obj.optString("message", "unknown error")
        }
        return -1 to json.optString("error", "unknown error")
    }
}


class RpcException(val code: Int, message: String) : Exception("RPC error $code: $message")

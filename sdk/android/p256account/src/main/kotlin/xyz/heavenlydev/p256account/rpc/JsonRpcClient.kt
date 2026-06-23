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
class JsonRpcClient(private val endpoint: String) {

    suspend fun chainId(): Long = withContext(Dispatchers.IO) {
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
    suspend fun getTransactionReceipt(txHash: String): JSONObject? = withContext(Dispatchers.IO) {
        val result = request("eth_getTransactionReceipt", JSONArray().put(txHash))
        result as? JSONObject
    }

    /** Reads a single uint256 return value (nonce / ownerX / ownerY). */
    suspend fun callUint(to: String, data: ByteArray): BigInteger {
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

        val conn = (URL(endpoint).openConnection() as HttpURLConnection).apply {
            requestMethod = "POST"
            doOutput = true
            setRequestProperty("Content-Type", "application/json")
            connectTimeout = 15_000
            readTimeout = 30_000
        }
        conn.outputStream.use { it.write(body.toByteArray()) }
        val text = (if (conn.responseCode in 200..299) conn.inputStream else conn.errorStream)
            .bufferedReader().use { it.readText() }
        val json = JSONObject(text)
        if (json.has("error") && !json.isNull("error")) {
            val err = json.getJSONObject("error")
            throw RpcException(err.optInt("code"), err.optString("message"))
        }
        return if (json.isNull("result")) null else json.get("result")
    }
}

class RpcException(val code: Int, message: String) : Exception("RPC error $code: $message")

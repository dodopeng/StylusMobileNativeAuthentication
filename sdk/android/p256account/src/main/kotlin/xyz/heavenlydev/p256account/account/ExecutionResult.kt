package xyz.heavenlydev.p256account.account

import org.json.JSONObject
import xyz.heavenlydev.p256account.crypto.Numeric

/**
 * Outcome of an `execute`, decoded from the contract's `Executed` event.
 *
 * The contract does NOT revert when the inner call fails — it consumes the
 * nonce and returns `(success = false, returnData = revert bytes)`. So a relayed
 * transaction can succeed at the EVM level while the action it carried reverted.
 * A bare tx hash therefore does not imply the action worked; decode this to know.
 */
data class ExecutionResult(val success: Boolean, val returnData: ByteArray)

internal object ExecutedEvent {
    /** keccak256("Executed(address,uint256,uint256,bool,bytes)"). */
    private const val TOPIC0 = "0xec126b3c24acfdb528f781ef219cb885a0dbf6110e42b118c3fae06edfe20480"

    /** Find and decode the account's `Executed` log in a receipt, or null. */
    fun decode(receipt: JSONObject, account: String): ExecutionResult? {
        val logs = receipt.optJSONArray("logs") ?: return null
        for (i in 0 until logs.length()) {
            val log = logs.getJSONObject(i)
            if (!log.optString("address").equals(account, ignoreCase = true)) continue
            val topics = log.optJSONArray("topics") ?: continue
            if (topics.length() == 0 || !topics.getString(0).equals(TOPIC0, ignoreCase = true)) continue

            return decodeData(Numeric.hexToBytes(log.getString("data")))
        }
        return null
    }

    /**
     * Decode the non-indexed `Executed` data:
     * `value(32) ‖ nonce(32) ‖ success(32) ‖ offset(32) ‖ len(32) ‖ bytes…`.
     * Pure (no JSON) so it is unit-testable.
     */
    fun decodeData(data: ByteArray): ExecutionResult {
        val success = data.size >= 96 && data[95].toInt() != 0
        val returnData = if (data.size >= 160) {
            val len = Numeric.toBigInteger(data.copyOfRange(128, 160)).toInt()
            if (len in 0..(data.size - 160)) data.copyOfRange(160, 160 + len) else ByteArray(0)
        } else ByteArray(0)
        return ExecutionResult(success, returnData)
    }
}

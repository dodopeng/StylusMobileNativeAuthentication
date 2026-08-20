package xyz.heavenlydev.p256account

import kotlinx.coroutines.test.runTest
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Test
import xyz.heavenlydev.p256account.account.P256Account
import xyz.heavenlydev.p256account.account.RESERVATION_TTL_MILLIS
import xyz.heavenlydev.p256account.action.Erc20
import xyz.heavenlydev.p256account.keystore.SoftwareP256Signer
import xyz.heavenlydev.p256account.rpc.AccountRpc
import xyz.heavenlydev.p256account.rpc.RpcException
import xyz.heavenlydev.p256account.rpc.SignedAction
import xyz.heavenlydev.p256account.rpc.TransactionRelay
import java.math.BigInteger

/**
 * Client-side nonce reservation.
 *
 * `nonce()` reads the chain at *latest*, which only advances when a relayed
 * transaction is mined. Every signing entry point must therefore take its nonce
 * through the client's nonce reservation and commit it after a successful relay —
 * `rotateOwner` included, since it shares the contract's monotonic nonce with
 * `execute`. A raw `nonce()` read anywhere in that set reintroduces a revert
 * that only shows up when two calls overlap, which no golden-vector test sees.
 *
 * Mirrors `Conformance/NonceReservation.swift` in the iOS SDK check for check.
 */
class NonceReservationTest {

    /** Relay that records the nonce it was handed, and can refuse a broadcast. */
    private class RecordingRelay : TransactionRelay {
        val seen = mutableListOf<BigInteger>()
        var failNext = false

        override suspend fun send(action: SignedAction): String {
            if (failNext) throw RpcException(-1, "relay refused")
            seen += action.nonce
            return "0xdeadbeef"
        }
    }

    /** RPC whose account nonce sits wherever the test puts it. */
    private class PinnedRpc(var chainNonce: BigInteger = BigInteger.ZERO) : AccountRpc {
        override suspend fun chainId(): Long = 412_346L
        override suspend fun callUint(to: String, data: ByteArray): BigInteger = chainNonce
        override suspend fun getTransactionReceipt(txHash: String): JSONObject? = null
    }

    private val token = "0x1111111111111111111111111111111111111111"
    private val bob = "0x2222222222222222222222222222222222222222"
    private val signer = SoftwareP256Signer()

    private fun account(
        rpc: PinnedRpc,
        relay: RecordingRelay,
        ttlMillis: Long = RESERVATION_TTL_MILLIS,
    ) = P256Account(
        address = "0x00000000000000000000000000000000000000aa",
        rpc = rpc,
        relay = relay,
        signer = signer,
        chainId = 412_346L,
        reservationTtlMillis = ttlMillis,
    )

    private fun transfer(amount: Long) = Erc20.transfer(token, bob, BigInteger.valueOf(amount))

    private fun nonces(vararg v: Long) = v.map { BigInteger.valueOf(it) }

    @Test
    fun `two sequential executes take successive nonces while the chain sits still`() = runTest {
        val rpc = PinnedRpc(); val relay = RecordingRelay()
        val a = account(rpc, relay)
        a.execute(transfer(1))
        a.execute(transfer(2))
        assertEquals(nonces(0, 1), relay.seen)
    }

    @Test
    fun `execute then rotateOwner continues the reservation`() = runTest {
        // The case that was broken: rotateOwner read the chain nonce directly,
        // picked up a stale 0, and reverted with NonceMismatch.
        val rpc = PinnedRpc(); val relay = RecordingRelay()
        val a = account(rpc, relay)
        a.execute(transfer(1))
        a.rotateOwner(signer.publicKey())
        assertEquals(nonces(0, 1), relay.seen)
    }

    @Test
    fun `rotateOwner then execute does not reuse the rotation's nonce`() = runTest {
        val rpc = PinnedRpc(); val relay = RecordingRelay()
        val a = account(rpc, relay)
        a.rotateOwner(signer.publicKey())
        a.execute(transfer(1))
        assertEquals(nonces(0, 1), relay.seen)
    }

    @Test
    fun `a failed relay leaves the reservation unadvanced`() = runTest {
        val rpc = PinnedRpc(); val relay = RecordingRelay()
        val a = account(rpc, relay)
        relay.failNext = true
        runCatching { a.execute(transfer(1)) }
        relay.failNext = false
        a.execute(transfer(2))
        // Nothing was broadcast the first time, so nonce 0 is still free.
        assertEquals(nonces(0), relay.seen)
    }

    @Test
    fun `a stale reservation falls back to the chain value`() = runTest {
        // Without the TTL a dropped or replaced transaction would leave the
        // client signing an unreachable nonce forever.
        val rpc = PinnedRpc(); val relay = RecordingRelay()
        // Negative, not 0: the check is `elapsed > ttl`, and two calls in the
        // same millisecond give elapsed == 0. A negative TTL means "already
        // expired" regardless of clock granularity, so the test is deterministic.
        val a = account(rpc, relay, ttlMillis = -1)
        a.execute(transfer(1))
        a.execute(transfer(2))
        assertEquals(nonces(0, 0), relay.seen)
    }

    @Test
    fun `the chain overtaking the reservation wins`() = runTest {
        val rpc = PinnedRpc(); val relay = RecordingRelay()
        val a = account(rpc, relay)
        a.execute(transfer(1))
        rpc.chainNonce = BigInteger.valueOf(7)
        a.execute(transfer(2))
        assertEquals(nonces(0, 7), relay.seen)
    }
}

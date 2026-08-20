import Foundation
import P256Account

/// Regression checks for the client-side nonce reservation.
///
/// `nonce()` reads the chain at *latest*, which only advances when a relayed
/// transaction is mined. Every signing entry point must therefore take its
/// nonce from `reserveNonce()` and commit it after a successful relay —
/// `rotateOwner` included, since it shares the contract's monotonic nonce with
/// `execute`. A raw `nonce()` read anywhere in that set reintroduces a revert
/// that only appears when two calls overlap, which no golden-vector test sees.
///
/// Lives in the `Conformance` target, not the XCTest suite, for the same reason
/// the template checks do: it must be runnable via `swift build` on a machine
/// without Xcode.
public enum NonceReservation {

    public struct Report {
        public let checked: Int
        public let failures: [String]
        public var passed: Bool { failures.isEmpty }
    }

    /// Relay that records the nonce of every action it is handed, and can be
    /// switched to throw — standing in for a rejected broadcast.
    final class RecordingRelay: TransactionRelay, @unchecked Sendable {
        private(set) var seen: [U256] = []
        var failNext = false

        func send(_ action: SignedAction) async throws -> String {
            if failNext { throw P256Error.rpc("relay refused") }
            seen.append(action.nonce)
            return "0xdeadbeef"
        }
    }

    /// RPC whose account nonce is held wherever the test puts it, mimicking a
    /// chain that has not yet mined the pending transaction.
    final class PinnedRPC: AccountRPC, @unchecked Sendable {
        var chainNonce: U256 = U256(0)

        func chainId() async throws -> UInt64 { 412_346 }

        func callUint(to: String, data: [UInt8]) async throws -> U256 { chainNonce }

        func getTransactionReceipt(_ txHash: String) async throws -> [String: Any]? { nil }
    }

    private static func client(
        rpc: PinnedRPC,
        relay: RecordingRelay,
        signer: SignProvider,
        ttl: TimeInterval = P256AccountClient.defaultReservationTTL
    ) -> P256AccountClient {
        P256AccountClient(
            address: "0x00000000000000000000000000000000000000aa",
            rpc: rpc,
            relay: relay,
            signer: signer,
            chainId: 412_346,
            reservationTTL: ttl
        )
    }

    private static let TOKEN = "0x1111111111111111111111111111111111111111"
    private static let BOB = "0x2222222222222222222222222222222222222222"

    public static func run() async throws -> Report {
        var failures: [String] = []
        var checked = 0

        /// Small-value nonces only — enough to read a failure message by.
        func small(_ vs: [U256]) -> [Int] {
            vs.map { v in Int([UInt8](v.data).suffix(8).reduce(0) { $0 << 8 | UInt64($1) }) }
        }
        func check(_ label: String, _ got: [U256], _ want: [Int]) {
            checked += 1
            let g = small(got)
            if g != want { failures.append("\(label): expected nonces \(want), got \(g)") }
        }

        let signer = try SoftwareP256Signer()
        let key = try signer.publicKey()

        // 1. Two sequential executes with the chain nonce pinned at 0.
        //    Without the reservation both sign nonce 0 and the second reverts.
        do {
            let rpc = PinnedRPC(), relay = RecordingRelay()
            let c = client(rpc: rpc, relay: relay, signer: signer)
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(1)))
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(2)))
            check("two sequential executes", relay.seen, [0, 1])
        }

        // 2. execute then rotateOwner — the case that was broken. rotateOwner
        //    shares the contract's nonce, so it must continue the reservation
        //    rather than re-read a chain value still sitting at 0.
        do {
            let rpc = PinnedRPC(), relay = RecordingRelay()
            let c = client(rpc: rpc, relay: relay, signer: signer)
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(1)))
            _ = try await c.rotateOwner(to: key)
            check("execute then rotateOwner", relay.seen, [0, 1])
        }

        // 3. ...and the reverse: a rotation must commit its reservation so a
        //    following execute does not reuse the rotation's nonce.
        do {
            let rpc = PinnedRPC(), relay = RecordingRelay()
            let c = client(rpc: rpc, relay: relay, signer: signer)
            _ = try await c.rotateOwner(to: key)
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(1)))
            check("rotateOwner then execute", relay.seen, [0, 1])
        }

        // 4. A throwing relay must leave the reservation unadvanced — nothing
        //    was broadcast, so the nonce is still free.
        do {
            let rpc = PinnedRPC(), relay = RecordingRelay()
            let c = client(rpc: rpc, relay: relay, signer: signer)
            relay.failNext = true
            _ = try? await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(1)))
            relay.failNext = false
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(2)))
            check("failed relay does not consume the nonce", relay.seen, [0])
        }

        // 5. After the TTL with no chain movement the reservation is assumed
        //    dropped and falls back to the chain value, instead of signing an
        //    unreachable nonce forever.
        do {
            let rpc = PinnedRPC(), relay = RecordingRelay()
            // Negative, not 0: the check is `elapsed > ttl`. A negative TTL means
            // "already expired" regardless of clock granularity, matching the
            // Kotlin suite so both are deterministic.
            let c = client(rpc: rpc, relay: relay, signer: signer, ttl: -1)
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(1)))
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(2)))
            check("stale reservation falls back to the chain", relay.seen, [0, 0])
        }

        // 6. When the chain does catch up, the reservation follows it rather
        //    than continuing from a stale local value.
        do {
            let rpc = PinnedRPC(), relay = RecordingRelay()
            let c = client(rpc: rpc, relay: relay, signer: signer)
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(1)))
            rpc.chainNonce = U256(7)
            _ = try await c.execute(Erc20.transfer(token: TOKEN, to: BOB, amount: U256(2)))
            check("chain overtaking the reservation wins", relay.seen, [0, 7])
        }

        return Report(checked: checked, failures: failures)
    }
}

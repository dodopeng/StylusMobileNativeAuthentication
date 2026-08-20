import Foundation
import LocalAuthentication

/// An outbound call to perform via the account.
/// Limits enforced by the contract. Mirrored in Kotlin (`MAX_BATCH_CALLS`) and
/// asserted against `sdk/actions.golden.json`'s `limits` block — which the
/// golden generator reads directly out of `lib.rs` — so the three copies cannot
/// drift from the contract silently.
public enum P256AccountLimits {
    public static let maxBatchCalls = 32
}

public struct Call {
    public let to: String
    public let value: U256
    public let data: [UInt8]
    public init(to: String, value: U256 = U256(0), data: [UInt8] = []) {
        self.to = to; self.value = value; self.data = data
    }
}

/// Outcome of an `execute`, decoded from the contract's `Executed` event.
///
/// The contract does NOT revert when the inner call fails — it consumes the
/// nonce and returns `(success: false, returnData: revert bytes)`. So a relayed
/// transaction can succeed at the EVM level while the action it carried
/// reverted; a bare tx hash does not prove the action worked.
public struct ExecutionResult {
    public let success: Bool
    public let returnData: [UInt8]
}

/// keccak256("Executed(address,uint256,uint256,bool,bytes)").
private let EXECUTED_TOPIC0 =
    "0xec126b3c24acfdb528f781ef219cb885a0dbf6110e42b118c3fae06edfe20480"

/// High-level handle to a deployed `P256Account` contract. Reads its state over
/// JSON-RPC, builds the EIP-712 digest, asks the [signer] (any ``SignProvider``
/// — the Secure Enclave in production, or ``SoftwareP256Signer`` on the
/// Simulator / in tests) for a signature, ABI-encodes the call, and hands it to
/// the [relay] to broadcast.
///
/// The account contract itself is deployed out-of-band via
/// `cargo stylus deploy --constructor-args <x> <y>` using the signer's public
/// key; this type operates an already-deployed account.
/// Serialised by actor isolation.
///
/// Must stay an `actor`, not a `final class`: `reserveNonce()` awaits `nonce()`
/// — a suspension point — then reads and writes `reservedNonce`. Without actor
/// isolation two concurrent `execute` calls interleave across that await and
/// take the same nonce; it is also a data race on mutable state across an
/// await, which Swift 6 strict concurrency rejects. Mirrors Kotlin's
/// `nonceMutex.withLock { … }` span.
public actor P256AccountClient {
    /// Immutable and Sendable, so callers may read it without `await`.
    public nonisolated let address: String
    private let rpc: AccountRPC
    private let relay: TransactionRelay
    private let signer: SignProvider
    private var cachedChainId: UInt64?

    public init(
        address: String,
        rpc: AccountRPC,
        relay: TransactionRelay,
        signer: SignProvider,
        chainId: UInt64? = nil,
        reservationTTL: TimeInterval = P256AccountClient.defaultReservationTTL
    ) {
        self.address = address
        self.rpc = rpc
        self.relay = relay
        self.signer = signer
        self.cachedChainId = chainId
        self.reservationTTL = reservationTTL
    }

    public func chainId() async throws -> UInt64 {
        if let c = cachedChainId { return c }
        let c = try await rpc.chainId(); cachedChainId = c; return c
    }

    public func nonce() async throws -> U256 {
        try await rpc.callUint(to: address, data: try ABI.encodeWithSelector("nonce()", []))
    }

    /// Poll for a relayed transaction's receipt and decode the account's
    /// `Executed` event. `result.success == false` means the inner call reverted
    /// (nonce still consumed) — the bare tx hash from `execute` does NOT prove
    /// the action worked, so call this to confirm. Throws if the transaction
    /// reverted, has no `Executed` log, or no receipt arrives in `attempts` tries.
    public func awaitExecuted(txHash: String, attempts: Int = 30, delaySeconds: Double = 1.0) async throws -> ExecutionResult {
        for _ in 0..<attempts {
            if let receipt = try await rpc.getTransactionReceipt(txHash) {
                if (receipt["status"] as? String)?.lowercased() == "0x0" {
                    throw P256Error.rpc("transaction \(txHash) reverted (status 0x0)")
                }
                guard let result = decodeExecuted(receipt: receipt) else {
                    throw P256Error.rpc("no Executed event from \(address) in receipt \(txHash)")
                }
                return result
            }
            try await Task.sleep(nanoseconds: UInt64(delaySeconds * 1_000_000_000))
        }
        throw P256Error.rpc("timed out waiting for receipt \(txHash)")
    }

    private func decodeExecuted(receipt: [String: Any]) -> ExecutionResult? {
        guard let logs = receipt["logs"] as? [[String: Any]] else { return nil }
        for log in logs {
            guard let addr = log["address"] as? String, addr.lowercased() == address.lowercased(),
                  let topics = log["topics"] as? [String], let t0 = topics.first,
                  t0.lowercased() == EXECUTED_TOPIC0,
                  let dataHex = log["data"] as? String, let data = Hex.toBytes(dataHex) else { continue }
            // value(32) ‖ nonce(32) ‖ success(32) ‖ offset(32) ‖ len(32) ‖ bytes…
            let success = data.count >= 96 && data[95] != 0
            var returnData: [UInt8] = []
            // Length arrives from an untrusted receipt. `Int(UInt64)` traps
            // above Int.max, and `160 + n` can overflow — both must be checked
            // BEFORE conversion, not after. The upper 24 bytes must also be
            // zero: a length needing more than 8 bytes is nonsense here, and
            // must be rejected rather than truncated.
            if data.count >= 160 {
                let lenBytes = Array(data[128..<160])
                let highIsZero = lenBytes[0..<24].allSatisfy { $0 == 0 }
                let low = lenBytes[24..<32].reduce(UInt64(0)) { ($0 << 8) | UInt64($1) }
                if highIsZero, low <= UInt64(Int.max),
                   case let n = Int(low), n >= 0, data.count - 160 >= n {
                    returnData = Array(data[160..<160 + n])
                }
            }
            return ExecutionResult(success: success, returnData: returnData)
        }
        return nil
    }
    public func ownerX() async throws -> U256 {
        try await rpc.callUint(to: address, data: try ABI.encodeWithSelector("ownerX()", []))
    }
    public func ownerY() async throws -> U256 {
        try await rpc.callUint(to: address, data: try ABI.encodeWithSelector("ownerY()", []))
    }

    /// Sign and relay an `execute`. The signer drives its own auth UI (the
    /// Secure Enclave shows the Face ID / Touch ID prompt automatically).
    /// Serialised nonce reservation — see `reserveNonce`.
    private var reservedNonce: U256?

    /// `nonce()` reads the chain at *latest*, which only advances once a relayed
    /// transaction is mined. Two calls started before the first confirms would
    /// otherwise both read the same value and the second would revert with
    /// `NonceMismatch`. `executeBatch` removes the need for back-to-back calls
    /// in the common approve→swap case; this covers genuinely independent ones.
    ///
    /// Scope and limits: this serialises calls through **this client instance**.
    /// Two instances, two devices, or a restart mid-flight still race, because
    /// the authoritative nonce lives on-chain and only moves on confirmation.
    /// The actor isolation on this class provides the mutual exclusion; a
    /// reservation is only committed after the relay succeeds.
    /// When the current reservation was made. A reservation only steps back when
    /// the chain overtakes it, which never happens if a broadcast transaction is
    /// dropped or replaced — the client would then sign an unreachable nonce
    /// forever and every call would fail `NonceMismatch` until the object was
    /// recreated. After `reservationTTL` with no chain progress, fall back to
    /// the chain value.
    private var reservedAt: Date?

    /// How long a reservation survives without the chain catching up.
    public static let defaultReservationTTL: TimeInterval = 120

    /// Overridable so the staleness fallback is testable without waiting out
    /// the real TTL.
    private let reservationTTL: TimeInterval

    private func reserveNonce() async throws -> U256 {
        let onChain = try await nonce()
        guard let reserved = reservedNonce else { return onChain }

        // Chain caught up or overtook: the reservation is spent.
        if onChain > reserved { return onChain }

        // Reservation went stale — assume the pending transaction was dropped.
        if let at = reservedAt, Date().timeIntervalSince(at) > reservationTTL {
            resetNonce()
            return onChain
        }
        return reserved
    }

    private func commitNonce(_ used: U256) {
        reservedNonce = used.adding(U256(1))
        reservedAt = Date()
    }

    /// Drop the local nonce reservation and resynchronise with the chain on the
    /// next call. Call this after a transaction is known to have been dropped
    /// or replaced, or to recover from repeated `NonceMismatch` failures.
    public func resetNonce() {
        reservedNonce = nil
        reservedAt = nil
    }

    @discardableResult
    public func execute(_ call: Call, context: LAContext? = nil) async throws -> String {
        let chainId = try await chainId()
        let nonce = try await reserveNonce()
        let digest = try EIP712.executeDigest(
            chainId: chainId, account: address, to: call.to,
            value: call.value, data: call.data, nonce: nonce
        )
        let signature = try await signer.sign(digest: digest, context: context)
        let callData = try ABI.encodeWithSelector(
            "execute(address,uint256,bytes,uint256,bytes)",
            [.address(call.to), .uint(call.value), .dynBytes(call.data), .uint(nonce), .dynBytes(signature)]
        )
        let txHash = try await relay.send(SignedAction(account: address, callData: callData, nonce: nonce))
        commitNonce(nonce)
        return txHash
    }

    /// Sign and relay a **batch** of calls under one signature and one nonce.
    ///
    /// This is the correct way to run multi-step flows such as approve → swap.
    /// Doing them as two separate `execute` calls means two biometric prompts
    /// and, because `nonce()` reads at *latest*, both get signed against the
    /// same nonce and the second reverts unless the user waits for the first to
    /// confirm. A batch has one nonce, so the race cannot happen.
    ///
    /// The contract reverts the whole batch if any call fails — the nonce is
    /// not consumed, and no partial state (e.g. a dangling approval) is left.
    @discardableResult
    public func executeBatch(_ calls: [Call], context: LAContext? = nil) async throws -> String {
        guard !calls.isEmpty else {
            throw P256Error.badReceipt("executeBatch requires at least one call")
        }
        guard calls.count <= P256AccountLimits.maxBatchCalls else {
            throw P256Error.badReceipt(
                "executeBatch accepts at most \(P256AccountLimits.maxBatchCalls) calls, got \(calls.count)")
        }
        let chainId = try await chainId()
        let nonce = try await reserveNonce()
        let digest = try EIP712.batchDigest(
            chainId: chainId, account: address, calls: calls, nonce: nonce
        )
        let signature = try await signer.sign(digest: digest, context: context)
        let callData = try ABI.encodeWithSelector(
            "executeBatch(address[],uint256[],bytes[],uint256,bytes)",
            [
                .addressArray(calls.map(\.to)),
                .uintArray(calls.map(\.value)),
                .bytesArray(calls.map(\.data)),
                .uint(nonce),
                .dynBytes(signature),
            ]
        )
        let txHash = try await relay.send(SignedAction(account: address, callData: callData, nonce: nonce))
        commitNonce(nonce)
        return txHash
    }

    /// Produce a signature for an arbitrary 32-byte hash, verifiable on-chain
    /// through this account's EIP-1271 `isValidSignature`.
    ///
    /// This is the signing half of EIP-1271. The contract has always exposed
    /// the verifying half, but without this an integrator had to reach past the
    /// client to `SignProvider` to sign an off-chain order (Permit2, Seaport,
    /// a login challenge) — so the "dApps can verify signatures from this
    /// account" story only worked in one direction.
    ///
    /// The hash is wrapped in `PersonalSign(bytes32 hash)` before signing, which
    /// is what `isValidSignature` verifies against.
    ///
    /// It must NOT be signed raw. An `Execute` digest is itself a 32-byte hash
    /// computable from public inputs, so a raw-signing 1271 path lets an
    /// attacker present `execute(to: attacker, value: 1 ETH)` as a login
    /// challenge and receive a valid transfer authorisation from the biometric
    /// prompt. The wrapper makes the domains disjoint by construction.
    public func signHash(_ hash: [UInt8], context: LAContext? = nil) async throws -> [UInt8] {
        guard hash.count == 32 else {
            throw P256Error.badSignature("EIP-1271 hash must be exactly 32 bytes, got \(hash.count)")
        }
        let chainId = try await chainId()
        let wrapped = try EIP712.personalSignDigest(chainId: chainId, account: address, hash: hash)
        return try await signer.sign(digest: wrapped, context: context)
    }

    /// Sign and relay an owner-key rotation. `newOwner` must be a real hardware key.
    @discardableResult
    public func rotateOwner(to newOwner: PublicKeyP256, context: LAContext? = nil) async throws -> String {
        let chainId = try await chainId()
        // Shares the contract's monotonic nonce with `execute`, so it must
        // share the client's reservation too — `reserveNonce`, never `nonce()`.
        let nonce = try await reserveNonce()
        let digest = try EIP712.rotateDigest(
            chainId: chainId, account: address, newX: newOwner.x, newY: newOwner.y, nonce: nonce
        )
        let signature = try await signer.sign(digest: digest, context: context)
        let callData = try ABI.encodeWithSelector(
            "rotateOwner(uint256,uint256,uint256,bytes)",
            [.uint(newOwner.x), .uint(newOwner.y), .uint(nonce), .dynBytes(signature)]
        )
        let txHash = try await relay.send(SignedAction(account: address, callData: callData, nonce: nonce))
        commitNonce(nonce)
        return txHash
    }
}

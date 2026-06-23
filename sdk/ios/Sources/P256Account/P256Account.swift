import Foundation

/// An outbound call to perform via the account.
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
public final class P256AccountClient {
    public let address: String
    private let rpc: JSONRPCClient
    private let relay: TransactionRelay
    private let signer: SignProvider
    private var cachedChainId: UInt64?

    public init(
        address: String,
        rpc: JSONRPCClient,
        relay: TransactionRelay,
        signer: SignProvider,
        chainId: UInt64? = nil
    ) {
        self.address = address
        self.rpc = rpc
        self.relay = relay
        self.signer = signer
        self.cachedChainId = chainId
    }

    public func chainId() async throws -> UInt64 {
        if let c = cachedChainId { return c }
        let c = try await rpc.chainId(); cachedChainId = c; return c
    }

    public func nonce() async throws -> U256 {
        try await rpc.callUint(to: address, data: ABI.encodeWithSelector("nonce()", []))
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
            if data.count >= 160, let len = U256(bigEndian: Array(data[128..<160])) {
                let n = Int(len.bytes.suffix(8).reduce(0) { ($0 << 8) | UInt64($1) })
                if n >= 0 && 160 + n <= data.count { returnData = Array(data[160..<160 + n]) }
            }
            return ExecutionResult(success: success, returnData: returnData)
        }
        return nil
    }
    public func ownerX() async throws -> U256 {
        try await rpc.callUint(to: address, data: ABI.encodeWithSelector("ownerX()", []))
    }
    public func ownerY() async throws -> U256 {
        try await rpc.callUint(to: address, data: ABI.encodeWithSelector("ownerY()", []))
    }

    /// Sign and relay an `execute`. The signer drives its own auth UI (the
    /// Secure Enclave shows the Face ID / Touch ID prompt automatically).
    @discardableResult
    public func execute(_ call: Call) async throws -> String {
        let chainId = try await chainId()
        let nonce = try await nonce()
        let digest = EIP712.executeDigest(
            chainId: chainId, account: address, to: call.to,
            value: call.value, data: call.data, nonce: nonce
        )
        let signature = try await signer.sign(digest: digest)
        let callData = ABI.encodeWithSelector(
            "execute(address,uint256,bytes,uint256,bytes)",
            [.address(call.to), .uint(call.value), .dynBytes(call.data), .uint(nonce), .dynBytes(signature)]
        )
        return try await relay.send(SignedAction(account: address, callData: callData, nonce: nonce))
    }

    /// Sign and relay an owner-key rotation. `newOwner` must be a real hardware key.
    @discardableResult
    public func rotateOwner(to newOwner: PublicKeyP256) async throws -> String {
        let chainId = try await chainId()
        let nonce = try await nonce()
        let digest = EIP712.rotateDigest(
            chainId: chainId, account: address, newX: newOwner.x, newY: newOwner.y, nonce: nonce
        )
        let signature = try await signer.sign(digest: digest)
        let callData = ABI.encodeWithSelector(
            "rotateOwner(uint256,uint256,uint256,bytes)",
            [.uint(newOwner.x), .uint(newOwner.y), .uint(nonce), .dynBytes(signature)]
        )
        return try await relay.send(SignedAction(account: address, callData: callData, nonce: nonce))
    }
}

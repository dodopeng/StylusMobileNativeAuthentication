import Foundation

/// A signed, ready-to-broadcast account action. `callData` is the full
/// `execute`/`rotateOwner` calldata addressed to the account contract.
public struct SignedAction {
    public let account: String
    public let callData: [UInt8]
    public let nonce: U256
}

/// Strategy for getting a signed action on-chain (sdk/SPEC.md §4).
public protocol TransactionRelay {
    /// Returns the broadcast transaction hash.
    func send(_ action: SignedAction) async throws -> String
}

/// POSTs the signed action to a relay service that pays gas and broadcasts —
/// the default gasless production path (no on-device ETH needed).
/// Wire format: `{ "account", "data", "nonce" }` → `{ "txHash" }`.
public final class HTTPRelay: TransactionRelay {
    private let url: URL
    private let session: URLSession

    public init(url: String, session: URLSession = .shared) {
        guard let u = URL(string: url) else { preconditionFailure("bad relay URL") }
        self.url = u
        self.session = session
    }

    public func send(_ action: SignedAction) async throws -> String {
        let body: [String: Any] = [
            "account": action.account,
            "data": Hex.toString(action.callData),
            "nonce": String(describing: U256AsDecimal(action.nonce)),
        ]
        var req = URLRequest(url: url)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)
        let (data, _) = try await session.data(for: req)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        if let err = json["error"] as? String { throw P256Error.rpc(err) }
        guard let hash = json["txHash"] as? String else { throw P256Error.rpc("no txHash in relay response") }
        return hash
    }
}

/// Self-relay path: the integrator supplies a closure that signs & sends a raw
/// EVM transaction (e.g. a funded secp256k1 dev EOA). Keeps the SDK free of a
/// secp256k1 dependency while supporting tests / self-hosting.
public final class BroadcasterRelay: TransactionRelay {
    public typealias Broadcaster = (_ to: String, _ data: [UInt8]) async throws -> String
    private let broadcaster: Broadcaster
    public init(_ broadcaster: @escaping Broadcaster) { self.broadcaster = broadcaster }
    public func send(_ action: SignedAction) async throws -> String {
        try await broadcaster(action.account, action.callData)
    }
}

/// Hex nonce → decimal string for the relay wire format (account nonces are
/// small, so a 64-bit window is plenty; falls back to hex for very large ones).
private func U256AsDecimal(_ v: U256) -> String {
    let trimmed = v.bytes.drop(while: { $0 == 0 })
    if trimmed.count <= 8 {
        var n: UInt64 = 0
        for b in trimmed { n = (n << 8) | UInt64(b) }
        return String(n)
    }
    return Hex.toString(Array(v.bytes))
}

import Foundation

/// Tiny Ethereum JSON-RPC client over URLSession. Only the read/broadcast paths
/// the SDK needs: `eth_call`, `eth_chainId`, `eth_sendRawTransaction`.
public final class JSONRPCClient {
    private let endpoint: URL
    private let session: URLSession

    public init(endpoint: String, session: URLSession = .shared) {
        guard let url = URL(string: endpoint) else { preconditionFailure("bad RPC URL") }
        self.endpoint = url
        self.session = session
    }

    public func chainId() async throws -> UInt64 {
        guard let hex = try await rpc("eth_chainId", []) as? String,
              hex.hasPrefix("0x"),
              let id = UInt64(hex.dropFirst(2), radix: 16), id != 0 else {
            // A wrong/zero chainId silently corrupts the EIP-712 domain and the
            // signature would be rejected on-chain with no clear cause — fail loud.
            throw P256Error.rpc("eth_chainId returned an invalid value")
        }
        return id
    }

    public func call(to: String, data: [UInt8]) async throws -> [UInt8] {
        let params: [Any] = [["to": to, "data": Hex.toString(data)], "latest"]
        let res = try await rpc("eth_call", params) as? String ?? "0x"
        return Hex.toBytes(res) ?? []
    }

    /// Reads a single uint256 (nonce / ownerX / ownerY).
    public func callUint(to: String, data: [UInt8]) async throws -> U256 {
        let ret = try await call(to: to, data: data)
        guard ret.count >= 32 else { throw P256Error.rpc("expected uint256, got \(ret.count) bytes") }
        return U256(bigEndian: Array(ret.suffix(32)))!
    }

    public func sendRawTransaction(_ rawTx: [UInt8]) async throws -> String {
        try await rpc("eth_sendRawTransaction", [Hex.toString(rawTx)]) as? String ?? ""
    }

    /// Transaction receipt, or `nil` if the tx is not yet mined.
    public func getTransactionReceipt(_ txHash: String) async throws -> [String: Any]? {
        try await rpc("eth_getTransactionReceipt", [txHash]) as? [String: Any]
    }

    private func rpc(_ method: String, _ params: [Any]) async throws -> Any? {
        let body: [String: Any] = ["jsonrpc": "2.0", "id": 1, "method": method, "params": params]
        var req = URLRequest(url: endpoint)
        req.httpMethod = "POST"
        req.setValue("application/json", forHTTPHeaderField: "Content-Type")
        req.httpBody = try JSONSerialization.data(withJSONObject: body)

        let (data, _) = try await session.data(for: req)
        let json = try JSONSerialization.jsonObject(with: data) as? [String: Any] ?? [:]
        if let err = json["error"] as? [String: Any] {
            throw P256Error.rpc("\(err["code"] ?? -1): \(err["message"] ?? "")")
        }
        return json["result"]
    }
}

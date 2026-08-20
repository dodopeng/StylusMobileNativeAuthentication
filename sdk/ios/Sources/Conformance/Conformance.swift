import Foundation
import P256Account

/// Milestone 4 conformance checks, deliberately written **without XCTest**.
///
/// XCTest is unavailable on a machine that has the Swift toolchain but not
/// Xcode (`swift test` fails with "no such module 'XCTest'"), so an
/// XCTest-only suite cannot be compiled *or* run there — the Swift templates
/// would ship unverified in exactly that setup. This target is a plain library
/// compiled by `swift build`, executed by `swift run p256account-conformance`,
/// and also called from the XCTest wrapper so there is exactly one copy of the
/// logic.
public enum Conformance {

    public struct Failure: Error, CustomStringConvertible {
        public let id: String
        public let field: String
        public let expected: String
        public let actual: String
        public var description: String {
            "\(id): \(field) mismatch\n    expected \(expected)\n    actual   \(actual)"
        }
    }

    public struct Report {
        public let checked: Int
        public let failures: [Failure]
        public var passed: Bool { failures.isEmpty }
    }

    /// Templates that must carry ETH value. A template that silently dropped
    /// `value` would encode correctly and only fail on-chain.
    static let payable: Set<String> = ["native.transfer", "weth.deposit", "univ2.swapExactETHForTokens"]

    /// Run every golden vector in `sdk/actions.golden.json` against the SDK.
    public static func run(goldenPath: String? = nil) throws -> Report {
        let url = try goldenURL(explicit: goldenPath)
        let obj = try JSONSerialization.jsonObject(with: try Data(contentsOf: url))
        guard let root = obj as? [String: Any],
              let fx = root["fixtures"] as? [String: String],
              let entries = root["templates"] as? [[String: Any]]
        else { throw Failure(id: "<file>", field: "shape", expected: "fixtures+templates", actual: "malformed") }

        let built = try buildTemplates(from: fx)
        var failures: [Failure] = []

        for t in entries {
            guard let id = t["id"] as? String,
                  let wantTo = t["to"] as? String,
                  let wantValueStr = t["value"] as? String,
                  let wantData = t["data"] as? String,
                  let wantValue = U256(decimal: wantValueStr)
            else {
                failures.append(Failure(id: "<entry>", field: "shape", expected: "id/to/value/data", actual: "\(t)"))
                continue
            }
            guard let call = built[id] else {
                failures.append(Failure(id: id, field: "implementation", expected: "a Swift template", actual: "none"))
                continue
            }
            if call.to.lowercased() != wantTo.lowercased() {
                failures.append(Failure(id: id, field: "to", expected: wantTo, actual: call.to))
            }
            if call.value != wantValue {
                failures.append(Failure(id: id, field: "value",
                                        expected: "\(wantValueStr) (\(Hex.toString(wantValue.data)))",
                                        actual: Hex.toString(call.value.data)))
            }
            let gotData = Hex.toString(call.data).lowercased()
            if gotData != wantData.lowercased() {
                failures.append(Failure(id: id, field: "data", expected: wantData, actual: gotData))
            }
        }

        // No Swift template may be absent from the golden file.
        let goldenIds = Set(entries.compactMap { $0["id"] as? String })
        for id in built.keys.sorted() where !goldenIds.contains(id) {
            failures.append(Failure(id: id, field: "coverage", expected: "a golden vector", actual: "none"))
        }

        // Payable set must be exactly as declared.
        for (id, call) in built {
            let carries = call.value > U256(0)
            if payable.contains(id) && !carries {
                failures.append(Failure(id: id, field: "payable", expected: "value > 0", actual: "0"))
            }
            if !payable.contains(id) && carries {
                failures.append(Failure(id: id, field: "payable", expected: "value == 0", actual: "> 0"))
            }
        }

        // executeBatch calldata — `bytes[]` is doubly dynamic and hand-rolled in
        // every SDK, so pin it against cast rather than trusting three
        // independent implementations of the same tricky layout.
        if let batches = root["batch"] as? [[String: Any]] {
            for b in batches {
                guard let id = b["id"] as? String,
                      let tos = b["to"] as? [String],
                      let values = b["value"] as? [String],
                      let datas = b["calldata"] as? [String],
                      let nonceStr = b["nonce"] as? String,
                      let sigHex = b["signature"] as? String,
                      let want = b["encoded"] as? String,
                      let nonce = U256(decimal: nonceStr),
                      let sig = Hex.toBytes(sigHex)
                else {
                    failures.append(Failure(id: "<batch>", field: "shape",
                                            expected: "to/value/calldata/nonce/signature/encoded",
                                            actual: "\(b)"))
                    continue
                }
                do {
                    let vals = try values.map { v -> U256 in
                        guard let u = U256(decimal: v) else {
                            throw Failure(id: id, field: "value", expected: "decimal", actual: v)
                        }
                        return u
                    }
                    let payloads = try datas.map { d -> [UInt8] in
                        guard let b = Hex.toBytes(d) else {
                            throw Failure(id: id, field: "calldata", expected: "hex", actual: d)
                        }
                        return b
                    }
                    let got = try ABI.encodeWithSelector(
                        "executeBatch(address[],uint256[],bytes[],uint256,bytes)",
                        [.addressArray(tos), .uintArray(vals), .bytesArray(payloads),
                         .uint(nonce), .dynBytes(sig)]
                    )
                    let gotHex = Hex.toString(got).lowercased()
                    if gotHex != want.lowercased() {
                        failures.append(Failure(id: "batch.\(id)", field: "encoded",
                                                expected: want, actual: gotHex))
                    }

                    // The DIGEST is what the signature actually covers. Pinning
                    // only the calldata would let batchDigest drift silently.
                    if let wantDigest = b["digest"] as? String,
                       let chainIdStr = b["chainId"] as? String,
                       let account = b["account"] as? String,
                       let chainId = UInt64(chainIdStr) {
                        let calls = zip(zip(tos, vals), payloads).map { pair in
                            Call(to: pair.0.0, value: pair.0.1, data: pair.1)
                        }
                        let gotDigest = try EIP712.batchDigest(
                            chainId: chainId, account: account, calls: calls, nonce: nonce)
                        let gotDigestHex = Hex.toString(gotDigest).lowercased()
                        if gotDigestHex != wantDigest.lowercased() {
                            failures.append(Failure(id: "batch.\(id)", field: "digest",
                                                    expected: wantDigest, actual: gotDigestHex))
                        }
                    }
                } catch let f as Failure {
                    failures.append(f)
                }
            }
        }

        // EIP-1271 PersonalSign wrapper. The golden deliberately wraps an
        // Execute digest — the exact value an attacker would present as a
        // "login challenge" — so this pins the case the wrapper exists for.
        if let entries = root["personalSign"] as? [[String: Any]] {
            for e in entries {
                guard let chainIdStr = e["chainId"] as? String,
                      let chainId = UInt64(chainIdStr),
                      let account = e["account"] as? String,
                      let hashHex = e["hash"] as? String,
                      let wantDigest = e["digest"] as? String,
                      let hash = Hex.toBytes(hashHex)
                else {
                    failures.append(Failure(id: "personalSign", field: "shape",
                                            expected: "chainId/account/hash/digest", actual: "\(e)"))
                    continue
                }
                do {
                    let got = try EIP712.personalSignDigest(
                        chainId: chainId, account: account, hash: hash)
                    let gotHex = Hex.toString(got).lowercased()
                    if gotHex != wantDigest.lowercased() {
                        failures.append(Failure(id: "personalSign", field: "digest",
                                                expected: wantDigest, actual: gotHex))
                    }
                    if gotHex == hashHex.lowercased() {
                        failures.append(Failure(id: "personalSign", field: "wrapping",
                                                expected: "a digest distinct from the raw hash",
                                                actual: "the raw hash — the 1271 exploit is open"))
                    }
                } catch let f as Failure {
                    failures.append(f)
                }
            }
        }

        // The contract's MAX_BATCH_CALLS, read out of lib.rs by the golden
        // generator. Catches an SDK constant drifting from the contract.
        if let limits = root["limits"] as? [String: Any],
           let maxBatch = limits["maxBatchCalls"] as? Int,
           maxBatch != P256AccountLimits.maxBatchCalls {
            failures.append(Failure(id: "limits", field: "maxBatchCalls",
                                    expected: "\(maxBatch) (contract)",
                                    actual: "\(P256AccountLimits.maxBatchCalls) (Swift SDK)"))
        }

        return Report(checked: entries.count, failures: failures)
    }

    /// Every template, built from the golden file's own fixture values.
    static func buildTemplates(from fx: [String: String]) throws -> [String: Call] {
        func addr(_ k: String) throws -> String {
            guard let v = fx[k] else { throw Failure(id: "<fixtures>", field: k, expected: "an address", actual: "missing") }
            return v
        }
        func num(_ k: String) throws -> U256 {
            guard let s = fx[k], let v = U256(decimal: s) else {
                throw Failure(id: "<fixtures>", field: k, expected: "a decimal uint", actual: fx[k] ?? "missing")
            }
            return v
        }

        let alice = try addr("alice"), bob = try addr("bob")
        let token = try addr("token"), token2 = try addr("token2")
        let router = try addr("router"), pool = try addr("pool")
        let nft = try addr("nft"), weth = try addr("weth")
        let amount = try num("amount"), amountMin = try num("amountMin")
        let wei = try num("wei"), tokenId = try num("tokenId")
        let deadline = try num("deadline"), variable = try num("interestRateModeVariable")

        return [
            "native.transfer": try Native.transfer(to: bob, amountWei: wei),

            "erc20.transfer": try Erc20.transfer(token: token, to: bob, amount: amount),
            "erc20.approve": try Erc20.approve(token: token, spender: router, amount: amount),
            "erc20.transferFrom": try Erc20.transferFrom(token: token, from: alice, to: bob, amount: amount),

            "erc721.safeTransferFrom": try Erc721.safeTransferFrom(nft: nft, from: alice, to: bob, tokenId: tokenId),
            "erc721.approve": try Erc721.approve(nft: nft, to: bob, tokenId: tokenId),
            "erc721.setApprovalForAll": try Erc721.setApprovalForAll(nft: nft, operator: bob, approved: true),

            "weth.deposit": try Weth.deposit(weth: weth, amountWei: wei),
            "weth.withdraw": try Weth.withdraw(weth: weth, amount: amount),

            "univ2.swapExactTokensForTokens": try UniswapV2.swapExactTokensForTokens(
                router: router, amountIn: amount, amountOutMin: amountMin,
                path: [token, token2], to: alice, deadline: deadline),
            "univ2.swapExactETHForTokens": try UniswapV2.swapExactETHForTokens(
                router: router, amountInWei: wei, amountOutMin: amountMin,
                path: [weth, token], to: alice, deadline: deadline),
            "univ2.swapExactTokensForETH": try UniswapV2.swapExactTokensForETH(
                router: router, amountIn: amount, amountOutMin: amountMin,
                path: [token, weth], to: alice, deadline: deadline),

            "aave.supply": try AaveV3.supply(pool: pool, asset: token, amount: amount, onBehalfOf: alice),
            "aave.borrow": try AaveV3.borrow(pool: pool, asset: token, amount: amount,
                                         interestRateMode: variable, onBehalfOf: alice),
            "aave.repay": try AaveV3.repay(pool: pool, asset: token, amount: amount,
                                       interestRateMode: variable, onBehalfOf: alice),
            "aave.withdraw": try AaveV3.withdraw(pool: pool, asset: token, amount: amount, to: alice),
        ]
    }

    /// Resolve `sdk/actions.golden.json` relative to this source file so the
    /// checks work under `swift run`, `swift test`, Xcode, and CI alike.
    static func goldenURL(explicit: String?) throws -> URL {
        if let explicit { return URL(fileURLWithPath: explicit) }
        var dir = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
        for _ in 0..<8 {
            let candidate = dir.appendingPathComponent("actions.golden.json")
            if FileManager.default.fileExists(atPath: candidate.path) { return candidate }
            dir = dir.deletingLastPathComponent()
        }
        throw Failure(id: "<file>", field: "actions.golden.json",
                      expected: "found above \(#filePath)",
                      actual: "missing — run sdk/tooling/scripts/gen-actions-golden.sh")
    }
}

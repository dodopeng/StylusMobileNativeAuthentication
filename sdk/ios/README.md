# P256Account — iOS SDK (Milestone 3)

Native iOS SDK for the Arbitrum Stylus `P256Account` smart account. Generates a
non-exportable P-256 key in the **Secure Enclave**, gates every signature behind
Face ID / Touch ID, builds the exact EIP-712 digest the contract verifies, and
relays the signed `execute` / `rotateOwner` call on-chain.

- Pure-Swift Keccak-256, ABI, and EIP-712 (no third-party dependencies).
- The private key never leaves the Secure Enclave; only `(x, y)` is exported.
- Signs with `.ecdsaSignatureDigestX962SHA256` so the ECDSA message hash equals
  the keccak digest — what RIP-7212 verifies (see `sdk/SPEC.md` §2).

## Requirements

- iOS 16+ (Secure Enclave P-256 + async/await). Real Secure Enclave needs a
  physical device; on the Simulator use `SoftwareP256Signer` (a drop-in
  `SignProvider` with the identical `.ecdsaSignatureDigestX962SHA256` algorithm
  but a software key) — the example app selects it automatically under
  `#if targetEnvironment(simulator)`, so the full pipeline runs without an enclave.

## Quick start

```swift
import P256Account

// 1. Create a Secure Enclave key (once). Register (x, y) on-chain by deploying
//    the contract: cargo stylus deploy --constructor-args <x> <y>.
let signer = SecureEnclaveSigner(tag: "xyz.heavenlydev.account", requireBiometric: true)
if !signer.exists() {
    let pub = try signer.create()        // pub.x / pub.y -> constructor args
}

// 2. Operate an already-deployed account.
let rpc   = JSONRPCClient(endpoint: "https://arb1.arbitrum.io/rpc")
let relay = HTTPRelay(url: "https://your-relayer.example/relay")   // gasless
let account = P256AccountClient(
    address: "0xYourDeployedAccount", rpc: rpc, relay: relay, signer: signer)

// 3. Do things — each call triggers Face ID (the enclave shows it), then relays.
let txHash = try await account.execute(Erc20.transfer(token: usdc, to: recipient, amount: U256(decimal: "1000000")!))
try await account.execute(UniswapV2.swapExactTokensForTokens(
    router: router, amountIn: amt, amountOutMin: minOut, path: [usdc, weth],
    to: account.address, deadline: U256(deadline)))
try await account.rotateOwner(to: try newSigner.create())

// 4. A tx hash does NOT mean the inner action succeeded — the contract returns
//    (success, returnData) without reverting. Confirm the real outcome:
let result = try await account.awaitExecuted(txHash: txHash)
if !result.success { /* the inner call reverted; result.returnData has the revert bytes */ }
```

### Safety notes

- `signer.create()` / `signer.publicKey()` **validate the key is on-curve**
  (`PublicKeyP256.init` throws otherwise) — an off-curve owner would permanently
  brick the account, so `rotateOwner(to:)` is guarded too.
- By default the key uses `.biometryAny`, so it **survives biometric
  re-enrollment**. Pass `invalidateOnEnrollment: true` for the stricter
  `.biometryCurrentSet` (more tamper-resistant, but re-enrollment destroys the
  key — only safe if you maintain a separate rotation/recovery path).

## Layout

```
Sources/P256Account/
  Keccak256.swift          pure-Swift Keccak-256 (verified vs cast)
  Hex.swift / U256.swift   hex + fixed-width 256-bit integer
  P256Curve.swift          DER→raw r‖s, strict low-S
  SecureEnclaveSigner.swift Secure Enclave key gen + biometric signing
  EIP712.swift             digest construction (typehashes pinned to contract)
  ABI.swift                ABI encoder + keccak-derived selectors
  JSONRPC.swift / Relay.swift  RPC client + HTTPRelay / BroadcasterRelay
  P256Account.swift        P256AccountClient, Call
  Actions.swift            Erc20 · Erc721 · UniswapV2 · AaveV3 (Milestone 4)
Tests/P256AccountTests/    InteropTests (golden vectors, parity with Android)
```

## Build & test

```bash
cd sdk/ios
swift build                 # builds the library (verified on Swift 6)
swift test                  # runs InteropTests (requires Xcode for XCTest)
```

The interop logic (Keccak / EIP-712 / ABI / low-S) is covered by `InteropTests`
with the same golden vectors as the Android SDK, so both platforms are proven to
produce byte-identical signatures and calldata for the contract.

> The example app in the milestone deliverables is a thin SwiftUI wrapper around
> the Quick start; the SDK surface and interop tests are the substantive part.

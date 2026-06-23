# Mocks & Simulators — what's faked, and what each proves

Two things in this stack cannot run in a headless/CI environment: **hardware
signing** (StrongBox / Secure Enclave need a real device) and a **live chain**
(the Stylus contract + RIP-7212 precompile need a Nitro devnode). Everything
else is real. To verify the pipeline anyway, each un-runnable piece has a mock
that uses the *identical* algorithm/semantics as the real thing.

The guiding rule: a mock replaces *where the key lives* or *where the contract
runs*, never *what is computed*. So a signature or a calldata that passes a mock
is byte-identical to one that would hit production.

| Mock | Stands in for | Runs | Proves | Does NOT prove |
|------|---------------|------|--------|----------------|
| `tooling/src/reference/ReferenceSigner` (noble) | StrongBox / Secure Enclave | here ✓ | raw low-S P-256 sign+verify over the digest == RIP-7212 | that hardware supports raw signing |
| `tooling/src/e2e/SimulatedAccount` | the on-chain contract + RIP-7212 precompile | here ✓ | the SDK's real encode → digest → verify → nonce, plus replay / wrong-nonce / tamper / high-S / off-curve-rotation / revert-still-bumps-nonce | the actual Stylus WASM bytecode + precompile |
| iOS `SoftwareP256Signer` | `SecureEnclaveSigner` | here ✓ (alg) + Simulator | `.ecdsaSignatureDigestX962SHA256` signs `e = digest`, verifies under noble, low-S | that the Secure Enclave supports that algorithm (it does, per Apple docs) |
| Android `SoftwareP256Signer` | `StrongBoxP256Signer` | their CI (JVM) | `NONEwithECDSA` signs `e = digest`, verifies, low-S | that a given StrongBox/TEE supports `DIGEST_NONE` keys |
| `HTTPRelay` ⇄ relayer / `SimulatedAccount.submit` | a production relayer + chain | here ✓ | the `{account, data, nonce}` wire format round-trips | a hardened, funded production relayer |

## What was actually executed on this machine

```
tooling:  17/17 tests pass — incl. 8 simulator cases (happy path, replay,
          wrong nonce, tamper, high-S, rotateOwner takeover, off-curve reject,
          A2 revert-still-bumps-nonce)
iOS:      SoftwareP256Signer signed a 32-byte digest with the enclave's exact
          algorithm; noble verified it over the RAW digest (== RIP-7212),
          confirmed low-S, and confirmed it is NOT a signature over sha256(digest)
```

The iOS cross-check is the important one: signing was done by Apple's Security
framework (`.ecdsaSignatureDigestX962SHA256`) and verification by an independent
library (noble, the same math the precompile runs). Agreement means the SDK's
signing algorithm is contract-correct regardless of where the key lives.

## How to run the mocks

```bash
# TS reference + simulator (no devnode, no hardware)
cd sdk/tooling && npm install && npm test

# iOS software signer + interop (Simulator / macOS; XCTest needs Xcode)
cd sdk/ios && swift test
# the example app auto-selects SoftwareP256Signer under #if targetEnvironment(simulator)

# Android software-signer JVM test (no device, no Android framework)
cd sdk/android && ./gradlew :p256account:testDebugUnitTest
```

## The residual — what still needs real hardware / a real chain

Mocks can't close these; they need the physical thing:

1. **Does the secure element actually support raw signing?** iOS Secure Enclave
   `.ecdsaSignatureDigestX962SHA256` — documented yes. Android StrongBox/TEE
   `DIGEST_NONE` — **device-dependent**; some secure elements reject it, in which
   case the key falls back to TEE or the approach needs revisiting. This is the
   single highest-risk unknown and only a device test settles it.
2. **The real contract + precompile on a chain.** Covered by
   `contracts/stylus/devnode-tests` (Rust, real P-256 sigs on a Nitro devnode)
   and the live `tooling/src/e2e/roundtrip.ts`. Both need a running devnode.

Everything between the signer and the contract — digest construction, ABI
encoding, low-S, nonce/replay handling, relay wire format, receipt decoding — is
proven here in software.

# Mobile SDK Stack

Mobile-native client SDKs for the Arbitrum Stylus `P256Account` smart account
(see `../contracts/stylus`). Together with the contract these implement
Milestones 2–4 of the grant.

| Milestone | Component | Path | Status |
|-----------|-----------|------|--------|
| M2 | Android SDK | [`android/`](android) | core complete + golden interop tests; example app |
| M3 | iOS SDK | [`ios/`](ios) | core complete, builds on Swift 6; interop verified; example app |
| M4 | Action templates | `*/action[s]` (Erc20 · Erc721 · UniswapV2 · AaveV3) | complete in both SDKs |
| — | Relayer + e2e + reference signer | [`tooling/`](tooling) | relayer service, round-trip harness, 9 passing tests |

The single source of truth for how the SDKs talk to the contract — signature
format, EIP-712 digest, ABI selectors, submission model — is **[`SPEC.md`](SPEC.md)**.
Both SDKs are tested against the *same* golden vectors derived from the contract,
so an Android signature and an iOS signature for the same action are byte-identical
and both verify on-chain.

## What each SDK does

1. Generates a non-exportable **P-256 key in hardware** (Android StrongBox/TEE,
   iOS Secure Enclave) and exports only the public key `(x, y)` — the on-chain
   account owner.
2. Reads the account's `nonce()` / `chainId` over JSON-RPC.
3. Builds the **EIP-712 digest** the contract expects and asks the hardware to
   **sign it behind a biometric** (Face ID / fingerprint), producing canonical
   64-byte `r‖s` (strict low-S, raw ECDSA over the digest — what RIP-7212 checks).
4. ABI-encodes `execute` / `rotateOwner` and hands it to a **relayer** that pays
   gas and broadcasts (the gasless mobile UX) — or to a self-relay broadcaster.
5. Ships **action templates** that produce ready-to-execute calls for the most
   common Arbitrum DeFi operations (ERC-20, ERC-721, Uniswap-V2 swaps, Aave-V3
   supply/borrow).

## Verifying interop

Selectors and typehashes were derived from the contract and checked with `cast`;
the Keccak-256 implementations were validated byte-for-byte against `cast keccak`.
Three independent implementations (Kotlin, Swift, TypeScript) reproduce the
*same* golden vectors, and the TS reference additionally does a real P-256
sign→verify, proving an SDK-shaped signature is on-chain valid.

```bash
# TypeScript reference + relayer guards (9 tests, runs anywhere)
cd tooling && npm install && npm test

# iOS (pure logic builds on Swift 6)
cd ios && swift build

# Android (JVM unit tests, golden vectors)
cd android && ./gradlew :p256account:testDebugUnitTest
```

## End-to-end

A full **sign → relay → on-chain** round trip is in [`tooling/`](tooling): the
[relayer service](tooling/src/relayer) (gasless `HttpRelay` wire format) plus the
[round-trip harness](tooling/src/e2e/roundtrip.ts) that deploys an account, signs
an `execute`, relays it, and asserts the nonce bumped — verifying the signature
through the RIP-7212 precompile. Hardware keys can't run headless, so the harness
uses a software P-256 signer identical in output to the enclave; the contract
side is independently proven by `../contracts/stylus/devnode-tests`.

For the parts that can't run without a device or a live chain, [`MOCKS.md`](MOCKS.md)
catalogs the mocks — a faithful in-memory **contract simulator**
([`SimulatedAccount`](tooling/src/e2e/simulator.ts)) and software signers on both
platforms — and exactly what each one proves vs. leaves to a device/devnode. The
simulator runs the SDK's *real* encoding through the contract's full security
model (replay, tamper, high-S, off-curve, revert-still-bumps-nonce) with no
devnode.

## Runnable example apps

- [`android/example`](android/example) — `./gradlew :example:installDebug`
- [`ios/Example`](ios/Example) — `xcodegen generate && open P256Example.xcodeproj`

Each: create a hardware key → deploy with the shown `(x, y)` → sign & relay a
test `execute` behind a biometric.

## Still external by design

- **Account deployment** is done via `cargo stylus deploy --constructor-args
  <x> <y>` in `../contracts/stylus` (the SDKs surface the `(x, y)` to use).
- The **relayer in `tooling/` is a reference** — production deployments can use
  any bundler/relayer that honours the `SPEC.md` §4 wire format.

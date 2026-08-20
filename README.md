# Stylus Mobile Native Authentication

First-ever RIP-7212 / P-256 (secp256r1) signature support on Arbitrum Stylus, powering a mobile-native smart account that signs transactions using hardware-backed keys (iOS Secure Enclave, Android StrongBox / passkeys).

### What "RIP-7212 support" means here — precisely

RIP-7212 is a **precompile specification**, not a library. This project does not
reimplement secp256r1 curve arithmetic; the account *consumes* the precompile at
`0x0000…0100`, passing it `(hash, r, s, x, y)` and acting on the result. That is
the correct and intended way to use RIP-7212 — reimplementing the curve in
contract code would be strictly slower and less safe.

This matters for one claim in the grant application, which says the
implementation is "written in Rust for maximum performance … at a fraction of
the gas cost of existing pure Solidity implementations." To be exact:

- The **gas saving vs. Solidity P-256 libraries is the precompile's**, not
  Rust's. Any contract on a chain with RIP-7212 enabled gets it.
- What **Stylus/Rust contributes** is the account itself — the EIP-712
  authorisation logic, nonce and replay handling, batch execution, and the
  receiver hooks — at Stylus's execution cost rather than the EVM's, in a
  language where the 256-bit and byte-layout work is checked at compile time.

The novel part is that this is the first account on Arbitrum Stylus wired to
RIP-7212 with a full mobile signing stack on top, not a novel implementation of
the curve. The M5 report should state it this way.

## Status

Code-complete milestones are marked done; the remaining boxes are gated on a
mainnet deployment, not on unwritten code. See [Outstanding](#outstanding).

- [x] **Milestone 1** — Mobile Smart Account on Stylus (RIP-7212 / P-256)
      · 75 host tests, 98.7% coverage of the authentication functions, batch
      execution, curve-membership validation, EIP-1271 `PersonalSign` domain
      separation, ERC-721/1155 receiver hooks · **not yet deployed to Arbitrum One**
- [x] **Milestone 2** — Android SDK · 17 JVM tests (Kotlin + a Java interop
      suite), StrongBox/TEE signer, example app, `maven-publish` configured
- [x] **Milestone 3** — iOS SDK · Secure Enclave signer, 16/16 template
      conformance runnable without Xcode, example app
- [x] **Milestone 4** — [Action templates](sdk/ACTIONS.md) · 16 templates × 3
      SDKs, golden-vector verified · **live-chain run pending M1 deployment**
- [ ] **Milestone 5** — Final report

## Structure

```
contracts/
  stylus/
    Cargo.toml             workspace root
    rust-toolchain.toml
    coverage.sh            M1 KPI: coverage of the authentication functions
    p256-account/          single-key P-256 smart account
      Cargo.toml
      Stylus.toml
      src/lib.rs           contract + #[cfg(test)] precompile shim
    devnode-tests/         end-to-end harness against a Nitro devnode
      Cargo.toml
      src/main.rs          deploy + sign + cast + assert
      README.md

sdk/                       mobile SDK stack (Milestones 2–4) — see sdk/README.md
  SPEC.md                  canonical wire format the SDKs implement
  ACTIONS.md               the 16 action templates + usage
  MOCKS.md                 what every mock proves, and what it does not
  actions.golden.json      cast-generated golden vectors (single source of truth)
  android/                 Kotlin SDK + example app
  ios/                     Swift SDK + example app + conformance CLI
  tooling/                 TS reference, relayer, simulator, e2e harnesses
```

## Verifying everything

```bash
cargo test -p p256-account --lib          # 75 contract tests   (contracts/stylus)
contracts/stylus/coverage.sh              # M1 coverage KPI     (needs cargo-llvm-cov)
cd sdk/tooling && npm test                # 70 tests            (needs node)
cd sdk/tooling && npm run bench           # M2 timing KPI, SDK compute leg
cd sdk/ios && swift run p256account-conformance   # 16/16 templates + 6 nonce checks, no Xcode needed
cd sdk/android && ./gradlew :p256account:testDebugUnitTest   # 24 tests (needs JDK 17 + Android SDK)
```

## Outstanding

The work that is *not* done, stated plainly:

1. **No Arbitrum One deployment.** Gates the M1 KPI ("deployed and verified on
   mainnet") and the M4 KPI ("each template tested end-to-end on Arbitrum One").
   No address or tx hash exists yet. The release wasm is comfortably under the
   128 KB a Nitro devnode is configured for, but the Arbitrum One limit has not
   been demonstrated on-chain. **The exact size is not repeated here** — it
   drifted from the real figure three revisions running. CI prints it to the job
   summary and fails the build above 128 KB; measure locally with:
   `stat -f%z contracts/stylus/target/wasm32-unknown-unknown/release/p256_account.wasm`

2. **Android SDK is configured for publishing but not published.**
   `maven-publish` produces a verified local Maven layout
   (`:p256account:publishReleasePublicationToLocalRepository`); pushing to
   GitHub Packages still needs credentials and a release tag.
3. **CI has never run.** `.github/workflows/ci.yml` exists and covers all five
   suites (contract, devnode end-to-end, TypeScript, iOS, Android) plus
   golden-drift and wasm-size checks, but no push has exercised it, so the
   workflow itself is unverified — the devnode job in particular has never
   spun up a node.
4. **Biometric round-trip time (M2 KPI, <30s) is only partly measured.**
   `cd sdk/tooling && npm run bench` measures the SDK compute leg — EIP-712
   digest + P-256 sign + ABI encode — at **0.274 ms p95**, i.e. 0.0009% of the
   30s budget. The two legs that dominate it are still open: the hardware sign
   plus biometric prompt (needs a device) and the chain confirmation (needs a
   deployment; `npm run bench -- --chain` measures it once one exists).
5. **`tooling/src/e2e/actions-live.ts` has never been executed** — there is no
   deployed account to run it against. Treat it as untested code.
6. **Milestone 5 report** is not written.

## Milestone 1 — Mobile Smart Account on Stylus

A custom-AA smart account written in Rust on Arbitrum Stylus. The account is owned by a single P-256 public key. Every state-changing call (`execute`, `rotate_owner`) requires a valid P-256 signature, verified on-chain through the RIP-7212 precompile at address `0x0000…0100`.

**Signature format:** 64 bytes (`r ‖ s`).
- `r` must lie in `(0, n)` (curve order).
- `s` must lie in `(0, n/2]` — strict low-S to block ECDSA malleability.

**Message hash — EIP-712 envelope, one typehash per message kind.** Every signable message is an EIP-712 envelope over a distinct typehash, including the EIP-1271 challenge wrapper. The envelope alone is not what provides the separation — see the EIP-1271 note below.

- **Domain:** `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)` with `name="P256Account"`, `version="1"`. The `chainId` and `verifyingContract` are read on-chain from the runtime.
- **`execute` struct:** `Execute(address to,uint256 value,bytes data,uint256 nonce)`.
- **`rotate_owner` struct:** `RotateOwner(uint256 newX,uint256 newY,uint256 nonce)`.
- **`execute_batch` struct:** `BatchExecute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)`.
- **EIP-1271 struct:** `PersonalSign(bytes32 hash)`.
- **Digest:** `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`.

All four struct typehashes differ, so a signature for one message kind can never be replayed as another, even with matching `(chainId, account, nonce)`.

**Owner rotation.** `rotate_owner(newX, newY, nonce, signature)` takes a P-256 signature from the *current* owner over the `RotateOwner` typed struct. Shares the monotonic nonce with `execute` (so rotation consumes a nonce slot too). The new key's components must each lie in `(0, p)` **and the point must be on the P-256 curve** — verified on-chain as `y² ≡ x³ − 3x + b (mod p)`. Rotating to an off-curve point would permanently brick the account, so the contract rejects it rather than relying on client-side care.

**EIP-1271.** `isValidSignature(bytes32 hash, bytes signature) → bytes4` is exposed for off-chain signature checking (returns `0x1626ba7e` on success, `0x00000000` on failure, never reverts). The supplied `hash` is verified against `PersonalSign(bytes32 hash)`, **not** raw.

This is a correctness requirement, not a nicety. An earlier version verified the raw hash and argued the `execute` envelope made collision infeasible. That was wrong: an `Execute` digest is itself a 32-byte hash whose every input is public, so an attacker could compute the digest for `execute(to: attacker, value: 1 ETH)`, present it as a login challenge, and receive a valid transfer authorisation from the user's biometric prompt. The `PersonalSign` typehash makes the domains disjoint structurally. See [`sdk/SPEC.md`](sdk/SPEC.md) §2d.

### Build

```bash
cd contracts/stylus
# Build only the contract crate for wasm32 — the devnode-tests crate
# pulls in getrandom and can't target wasm32-unknown-unknown.
cargo build --release --target wasm32-unknown-unknown -p p256-account
```

### Test (host-side unit tests)

```bash
cd contracts/stylus
cargo test -p p256-account --lib
```

50 host-side tests cover constants, EIP-712 typehashes, hash determinism, the precompile input layout, every error arm of `validate_p256_signature` (length, `InvalidR`, `InvalidS`, `HighS`, `InvalidSignature`, happy path) via a `#[cfg(test)]` precompile shim, and the pure state-machine validators (`validate_constructor_args`, `validate_execute_request`, `validate_rotation_request`, `execute_outcome`, `eip1271_response`).

### Test (end-to-end on a Nitro devnode)

Requires a running Nitro devnode, cargo-stylus **0.6.x** (the constructor flags weren't added until 0.6.0), and foundry's `cast` on `PATH`. See [`contracts/stylus/devnode-tests/README.md`](contracts/stylus/devnode-tests/README.md) for the full setup.

```bash
cd contracts/stylus
cargo run -p devnode-tests --release
```

Verified against Nitro `v3.7.1-926f1ab` (chain id 412346), cargo-stylus 0.6.1, cast 1.5.1 — all five tests pass:
- `happy_path` — `execute` with valid sig, nonce 0 → 1
- `reverting_target_consumes_nonce` — nonce-before-call invariant ([SPEC.md §5](sdk/SPEC.md#5-nonce--replay-rules-from-the-contract)): inner-call revert still bumps the nonce; receipt's `Executed.returnData` carries the revert payload
- `value_exceeds_balance` — funds account with 1 wei, attempts to send 2 wei → `Executed.success = false` with balance unchanged. Pins down stylus-sdk's mapping of insufficient-balance CALL: it's `Err(Revert)` not `Ok(empty)`, so no `vm().balance()` guard is needed in the contract
- `rotate_owner` — ownership transition + nonce
- `nonce_monotonicity` — chained `execute → rotate → execute` with the new key

The harness deploys a fresh account per test via `cargo stylus deploy --wasm-file … --constructor-signature 'constructor(uint256,uint256)' --constructor-args $X $Y`, so the Stylus constructor (atomic ownership initialisation) is genuinely exercised.

### Deploy

The owner public key `(x, y)` is set atomically by the Stylus constructor. **Do not** deploy without supplying `--constructor-signature` and `--constructor-args` — the contract will activate with `owner = (0, 0)` and no signature will ever verify, bricking the deployment.

```bash
cd contracts/stylus/p256-account

# X and Y are the P-256 public-key coordinates as uint256 (decimal or 0x-hex)
OWNER_X=0xc3964…   # 32-byte field element
OWNER_Y=0xd4a4f…   # 32-byte field element

cargo stylus deploy \
    --no-verify \
    --endpoint <ARB_RPC> \
    --private-key <KEY> \
    --constructor-signature 'constructor(uint256,uint256)' \
    --constructor-args "$OWNER_X" "$OWNER_Y"
```

## Requirements

- Rust + `wasm32-unknown-unknown` target (`rustup target add wasm32-unknown-unknown`)
- `cargo stylus` CLI **0.6.x** for deploy / activation (`cargo install --locked cargo-stylus@0.6.1`). 0.5.x predates constructor support; 0.10+ needs rustc ≥ 1.87.
- Arbitrum One, Arbitrum Sepolia, or any Orbit chain with the RIP-7212 precompile enabled
- The release wasm is **well above the default EIP-170 24 KB code limit** — it has grown substantially past the original ~64 KB with re-entrancy support, batch execution, curve-membership validation and the token receiver hooks. Orbit chains must raise their per-contract size cap (Nitro devnode: `./run-dev-node.sh --contract-size 128000`). Arbitrum One/Sepolia already permit this size.
  - **Measure it, don't trust a number in this file** — a hardcoded figure here drifted from reality three revisions running, and this is the line an operator sizing an Orbit cap would act on:
    `stat -f%z contracts/stylus/target/wasm32-unknown-unknown/release/p256_account.wasm`
    CI prints the exact size to the job summary and fails the build above 128 KB.

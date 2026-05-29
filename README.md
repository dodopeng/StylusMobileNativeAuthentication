# Stylus Mobile Native Authentication

First-ever RIP-7212 / P-256 (secp256r1) signature support on Arbitrum Stylus, powering a mobile-native smart account that signs transactions using hardware-backed keys (iOS Secure Enclave, Android StrongBox / passkeys).

## Status

- [ ] Milestone 1: Mobile Smart Account on Stylus (RIP-7212 / P-256)
- [ ] Milestone 2: Android SDK
- [ ] Milestone 3: iOS SDK
- [ ] Milestone 4: Common Blockchain Action Templates
- [ ] Milestone 5: Final report

## Structure

```
contracts/
  stylus/
    Cargo.toml             workspace root
    rust-toolchain.toml
    p256-account/          single-key P-256 smart account
      Cargo.toml
      Stylus.toml
      src/lib.rs           contract + #[cfg(test)] precompile shim
    devnode-tests/         end-to-end harness against a Nitro devnode
      Cargo.toml
      src/main.rs          deploy + sign + cast + assert
      README.md
```

## Milestone 1 — Mobile Smart Account on Stylus

A custom-AA smart account written in Rust on Arbitrum Stylus. The account is owned by a single P-256 public key. Every state-changing call (`execute`, `rotate_owner`) requires a valid P-256 signature, verified on-chain through the RIP-7212 precompile at address `0x0000…0100`.

**Signature format:** 64 bytes (`r ‖ s`).
- `r` must lie in `(0, n)` (curve order).
- `s` must lie in `(0, n/2]` — strict low-S to block ECDSA malleability.

**Message hash — EIP-712 envelope.** A plain `keccak256(...)` would let any 32-byte challenge presented via EIP-1271 collide with a valid `execute` digest; the EIP-712 prefix prevents that.

- **Domain:** `EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)` with `name="P256Account"`, `version="1"`. The `chainId` and `verifyingContract` are read on-chain from the runtime.
- **`execute` struct:** `Execute(address to,uint256 value,bytes data,uint256 nonce)`.
- **`rotate_owner` struct:** `RotateOwner(uint256 newX,uint256 newY,uint256 nonce)`.
- **Digest:** `keccak256(0x1901 ‖ domainSeparator ‖ structHash)`.

The two struct typehashes differ, so a rotation signature can never be replayed as an execute signature (and vice versa) even with matching `(chainId, account, nonce)`.

**Owner rotation.** `rotate_owner(newX, newY, nonce, signature)` takes a P-256 signature from the *current* owner over the `RotateOwner` typed struct. Shares the monotonic nonce with `execute` (so rotation consumes a nonce slot too). The new key's components must each lie in `(0, p)`; full on-curve membership is not verified — see the **Off-curve risk** note in the contract docs.

**EIP-1271.** `isValidSignature(bytes32 hash, bytes signature) → bytes4` is exposed for off-chain signature checking by dApps and infrastructure (returns `0x1626ba7e` on success, `0x00000000` on failure, never reverts). The EIP-712 envelope used by `execute` / `rotate_owner` ensures arbitrary 32-byte challenges presented via this path cannot collide with the internal authorisation hashes.

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
- `reverting_target_consumes_nonce` — A2 invariant: inner-call revert still bumps the nonce; receipt's `Executed.returnData` carries the revert payload
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
- The release wasm is ~64 KB — above the default EIP-170 24 KB code limit. Orbit chains must raise their per-contract size cap (Nitro devnode: `./run-dev-node.sh --contract-size 128000`). Arbitrum One/Sepolia already permit this size.

# `devnode-tests`

End-to-end integration harness for `P256Account` against a local Nitro devnode. Closes the test-coverage gaps that the host-side `#[cfg(test)]` shim can't reach — it exercises real signatures, real storage, real outbound calls.

## What's covered

| Test name | Asserts | Verified |
|---|---|---|
| `happy_path` | `execute` with valid sig → tx success, nonce `0 → 1`, ETH transferred | ✅ on Nitro `v3.7.1-926f1ab` |
| `reverting_target_consumes_nonce` | inner-call target reverts → tx still succeeds, nonce still bumps, `Executed.success = false` (the A2 invariant) | ✅ |
| `value_exceeds_balance` | account funded with 1 wei, `execute` requests transfer of 2 wei → `Executed.success = false`, balance unchanged, nonce still bumps. Pins down stylus-sdk's mapping of insufficient-balance CALL: it's `Err(Revert)` not `Ok(empty)`, so no `vm().balance() >= value` guard is needed in the contract. | ✅ |
| `rotate_owner` | new key signature verifies, `ownerX` / `ownerY` overwritten on-chain, nonce bumps | ✅ |
| `nonce_monotonicity` | chained `execute → rotate → execute` with the rotated key; nonce strictly `0 → 1 → 2 → 3` | ✅ |

## Prerequisites

1. **Docker + Nitro devnode**

   ```bash
   git clone https://github.com/OffchainLabs/nitro-devnode.git
   cd nitro-devnode
   ./run-dev-node.sh --contract-size 128000
   ```
   The `--contract-size 128000` raise is required so Stylus contracts above the EIP-170 24 KB limit can deploy.

2. **`cargo-stylus` 0.6.x** (deployment CLI with constructor support)

   `cargo-stylus` 0.5.x predates the `--constructor-signature` / `--constructor-args` flags. The harness validated against **0.6.1** specifically. Newer 0.x releases need rustc ≥ 1.87, which doesn't match the contract's pinned `1.86.0`. The harness prints a startup warning if `cargo stylus --version` reports anything outside 0.6.x and falls back to scanning for any `0x{40-hex}` in stdout — but the address parser was tuned for 0.6.1's output.

   ```bash
   rustup target add wasm32-unknown-unknown
   cargo install --locked cargo-stylus@0.6.1
   ```

   The contract crate carries its own `rust-toolchain.toml` pinned to 1.86.0 (`p256-account/rust-toolchain.toml`) because cargo-stylus requires it sit next to the crate's `Cargo.toml`, not at the workspace root.

3. **Foundry's `cast`** (RPC interactions)

   ```bash
   curl -L https://foundry.paradigm.xyz | bash
   foundryup
   ```

## Run

From `contracts/stylus/`:

```bash
# Run every test, deploying a fresh account per test.
cargo run -p devnode-tests --release

# Just one.
cargo run -p devnode-tests --release -- run happy_path

# Show available tests.
cargo run -p devnode-tests --release -- list
```

## What this proves

The host-side `#[cfg(test)]` shim mocks the precompile and tests `validate_p256_signature`'s input layout + every error arm — but it cannot exercise the storage layer, the EVM call layer, or the actual RIP-7212 precompile. This harness fills that gap on a real chain:

- The off-chain EIP-712 hash builder in `src/main.rs` is a literal mirror of the contract's `compute_execute_hash` / `compute_rotate_hash` / `domain_separator` / `envelope` functions. If a signature produced by `Keypair::sign` ever verifies on-chain, the two hash implementations are byte-identical.
- The signing path uses `p256` (the same curve the contract verifies), normalised to low-S via `Signature::normalize_s` to satisfy the contract's malleability check.
- Tests deploy a *fresh* account per case so each starts from `nonce = 0` and a known owner, isolating failures.

## Limitations

- **cargo-stylus output coupling.** The harness still parses `cargo stylus deploy`'s stdout to find the new contract address. The parser knows seven canonical phrasings, accepts upper- and lower-case `0x`, tolerates comma/backtick delimiters, and falls back to scanning for any isolated `0x{40-hex}` that isn't the deployer's own EOA (the dev wallet is now passed in at runtime — not hardcoded — so a key rotation cannot silently misroute the fallback). It also calls `cargo stylus --version` at startup and warns if the running version isn't 0.6.x — the version range the parser was validated against (see `parser_tests` for the matrix). 0.5.x predates constructor support and is explicitly unsupported; newer 0.x releases need rustc ≥ 1.87 which doesn't match the contract's pinned 1.86.0. A future format shift will only break the run when the parser can't find an address at all; otherwise it surfaces clearly via the version warning.
- **`cast` process-spawn overhead.** Each RPC call spawns a process (~tens to hundreds of ms). Acceptable for a 5-test harness; an upgrade to a long-lived `alloy` or `ethers-rs` provider is the right move if the suite grows.
- **Self-reverting target trick.** The reverting-target test uses the account's own fallback as the call target (it reverts on any unknown selector — see `p256-account/src/lib.rs:395`). If the fallback semantics change to silently accept unknown calldata, that test will pass spuriously — replace with a dedicated "always-reverts" deploy.
- **Fresh account per test.** Each test deploys a new contract so it starts from `nonce = 0` with a known owner. Intentional for isolation; the cost is paying the full Stylus activation per case (~one-time per test).

## Host-side tests (no devnode)

Run with no devnode required:

```bash
cargo test -p devnode-tests
```

15 tests, all chain-free:

- **10 cargo-stylus parser tests** — the seven known output phrasings, two dev-wallet skip fallback tests (one anchored to the canonical address, one proving the skip uses a runtime-provided wallet rather than a hardcoded constant), malformed-address rejection, `first_address_token` boundaries.
- **5 harness audits** — `DOMAIN_TYPEHASH`, `EXECUTE_TYPEHASH`, `ROTATE_TYPEHASH`, `NAME_HASH` + `VERSION_HASH` (one test for both since they're trivially short), and `EXECUTED_TOPIC_HEX` (the event topic[0] used by the receipt parser). Each constant is asserted against `keccak256(type_string)` computed at runtime via `tiny-keccak`. Mirror of the contract-side `*_typehash_matches_string` tests — without these, a contract type-string change with a missed harness update would surface only at integration-run time as "signature did not verify" or "Executed event not found in receipt logs".

These catch harness regressions independent of the integration suite.

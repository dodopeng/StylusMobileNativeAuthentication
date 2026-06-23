# Tooling — reference signer · relayer · e2e harness

The off-device pieces that complete the mobile stack: a TypeScript **reference
signer** (the software twin of StrongBox / Secure Enclave), a **relayer
service** implementing the `HttpRelay` wire format, and an **end-to-end
round-trip** harness that drives the full sign → relay → on-chain pipeline.

```bash
cd sdk/tooling
npm install
npm test         # 9 tests: golden-vector parity + a real P-256 sign→verify + relayer guards
npm run typecheck
```

## Reference signer (`src/reference/`)

`ReferenceSigner` (`@noble/curves` P-256) produces exactly what the hardware
signers produce: a public key `(x, y)` and a canonical 64-byte `r‖s` low-S
signature over a 32-byte digest, signing the digest **raw** (no inner hash) —
what RIP-7212 verifies. `eip712.ts` builds the digest and calldata with viem's
audited primitives.

`interop.test.ts` proves two things:
- The digest / selector / ERC-20 golden vectors match the Android `InteropTest`
  and iOS `InteropTests` byte-for-byte (so all three platforms agree).
- A signature this path produces **verifies under P-256** and is **low-S** —
  i.e. an SDK-shaped signature is on-chain-valid. This closes the crypto loop in
  software for the part hardware would otherwise own.

## Relayer service (`src/relayer/`)

A gasless paymaster. The phone signs and POSTs `{account, data, nonce}`; the
relayer broadcasts `{to: account, data, value: 0}` and pays gas.

```bash
RPC_URL=http://localhost:8547 \
RELAYER_PRIVATE_KEY=0x<funded-eoa-key> \
PORT=8080 MAX_GAS=2000000 \
npm run relayer
# POST /relay {account,data,nonce} -> {txHash};  GET /health
```

Guards (`guard.ts`, unit-tested): rejects anything whose selector isn't
`execute` / `rotateOwner` (so a leaked endpoint isn't an arbitrary-calldata
oracle), rejects malformed addresses/data, fails fast on a stale nonce, and caps
gas. **Authorisation is the P-256 signature in `data`** — the relayer only pays.

## End-to-end round trip (`src/e2e/roundtrip.ts`)

The missing on-chain round trip for the SDK path. Generates an owner key,
deploys a fresh `P256Account` (or attaches to `ACCOUNT_ADDRESS`), reads `nonce()`,
builds + signs an `execute` digest, relays it, and asserts `nonce` bumped
`0 → 1` — proving the signature verified through the RIP-7212 precompile.

```bash
# 1. start a Nitro devnode (see contracts/stylus/devnode-tests/README.md)
# 2. build the wasm:  (cd ../../contracts/stylus && cargo build --release \
#       --target wasm32-unknown-unknown -p p256-account)
# 3. start the relayer (above)
# 4. run the round trip:
RPC_URL=http://localhost:8547 RELAYER_URL=http://localhost:8080 \
DEPLOYER_KEY=0x<devnode-funded-key> npm run e2e
```

Hardware keys can't run headless, but on-chain verification is identical
wherever the key lives — so this exercises every link the device flow uses
except the enclave itself. The Rust harness in
`contracts/stylus/devnode-tests` independently proves the contract side with its
own P-256 signer.

## ABI golden check (`scripts/check-abi.sh`)

The SDKs depend on stylus-sdk renaming Rust `snake_case` methods to `camelCase`
Solidity selectors. A rename or stylus-sdk behaviour change would turn every SDK
call into `UnknownSelector`. This CI script exports the contract's ABI
(`cargo stylus export-abi`) and asserts the camelCase names + golden selectors
still match what the SDKs encode (requires `cargo-stylus` + `cast`):

```bash
sdk/tooling/scripts/check-abi.sh
```

> The 2 npm-audit advisories are in dev-only transitive deps (the TS runner);
> they don't ship in any SDK artifact.

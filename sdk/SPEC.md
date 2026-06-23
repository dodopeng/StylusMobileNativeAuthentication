# Mobile SDK ⇄ Stylus P256Account — Interop Spec

This is the canonical, language-agnostic contract that the Android (Milestone 2)
and iOS (Milestone 3) SDKs implement. Anything that signs or encodes a call to
the on-chain account MUST match this byte-for-byte. The values below were
derived from `contracts/stylus/p256-account/src/lib.rs` and verified with
`cast` (see the repo README review notes).

## 1. Curve & signature

- Curve: **P-256 / secp256r1** (NIST P-256). This is the curve the iOS Secure
  Enclave and Android StrongBox/Keystore use for hardware keys and passkeys.
- The owner is a public key `(x, y)`, each a 32-byte big-endian field element
  in `(0, p)` where `p = 2^256 − 2^224 + 2^192 + 2^96 − 1`.
- A signature is **exactly 64 bytes: `r ‖ s`**, each a 32-byte big-endian
  scalar.
  - `r ∈ (0, n)`, `s ∈ (0, n/2]` where `n` is the P-256 group order.
  - **Strict low-S is mandatory.** Hardware signers return a DER-encoded
    `SEQUENCE { INTEGER r, INTEGER s }` and do *not* normalise S. The SDK MUST:
    1. DER-decode to `(r, s)`.
    2. If `s > n/2`, replace `s ← n − s` (this is the canonical low-S form and
       remains a valid signature for the same message/key).
    3. Left-pad `r` and `s` to 32 bytes each and concatenate.
  - `n   = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551`
  - `n/2 = 0x7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8`

The contract rejects `s = 0`, `s > n/2` (`HighS`), `r ∉ (0,n)` (`InvalidR`),
non-64-byte signatures (`InvalidSignatureLength`), and any `(r,s)` the RIP-7212
precompile does not accept (`InvalidSignature`).

## 2. The digest that gets signed (EIP-712)

The signer never signs raw calldata. It signs `digest`, a 32-byte EIP-712 hash.

**Critical:** RIP-7212 uses the 32-byte input as the ECDSA message hash `e`
**directly** — the precompile does not hash it again. The contract passes the
keccak EIP-712 digest straight to the precompile (`e = digest`). Therefore the
hardware signer must produce ECDSA over `e = digest` with **no additional
hashing**:

- **Android:** generate the Keystore key with `DIGEST_NONE` and sign with
  `"NONEwithECDSA"`, passing the 32-byte digest as the input (used as `e`
  verbatim). Do **not** use `"SHA256withECDSA"` — that would sign
  `SHA256(digest)` and every signature would be rejected on-chain.
- **iOS:** sign with `SecKeyCreateSignature(key, .ecdsaSignatureDigestX962SHA256,
  digest)`. The `…DigestX962…` ("digest", not "message") variant signs the
  provided 32-byte digest as-is rather than re-hashing it.

Device caveat: a few StrongBox secure elements reject `DIGEST_NONE`. The Android
signer requests StrongBox first and the caller falls back to a TEE-backed key
(which supports raw ECDSA) if generation fails.

```
domainSeparator = keccak256(
    DOMAIN_TYPEHASH ‖ NAME_HASH ‖ VERSION_HASH ‖ uint256(chainId) ‖ uint256(uint160(account))
)
digest = keccak256(0x19 ‖ 0x01 ‖ domainSeparator ‖ structHash)
```

Constants (hex, 32 bytes; verified against the contract):

| Name | Value |
|------|-------|
| `DOMAIN_TYPEHASH` | `0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f` |
| `NAME_HASH` = keccak256("P256Account") | `0x0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d` |
| `VERSION_HASH` = keccak256("1") | `0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6` |
| `EXECUTE_TYPEHASH` | `0x5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c` |
| `ROTATE_TYPEHASH` | `0x8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a` |

`DOMAIN_TYPEHASH = keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.

Note the domain binds `chainId` and `account` (the deployed account address), so
a signature is non-replayable across chains and across accounts.

### 2a. `execute` structHash

```
structHash = keccak256(
    EXECUTE_TYPEHASH ‖ uint256(uint160(to)) ‖ uint256(value) ‖ keccak256(data) ‖ uint256(nonce)
)
```
`EXECUTE_TYPEHASH = keccak256("Execute(address to,uint256 value,bytes data,uint256 nonce)")`.
`data` is the inner calldata being executed (see §4 action templates); `keccak256(data)`
is the EIP-712 encoding of a dynamic `bytes` field.

### 2b. `rotateOwner` structHash

```
structHash = keccak256(
    ROTATE_TYPEHASH ‖ uint256(newX) ‖ uint256(newY) ‖ uint256(nonce)
)
```
`ROTATE_TYPEHASH = keccak256("RotateOwner(uint256 newX,uint256 newY,uint256 nonce)")`.
Signed by the **current** owner key. Because the typehash differs from
`EXECUTE_TYPEHASH`, an execute signature can never be replayed as a rotation.

## 3. Function ABI & selectors

camelCase names — stylus-sdk renames the Rust snake_case methods for the
Solidity ABI (confirmed: the contract's EIP-1271 magic equals
`bytes4(keccak256("isValidSignature(bytes32,bytes)"))`).

| Method | Selector | Signature |
|--------|----------|-----------|
| execute | `0xd2c88a7c` | `execute(address to,uint256 value,bytes data,uint256 nonce,bytes signature)` → `(bool,bytes)` |
| rotateOwner | `0x82bed5b3` | `rotateOwner(uint256 newX,uint256 newY,uint256 nonce,bytes signature)` |
| nonce | `0xaffed0e0` | `nonce()` → `uint256` |
| ownerX | `0xdbecca6f` | `ownerX()` → `uint256` |
| ownerY | `0xa2d57acf` | `ownerY()` → `uint256` |
| isValidSignature | `0x1626ba7e` | `isValidSignature(bytes32 hash,bytes signature)` → `bytes4` (EIP-1271) |
| verify | `0x258ae582` | `verify(bytes32 hash,bytes signature)` → `bool` |

Constructor (set once at deploy, atomically): `constructor(uint256 x,uint256 y)`.

## 4. Submission model

`execute` and `rotateOwner` are **permissioned by signature, not by
`msg.sender`** — any address may broadcast the transaction as long as the P-256
signature is valid. This enables the gasless mobile UX: the phone signs with the
enclave key, and a **relayer** (a funded EOA, or a relay service) pays the gas
and broadcasts the EVM transaction.

Both SDKs expose a `TransactionRelay` abstraction with two built-in strategies:

- `HttpRelay(url)` — POSTs the signed action to a relay endpoint that
  broadcasts it. The SDK has already ABI-encoded the full
  `execute(...)`/`rotateOwner(...)` call, so the wire payload is the
  pre-built calldata, not its components:

  ```json
  { "account": "0x<account>", "data": "0x<execute|rotateOwner calldata>", "nonce": 5 }
  ```

  Response: `{ "txHash": "0x…" }`. The relayer broadcasts `{to: account, data,
  value: 0}` and need not understand the ABI — it only checks the 4-byte
  selector is `execute`/`rotateOwner` (so it can't be used as an
  arbitrary-calldata oracle), since authorisation is the P-256 signature
  embedded in `data`. `nonce` is advisory, letting the relayer reject a stale
  submission before paying gas.
- `BroadcasterRelay(signer)` — the integrator supplies an object that can sign &
  send a raw secp256k1 EVM transaction (e.g. a dev/test EOA). Useful for tests
  and self-relaying.

The nonce in §2 is the **account contract's** monotonic nonce (read via
`nonce()`), NOT the relayer EOA's transaction nonce.

## 5. Nonce & replay rules (from the contract)

- One monotonic nonce shared by `execute` and `rotateOwner`.
- A call must pass the *current* `nonce()`; mismatch reverts with `NonceMismatch`.
- The nonce is committed **before** the outbound call, so a payload whose inner
  call reverts still consumes the nonce, and `execute` returns
  `(success=false, revertBytes)` rather than reverting the whole tx.
- After any successful `execute`/`rotateOwner`, the SDK should refresh `nonce()`.

## 6. Off-curve / bricking safety (SDK responsibility)

The contract validates only `0 < x,y < p`; it does **not** verify on-curve
membership. Deploying or rotating to an off-curve `(x,y)` permanently bricks the
account. Therefore both SDKs MUST derive `(x, y)` from a real hardware key (the
public key the enclave returns is always on-curve) and MUST NOT accept
arbitrary user-supplied coordinates for `constructor`/`rotateOwner` without a
curve check. See `pointIsOnCurve` in each SDK.

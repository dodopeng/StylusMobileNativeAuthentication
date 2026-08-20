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
| `BATCH_TYPEHASH` | `0xe4c4e9c11a8826c10f239085bcd6b1f837ac8891ef69510451fb4e86df1ff4fb` |
| `CALL_TYPEHASH` | `0x9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483` |
| `PERSONAL_SIGN_TYPEHASH` | `0x2431bd832cbb131f8882ef79f68ed6ae065cca9270f5bce0f2e4f75a9cd814b7` |

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

### 2c. `executeBatch` structHash

One signature, one nonce, one biometric prompt for an ordered list of calls.
This is the correct way to run approve→swap: as two separate `execute` calls the
client reads `nonce()` at *latest* for both, signs both against the same value,
and the second reverts unless the user waits for the first to confirm.

```
BATCH_TYPEHASH = keccak256(
    "BatchExecute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)")
CALL_TYPEHASH  = keccak256("Call(address to,uint256 value,bytes data)")

callHash_i = keccak256(CALL_TYPEHASH ‖ uint256(uint160(to_i)) ‖ uint256(value_i) ‖ keccak256(data_i))
callsHash  = keccak256(callHash_0 ‖ callHash_1 ‖ … ‖ callHash_n-1)
structHash = keccak256(BATCH_TYPEHASH ‖ callsHash ‖ uint256(nonce))
```

Note the EIP-712 encodeType rule: the referenced `Call` type is appended to the
primary type, and array members hash to the keccak of their concatenated
`hashStruct`s. **Order is part of the hash**, so a relayer cannot reorder a
signed batch.

At most **32** calls per batch. A batch is **all-or-nothing**: if any inner call
reverts the whole transaction reverts and the nonce is *not* consumed — unlike
single `execute`, which records the failure and still consumes it. A half-applied
approve/swap is worse than none.

### 2d. EIP-1271 — `PersonalSign(bytes32 hash)`

Challenges are **wrapped**, never signed raw:

```
PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes32 hash)")
                       = 0x2431bd832cbb131f8882ef79f68ed6ae065cca9270f5bce0f2e4f75a9cd814b7

structHash = keccak256(PERSONAL_SIGN_TYPEHASH ‖ hash)
digest     = keccak256(0x1901 ‖ domainSeparator ‖ structHash)
```

`isValidSignature(hash, sig)` verifies `sig` against that digest. SDK entry
points `signHash(...)` apply the identical wrapper before signing.

**Why this is not optional.** Verifying the raw hash was exploitable. An
`Execute` digest is itself a 32-byte hash and every input to it — chainId,
account, `to`, `value`, `data`, `nonce` — is public. An attacker could compute
the digest for `execute(to: attacker, value: 1 ETH, nonce: 0)`, present it as a
login challenge, and the 64 bytes returned from the user's biometric prompt were
a valid transfer authorisation.

Domain separation by envelope alone does **not** close this: the envelope
protects the `execute` path, but the 1271 path accepted any 32-byte value,
including an envelope output. Separation has to be structural — a typehash no
authorisation path uses — which is what `PersonalSign` provides. A signature
produced for a challenge cannot authorise `execute`, `executeBatch` or
`rotateOwner`, and vice versa.

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
| executeBatch | `0xa428824f` | `executeBatch(address[] to,uint256[] value,bytes[] data,uint256 nonce,bytes signature)` |
| onERC721Received | `0x150b7a02` | ERC-721 receiver hook — returns its own selector |
| onERC1155Received | `0xf23a6e61` | ERC-1155 receiver hook |
| onERC1155BatchReceived | `0xbc197c81` | ERC-1155 batch receiver hook |
| supportsInterface | `0x01ffc9a7` | ERC-165 |
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
  selector is `execute`/`executeBatch`/`rotateOwner` (so it can't be used as an
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
- <a name="nonce-before-call"></a>**Nonce-before-call.** The nonce is committed
  **before** the outbound call, so a payload whose inner call reverts still
  consumes the nonce, and `execute` returns `(success=false, revertBytes)`
  rather than reverting the whole tx. Pinned by the contract test
  `reverting_target_consumes_nonce`, the devnode harness, and `simulate.test.ts`.
- After any successful `execute`/`rotateOwner`, the SDK should refresh `nonce()`.

## 6. Off-curve / bricking safety

The contract verifies **full curve membership** on every owner key it accepts —
`constructor` and `rotateOwner` both run `is_valid_pubkey`, which checks
`0 < x,y < p` *and* `y² ≡ x³ − 3x + b (mod p)`, rejecting anything else with
`InvalidPublicKey`.

An off-curve owner is unrecoverable — accepted at write time, after which no
signature can ever verify — which is why the check is on-chain rather than left
to callers.

The SDK-side check is defence in depth, not the only line of defence, but it
still holds: both SDKs MUST derive `(x, y)` from a real hardware key (the public
key an enclave returns is always on-curve) and SHOULD reject arbitrary
user-supplied coordinates locally, so the failure surfaces before a transaction
is signed and paid for. See `pointIsOnCurve` in each SDK.

On-curve is necessary but not sufficient: a point that is on the curve yet not
backed by the device's secure hardware is still an unrecoverable loss of
control. Only the enclave's own public key is safe to rotate to.

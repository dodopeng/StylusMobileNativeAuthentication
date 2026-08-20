//! P-256 smart account for Arbitrum Stylus.
//!
//! Custom-AA single-owner account. The owner is a P-256 (secp256r1) public key
//! `(x, y)`, set atomically at deployment by the Stylus `#[constructor]`. Every
//! state-changing call goes through `execute(...)`, which verifies a P-256
//! signature on-chain via the RIP-7212 precompile at `0x0000…0100`.
//!
//! ## Signature scheme
//! - 64-byte signature `(r ‖ s)`.
//! - `r` must lie in `(0, n)` (curve order); `s` must lie in `(0, n/2]` (strict
//!   low-S to block malleability).
//! - Every signable message is an EIP-712 envelope over a **distinct typehash**:
//!   `Execute`, `BatchExecute`, `RotateOwner`, and `PersonalSign` (the EIP-1271
//!   challenge wrapper). Domain separation alone is not enough — it was not,
//!   while `isValidSignature` verified the raw hash, because an `Execute` digest
//!   is itself a 32-byte hash that an attacker can compute from public inputs
//!   and present as a login challenge. Wrapping the 1271 path in its own
//!   typehash is what actually makes the domains disjoint.
//!
//! ## EIP-712 domain
//! ```text
//! EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)
//! name    = "P256Account"
//! version = "1"
//! ```
//!
//! ## Nonce semantics
//! `execute` and `rotate_owner` share a single monotonic nonce. The nonce is
//! committed to storage **before** the outbound call, so a signed payload whose
//! target reverts still consumes the nonce — eliminating the "sign now, replay
//! when state turns favourable" attack. The success flag and any revert bytes
//! are surfaced to callers via the `Executed` event and the tuple return.
//!
//! ## Front-running
//! `init` from the previous design has been replaced by a Stylus
//! `#[constructor]`, which runs atomically with deployment via `cargo stylus
//! deploy --constructor-signature 'constructor(uint256,uint256)'`. There is no
//! window between code activation and owner-key set.
//!
//! ## Curve membership
//! Public keys are validated for full curve membership — `y² ≡ x³ − 3x + b
//! (mod p)` — in both the constructor and `rotate_owner`, not merely
//! range-checked. An off-curve point would deploy or rotate successfully and
//! then make every subsequent signature unverifiable, permanently bricking the
//! account. Three modular multiplications is a cheap price for removing a
//! footgun whose blast radius is the whole account, so the earlier
//! range-check-only design (C1) has been replaced.

#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
extern crate alloc;

use alloc::vec::Vec;
use alloy_primitives::{b256, Address, FixedBytes, B256, U256};
use alloy_sol_types::sol;
// `stylus_sdk::call::{call, Call, Error}` are deprecated in 0.9.0 in favour of
// `stylus_core::calls::*` reached through `self.vm()`. That migration does not
// compile here: `Call::new_in(self)` holds `&mut self` for the context's
// lifetime while `self.vm()` needs `&self`, so the two borrows conflict
// (E0502). The SDK is pinned at =0.9.0, the deprecated path is still the
// supported one at that version, and this is the contract's only external-call
// site — so the warning is silenced deliberately and locally rather than left
// as noise or worked around with an unsafe rewrite of the call path.
// Revisit when the SDK pin moves.
#[allow(deprecated)]
use stylus_sdk::{
    abi::Bytes,
    call::{self, Call},
    crypto::keccak,
    prelude::*,
    storage::{StorageBool, StorageU256},
    ArbResult,
};
// Only the non-test `precompile_staticcall` issues the raw STATICCALL; under
// `cfg(test)` that function is replaced by the shim, so an unconditional import
// is an unused-import warning in every test build.
#[cfg(not(test))]
use stylus_sdk::call::RawCall;

// =====================================================================
// Constants
// =====================================================================

/// RIP-7212 precompile address: `0x0000000000000000000000000000000000000100`.
const P256_PRECOMPILE: Address = Address::new([
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x01, 0x00,
]);

/// P-256 base field prime `p = 2^256 − 2^224 + 2^192 + 2^96 − 1`.
const P256_FIELD_PRIME: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
];

/// P-256 group order `n`. Used to bound `r ∈ (0, n)` for any valid ECDSA sig.
const P256_ORDER_N: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84, 0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

/// P-256 curve coefficient `b` in `y² = x³ − 3x + b (mod p)`.
/// `0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B`.
const P256_B: [u8; 32] = [
    0x5A, 0xC6, 0x35, 0xD8, 0xAA, 0x3A, 0x93, 0xE7, 0xB3, 0xEB, 0xBD, 0x55, 0x76, 0x98, 0x86, 0xBC,
    0x65, 0x1D, 0x06, 0xB0, 0xCC, 0x53, 0xB0, 0xF6, 0x3B, 0xCE, 0x3C, 0x3E, 0x27, 0xD2, 0x60, 0x4B,
];

/// `floor(n / 2)` — strict low-S boundary against signature malleability.
const P256_HALF_ORDER: [u8; 32] = [
    0x7F, 0xFF, 0xFF, 0xFF, 0x80, 0x00, 0x00, 0x00, 0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xDE, 0x73, 0x7D, 0x56, 0xD3, 0x8B, 0xCF, 0x42, 0x79, 0xDC, 0xE5, 0x61, 0x7E, 0x31, 0x92, 0xA8,
];

// EIP-712 typehashes — `cast keccak <type-string>`, verified at runtime in
// `tests::*_typehash_matches_string`.

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`.
const DOMAIN_TYPEHASH: B256 =
    b256!("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f");

/// `keccak256("Execute(address to,uint256 value,bytes data,uint256 nonce)")`.
const EXECUTE_TYPEHASH: B256 =
    b256!("5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c");

/// `keccak256("RotateOwner(uint256 newX,uint256 newY,uint256 nonce)")`.
const ROTATE_TYPEHASH: B256 =
    b256!("8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a");

/// `keccak256("BatchExecute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)")`.
/// Per EIP-712 the referenced `Call` type is appended to the primary type.
const BATCH_TYPEHASH: B256 =
    b256!("e4c4e9c11a8826c10f239085bcd6b1f837ac8891ef69510451fb4e86df1ff4fb");

/// `keccak256("PersonalSign(bytes32 hash)")`.
///
/// EIP-1271 challenges are wrapped in this struct before verification. Without
/// it, `isValidSignature` verified the RAW 32-byte hash — and an `Execute`
/// digest is itself a raw 32-byte hash computable from public inputs. An
/// attacker could hand the user an `execute(to: attacker, value: 1 ETH)` digest
/// as a "login challenge"; the 64 bytes returned were a valid `execute`
/// authorisation. Wrapping makes the two domains disjoint by construction
/// instead of by convention.
const PERSONAL_SIGN_TYPEHASH: B256 =
    b256!("2431bd832cbb131f8882ef79f68ed6ae065cca9270f5bce0f2e4f75a9cd814b7");

/// `keccak256("Call(address to,uint256 value,bytes data)")` — the member type
/// hashed once per element of `BatchExecute.calls`.
const CALL_TYPEHASH: B256 =
    b256!("9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483");

/// `bytes4(keccak256("onERC721Received(address,address,uint256,bytes)"))`.
const ERC721_RECEIVED_MAGIC: [u8; 4] = [0x15, 0x0b, 0x7a, 0x02];

/// `bytes4(keccak256("onERC1155Received(address,address,uint256,uint256,bytes)"))`.
const ERC1155_RECEIVED_MAGIC: [u8; 4] = [0xf2, 0x3a, 0x6e, 0x61];

/// `bytes4(keccak256("onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)"))`.
const ERC1155_BATCH_RECEIVED_MAGIC: [u8; 4] = [0xbc, 0x19, 0x7c, 0x81];

/// Upper bound on calls in a single `execute_batch`. Prevents a signed batch
/// from being large enough to exceed the block gas limit in a way that makes
/// the consumed nonce unrecoverable.
const MAX_BATCH_CALLS: usize = 32;

/// `keccak256("P256Account")` — EIP-712 domain `name`.
const NAME_HASH: B256 = b256!("0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d");

/// `keccak256("1")` — EIP-712 domain `version`.
const VERSION_HASH: B256 =
    b256!("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6");

/// `bytes4(keccak256("isValidSignature(bytes32,bytes)"))` — EIP-1271 success.
const EIP1271_MAGIC: [u8; 4] = [0x16, 0x26, 0xba, 0x7e];

// =====================================================================
// Events
// =====================================================================

sol! {
    /// Emitted by the constructor with the initial owner public key.
    event OwnerInitialized(uint256 x, uint256 y);
    /// Emitted by every `execute` call, success or failure. `returnData`
    /// carries the inner call's return bytes on success and the revert bytes
    /// on failure.
    event Executed(
        address indexed to,
        uint256 value,
        uint256 nonce,
        bool success,
        bytes returnData
    );
    /// Emitted once per successful `executeBatch`, after every inner call has
    /// run. A batch is all-or-nothing, so this only ever appears on the success
    /// path — a failure reverts the transaction (and these logs with it) and is
    /// reported through the `BatchCallFailed(index, returnData)` error instead.
    event BatchExecuted(uint256 calls, uint256 nonce);
    /// Emitted on successful `rotate_owner`. Carries both keys so indexers
    /// don't have to walk history, plus the consumed nonce so this can be
    /// ordered against `Executed` events in the shared monotonic nonce space.
    event OwnerRotated(
        uint256 prevX,
        uint256 prevY,
        uint256 newX,
        uint256 newY,
        uint256 nonce
    );
}

// =====================================================================
// Errors
// =====================================================================

sol! {
    #[derive(Debug)]
    error InvalidPublicKey();
    #[derive(Debug)]
    error InvalidSignatureLength(uint64 got);
    #[derive(Debug)]
    error InvalidSignature();
    #[derive(Debug)]
    error InvalidR();
    #[derive(Debug)]
    error InvalidS();
    #[derive(Debug)]
    error NonceMismatch(uint256 expected, uint256 got);
    #[derive(Debug)]
    error HighS();
    #[derive(Debug)]
    error UnknownSelector();
    /// A nested `execute` / `executeBatch` / `rotateOwner` was attempted while
    /// one was already on the stack. Plain `receive()` callbacks are allowed —
    /// blocking those is what broke every ETH-returning action.
    #[derive(Debug)]
    error Reentrancy();
    /// `executeBatch` was given mismatched array lengths, no calls at all, or
    /// more than `MAX_BATCH_CALLS`.
    #[derive(Debug)]
    error InvalidBatch(uint64 calls, uint64 values, uint64 datas);
    /// An inner call in `executeBatch` reverted. Carries the 0-based index and
    /// the callee's revert payload.
    ///
    /// A batch reverts as a whole, which discards the `Executed` logs emitted
    /// for the calls that did run — so without this error there was no way to
    /// learn WHICH call failed. Returning `InvalidSignature` (as this used to)
    /// was actively misleading: the signature was fine.
    #[derive(Debug)]
    error BatchCallFailed(uint256 index, bytes returnData);
}

#[derive(SolidityError, Debug)]
pub enum P256AccountError {
    InvalidPublicKey(InvalidPublicKey),
    InvalidSignatureLength(InvalidSignatureLength),
    InvalidSignature(InvalidSignature),
    InvalidR(InvalidR),
    InvalidS(InvalidS),
    NonceMismatch(NonceMismatch),
    HighS(HighS),
    UnknownSelector(UnknownSelector),
    Reentrancy(Reentrancy),
    InvalidBatch(InvalidBatch),
    BatchCallFailed(BatchCallFailed),
}

// =====================================================================
// Storage
// =====================================================================

#[entrypoint]
#[storage]
pub struct P256Account {
    owner_x: StorageU256,
    owner_y: StorageU256,
    /// Monotonic nonce shared by `execute`, `execute_batch` and `rotate_owner`.
    nonce: StorageU256,
    /// Re-entrancy guard. Set for the duration of an authorised call so that a
    /// callback cannot start a second one.
    ///
    /// The contract is built with stylus-sdk's `reentrant` feature because the
    /// account MUST accept being called back: WETH.withdraw and any swap ending
    /// in ETH send value to the account, invoking `receive()` while `execute` is
    /// still on the stack. The blanket non-reentrant build reverts those, which
    /// silently breaks every ETH-returning action. This flag restores the part
    /// of that protection that actually matters — no nested authorised call —
    /// while leaving `receive()` free.
    in_call: StorageBool,
}

// =====================================================================
// Public ABI
// =====================================================================

#[public]
impl P256Account {
    /// Stylus constructor. Runs atomically with deployment via
    /// `cargo stylus deploy --constructor-signature 'constructor(uint256,uint256)'
    ///   --constructor-args $X $Y`. The Stylus runtime guarantees this can
    /// only run once per deployed instance, removing the front-running
    /// window that an explicit `init` would have.
    ///
    /// Validates each pubkey component lies in `(0, p)` **and** that `(x, y)` is
    /// on the P-256 curve. A point that is merely in range but off-curve would
    /// deploy fine and then reject every signature forever.
    #[constructor]
    pub fn constructor(&mut self, x: U256, y: U256) -> Result<(), P256AccountError> {
        validate_constructor_args(x, y)?;
        self.owner_x.set(x);
        self.owner_y.set(y);
        log(self.vm(), OwnerInitialized { x, y });
        Ok(())
    }

    pub fn owner_x(&self) -> U256 {
        self.owner_x.get()
    }

    pub fn owner_y(&self) -> U256 {
        self.owner_y.get()
    }

    pub fn nonce(&self) -> U256 {
        self.nonce.get()
    }

    /// Authorize and execute an outbound call.
    ///
    /// On success the inner call's return bytes are returned with
    /// `success = true`. On inner-call revert the nonce is still consumed
    /// and the revert bytes are returned with `success = false` — this
    /// eliminates the "sign now, replay when state turns favourable" attack
    /// while matching ERC-4337 / Safe semantics.
    ///
    /// Signature failure (bad sig, wrong nonce, malleable s, out-of-range
    /// r/s) reverts the entire tx and the nonce is NOT consumed.
    ///
    /// ## Re-entrancy
    /// The nonce is bumped *before* the external call (CEI), so the same
    /// signature cannot be replayed re-entrantly. The outer callee MAY
    /// call back into `execute` with a fresh nonce/signature — that is
    /// intentional (enables chained mobile-SDK flows).
    ///
    /// ## Data size
    /// `data` is unbounded by this contract — Stylus's own calldata limits
    /// apply, but the mobile SDK should cap the payload sensibly to avoid
    /// surprising users on gas with a maximally-large transaction body.
    pub fn execute(
        &mut self,
        to: Address,
        value: U256,
        data: Bytes,
        nonce: U256,
        signature: Bytes,
    ) -> Result<(bool, Bytes), P256AccountError> {
        self.enter()?;

        let chain_id = self.vm().chain_id();
        let account = self.vm().contract_address();
        let current_nonce = self.nonce.get();
        let owner_x = self.owner_x.get();
        let owner_y = self.owner_y.get();

        // A rejected request must not leave the guard latched.
        if let Err(e) = validate_execute_request(&ExecuteRequest {
            owner_x,
            owner_y,
            current_nonce,
            chain_id,
            account,
            to,
            value,
            data: data.as_ref(),
            nonce,
            signature: signature.as_ref(),
        }) {
            self.exit();
            return Err(e);
        }

        // CEI: commit nonce before the external call.
        self.nonce.set(current_nonce + U256::from(1));

        #[allow(deprecated)]
        let call_result = call::call(Call::new_in(self).value(value), to, data.as_ref());
        let (success, return_data) = execute_outcome(call_result);

        log(
            self.vm(),
            Executed {
                to,
                value,
                nonce,
                success,
                returnData: return_data.clone().into(),
            },
        );

        self.exit();
        // `Vec<u8>` would export as `uint8[]`; SPEC.md §3 and every SDK expect
        // `bytes`.
        Ok((success, return_data.into()))
    }

    /// Execute several calls under a **single** P-256 signature and a single
    /// nonce.
    ///
    /// This is what makes multi-step DeFi usable on mobile. `approve` then
    /// `swap` as two separate `execute` calls needs two biometric prompts and
    /// two nonces, and because the client reads `nonce()` at *latest* it will
    /// sign both against the same value and the second reverts unless the user
    /// waits for the first to confirm. One batch is one prompt, one nonce, and
    /// no race.
    ///
    /// ## All-or-nothing
    /// Unlike single `execute` — which records an inner revert in `Executed`
    /// and still consumes the nonce — a batch **reverts entirely** if any call
    /// fails. A half-applied `approve`/`swap` is worse than none, and the
    /// caller signed for the whole sequence, not a prefix of it. The nonce is
    /// therefore not consumed on failure.
    ///
    /// Arrays are parallel: `to[i]`, `value[i]`, `data[i]`. All three must be
    /// the same non-zero length, at most `MAX_BATCH_CALLS`.
    ///
    /// Deliberately NOT `#[payable]`, matching `execute`. The inner calls are
    /// funded from the account's own balance via `value[i]`, which IS covered by
    /// the signature; an attached `msg.value` would not be, so accepting one
    /// would mean moving unsigned value through a signed entry point. Fund the
    /// account through `receive()` instead.
    pub fn execute_batch(
        &mut self,
        to: Vec<Address>,
        value: Vec<U256>,
        data: Vec<Bytes>,
        nonce: U256,
        signature: Bytes,
    ) -> Result<(), P256AccountError> {
        self.enter()?;

        if let Err(e) = validate_batch_shape(to.len(), value.len(), data.len()) {
            self.exit();
            return Err(e);
        }

        let chain_id = self.vm().chain_id();
        let account = self.vm().contract_address();
        let current_nonce = self.nonce.get();
        let owner_x = self.owner_x.get();
        let owner_y = self.owner_y.get();

        let data_refs: Vec<&[u8]> = data.iter().map(|d| d.as_ref()).collect();
        let batch_hash = compute_batch_hash(chain_id, account, &to, &value, &data_refs, nonce);

        if let Err(e) = validate_authorised_hash(
            batch_hash,
            current_nonce,
            nonce,
            owner_x,
            owner_y,
            signature.as_ref(),
        ) {
            self.exit();
            return Err(e);
        }

        self.nonce.set(current_nonce + U256::from(1));

        for i in 0..to.len() {
            #[allow(deprecated)]
            let result = call::call(Call::new_in(self).value(value[i]), to[i], data_refs[i]);
            let (success, return_data) = execute_outcome(result);

            log(
                self.vm(),
                Executed {
                    to: to[i],
                    value: value[i],
                    nonce,
                    success,
                    returnData: return_data.clone().into(),
                },
            );

            if !success {
                // Revert the whole batch, undoing the nonce bump and every
                // prior call in this transaction. The revert discards the
                // `Executed` logs above, so the index and payload are carried
                // in the error itself — otherwise a failed batch is undebuggable.
                self.exit();
                return Err(P256AccountError::BatchCallFailed(BatchCallFailed {
                    index: U256::from(i),
                    returnData: return_data.into(),
                }));
            }
        }

        log(
            self.vm(),
            BatchExecuted {
                calls: U256::from(to.len()),
                nonce,
            },
        );

        self.exit();
        Ok(())
    }

    /// Rotate the owner key. The caller must provide a P-256 signature from
    /// the *current* owner over the EIP-712 `RotateOwner` struct. Shares the
    /// monotonic nonce with `execute`.
    ///
    /// ## Curve membership on rotation
    /// `(new_x, new_y)` is checked for full curve membership, not just range.
    /// An off-curve target would **permanently brick** the account — no future
    /// signature could verify and no further rotation could be authorised — so
    /// this is enforced on-chain rather than delegated to client-side care.
    ///
    /// On-curve is necessary but not sufficient: a key that is a valid curve
    /// point yet not backed by the enclave is still an unrecoverable loss of
    /// control. The SDK remains responsible for that half.
    pub fn rotate_owner(
        &mut self,
        new_x: U256,
        new_y: U256,
        nonce: U256,
        signature: Bytes,
    ) -> Result<(), P256AccountError> {
        self.enter()?;

        let chain_id = self.vm().chain_id();
        let account = self.vm().contract_address();
        let current_nonce = self.nonce.get();
        let owner_x = self.owner_x.get();
        let owner_y = self.owner_y.get();

        if let Err(e) = validate_rotation_request(&RotationRequest {
            owner_x,
            owner_y,
            current_nonce,
            chain_id,
            account,
            new_x,
            new_y,
            nonce,
            signature: signature.as_ref(),
        }) {
            self.exit();
            return Err(e);
        }

        self.nonce.set(current_nonce + U256::from(1));
        self.owner_x.set(new_x);
        self.owner_y.set(new_y);
        log(
            self.vm(),
            OwnerRotated {
                prevX: owner_x,
                prevY: owner_y,
                newX: new_x,
                newY: new_y,
                nonce,
            },
        );
        self.exit();
        Ok(())
    }

    /// Read-only signature check against the stored owner key. Returns the
    /// boolean result of the precompile verification; intended for SDK /
    /// test usage. Production dApps should prefer the EIP-1271 entry point.
    pub fn verify(&self, hash: B256, signature: Bytes) -> bool {
        validate_p256_signature(
            hash,
            signature.as_ref(),
            self.owner_x.get(),
            self.owner_y.get(),
        )
        .is_ok()
    }

    /// EIP-1271 signature check. Returns `0x1626ba7e` on success, all-zeros
    /// otherwise. Never reverts.
    ///
    /// The `hash` is caller-supplied, so it is verified against
    /// `PersonalSign(hash)` — its own EIP-712 typed domain — never raw. See
    /// `PERSONAL_SIGN_TYPEHASH` for why raw verification was exploitable.
    pub fn is_valid_signature(&self, hash: B256, signature: Bytes) -> FixedBytes<4> {
        // PersonalSign(hash), never the raw hash — see PERSONAL_SIGN_TYPEHASH.
        let wrapped = compute_personal_sign_hash(
            self.vm().chain_id(),
            self.vm().contract_address(),
            hash,
        );
        let ok = validate_p256_signature(
            wrapped,
            signature.as_ref(),
            self.owner_x.get(),
            self.owner_y.get(),
        )
        .is_ok();
        FixedBytes::new(eip1271_response(ok))
    }

    /// ERC-721 safe-transfer acceptance. Without this every `safeTransferFrom`
    /// **into** the account reverts (the fallback rejects unknown selectors),
    /// which would make an account that ships ERC-721 action templates unable
    /// to receive the very tokens those templates move.
    ///
    /// Unconditional acceptance is deliberate: refusing here cannot protect the
    /// owner from unwanted tokens (a plain `transferFrom` bypasses the hook
    /// entirely) and would only break legitimate marketplace and mint flows.
    ///
    /// The `#[selector]` override is load-bearing: stylus-proc renders
    /// `on_erc721_received` as `onErc721Received` (selector `0x5ca688d3`), but
    /// ERC-721 calls `onERC721Received` (`0x150b7a02`). Without this the hook is
    /// never reached, the fallback rejects the transfer, and the account still
    /// cannot receive NFTs — silently, because no selector in our own ABI moved.
    #[selector(name = "onERC721Received")]
    #[allow(clippy::too_many_arguments)]
    pub fn on_erc721_received(
        &mut self,
        _operator: Address,
        _from: Address,
        _token_id: U256,
        _data: Bytes,
    ) -> FixedBytes<4> {
        FixedBytes(ERC721_RECEIVED_MAGIC)
    }

    /// ERC-1155 single-transfer acceptance. Same rationale as the ERC-721 hook,
    /// including the selector override.
    #[selector(name = "onERC1155Received")]
    pub fn on_erc1155_received(
        &mut self,
        _operator: Address,
        _from: Address,
        _id: U256,
        _value: U256,
        _data: Bytes,
    ) -> FixedBytes<4> {
        FixedBytes(ERC1155_RECEIVED_MAGIC)
    }

    /// ERC-1155 batch-transfer acceptance.
    #[selector(name = "onERC1155BatchReceived")]
    pub fn on_erc1155_batch_received(
        &mut self,
        _operator: Address,
        _from: Address,
        _ids: Vec<U256>,
        _values: Vec<U256>,
        _data: Bytes,
    ) -> FixedBytes<4> {
        FixedBytes(ERC1155_BATCH_RECEIVED_MAGIC)
    }

    /// ERC-165. Advertises ERC-165 itself, EIP-1271, and both token receiver
    /// interfaces so marketplaces and bridges can detect support before
    /// attempting a safe transfer.
    pub fn supports_interface(&self, interface_id: FixedBytes<4>) -> bool {
        let id: [u8; 4] = interface_id.0;
        id == [0x01, 0xff, 0xc9, 0xa7]      // ERC-165
            || id == EIP1271_MAGIC           // EIP-1271 isValidSignature
            || id == ERC721_RECEIVED_MAGIC   // ERC721TokenReceiver
            || id == [0x4e, 0x23, 0x12, 0xe0] // ERC1155TokenReceiver
    }

    /// Reverts on any unknown selector.
    ///
    /// Stylus dispatches empty calldata to `#[receive]`, so anything reaching
    /// this handler is a non-empty unrecognised call — refuse it, to avoid
    /// ABI-probing false positives and to surface integration bugs in callers.
    ///
    /// `fallback` reverts with `UnknownSelector` while `receive` accepts ETH
    /// silently: a bare value transfer is a legitimate way to fund the account,
    /// whereas calldata the account does not implement is a caller mistake that
    /// should surface. The asymmetry is intentional.
    ///
    /// Note the differing return types: `#[fallback]` returns `ArbResult`
    /// (= `Result<Vec<u8>, Vec<u8>>`) because Solidity fallback semantics permit
    /// returning data, whereas `#[receive]` returns `Result<(), Vec<u8>>`.
    #[payable]
    #[fallback]
    pub fn fallback(&mut self, _input: &[u8]) -> ArbResult {
        Err(P256AccountError::UnknownSelector(UnknownSelector {}).into())
    }

    /// Accept incoming ETH so the account can hold a balance for outbound
    /// `execute` calls.
    #[payable]
    #[receive]
    pub fn receive(&mut self) -> Result<(), Vec<u8>> {
        Ok(())
    }
}

// =====================================================================
// Re-entrancy guard
// =====================================================================

impl P256Account {
    /// Latch the guard, or reject if an authorised call is already on the stack.
    ///
    /// This is NOT a substitute for the nonce: the nonce prevents replay across
    /// transactions, the guard prevents a callee from starting a second
    /// authorised call *within* one. Both are needed once `reentrant` is on.
    fn enter(&mut self) -> Result<(), P256AccountError> {
        if self.in_call.get() {
            return Err(P256AccountError::Reentrancy(Reentrancy {}));
        }
        self.in_call.set(true);
        Ok(())
    }

    /// Release the guard. Must run on every exit path, including error paths —
    /// a latched guard left behind would brick the account for the rest of the
    /// transaction. Reverting paths unwind storage anyway, but `execute`
    /// returns `Ok` with `success = false` for a failed inner call, and that
    /// path does not unwind.
    fn exit(&mut self) {
        self.in_call.set(false);
    }
}

// =====================================================================
// Internal helpers
// =====================================================================

// =====================================================================
// Pure validators — all storage / VM access happens at the call sites in
// the public methods above. These functions are deliberately free of the
// runtime context so the full state-machine matrix (constructor reject
// paths, execute revert mapping, rotate_owner nonce/bounds/sig, EIP-1271
// response) can be exercised host-side with the `#[cfg(test)]` precompile
// shim.
// =====================================================================

/// Bag of inputs for `validate_execute_request`. Lifetime `'a` ties the
/// borrowed `data` and `signature` slices together; nothing escapes.
struct ExecuteRequest<'a> {
    owner_x: U256,
    owner_y: U256,
    current_nonce: U256,
    chain_id: u64,
    account: Address,
    to: Address,
    value: U256,
    data: &'a [u8],
    nonce: U256,
    signature: &'a [u8],
}

/// Bag of inputs for `validate_rotation_request`.
struct RotationRequest<'a> {
    owner_x: U256,
    owner_y: U256,
    current_nonce: U256,
    chain_id: u64,
    account: Address,
    new_x: U256,
    new_y: U256,
    nonce: U256,
    signature: &'a [u8],
}

fn validate_constructor_args(x: U256, y: U256) -> Result<(), P256AccountError> {
    if !is_valid_pubkey(x, y) {
        return Err(P256AccountError::InvalidPublicKey(InvalidPublicKey {}));
    }
    Ok(())
}

fn validate_execute_request(r: &ExecuteRequest<'_>) -> Result<(), P256AccountError> {
    if r.current_nonce != r.nonce {
        return Err(P256AccountError::NonceMismatch(NonceMismatch {
            expected: r.current_nonce,
            got: r.nonce,
        }));
    }
    let hash = compute_execute_hash(r.chain_id, r.account, r.to, r.value, r.data, r.nonce);
    validate_p256_signature(hash, r.signature, r.owner_x, r.owner_y)
}

fn validate_rotation_request(r: &RotationRequest<'_>) -> Result<(), P256AccountError> {
    if r.current_nonce != r.nonce {
        return Err(P256AccountError::NonceMismatch(NonceMismatch {
            expected: r.current_nonce,
            got: r.nonce,
        }));
    }
    // Full curve membership, not just range: an off-curve rotation target
    // permanently bricks the account.
    if !is_valid_pubkey(r.new_x, r.new_y) {
        return Err(P256AccountError::InvalidPublicKey(InvalidPublicKey {}));
    }
    let hash = compute_rotate_hash(r.chain_id, r.account, r.new_x, r.new_y, r.nonce);
    validate_p256_signature(hash, r.signature, r.owner_x, r.owner_y)
}

/// Maps the `call::call` result onto the public `(success, return_data)`
/// shape that `execute` returns.
///
/// The nonce-before-call invariant (SPEC.md §5) — the nonce is committed
/// *before* this is reached, so a reverting inner call still consumes it — is
/// enforced structurally at the call site in `execute`. This helper exists so
/// the mapping itself is unit-testable.
#[allow(deprecated)]
fn execute_outcome(call_result: Result<Vec<u8>, call::Error>) -> (bool, Vec<u8>) {
    match call_result {
        Ok(bytes) => (true, bytes),
        Err(call::Error::Revert(bytes)) => (false, bytes),
        Err(call::Error::AbiDecodingFailed(_)) => (false, Vec::new()),
    }
}

/// EIP-1271 response: returns the 4-byte magic on success, all-zeros on
/// failure. Kept as a pure function so the mapping is unit-testable
/// independent of the precompile shim.
fn eip1271_response(verified: bool) -> [u8; 4] {
    if verified {
        EIP1271_MAGIC
    } else {
        [0u8; 4]
    }
}

/// Strict P-256 signature validator. Pure function — takes the owner key as
/// parameters rather than reading storage, so the full happy-path / error-arm
/// matrix can be exercised host-side via the `#[cfg(test)]` precompile shim.
///
/// Returns one of:
/// - `InvalidSignatureLength`: not 64 bytes
/// - `InvalidR`:  `r` not in `(0, n)`
/// - `InvalidS`:  `s` not in `(0, n)`  (separated from `HighS` for clarity)
/// - `HighS`:     `s > n/2` (malleable half)
/// - `InvalidSignature`: precompile rejected `(r, s)` for `(x, y, hash)`
fn validate_p256_signature(
    hash: B256,
    signature: &[u8],
    owner_x: U256,
    owner_y: U256,
) -> Result<(), P256AccountError> {
    if signature.len() != 64 {
        return Err(P256AccountError::InvalidSignatureLength(
            InvalidSignatureLength {
                got: signature.len() as u64,
            },
        ));
    }
    let r = U256::from_be_slice(&signature[0..32]);
    let s = U256::from_be_slice(&signature[32..64]);
    if !is_valid_scalar(r) {
        return Err(P256AccountError::InvalidR(InvalidR {}));
    }
    if !is_valid_scalar(s) {
        return Err(P256AccountError::InvalidS(InvalidS {}));
    }
    if !is_low_s(s) {
        return Err(P256AccountError::HighS(HighS {}));
    }
    if !verify_p256_precompile(hash, r, s, owner_x, owner_y) {
        return Err(P256AccountError::InvalidSignature(InvalidSignature {}));
    }
    Ok(())
}

/// Builds the RIP-7212 input and dispatches it through `precompile_staticcall`,
/// which is the real `STATICCALL` in non-test builds and a stub in tests.
fn verify_p256_precompile(hash: B256, r: U256, s: U256, x: U256, y: U256) -> bool {
    let mut input = [0u8; 160];
    input[0..32].copy_from_slice(hash.as_slice());
    input[32..64].copy_from_slice(&r.to_be_bytes::<32>());
    input[64..96].copy_from_slice(&s.to_be_bytes::<32>());
    input[96..128].copy_from_slice(&x.to_be_bytes::<32>());
    input[128..160].copy_from_slice(&y.to_be_bytes::<32>());

    match precompile_staticcall(&input) {
        Some(output) => output.len() == 32 && output[31] == 1,
        None => false,
    }
}

#[cfg(not(test))]
fn precompile_staticcall(input: &[u8; 160]) -> Option<Vec<u8>> {
    // SAFETY: `STATICCALL` to a fixed precompile address with a fixed-length
    // input. The precompile has no side effects, no state, and returns at
    // most 32 bytes. Any failure (e.g. precompile not enabled on the
    // chain) becomes `None`, which the caller treats as "verification
    // failed".
    unsafe { RawCall::new_static().call(P256_PRECOMPILE, input) }.ok()
}

#[cfg(test)]
fn precompile_staticcall(input: &[u8; 160]) -> Option<Vec<u8>> {
    test_precompile::dispatch(input)
}

#[cfg(test)]
mod test_precompile {
    //! Host-side stub for the RIP-7212 staticcall, so tests can exercise the
    //! `validate_p256_signature` matrix without a Stylus VM. Thread-local
    //! state, isolated per test thread; tests call `clear()` first to scrub
    //! anything left by an earlier test on the same thread.

    use alloc::vec;
    use alloc::vec::Vec;
    use core::cell::Cell;

    thread_local! {
        /// Next dispatch's outcome:
        ///   Some(true)  -> precompile returns 32-byte word `0…01`
        ///   Some(false) -> precompile returns 32-byte word `0…00`
        ///   None        -> precompile call failed (Err)
        static NEXT: Cell<Option<bool>> = const { Cell::new(None) };
        /// Last 160-byte input seen, so tests can assert layout.
        static LAST_INPUT: Cell<Option<[u8; 160]>> = const { Cell::new(None) };
    }

    pub fn expect_next(result: bool) {
        NEXT.with(|c| c.set(Some(result)));
    }

    pub fn clear() {
        NEXT.with(|c| c.set(None));
        LAST_INPUT.with(|c| c.set(None));
    }

    pub fn last_input() -> Option<[u8; 160]> {
        LAST_INPUT.with(|c| c.get())
    }

    pub(super) fn dispatch(input: &[u8; 160]) -> Option<Vec<u8>> {
        LAST_INPUT.with(|c| c.set(Some(*input)));
        match NEXT.with(|c| c.take()) {
            Some(true) => {
                let mut out = vec![0u8; 32];
                out[31] = 1;
                Some(out)
            }
            Some(false) => Some(vec![0u8; 32]),
            None => None,
        }
    }
}

/// EIP-712 domain separator:
/// `keccak256(DOMAIN_TYPEHASH ‖ NAME_HASH ‖ VERSION_HASH ‖ chainId ‖ this)`.
/// Batch shape validation, split out so it is unit-testable off-chain.
fn validate_batch_shape(
    to_len: usize,
    value_len: usize,
    data_len: usize,
) -> Result<(), P256AccountError> {
    if to_len == 0
        || to_len != value_len
        || to_len != data_len
        || to_len > MAX_BATCH_CALLS
    {
        return Err(P256AccountError::InvalidBatch(InvalidBatch {
            calls: to_len as u64,
            values: value_len as u64,
            datas: data_len as u64,
        }));
    }
    Ok(())
}

/// Shared nonce + signature check for an already-computed authorisation hash.
/// `execute` / `rotate_owner` build their hash inside their own validators;
/// batch uses this directly because its hash needs the full call array.
fn validate_authorised_hash(
    hash: B256,
    current_nonce: U256,
    nonce: U256,
    owner_x: U256,
    owner_y: U256,
    signature: &[u8],
) -> Result<(), P256AccountError> {
    if nonce != current_nonce {
        return Err(P256AccountError::NonceMismatch(NonceMismatch {
            expected: current_nonce,
            got: nonce,
        }));
    }
    validate_p256_signature(hash, signature, owner_x, owner_y)
}

/// EIP-712 hash of `PersonalSign(bytes32 hash)` — the EIP-1271 message domain.
///
/// Binds an arbitrary challenge into this account's domain (chainId +
/// verifyingContract) under a typehash that no authorisation path uses, so a
/// signature produced for a 1271 challenge cannot be replayed as `execute`,
/// `executeBatch` or `rotateOwner`, and vice versa.
fn compute_personal_sign_hash(chain_id: u64, account: Address, hash: B256) -> B256 {
    let mut struct_buf = [0u8; 64];
    struct_buf[0..32].copy_from_slice(PERSONAL_SIGN_TYPEHASH.as_slice());
    struct_buf[32..64].copy_from_slice(hash.as_slice());
    let struct_hash = keccak(struct_buf);
    eip712_envelope(chain_id, account, struct_hash)
}

/// EIP-712 hash of `BatchExecute(Call[] calls,uint256 nonce)`.
///
/// Per EIP-712, an array member hashes to `keccak256` of the concatenated
/// `hashStruct` of each element, and each `Call` hashes as
/// `keccak256(CALL_TYPEHASH || to || value || keccak256(data))`.
fn compute_batch_hash(
    chain_id: u64,
    account: Address,
    to: &[Address],
    value: &[U256],
    data: &[&[u8]],
    nonce: U256,
) -> B256 {
    let mut concatenated = Vec::with_capacity(to.len() * 32);
    for i in 0..to.len() {
        let data_hash = keccak(data[i]);
        let mut call_buf = [0u8; 128];
        call_buf[0..32].copy_from_slice(CALL_TYPEHASH.as_slice());
        call_buf[44..64].copy_from_slice(to[i].as_slice());
        call_buf[64..96].copy_from_slice(&value[i].to_be_bytes::<32>());
        call_buf[96..128].copy_from_slice(data_hash.as_slice());
        concatenated.extend_from_slice(keccak(call_buf).as_slice());
    }
    let calls_hash = keccak(&concatenated);

    let mut struct_buf = [0u8; 96];
    struct_buf[0..32].copy_from_slice(BATCH_TYPEHASH.as_slice());
    struct_buf[32..64].copy_from_slice(calls_hash.as_slice());
    struct_buf[64..96].copy_from_slice(&nonce.to_be_bytes::<32>());
    let struct_hash = keccak(struct_buf);

    eip712_envelope(chain_id, account, struct_hash)
}

fn compute_domain_separator(chain_id: u64, account: Address) -> B256 {
    let mut buf = [0u8; 160];
    buf[0..32].copy_from_slice(DOMAIN_TYPEHASH.as_slice());
    buf[32..64].copy_from_slice(NAME_HASH.as_slice());
    buf[64..96].copy_from_slice(VERSION_HASH.as_slice());
    // chainId, big-endian, left-padded to a 32-byte word
    buf[120..128].copy_from_slice(&chain_id.to_be_bytes());
    // account, left-padded to a 32-byte word
    buf[140..160].copy_from_slice(account.as_slice());
    keccak(buf)
}

/// EIP-712 envelope around the `Execute(...)` struct.
fn compute_execute_hash(
    chain_id: u64,
    account: Address,
    to: Address,
    value: U256,
    data: &[u8],
    nonce: U256,
) -> B256 {
    let data_hash = keccak(data);

    // structHash = keccak256(EXECUTE_TYPEHASH || to (padded) || value || data_hash || nonce)
    let mut struct_buf = [0u8; 160];
    struct_buf[0..32].copy_from_slice(EXECUTE_TYPEHASH.as_slice());
    struct_buf[44..64].copy_from_slice(to.as_slice());
    struct_buf[64..96].copy_from_slice(&value.to_be_bytes::<32>());
    struct_buf[96..128].copy_from_slice(data_hash.as_slice());
    struct_buf[128..160].copy_from_slice(&nonce.to_be_bytes::<32>());
    let struct_hash = keccak(struct_buf);

    eip712_envelope(chain_id, account, struct_hash)
}

/// EIP-712 envelope around the `RotateOwner(...)` struct.
fn compute_rotate_hash(
    chain_id: u64,
    account: Address,
    new_x: U256,
    new_y: U256,
    nonce: U256,
) -> B256 {
    // structHash = keccak256(ROTATE_TYPEHASH || newX || newY || nonce)
    let mut struct_buf = [0u8; 128];
    struct_buf[0..32].copy_from_slice(ROTATE_TYPEHASH.as_slice());
    struct_buf[32..64].copy_from_slice(&new_x.to_be_bytes::<32>());
    struct_buf[64..96].copy_from_slice(&new_y.to_be_bytes::<32>());
    struct_buf[96..128].copy_from_slice(&nonce.to_be_bytes::<32>());
    let struct_hash = keccak(struct_buf);

    eip712_envelope(chain_id, account, struct_hash)
}

/// `keccak256("\x19\x01" || domainSeparator || structHash)`.
fn eip712_envelope(chain_id: u64, account: Address, struct_hash: B256) -> B256 {
    let domain = compute_domain_separator(chain_id, account);
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(domain.as_slice());
    buf[34..66].copy_from_slice(struct_hash.as_slice());
    keccak(buf)
}

/// Strict low-S: `s ∈ (0, n/2]`. Rejects the malleable upper half.
fn is_low_s(s: U256) -> bool {
    s != U256::ZERO && s <= U256::from_be_bytes(P256_HALF_ORDER)
}

/// ECDSA scalar bound: `c ∈ (0, n)`. Required of both `r` and `s`.
fn is_valid_scalar(c: U256) -> bool {
    c != U256::ZERO && c < U256::from_be_bytes(P256_ORDER_N)
}

/// Field-element range check: `c ∈ (0, p)`. Necessary but not sufficient —
/// pair it with [`is_on_curve`].
fn is_valid_pubkey_component(c: U256) -> bool {
    c != U256::ZERO && c < U256::from_be_bytes(P256_FIELD_PRIME)
}

/// Full curve-membership test: `y² ≡ x³ − 3x + b (mod p)`.
///
/// Range-checking `(x, y)` is not enough on its own: an off-curve owner
/// deploys fine and then makes every future signature unverifiable — a
/// **permanent, unrecoverable brick**. Three modular multiplications is a cheap
/// price for a footgun whose blast radius is the entire account. Do not drop
/// this in favour of the range check alone.
///
/// The subtraction is done as `+ (p − 3x)`, which cannot underflow because
/// `3x mod p < p`.
fn is_on_curve(x: U256, y: U256) -> bool {
    let p = U256::from_be_bytes(P256_FIELD_PRIME);
    let b = U256::from_be_bytes(P256_B);

    let y2 = y.mul_mod(y, p);
    let x3 = x.mul_mod(x, p).mul_mod(x, p);
    let three_x = x.mul_mod(U256::from(3), p);
    let rhs = x3.add_mod(p - three_x, p).add_mod(b, p);

    y2 == rhs
}

/// A public key is usable iff both components are in range AND the point is on
/// the curve.
fn is_valid_pubkey(x: U256, y: U256) -> bool {
    is_valid_pubkey_component(x) && is_valid_pubkey_component(y) && is_on_curve(x, y)
}

// =====================================================================
// Tests
// =====================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use alloy_primitives::keccak256;

    // ---- constants ----

    #[test]
    fn precompile_address_is_0x100() {
        let mut expected = [0u8; 20];
        expected[18] = 0x01;
        assert_eq!(P256_PRECOMPILE, Address::from(expected));
    }

    #[test]
    fn p256_order_constant_matches_spec() {
        let n = U256::from_be_bytes(P256_ORDER_N);
        let expected: U256 = "0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551"
            .parse()
            .unwrap();
        assert_eq!(n, expected);
    }

    #[test]
    fn p256_field_prime_constant_matches_spec() {
        let p = U256::from_be_bytes(P256_FIELD_PRIME);
        let expected: U256 = "0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF"
            .parse()
            .unwrap();
        assert_eq!(p, expected);
    }

    #[test]
    fn half_order_is_floor_n_over_2() {
        let n = U256::from_be_bytes(P256_ORDER_N);
        let half = U256::from_be_bytes(P256_HALF_ORDER);
        assert_eq!(half * U256::from(2) + U256::from(1), n);
    }

    #[test]
    fn eip1271_magic_value_matches_spec() {
        // bytes4(keccak256("isValidSignature(bytes32,bytes)")) = 0x1626ba7e
        assert_eq!(EIP1271_MAGIC, [0x16, 0x26, 0xba, 0x7e]);
    }

    // ---- EIP-712 typehash audit ----

    #[test]
    fn domain_typehash_matches_string() {
        let expected = keccak256(
            "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
        );
        assert_eq!(DOMAIN_TYPEHASH, expected);
    }

    #[test]
    fn execute_typehash_matches_string() {
        let expected = keccak256("Execute(address to,uint256 value,bytes data,uint256 nonce)");
        assert_eq!(EXECUTE_TYPEHASH, expected);
    }

    #[test]
    fn rotate_typehash_matches_string() {
        let expected = keccak256("RotateOwner(uint256 newX,uint256 newY,uint256 nonce)");
        assert_eq!(ROTATE_TYPEHASH, expected);
    }

    #[test]
    fn name_and_version_hashes_match_strings() {
        assert_eq!(NAME_HASH, keccak256("P256Account"));
        assert_eq!(VERSION_HASH, keccak256("1"));
    }

    // ---- bounds predicates ----

    #[test]
    fn low_s_accepts_boundary_and_rejects_above() {
        let half = U256::from_be_bytes(P256_HALF_ORDER);
        let n = U256::from_be_bytes(P256_ORDER_N);
        assert!(!is_low_s(U256::ZERO));
        assert!(is_low_s(U256::from(1)));
        assert!(is_low_s(half));
        assert!(!is_low_s(half + U256::from(1)));
        assert!(!is_low_s(n - U256::from(1)));
    }

    #[test]
    fn scalar_bound_accepts_in_range_rejects_out_of_range() {
        let n = U256::from_be_bytes(P256_ORDER_N);
        assert!(!is_valid_scalar(U256::ZERO));
        assert!(is_valid_scalar(U256::from(1)));
        assert!(is_valid_scalar(n - U256::from(1)));
        assert!(!is_valid_scalar(n));
        assert!(!is_valid_scalar(n + U256::from(1)));
        assert!(!is_valid_scalar(U256::MAX));
        let half = U256::from_be_bytes(P256_HALF_ORDER);
        assert!(is_valid_scalar(half));
    }

    #[test]
    fn pubkey_component_validation_rejects_extremes() {
        let p = U256::from_be_bytes(P256_FIELD_PRIME);
        assert!(!is_valid_pubkey_component(U256::ZERO));
        assert!(!is_valid_pubkey_component(p));
        assert!(!is_valid_pubkey_component(p + U256::from(1)));
        assert!(!is_valid_pubkey_component(U256::MAX));
        assert!(is_valid_pubkey_component(U256::from(1)));
        assert!(is_valid_pubkey_component(p - U256::from(1)));
    }

    // ---- hash determinism & domain separation ----

    #[test]
    fn execute_hash_is_domain_separated() {
        let acct = Address::from([0x11; 20]);
        let to = Address::from([0x22; 20]);
        let val = U256::from(1_000u64);
        let data: &[u8] = b"hello";

        let h1 = compute_execute_hash(42161, acct, to, val, data, U256::ZERO);
        let h2 = compute_execute_hash(42161, acct, to, val, data, U256::ZERO);
        assert_eq!(h1, h2);

        // chainId / account / nonce / to / value / data must each change the hash
        assert_ne!(
            h1,
            compute_execute_hash(421614, acct, to, val, data, U256::ZERO)
        );
        assert_ne!(
            h1,
            compute_execute_hash(42161, Address::from([0x99; 20]), to, val, data, U256::ZERO)
        );
        assert_ne!(
            h1,
            compute_execute_hash(42161, acct, to, val, data, U256::from(1))
        );
        assert_ne!(
            h1,
            compute_execute_hash(42161, acct, Address::from([0x33; 20]), val, data, U256::ZERO)
        );
        assert_ne!(
            h1,
            compute_execute_hash(42161, acct, to, U256::from(2_000u64), data, U256::ZERO)
        );
        assert_ne!(
            h1,
            compute_execute_hash(42161, acct, to, val, b"world", U256::ZERO)
        );
    }

    #[test]
    fn rotate_hash_is_domain_separated_and_distinct_from_execute() {
        let acct = Address::from([0x11; 20]);
        let new_x = U256::from(0xAAu64);
        let new_y = U256::from(0xBBu64);

        let h1 = compute_rotate_hash(42161, acct, new_x, new_y, U256::ZERO);
        let h2 = compute_rotate_hash(42161, acct, new_x, new_y, U256::ZERO);
        assert_eq!(h1, h2);

        // chain, account, newX, newY, nonce all matter
        assert_ne!(
            h1,
            compute_rotate_hash(421614, acct, new_x, new_y, U256::ZERO)
        );
        assert_ne!(
            h1,
            compute_rotate_hash(42161, Address::from([0x99; 20]), new_x, new_y, U256::ZERO)
        );
        assert_ne!(
            h1,
            compute_rotate_hash(42161, acct, U256::from(0xAAu64) + U256::from(1), new_y, U256::ZERO)
        );
        assert_ne!(
            h1,
            compute_rotate_hash(42161, acct, new_x, U256::from(0xBBu64) + U256::from(1), U256::ZERO)
        );
        assert_ne!(
            h1,
            compute_rotate_hash(42161, acct, new_x, new_y, U256::from(1))
        );

        // Critical: rotate hash MUST differ from any execute hash even on
        // matching account / chain / nonce — different typehash in the struct.
        let exec = compute_execute_hash(42161, acct, Address::ZERO, U256::ZERO, &[], U256::ZERO);
        assert_ne!(h1, exec);
    }

    #[test]
    fn eip712_envelope_matches_manual_construction() {
        // Cross-check eip712_envelope against an inline reconstruction.
        let acct = Address::from([0x42; 20]);
        let chain_id: u64 = 42161;
        let struct_hash = B256::from([0xAB; 32]);

        let got = eip712_envelope(chain_id, acct, struct_hash);

        let domain = compute_domain_separator(chain_id, acct);
        let mut manual = Vec::with_capacity(66);
        manual.push(0x19);
        manual.push(0x01);
        manual.extend_from_slice(domain.as_slice());
        manual.extend_from_slice(struct_hash.as_slice());
        let expected = keccak256(&manual);

        assert_eq!(got, expected);
    }

    // ---- precompile input layout ----

    #[test]
    fn precompile_input_layout_is_hash_r_s_x_y() {
        // Reproduce the exact byte layout `verify_p256_precompile` builds and
        // assert it matches RIP-7212: `hash(32) || r(32) || s(32) || x(32) || y(32)`.
        let hash = B256::from([0x11; 32]);
        let r = U256::from(0x22u64);
        let s = U256::from(0x33u64);
        let x = U256::from(0x44u64);
        let y = U256::from(0x55u64);

        let mut expected = [0u8; 160];
        expected[0..32].copy_from_slice(&[0x11; 32]);
        expected[32..64].copy_from_slice(&r.to_be_bytes::<32>());
        expected[64..96].copy_from_slice(&s.to_be_bytes::<32>());
        expected[96..128].copy_from_slice(&x.to_be_bytes::<32>());
        expected[128..160].copy_from_slice(&y.to_be_bytes::<32>());

        // mirror the body of verify_p256_precompile (sans the staticcall)
        let mut input = [0u8; 160];
        input[0..32].copy_from_slice(hash.as_slice());
        input[32..64].copy_from_slice(&r.to_be_bytes::<32>());
        input[64..96].copy_from_slice(&s.to_be_bytes::<32>());
        input[96..128].copy_from_slice(&x.to_be_bytes::<32>());
        input[128..160].copy_from_slice(&y.to_be_bytes::<32>());

        assert_eq!(input, expected);
        assert_eq!(input.len(), 160);
    }

    // ---- error shapes ----

    #[test]
    fn error_variants_are_distinct() {
        let e_bad_r = P256AccountError::InvalidR(InvalidR {});
        let e_bad_s = P256AccountError::InvalidS(InvalidS {});
        let e_high_s = P256AccountError::HighS(HighS {});
        let e_bad_sig = P256AccountError::InvalidSignature(InvalidSignature {});
        let e_nonce = P256AccountError::NonceMismatch(NonceMismatch {
            expected: U256::from(5),
            got: U256::from(7),
        });
        let e_unknown = P256AccountError::UnknownSelector(UnknownSelector {});
        assert!(matches!(e_bad_r, P256AccountError::InvalidR(_)));
        assert!(matches!(e_bad_s, P256AccountError::InvalidS(_)));
        assert!(matches!(e_high_s, P256AccountError::HighS(_)));
        assert!(matches!(e_bad_sig, P256AccountError::InvalidSignature(_)));
        assert!(matches!(e_unknown, P256AccountError::UnknownSelector(_)));
        if let P256AccountError::NonceMismatch(NonceMismatch { expected, got }) = e_nonce {
            assert_eq!(expected, U256::from(5));
            assert_eq!(got, U256::from(7));
        } else {
            panic!("wrong variant");
        }
    }

    #[test]
    fn invalid_signature_length_is_uint64_and_carries_value() {
        let err = InvalidSignatureLength { got: 42u64 };
        assert_eq!(err.got, 42u64);
    }

    // ---- signature validation via mocked precompile ----

    /// Helper: a syntactically valid 64-byte sig with arbitrary in-range
    /// scalars `r = 1`, `s = 1`. Layout exercises every byte of the
    /// signature buffer.
    fn well_formed_sig() -> [u8; 64] {
        let mut sig = [0u8; 64];
        sig[31] = 1; // r = 0x00…01
        sig[63] = 1; // s = 0x00…01
        sig
    }

    #[test]
    fn validate_rejects_wrong_length() {
        test_precompile::clear();
        let err = validate_p256_signature(
            B256::ZERO,
            &[0u8; 63],
            U256::from(1),
            U256::from(1),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            P256AccountError::InvalidSignatureLength(InvalidSignatureLength { got: 63 })
        ));
    }

    #[test]
    fn validate_rejects_zero_r() {
        test_precompile::clear();
        let mut sig = well_formed_sig();
        sig[0..32].fill(0); // r = 0
        let err =
            validate_p256_signature(B256::ZERO, &sig, U256::from(1), U256::from(1)).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidR(_)));
    }

    #[test]
    fn validate_rejects_r_above_or_equal_to_n() {
        test_precompile::clear();
        let mut sig = well_formed_sig();
        // r = n (out of range; valid scalars must be in (0, n))
        sig[0..32].copy_from_slice(&P256_ORDER_N);
        let err =
            validate_p256_signature(B256::ZERO, &sig, U256::from(1), U256::from(1)).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidR(_)));
    }

    #[test]
    fn validate_rejects_zero_s_as_invalid_s() {
        test_precompile::clear();
        let mut sig = well_formed_sig();
        sig[32..64].fill(0); // s = 0
        let err =
            validate_p256_signature(B256::ZERO, &sig, U256::from(1), U256::from(1)).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidS(_)));
    }

    #[test]
    fn validate_rejects_high_s_with_dedicated_error() {
        test_precompile::clear();
        // s = n/2 + 1 (smallest high-S value): in-range as a scalar but
        // above the malleability boundary, so `InvalidS` (range) must not
        // fire and `HighS` must.
        let half = U256::from_be_bytes(P256_HALF_ORDER);
        let s = half + U256::from(1);
        let mut sig = well_formed_sig();
        sig[32..64].copy_from_slice(&s.to_be_bytes::<32>());
        let err =
            validate_p256_signature(B256::ZERO, &sig, U256::from(1), U256::from(1)).unwrap_err();
        assert!(matches!(err, P256AccountError::HighS(_)));
    }

    #[test]
    fn validate_rejects_when_precompile_returns_false() {
        test_precompile::clear();
        test_precompile::expect_next(false);
        let sig = well_formed_sig();
        let err =
            validate_p256_signature(B256::ZERO, &sig, U256::from(1), U256::from(1)).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidSignature(_)));
    }

    #[test]
    fn validate_rejects_when_precompile_unavailable() {
        test_precompile::clear(); // dispatch -> None (simulates precompile error)
        let sig = well_formed_sig();
        let err =
            validate_p256_signature(B256::ZERO, &sig, U256::from(1), U256::from(1)).unwrap_err();
        // No magic value -> staticcall returned Err -> precompile rejected.
        assert!(matches!(err, P256AccountError::InvalidSignature(_)));
    }

    #[test]
    fn validate_accepts_when_precompile_returns_magic_one() {
        test_precompile::clear();
        test_precompile::expect_next(true);
        let sig = well_formed_sig();
        assert!(validate_p256_signature(B256::ZERO, &sig, U256::from(1), U256::from(1)).is_ok());
    }

    // ---- execute_outcome (revert-path mapping) ----

    #[test]
    fn execute_outcome_maps_ok_to_success_with_return_bytes() {
        let r = execute_outcome(Ok(alloc::vec![0xCA, 0xFE]));
        assert_eq!(r, (true, alloc::vec![0xCA, 0xFE]));
    }

    #[test]
    // Same SDK-0.9.0 deprecation as the import above: constructing the variant
    // is the only way to exercise `execute_outcome`'s revert arm at this pin.
    #[allow(deprecated)]
    fn execute_outcome_maps_revert_to_failure_carrying_bytes() {
        let revert = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
        let r = execute_outcome(Err(call::Error::Revert(revert.clone())));
        // Critical: success = false but the revert bytes are preserved, so the
        // SDK can surface the target's revert reason instead of a bare failure.
        // Dropping them here would make every failed inner call indistinguishable.
        assert_eq!(r, (false, revert));
    }

    #[test]
    #[allow(deprecated)]
    fn execute_outcome_preserves_empty_revert_bytes() {
        // Some reverts carry no data (e.g. `revert()` with no message).
        let r = execute_outcome(Err(call::Error::Revert(Vec::new())));
        assert_eq!(r, (false, Vec::new()));
    }

    // ---- EIP-1271 response mapping ----

    #[test]
    fn eip1271_response_returns_magic_on_verified() {
        assert_eq!(eip1271_response(true), EIP1271_MAGIC);
    }

    #[test]
    fn eip1271_response_returns_zeros_on_unverified() {
        assert_eq!(eip1271_response(false), [0u8; 4]);
        // And the zero sentinel is NOT a prefix of the magic (no near-miss
        // collisions that could fool a buggy caller).
        assert_ne!(eip1271_response(false), EIP1271_MAGIC);
    }

    // ---- constructor validation ----

    #[test]
    fn constructor_rejects_zero_x() {
        assert!(matches!(
            validate_constructor_args(U256::ZERO, U256::from(1)),
            Err(P256AccountError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn constructor_rejects_zero_y() {
        assert!(matches!(
            validate_constructor_args(U256::from(1), U256::ZERO),
            Err(P256AccountError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn constructor_rejects_x_at_p() {
        let p = U256::from_be_bytes(P256_FIELD_PRIME);
        assert!(matches!(
            validate_constructor_args(p, U256::from(1)),
            Err(P256AccountError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn constructor_rejects_y_at_p() {
        let p = U256::from_be_bytes(P256_FIELD_PRIME);
        assert!(matches!(
            validate_constructor_args(U256::from(1), p),
            Err(P256AccountError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn constructor_rejects_when_both_are_invalid() {
        assert!(matches!(
            validate_constructor_args(U256::ZERO, U256::ZERO),
            Err(P256AccountError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn constructor_accepts_in_range_pubkey() {
        // Must be a real curve point now that membership is verified.
        assert!(validate_constructor_args(u(GX), u(GY)).is_ok());
        // In range but NOT on the curve — accepted before curve membership was
        // enforced, and it would have deployed a permanently bricked account.
        let p_minus_1 = U256::from_be_bytes(P256_FIELD_PRIME) - U256::from(1);
        assert!(matches!(
            validate_constructor_args(p_minus_1, p_minus_1),
            Err(P256AccountError::InvalidPublicKey(_))
        ));
    }

    // ---- execute request validation ----

    fn fixture_execute_request<'a>(sig: &'a [u8]) -> ExecuteRequest<'a> {
        ExecuteRequest {
            owner_x: u(GX),
            owner_y: u(GY),
            current_nonce: U256::ZERO,
            chain_id: 42161,
            account: Address::from([0x11; 20]),
            to: Address::from([0x22; 20]),
            value: U256::from(1_000u64),
            data: &[],
            nonce: U256::ZERO,
            signature: sig,
        }
    }

    #[test]
    fn execute_request_rejects_nonce_mismatch() {
        test_precompile::clear();
        let sig = well_formed_sig();
        let mut req = fixture_execute_request(&sig);
        req.current_nonce = U256::from(5);
        req.nonce = U256::from(7);
        let err = validate_execute_request(&req).unwrap_err();
        if let P256AccountError::NonceMismatch(NonceMismatch { expected, got }) = err {
            assert_eq!(expected, U256::from(5));
            assert_eq!(got, U256::from(7));
        } else {
            panic!("expected NonceMismatch, got {:?}", err);
        }
    }

    #[test]
    fn execute_request_rejects_invalid_signature() {
        test_precompile::clear();
        test_precompile::expect_next(false); // precompile rejects
        let sig = well_formed_sig();
        let req = fixture_execute_request(&sig);
        let err = validate_execute_request(&req).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidSignature(_)));
    }

    #[test]
    fn execute_request_accepts_when_all_checks_pass() {
        test_precompile::clear();
        test_precompile::expect_next(true);
        let sig = well_formed_sig();
        let req = fixture_execute_request(&sig);
        assert!(validate_execute_request(&req).is_ok());
    }

    #[test]
    fn execute_request_dispatches_with_execute_hash_not_rotate_hash() {
        // Domain-separation regression guard: the validator must use the
        // execute_typehash path, not the rotate one.
        test_precompile::clear();
        test_precompile::expect_next(true);
        let sig = well_formed_sig();
        let req = fixture_execute_request(&sig);
        validate_execute_request(&req).unwrap();
        let seen_hash = &test_precompile::last_input().unwrap()[0..32];
        let expected = compute_execute_hash(
            req.chain_id,
            req.account,
            req.to,
            req.value,
            req.data,
            req.nonce,
        );
        assert_eq!(seen_hash, expected.as_slice());
    }

    // ---- rotate_owner request validation ----

    fn fixture_rotation_request<'a>(sig: &'a [u8]) -> RotationRequest<'a> {
        RotationRequest {
            owner_x: u(GX),
            owner_y: u(GY),
            current_nonce: U256::ZERO,
            chain_id: 42161,
            account: Address::from([0x11; 20]),
            new_x: u(G2X),
            new_y: u(G2Y),
            nonce: U256::ZERO,
            signature: sig,
        }
    }

    #[test]
    fn rotation_request_rejects_nonce_mismatch() {
        test_precompile::clear();
        let sig = well_formed_sig();
        let mut req = fixture_rotation_request(&sig);
        req.current_nonce = U256::from(3);
        req.nonce = U256::from(9);
        let err = validate_rotation_request(&req).unwrap_err();
        assert!(matches!(err, P256AccountError::NonceMismatch(_)));
    }

    #[test]
    fn rotation_request_rejects_zero_new_x() {
        test_precompile::clear();
        let sig = well_formed_sig();
        let mut req = fixture_rotation_request(&sig);
        req.new_x = U256::ZERO;
        let err = validate_rotation_request(&req).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidPublicKey(_)));
    }

    #[test]
    fn rotation_request_rejects_zero_new_y() {
        test_precompile::clear();
        let sig = well_formed_sig();
        let mut req = fixture_rotation_request(&sig);
        req.new_y = U256::ZERO;
        let err = validate_rotation_request(&req).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidPublicKey(_)));
    }

    #[test]
    fn rotation_request_rejects_new_x_at_or_above_p() {
        test_precompile::clear();
        let sig = well_formed_sig();
        let mut req = fixture_rotation_request(&sig);
        req.new_x = U256::from_be_bytes(P256_FIELD_PRIME);
        let err = validate_rotation_request(&req).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidPublicKey(_)));
    }

    #[test]
    fn rotation_request_rejects_when_signature_fails() {
        test_precompile::clear();
        test_precompile::expect_next(false);
        let sig = well_formed_sig();
        let req = fixture_rotation_request(&sig);
        let err = validate_rotation_request(&req).unwrap_err();
        assert!(matches!(err, P256AccountError::InvalidSignature(_)));
    }

    #[test]
    fn rotation_request_signature_is_verified_against_current_owner() {
        // Belt-and-braces: assert the precompile receives the CURRENT
        // owner's key as (x, y), not the candidate new key. A subtle
        // mis-edit could swap them and let the new owner unilaterally
        // claim the account.
        test_precompile::clear();
        test_precompile::expect_next(true);
        let sig = well_formed_sig();
        let mut req = fixture_rotation_request(&sig);
        req.owner_x = U256::from(0xCAFEu64);
        req.owner_y = U256::from(0xBEEFu64);
        // The rotation TARGET must be a real curve point; the current owner is
        // not curve-checked here (this test is about which key reaches the
        // precompile), so it stays an arbitrary sentinel.
        req.new_x = u(G2X);
        req.new_y = u(G2Y);
        validate_rotation_request(&req).unwrap();
        let seen = test_precompile::last_input().unwrap();
        // bytes [96..128] of the precompile input = x; [128..160] = y
        let mut want_x = [0u8; 32];
        want_x[24..32].copy_from_slice(&0xCAFEu64.to_be_bytes());
        let mut want_y = [0u8; 32];
        want_y[24..32].copy_from_slice(&0xBEEFu64.to_be_bytes());
        assert_eq!(&seen[96..128], &want_x, "x must be CURRENT owner_x");
        assert_eq!(&seen[128..160], &want_y, "y must be CURRENT owner_y");
    }

    #[test]
    fn rotation_request_accepts_when_all_checks_pass() {
        test_precompile::clear();
        test_precompile::expect_next(true);
        let sig = well_formed_sig();
        let req = fixture_rotation_request(&sig);
        assert!(validate_rotation_request(&req).is_ok());
    }

    #[test]
    fn rotation_request_dispatches_with_rotate_hash_not_execute_hash() {
        // Cross-replay regression guard: the validator must use the
        // RotateOwner typehash path. If a future edit slipped it through
        // execute_hash, an execute signature could authorise a rotation.
        test_precompile::clear();
        test_precompile::expect_next(true);
        let sig = well_formed_sig();
        let req = fixture_rotation_request(&sig);
        validate_rotation_request(&req).unwrap();
        let seen_hash = &test_precompile::last_input().unwrap()[0..32];
        let expected = compute_rotate_hash(
            req.chain_id,
            req.account,
            req.new_x,
            req.new_y,
            req.nonce,
        );
        assert_eq!(seen_hash, expected.as_slice());
    }

    #[test]
    fn validate_dispatches_canonical_rip7212_layout() {
        // Asserts the validator builds the precompile input in the order
        // RIP-7212 specifies: hash(32) || r(32) || s(32) || x(32) || y(32).
        test_precompile::clear();
        test_precompile::expect_next(true);
        let hash = B256::from([0x77; 32]);
        let r = U256::from(0x1234_5678u64);
        let s = U256::from(0x9ABC_DEF0u64);
        let x = U256::from(0xAAAA_BBBBu64);
        let y = U256::from(0xCCCC_DDDDu64);
        let mut sig = [0u8; 64];
        sig[0..32].copy_from_slice(&r.to_be_bytes::<32>());
        sig[32..64].copy_from_slice(&s.to_be_bytes::<32>());

        validate_p256_signature(hash, &sig, x, y).expect("happy path");

        let seen = test_precompile::last_input().expect("dispatch was called");
        assert_eq!(&seen[0..32], hash.as_slice());
        assert_eq!(&seen[32..64], r.to_be_bytes::<32>().as_slice());
        assert_eq!(&seen[64..96], s.to_be_bytes::<32>().as_slice());
        assert_eq!(&seen[96..128], x.to_be_bytes::<32>().as_slice());
        assert_eq!(&seen[128..160], y.to_be_bytes::<32>().as_slice());
    }

    // -----------------------------------------------------------------
    // Batch execute (EIP-712 + shape validation)
    // -----------------------------------------------------------------

    #[test]
    fn batch_typehash_matches_string() {
        let expected = keccak(
            b"BatchExecute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)"
                .as_slice(),
        );
        assert_eq!(BATCH_TYPEHASH, expected);
    }

    #[test]
    fn call_typehash_matches_string() {
        let expected = keccak(b"Call(address to,uint256 value,bytes data)".as_slice());
        assert_eq!(CALL_TYPEHASH, expected);
    }

    #[test]
    fn batch_typehash_is_distinct_from_execute_and_rotate() {
        assert_ne!(BATCH_TYPEHASH, EXECUTE_TYPEHASH);
        assert_ne!(BATCH_TYPEHASH, ROTATE_TYPEHASH);
        assert_ne!(BATCH_TYPEHASH, CALL_TYPEHASH);
    }

    #[test]
    fn batch_shape_rejects_empty_mismatched_and_oversized() {
        assert!(validate_batch_shape(0, 0, 0).is_err(), "empty batch");
        assert!(validate_batch_shape(2, 1, 2).is_err(), "value len mismatch");
        assert!(validate_batch_shape(2, 2, 1).is_err(), "data len mismatch");
        assert!(
            validate_batch_shape(MAX_BATCH_CALLS + 1, MAX_BATCH_CALLS + 1, MAX_BATCH_CALLS + 1)
                .is_err(),
            "over cap"
        );
        assert!(validate_batch_shape(1, 1, 1).is_ok());
        assert!(validate_batch_shape(MAX_BATCH_CALLS, MAX_BATCH_CALLS, MAX_BATCH_CALLS).is_ok());
    }

    #[test]
    fn batch_shape_error_carries_all_three_lengths() {
        match validate_batch_shape(3, 2, 1) {
            Err(P256AccountError::InvalidBatch(e)) => {
                assert_eq!(e.calls, 3);
                assert_eq!(e.values, 2);
                assert_eq!(e.datas, 1);
            }
            other => panic!("expected InvalidBatch, got {other:?}"),
        }
    }

    fn batch_fixture() -> (Vec<Address>, Vec<U256>, Vec<&'static [u8]>) {
        (
            vec![Address::from([0x11u8; 20]), Address::from([0x22u8; 20])],
            vec![U256::from(0), U256::from(7)],
            vec![b"approve".as_slice(), b"swap".as_slice()],
        )
    }

    #[test]
    fn batch_hash_is_domain_separated() {
        let (to, value, data) = batch_fixture();
        let acct = Address::from([0xaau8; 20]);
        let other = Address::from([0xbbu8; 20]);

        let base = compute_batch_hash(42161, acct, &to, &value, &data, U256::from(0));
        assert_ne!(
            base,
            compute_batch_hash(1, acct, &to, &value, &data, U256::from(0)),
            "chainId must bind"
        );
        assert_ne!(
            base,
            compute_batch_hash(42161, other, &to, &value, &data, U256::from(0)),
            "account must bind"
        );
        assert_ne!(
            base,
            compute_batch_hash(42161, acct, &to, &value, &data, U256::from(1)),
            "nonce must bind"
        );
    }

    #[test]
    fn batch_hash_is_order_sensitive() {
        // approve-then-swap must not hash the same as swap-then-approve, or a
        // relayer could reorder a signed batch into something harmful.
        let (to, value, data) = batch_fixture();
        let acct = Address::from([0xaau8; 20]);

        let forward = compute_batch_hash(42161, acct, &to, &value, &data, U256::from(0));

        let to_rev: Vec<Address> = to.iter().rev().copied().collect();
        let value_rev: Vec<U256> = value.iter().rev().copied().collect();
        let data_rev: Vec<&[u8]> = data.iter().rev().copied().collect();
        let reversed =
            compute_batch_hash(42161, acct, &to_rev, &value_rev, &data_rev, U256::from(0));

        assert_ne!(forward, reversed);
    }

    #[test]
    fn batch_hash_binds_every_field_of_every_call() {
        let (to, value, data) = batch_fixture();
        let acct = Address::from([0xaau8; 20]);
        let base = compute_batch_hash(42161, acct, &to, &value, &data, U256::from(0));

        let mut to2 = to.clone();
        to2[1] = Address::from([0x33u8; 20]);
        assert_ne!(base, compute_batch_hash(42161, acct, &to2, &value, &data, U256::from(0)));

        let mut value2 = value.clone();
        value2[1] = U256::from(8);
        assert_ne!(base, compute_batch_hash(42161, acct, &to, &value2, &data, U256::from(0)));

        let data2: Vec<&[u8]> = vec![b"approve".as_slice(), b"swap!".as_slice()];
        assert_ne!(base, compute_batch_hash(42161, acct, &to, &value, &data2, U256::from(0)));
    }

    #[test]
    fn single_call_batch_does_not_collide_with_execute() {
        // The whole point of a separate typehash: a 1-call batch signature must
        // not be replayable as a plain `execute` signature or vice versa.
        let acct = Address::from([0xaau8; 20]);
        let to = Address::from([0x11u8; 20]);
        let value = U256::from(5);
        let data = b"x".as_slice();
        let nonce = U256::from(3);

        let batch = compute_batch_hash(42161, acct, &[to], &[value], &[data], nonce);
        let single = compute_execute_hash(42161, acct, to, value, data, nonce);
        assert_ne!(batch, single);
    }

    #[test]
    fn authorised_hash_rejects_nonce_mismatch_before_checking_signature() {
        test_precompile::clear();
        let hash = B256::from([0x42u8; 32]);
        let sig = well_formed_sig();
        let res = validate_authorised_hash(
            hash,
            U256::from(5),
            U256::from(4),
            U256::from(1),
            U256::from(2),
            &sig,
        );
        assert!(matches!(res, Err(P256AccountError::NonceMismatch(_))));
        // The precompile must not have been consulted at all.
        assert!(test_precompile::last_input().is_none());
    }

    #[test]
    fn authorised_hash_rejects_bad_signature_and_accepts_good_one() {
        let hash = B256::from([0x42u8; 32]);
        let sig = well_formed_sig();

        test_precompile::clear();
        test_precompile::expect_next(false);
        assert!(matches!(
            validate_authorised_hash(hash, U256::ZERO, U256::ZERO, u(GX), u(GY), &sig),
            Err(P256AccountError::InvalidSignature(_))
        ));

        test_precompile::clear();
        test_precompile::expect_next(true);
        assert!(validate_authorised_hash(
            hash,
            U256::ZERO,
            U256::ZERO,
            U256::from(1),
            U256::from(2),
            &sig
        )
        .is_ok());
        // and it dispatched exactly the hash it was handed, not some
        // re-derived digest — the fixture is a 0x42.. sentinel, not a batch hash
        let seen = test_precompile::last_input().expect("precompile called");
        assert_eq!(&seen[0..32], hash.as_slice());
    }

    // -----------------------------------------------------------------
    // Token receiver hooks
    // -----------------------------------------------------------------

    #[test]
    fn receiver_magic_values_match_their_signatures() {
        assert_eq!(
            ERC721_RECEIVED_MAGIC,
            keccak(b"onERC721Received(address,address,uint256,bytes)".as_slice()).as_slice()[0..4]
        );
        assert_eq!(
            ERC1155_RECEIVED_MAGIC,
            keccak(b"onERC1155Received(address,address,uint256,uint256,bytes)".as_slice())
                .as_slice()[0..4]
        );
        assert_eq!(
            ERC1155_BATCH_RECEIVED_MAGIC,
            keccak(
                b"onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)".as_slice()
            )
            .as_slice()[0..4]
        );
    }

    #[test]
    fn receiver_magics_are_distinct_from_the_eip1271_magic() {
        // A collision here would let a token callback masquerade as a valid
        // 1271 response to a caller that only checks four bytes.
        assert_ne!(ERC721_RECEIVED_MAGIC, EIP1271_MAGIC);
        assert_ne!(ERC1155_RECEIVED_MAGIC, EIP1271_MAGIC);
        assert_ne!(ERC1155_BATCH_RECEIVED_MAGIC, EIP1271_MAGIC);
    }

    // -----------------------------------------------------------------
    // Curve membership (C1 — off-curve rotation brick)
    // -----------------------------------------------------------------

    /// P-256 generator G.
    const GX: &str = "6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296";
    const GY: &str = "4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5";
    /// 2G — a second independent on-curve point.
    const G2X: &str = "7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc47669978";
    const G2Y: &str = "07775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1";

    fn u(hex: &str) -> U256 {
        U256::from_be_bytes::<32>(
            <[u8; 32]>::try_from(
                (0..32)
                    .map(|i| u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap())
                    .collect::<Vec<u8>>()
                    .as_slice(),
            )
            .unwrap(),
        )
    }

    #[test]
    fn curve_b_constant_matches_the_standard() {
        // b = 0x5AC6...604B from FIPS 186-4 / SEC 2 for P-256.
        assert_eq!(
            U256::from_be_bytes(P256_B),
            u("5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
        );
    }

    #[test]
    fn generator_and_double_are_on_curve() {
        assert!(is_on_curve(u(GX), u(GY)), "G must satisfy the curve equation");
        assert!(is_on_curve(u(G2X), u(G2Y)), "2G must satisfy the curve equation");
    }

    #[test]
    fn perturbing_either_coordinate_leaves_the_curve() {
        let (x, y) = (u(GX), u(GY));
        assert!(!is_on_curve(x + U256::from(1), y));
        assert!(!is_on_curve(x, y + U256::from(1)));
        // Swapping coordinates is the classic transcription error.
        assert!(!is_on_curve(y, x));
    }

    #[test]
    fn negated_y_is_still_on_curve() {
        // (x, p - y) is the reflection of a curve point and IS valid — the check
        // must not reject it, or half of all legitimate keys would be refused.
        let p = U256::from_be_bytes(P256_FIELD_PRIME);
        assert!(is_on_curve(u(GX), p - u(GY)));
    }

    #[test]
    fn rotation_to_an_off_curve_point_is_rejected() {
        // Range-checking (x, y) without curve membership is what bricks the
        // account: an off-curve owner is accepted, and from then on no
        // signature can ever verify. Unrecoverable — there is no path back.
        // See SPEC.md §6.
        test_precompile::clear();
        test_precompile::expect_next(true);
        let sig = well_formed_sig();
        let req = RotationRequest {
            owner_x: u(GX),
            owner_y: u(GY),
            current_nonce: U256::ZERO,
            chain_id: 42161,
            account: Address::from([0xaau8; 20]),
            new_x: u(GX) + U256::from(1), // in range, off curve
            new_y: u(GY),
            nonce: U256::ZERO,
            signature: &sig,
        };
        assert!(matches!(
            validate_rotation_request(&req),
            Err(P256AccountError::InvalidPublicKey(_))
        ));
    }

    #[test]
    fn rotation_to_a_real_curve_point_is_accepted() {
        test_precompile::clear();
        test_precompile::expect_next(true);
        let sig = well_formed_sig();
        let req = RotationRequest {
            owner_x: u(GX),
            owner_y: u(GY),
            current_nonce: U256::ZERO,
            chain_id: 42161,
            account: Address::from([0xaau8; 20]),
            new_x: u(G2X),
            new_y: u(G2Y),
            nonce: U256::ZERO,
            signature: &sig,
        };
        assert!(validate_rotation_request(&req).is_ok());
    }

    #[test]
    fn constructor_rejects_off_curve_and_accepts_the_generator() {
        assert!(validate_constructor_args(u(GX), u(GY)).is_ok());
        assert!(matches!(
            validate_constructor_args(u(GX), u(GY) + U256::from(1)),
            Err(P256AccountError::InvalidPublicKey(_))
        ));
    }

    // -----------------------------------------------------------------
    // EIP-1271 / PersonalSign domain separation
    // -----------------------------------------------------------------

    #[test]
    fn personal_sign_typehash_matches_string() {
        assert_eq!(
            PERSONAL_SIGN_TYPEHASH,
            keccak(b"PersonalSign(bytes32 hash)".as_slice()),
        );
    }

    #[test]
    fn an_execute_digest_presented_as_a_1271_challenge_no_longer_round_trips() {
        // THE attack this wrapper exists for.
        //
        // 1. Attacker computes an Execute digest from public inputs
        //    (chainId, account, to = attacker, value = 1 ETH, nonce = 0).
        // 2. Presents it to the user as a "login challenge".
        // 3. The wallet signs it via the EIP-1271 path.
        //
        // Before the wrapper, step 3 produced a signature over the Execute
        // digest itself — i.e. a valid transfer authorisation. Now the 1271 path
        // signs PersonalSign(digest), which is a different message entirely.
        let chain_id = 42161u64;
        let account = Address::from([0xaau8; 20]);
        let attacker = Address::from([0xbau8; 20]);

        let execute_digest = compute_execute_hash(
            chain_id,
            account,
            attacker,
            U256::from(1_000_000_000_000_000_000u64),
            &[],
            U256::ZERO,
        );

        let challenge = compute_personal_sign_hash(chain_id, account, execute_digest);

        // The bytes actually signed on the 1271 path are NOT the execute digest.
        assert_ne!(
            challenge, execute_digest,
            "a 1271 challenge must never equal the Execute digest it wraps",
        );
    }

    #[test]
    fn personal_sign_is_domain_separated() {
        let hash = B256::from([0x11u8; 32]);
        let a = Address::from([0xaau8; 20]);
        let b = Address::from([0xbbu8; 20]);
        let base = compute_personal_sign_hash(42161, a, hash);
        assert_ne!(base, compute_personal_sign_hash(1, a, hash), "chainId must bind");
        assert_ne!(base, compute_personal_sign_hash(42161, b, hash), "account must bind");
        assert_ne!(
            base,
            compute_personal_sign_hash(42161, a, B256::from([0x12u8; 32])),
            "the wrapped hash must bind",
        );
    }

    #[test]
    fn personal_sign_cannot_collide_with_any_authorisation_hash() {
        let chain_id = 42161u64;
        let account = Address::from([0xaau8; 20]);
        let to = Address::from([0x11u8; 20]);
        let nonce = U256::ZERO;

        let exec = compute_execute_hash(chain_id, account, to, U256::ZERO, &[], nonce);
        let rotate = compute_rotate_hash(chain_id, account, u(GX), u(GY), nonce);
        let batch = compute_batch_hash(chain_id, account, &[to], &[U256::ZERO], &[&[]], nonce);

        // Wrapping ANY of them yields something distinct from all of them.
        for target in [exec, rotate, batch] {
            let wrapped = compute_personal_sign_hash(chain_id, account, target);
            assert_ne!(wrapped, exec);
            assert_ne!(wrapped, rotate);
            assert_ne!(wrapped, batch);
        }
    }

    #[test]
    fn selector_overrides_for_the_token_hooks_are_present_in_source() {
        // Regression guard for the bug where stylus-proc exported
        // `onErc721Received` (0x5ca688d3) instead of `onERC721Received`
        // (0x150b7a02), silently making the account unable to receive NFTs.
        //
        // The magic-value constants passed throughout that bug because they
        // check the constants, not the router's exported names. check-abi.sh
        // catches it but needs cargo-stylus and only runs in CI, so assert the
        // overrides here where `cargo test` will see them.
        let src = include_str!("lib.rs");
        for name in [
            "onERC721Received",
            "onERC1155Received",
            "onERC1155BatchReceived",
        ] {
            assert!(
                src.contains(&alloc::format!("#[selector(name = \"{name}\")]")),
                "missing #[selector(name = \"{name}\")] — stylus-proc would export \
                 the camel-cased Rust name instead, and the hook would never fire",
            );
        }
    }
}

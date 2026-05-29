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
//! - The hash signed is an EIP-712 envelope so a P-256 signature on an
//!   `Execute(...)` typed struct cannot collide with an arbitrary 32-byte
//!   challenge presented via EIP-1271, and vice versa.
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
//! ## Off-curve risk
//! The constructor accepts any `(x, y)` with each component in `(0, p)`. A
//! malformed point (not on the curve) deploys successfully but every signature
//! verification thereafter will fail — the account is bricked. The mobile SDK
//! MUST derive `(x, y)` from a real secure-enclave key. The contract does not
//! perform full curve-membership math by design (C1).

#![cfg_attr(not(any(test, feature = "export-abi")), no_main)]
extern crate alloc;

use alloc::vec::Vec;
use alloy_primitives::{b256, Address, FixedBytes, B256, U256};
use alloy_sol_types::sol;
use stylus_sdk::{
    abi::Bytes,
    call::{self, Call, RawCall},
    crypto::keccak,
    prelude::*,
    storage::StorageU256,
    ArbResult,
};

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
}

// =====================================================================
// Storage
// =====================================================================

#[entrypoint]
#[storage]
pub struct P256Account {
    owner_x: StorageU256,
    owner_y: StorageU256,
    /// Monotonic nonce shared by `execute` and `rotate_owner`.
    nonce: StorageU256,
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
    /// Validates each pubkey component lies in `(0, p)`. Full on-curve
    /// membership is not verified here — see the crate-level note on the
    /// off-curve risk.
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
    ) -> Result<(bool, Vec<u8>), P256AccountError> {
        let chain_id = self.vm().chain_id();
        let account = self.vm().contract_address();
        let current_nonce = self.nonce.get();
        let owner_x = self.owner_x.get();
        let owner_y = self.owner_y.get();

        validate_execute_request(&ExecuteRequest {
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
        })?;

        // CEI: commit nonce before the external call.
        self.nonce.set(current_nonce + U256::from(1));

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

        Ok((success, return_data))
    }

    /// Rotate the owner key. The caller must provide a P-256 signature from
    /// the *current* owner over the EIP-712 `RotateOwner` struct. Shares the
    /// monotonic nonce with `execute`.
    ///
    /// ## Off-curve risk on rotation
    /// The contract validates only that each component of the new key lies
    /// in `(0, p)`. The new `(new_x, new_y)` is NOT checked for curve
    /// membership. A current owner who rotates to an off-curve point will
    /// **permanently brick** the account — no future signature will verify
    /// and no further rotation can be authorised. The mobile SDK is
    /// responsible for ensuring the rotation target is a real
    /// secure-enclave key, matching the constructor's contract.
    pub fn rotate_owner(
        &mut self,
        new_x: U256,
        new_y: U256,
        nonce: U256,
        signature: Bytes,
    ) -> Result<(), P256AccountError> {
        let chain_id = self.vm().chain_id();
        let account = self.vm().contract_address();
        let current_nonce = self.nonce.get();
        let owner_x = self.owner_x.get();
        let owner_y = self.owner_y.get();

        validate_rotation_request(&RotationRequest {
            owner_x,
            owner_y,
            current_nonce,
            chain_id,
            account,
            new_x,
            new_y,
            nonce,
            signature: signature.as_ref(),
        })?;

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
    /// Because the `hash` here is supplied by the caller (typically a dApp
    /// presenting an arbitrary 32-byte challenge) it could in principle
    /// collide with the preimage of an `execute` hash — except that
    /// `compute_execute_hash` is the keccak of an EIP-712 envelope starting
    /// with `\x19\x01 ‖ domainSeparator`, which a dApp-supplied challenge
    /// cannot reproduce without already controlling the construction. The
    /// EIP-1271 path is therefore safe against `execute` replay.
    pub fn is_valid_signature(&self, hash: B256, signature: Bytes) -> FixedBytes<4> {
        FixedBytes::new(eip1271_response(self.verify(hash, signature)))
    }

    /// Reverts on any unknown selector. Stylus dispatches empty calldata to
    /// `#[receive]`, so anything that reaches this handler is a non-empty
    /// unrecognised call — refuse it to avoid ABI-probing false positives
    /// and to surface integration bugs in callers.
    ///
    /// Note: `#[fallback]` returns `ArbResult` (= `Result<Vec<u8>, Vec<u8>>`)
    /// because Solidity fallback semantics permit returning data;
    /// `#[receive]` returns `Result<(), Vec<u8>>` because receive has no
    /// return value by convention. The asymmetry is intentional.
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
    if !is_valid_pubkey_component(x) || !is_valid_pubkey_component(y) {
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
    if !is_valid_pubkey_component(r.new_x) || !is_valid_pubkey_component(r.new_y) {
        return Err(P256AccountError::InvalidPublicKey(InvalidPublicKey {}));
    }
    let hash = compute_rotate_hash(r.chain_id, r.account, r.new_x, r.new_y, r.nonce);
    validate_p256_signature(hash, r.signature, r.owner_x, r.owner_y)
}

/// Maps the `call::call` result onto the public `(success, return_data)`
/// shape that `execute` returns. The A2 invariant — nonce is committed
/// *before* this is called — is enforced structurally at the call site in
/// `execute`; this helper exists so the mapping itself is unit-testable.
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

/// Coarse pubkey-component sanity: `c ∈ (0, p)`. Off-curve points are NOT
/// rejected here (see crate-level docs); the RIP-7212 precompile rejects
/// them at signature-check time.
fn is_valid_pubkey_component(c: U256) -> bool {
    c != U256::ZERO && c < U256::from_be_bytes(P256_FIELD_PRIME)
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
    fn execute_outcome_maps_revert_to_failure_carrying_bytes() {
        let revert = alloc::vec![0xDE, 0xAD, 0xBE, 0xEF];
        let r = execute_outcome(Err(call::Error::Revert(revert.clone())));
        // Critical: success = false but the revert bytes are preserved so
        // the SDK can surface them — closes finding #12.
        assert_eq!(r, (false, revert));
    }

    #[test]
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
        assert!(validate_constructor_args(U256::from(1), U256::from(2)).is_ok());
        let p_minus_1 = U256::from_be_bytes(P256_FIELD_PRIME) - U256::from(1);
        assert!(validate_constructor_args(p_minus_1, p_minus_1).is_ok());
    }

    // ---- execute request validation ----

    fn fixture_execute_request<'a>(sig: &'a [u8]) -> ExecuteRequest<'a> {
        ExecuteRequest {
            owner_x: U256::from(1),
            owner_y: U256::from(2),
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
            owner_x: U256::from(1),
            owner_y: U256::from(2),
            current_nonce: U256::ZERO,
            chain_id: 42161,
            account: Address::from([0x11; 20]),
            new_x: U256::from(3),
            new_y: U256::from(4),
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
        req.new_x = U256::from(0x1111u64);
        req.new_y = U256::from(0x2222u64);
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
}

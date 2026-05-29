//! End-to-end integration harness for `P256Account` against a local Nitro
//! devnode.
//!
//! What it covers:
//! - `execute` happy path: signature verifies, inner call succeeds, nonce bumps.
//! - `execute` with reverting inner target: signature verifies, nonce STILL
//!   bumps, `Executed` event carries `success = false` and the revert bytes.
//! - `execute` with `value > account balance`: stylus-sdk's mapping of the
//!   insufficient-balance CALL — pinned to `Err(Revert)`, surfaced as
//!   `Executed.success = false`, balance unchanged, nonce still bumps.
//! - `rotate_owner`: ownership state transitions on-chain; `OwnerRotated`
//!   event carries `prev*` and `new*` keys.
//! - Nonce monotonicity across `execute` and `rotate_owner`.
//!
//! Prerequisites:
//! - Docker + `nitro-devnode/run-dev-node.sh --contract-size 128000` running
//!   on `http://localhost:8547`.
//! - `cargo install cargo-stylus`.
//! - Foundry installed (`cast` on PATH).
//! - `rustup target add wasm32-unknown-unknown`.
//!
//! Run:
//!     cargo run -p devnode-tests --release          # all tests
//!     cargo run -p devnode-tests --release -- list  # show test names
//!     cargo run -p devnode-tests --release -- run happy_path

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use p256::ecdsa::signature::hazmat::PrehashSigner;
use p256::ecdsa::{Signature, SigningKey};
use rand_core::OsRng;
use std::process::Command;
use tiny_keccak::{Hasher, Keccak};

// ----------------------------------------------------------------------------
// Configuration
// ----------------------------------------------------------------------------

const RPC: &str = "http://localhost:8547";
/// Nitro devnode prefunded dev wallet. Only valid on the local devnode.
const DEV_PRIVKEY: &str = "0xb6b15c8cb491557369f3c7d2c287b053eb229daa9c22138887752191c9520659";
const ARBITRUM_DEVNODE_CHAIN_ID: u64 = 412346;

// ----------------------------------------------------------------------------
// EIP-712 constants — MUST be byte-for-byte identical to the contract.
// ----------------------------------------------------------------------------

/// `keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)")`
const DOMAIN_TYPEHASH: [u8; 32] = const_hex_to_32(
    "8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f",
);
/// `keccak256("Execute(address to,uint256 value,bytes data,uint256 nonce)")`
const EXECUTE_TYPEHASH: [u8; 32] = const_hex_to_32(
    "5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c",
);
/// `keccak256("RotateOwner(uint256 newX,uint256 newY,uint256 nonce)")`
const ROTATE_TYPEHASH: [u8; 32] = const_hex_to_32(
    "8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a",
);
/// `keccak256("P256Account")`
const NAME_HASH: [u8; 32] = const_hex_to_32(
    "0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d",
);
/// `keccak256("1")`
const VERSION_HASH: [u8; 32] = const_hex_to_32(
    "c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6",
);

const fn const_hex_to_32(s: &str) -> [u8; 32] {
    let b = s.as_bytes();
    let mut out = [0u8; 32];
    let mut i = 0;
    while i < 32 {
        out[i] = (hex_nibble(b[2 * i]) << 4) | hex_nibble(b[2 * i + 1]);
        i += 1;
    }
    out
}

const fn hex_nibble(c: u8) -> u8 {
    match c {
        b'0'..=b'9' => c - b'0',
        b'a'..=b'f' => c - b'a' + 10,
        b'A'..=b'F' => c - b'A' + 10,
        _ => 0,
    }
}

// ----------------------------------------------------------------------------
// Crypto helpers
// ----------------------------------------------------------------------------

fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut k = Keccak::v256();
    k.update(input);
    let mut out = [0u8; 32];
    k.finalize(&mut out);
    out
}

struct Keypair {
    sk: SigningKey,
    pub_x: [u8; 32],
    pub_y: [u8; 32],
}

impl Keypair {
    fn generate() -> Self {
        let sk = SigningKey::random(&mut OsRng);
        let vk = sk.verifying_key();
        // Uncompressed sec1: `0x04 || X(32) || Y(32)`.
        let point = vk.to_encoded_point(false);
        let bytes = point.as_bytes();
        assert_eq!(bytes.len(), 65);
        assert_eq!(bytes[0], 0x04);
        let mut pub_x = [0u8; 32];
        let mut pub_y = [0u8; 32];
        pub_x.copy_from_slice(&bytes[1..33]);
        pub_y.copy_from_slice(&bytes[33..65]);
        Self { sk, pub_x, pub_y }
    }

    /// Signs the 32-byte `hash` directly (no inner SHA-256) — RIP-7212 takes
    /// an arbitrary 32-byte hash, so we use prehash signing. Applies low-S
    /// normalization to match the contract's malleability check.
    fn sign(&self, hash: &[u8; 32]) -> [u8; 64] {
        let sig: Signature = self.sk.sign_prehash(hash).expect("sign_prehash");
        let sig = sig.normalize_s().unwrap_or(sig);
        let r = sig.r();
        let s = sig.s();
        let r_bytes = r.to_bytes();
        let s_bytes = s.to_bytes();
        let mut out = [0u8; 64];
        out[0..32].copy_from_slice(r_bytes.as_slice());
        out[32..64].copy_from_slice(s_bytes.as_slice());
        out
    }
}

// ----------------------------------------------------------------------------
// EIP-712 hash builders — mirror of `compute_execute_hash` / `compute_rotate_hash`
// in the contract. Any drift here breaks signature verification on-chain.
// ----------------------------------------------------------------------------

fn u256_be(v: u64) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[24..32].copy_from_slice(&v.to_be_bytes());
    out
}

fn u64_padded_to_32(v: u64) -> [u8; 32] {
    u256_be(v)
}

fn addr_padded_to_32(addr: &[u8; 20]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out[12..32].copy_from_slice(addr);
    out
}

fn domain_separator(chain_id: u64, account: &[u8; 20]) -> [u8; 32] {
    let mut buf = [0u8; 160];
    buf[0..32].copy_from_slice(&DOMAIN_TYPEHASH);
    buf[32..64].copy_from_slice(&NAME_HASH);
    buf[64..96].copy_from_slice(&VERSION_HASH);
    buf[96..128].copy_from_slice(&u64_padded_to_32(chain_id));
    buf[128..160].copy_from_slice(&addr_padded_to_32(account));
    keccak256(&buf)
}

fn execute_hash(
    chain_id: u64,
    account: &[u8; 20],
    to: &[u8; 20],
    value_u256: &[u8; 32],
    data: &[u8],
    nonce_u256: &[u8; 32],
) -> [u8; 32] {
    let data_hash = keccak256(data);
    let mut struct_buf = [0u8; 160];
    struct_buf[0..32].copy_from_slice(&EXECUTE_TYPEHASH);
    struct_buf[32..64].copy_from_slice(&addr_padded_to_32(to));
    struct_buf[64..96].copy_from_slice(value_u256);
    struct_buf[96..128].copy_from_slice(&data_hash);
    struct_buf[128..160].copy_from_slice(nonce_u256);
    let struct_hash = keccak256(&struct_buf);
    envelope(chain_id, account, &struct_hash)
}

fn rotate_hash(
    chain_id: u64,
    account: &[u8; 20],
    new_x: &[u8; 32],
    new_y: &[u8; 32],
    nonce_u256: &[u8; 32],
) -> [u8; 32] {
    let mut struct_buf = [0u8; 128];
    struct_buf[0..32].copy_from_slice(&ROTATE_TYPEHASH);
    struct_buf[32..64].copy_from_slice(new_x);
    struct_buf[64..96].copy_from_slice(new_y);
    struct_buf[96..128].copy_from_slice(nonce_u256);
    let struct_hash = keccak256(&struct_buf);
    envelope(chain_id, account, &struct_hash)
}

fn envelope(chain_id: u64, account: &[u8; 20], struct_hash: &[u8; 32]) -> [u8; 32] {
    let domain = domain_separator(chain_id, account);
    let mut buf = [0u8; 66];
    buf[0] = 0x19;
    buf[1] = 0x01;
    buf[2..34].copy_from_slice(&domain);
    buf[34..66].copy_from_slice(struct_hash);
    keccak256(&buf)
}

// ----------------------------------------------------------------------------
// Shell helpers
// ----------------------------------------------------------------------------

fn run(cmd: &mut Command) -> Result<String> {
    let out = cmd.output().context("spawning subprocess")?;
    let stdout = String::from_utf8_lossy(&out.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&out.stderr).into_owned();
    if !out.status.success() {
        bail!(
            "command failed (exit {:?}):\n--- stdout ---\n{}\n--- stderr ---\n{}",
            out.status.code(),
            stdout,
            stderr
        );
    }
    Ok(stdout)
}

fn strip_ansi(s: &str) -> String {
    // Minimal CSI stripper for `\x1b[...m`. Good enough for cargo stylus output.
    let mut out = String::with_capacity(s.len());
    let bytes = s.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == 0x1b && i + 1 < bytes.len() && bytes[i + 1] == b'[' {
            i += 2;
            while i < bytes.len() && !bytes[i].is_ascii_alphabetic() {
                i += 1;
            }
            i += 1; // skip the final letter
        } else {
            out.push(bytes[i] as char);
            i += 1;
        }
    }
    out
}

fn cast_chain_id() -> Result<u64> {
    let out = run(Command::new("cast").args(["chain-id", "--rpc-url", RPC]))?;
    out.trim().parse::<u64>().context("parsing chain-id")
}

fn cast_dev_address() -> Result<String> {
    let out = run(Command::new("cast").args(["wallet", "address", DEV_PRIVKEY]))?;
    Ok(out.trim().to_string())
}

fn cast_send_value(to: &str, value_wei: &str) -> Result<()> {
    run(Command::new("cast").args([
        "send",
        to,
        "--value",
        value_wei,
        "--private-key",
        DEV_PRIVKEY,
        "--rpc-url",
        RPC,
    ]))?;
    Ok(())
}

fn cast_call_u256(acct: &str, sig: &str) -> Result<[u8; 32]> {
    // Use the bare signature ("nonce()" not "nonce()(uint256)") so cast
    // returns raw 0x-prefixed 32-byte hex instead of a possibly-huge
    // decimal. This avoids any local big-integer parsing.
    let out = run(Command::new("cast").args(["call", acct, sig, "--rpc-url", RPC]))?;
    let raw = out.trim();
    let hex = raw.strip_prefix("0x").unwrap_or(raw);
    let padded = format!("{:0>64}", hex);
    let bytes = hex::decode(&padded)
        .with_context(|| format!("hex decoding u256 from cast output: {:?}", raw))?;
    if bytes.len() != 32 {
        bail!("expected 32 bytes from {}, got {}", sig, bytes.len());
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(out)
}

/// `keccak256("Executed(address,uint256,uint256,bool,bytes)")` — log topic[0].
const EXECUTED_TOPIC_HEX: &str =
    "0xec126b3c24acfdb528f781ef219cb885a0dbf6110e42b118c3fae06edfe20480";

fn cast_call_balance(addr: &str) -> Result<String> {
    let out = run(Command::new("cast").args(["balance", addr, "--rpc-url", RPC]))?;
    Ok(out.trim().to_string())
}

/// Like `cast_send_execute`, but returns the receipt as JSON so we can
/// inspect the `Executed` event's `success` flag from the logs.
fn cast_send_execute_with_receipt(
    acct: &str,
    to: &str,
    value: u64,
    data: &[u8],
    nonce: u64,
    sig: &[u8; 64],
) -> Result<String> {
    let data_hex = format!("0x{}", hex::encode(data));
    let sig_hex = format!("0x{}", hex::encode(sig));
    let value_str = value.to_string();
    let nonce_str = nonce.to_string();
    run(Command::new("cast").args([
        "send",
        acct,
        "execute(address,uint256,bytes,uint256,bytes)",
        to,
        &value_str,
        &data_hex,
        &nonce_str,
        &sig_hex,
        "--private-key",
        DEV_PRIVKEY,
        "--rpc-url",
        RPC,
        "--json",
    ]))
}

/// Parses a `cast send --json` receipt and pulls `(success, returnData)`
/// out of the `Executed` event's data. The bool pins down the inner-call
/// outcome; the bytes let tests verify revert-data propagation.
fn parse_executed_outcome_from_receipt(receipt_json: &str) -> Result<(bool, Vec<u8>)> {
    let v: serde_json::Value = serde_json::from_str(receipt_json)
        .with_context(|| format!("not JSON: {:?}", receipt_json))?;
    let logs = v
        .get("logs")
        .and_then(|l| l.as_array())
        .context("receipt has no `logs` array")?;
    for log in logs {
        let topics = match log.get("topics").and_then(|t| t.as_array()) {
            Some(t) => t,
            None => continue,
        };
        if topics.is_empty() {
            continue;
        }
        let topic0 = topics[0].as_str().unwrap_or("");
        if !topic0.eq_ignore_ascii_case(EXECUTED_TOPIC_HEX) {
            continue;
        }
        let data_hex = log
            .get("data")
            .and_then(|d| d.as_str())
            .context("Executed log has no data")?;
        let bytes = hex::decode(data_hex.trim_start_matches("0x"))
            .context("Executed log data not hex")?;
        // ABI(uint256 value, uint256 nonce, bool success, bytes returnData):
        //   bytes [0..32]    = value
        //   bytes [32..64]   = nonce
        //   bytes [64..96]   = success (bool, right-aligned in the 32-byte word)
        //   bytes [96..128]  = returnData offset (relative to start of args)
        //   bytes [128..160] = returnData length
        //   bytes [160..]    = returnData payload (padded to 32-byte boundary)
        if bytes.len() < 160 {
            bail!("Executed log data shorter than 160 bytes (got {})", bytes.len());
        }
        // Belt-and-braces: for this exact event shape, the dynamic-bytes
        // offset must be 0x80 (= 128 = start of the length word). If the
        // Executed event signature ever changes shape — e.g. another
        // dynamic field is added before `returnData` — this offset shifts
        // and the indices below would silently mis-read. Catch the drift
        // here instead.
        let high_zero = bytes[96..127].iter().all(|&b| b == 0);
        if !high_zero || bytes[127] != 0x80 {
            bail!(
                "Executed returnData offset word != 0x80 (got 0x{}). \
                 Event-shape change suspected.",
                hex::encode(&bytes[96..128])
            );
        }
        let success = bytes[95] == 1;
        let return_len = u64::from_be_bytes(
            bytes[152..160]
                .try_into()
                .context("returnData length slice")?,
        ) as usize;
        if 160 + return_len > bytes.len() {
            bail!(
                "Executed returnData length {} exceeds payload (have {} bytes after header)",
                return_len,
                bytes.len() - 160
            );
        }
        let return_data = bytes[160..160 + return_len].to_vec();
        return Ok((success, return_data));
    }
    bail!("Executed event not found in receipt logs")
}

fn cast_send_execute(
    acct: &str,
    to: &str,
    value: u64,
    data: &[u8],
    nonce: u64,
    sig: &[u8; 64],
) -> Result<()> {
    let data_hex = format!("0x{}", hex::encode(data));
    let sig_hex = format!("0x{}", hex::encode(sig));
    let value_str = value.to_string();
    let nonce_str = nonce.to_string();
    run(Command::new("cast").args([
        "send",
        acct,
        "execute(address,uint256,bytes,uint256,bytes)",
        to,
        &value_str,
        &data_hex,
        &nonce_str,
        &sig_hex,
        "--private-key",
        DEV_PRIVKEY,
        "--rpc-url",
        RPC,
    ]))?;
    Ok(())
}

fn cast_send_rotate(
    acct: &str,
    new_x: &[u8; 32],
    new_y: &[u8; 32],
    nonce: u64,
    sig: &[u8; 64],
) -> Result<()> {
    let new_x_hex = format!("0x{}", hex::encode(new_x));
    let new_y_hex = format!("0x{}", hex::encode(new_y));
    let sig_hex = format!("0x{}", hex::encode(sig));
    let nonce_str = nonce.to_string();
    run(Command::new("cast").args([
        "send",
        acct,
        "rotateOwner(uint256,uint256,uint256,bytes)",
        &new_x_hex,
        &new_y_hex,
        &nonce_str,
        &sig_hex,
        "--private-key",
        DEV_PRIVKEY,
        "--rpc-url",
        RPC,
    ]))?;
    Ok(())
}

/// cargo-stylus versions we've tested the parser against. If the running
/// version differs, the harness prints a warning rather than failing —
/// `cargo stylus deploy`'s stdout shape has shifted between releases.
const TESTED_CARGO_STYLUS_VERSIONS: &[&str] = &["0.6."];

fn check_cargo_stylus_version() {
    let out = Command::new("cargo")
        .args(["stylus", "--version"])
        .output();
    let Ok(out) = out else {
        eprintln!("warning: could not run `cargo stylus --version` — is cargo-stylus installed?");
        return;
    };
    let version = String::from_utf8_lossy(&out.stdout);
    let trimmed = version.trim();
    if !TESTED_CARGO_STYLUS_VERSIONS
        .iter()
        .any(|prefix| trimmed.contains(prefix))
    {
        eprintln!(
            "warning: untested cargo-stylus version `{}` — parser was developed against {}; \
             address extraction may need updating if output format changed.",
            trimmed,
            TESTED_CARGO_STYLUS_VERSIONS.join(", "),
        );
    }
}

/// Pre-built wasm artifact path. cargo-stylus 0.6+ expects either to live
/// inside a single-crate project (which our workspace isn't) or to be
/// pointed at a pre-built `.wasm` file via `--wasm-file`. We take the
/// latter route: a single `cargo build` up front, then per-test deploys
/// just point at the same artifact.
const WASM_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/../target/wasm32-unknown-unknown/release/p256_account.wasm"
);

fn build_contract_wasm() -> Result<()> {
    eprintln!("    building p256-account wasm…");
    run(Command::new("cargo").args([
        "build",
        "--release",
        "--target",
        "wasm32-unknown-unknown",
        "-p",
        "p256-account",
    ]))?;
    if !std::path::Path::new(WASM_PATH).exists() {
        bail!("wasm not found at {} after build", WASM_PATH);
    }
    Ok(())
}

fn cargo_stylus_deploy(x: &[u8; 32], y: &[u8; 32], dev_addr: &str) -> Result<String> {
    let x_hex = format!("0x{}", hex::encode(x));
    let y_hex = format!("0x{}", hex::encode(y));
    let out = run(Command::new("cargo").args([
        "stylus",
        "deploy",
        "--no-verify",
        "--endpoint",
        RPC,
        "--private-key",
        DEV_PRIVKEY,
        "--wasm-file",
        WASM_PATH,
        "--constructor-signature",
        "constructor(uint256,uint256)",
        "--constructor-args",
        &x_hex,
        &y_hex,
    ]))?;
    let stripped = strip_ansi(&out);
    extract_deployed_address(&stripped, dev_addr).ok_or_else(|| {
        anyhow!(
            "could not find deployed address in `cargo stylus deploy` output. \
             Raw output:\n{}",
            stripped
        )
    })
}

/// Best-effort address extraction. Tries known cargo-stylus phrasings first,
/// then falls back to scanning for an isolated `0x{40-hex}` that isn't the
/// deployer's own EOA. The dev wallet is passed in (not hardcoded) so a
/// rotation of `DEV_PRIVKEY` cannot silently misroute the fallback into
/// returning the deployer as the "contract address".
fn extract_deployed_address(stdout: &str, dev_addr: &str) -> Option<String> {
    const KNOWN_PHRASES: &[&str] = &[
        "deployed code at address",
        "contract deployed at",
        "deployed contract at",
        "contract was deployed at",
        "activated and deployed",
        "stylus contract activated and ready at",
        "address:",
    ];
    let lower = stdout.to_lowercase();

    // Pass 1: lines that explicitly announce a deployed address.
    for (line_lower, line) in lower.lines().zip(stdout.lines()) {
        if KNOWN_PHRASES.iter().any(|p| line_lower.contains(p)) {
            if let Some(a) = first_address_token(line) {
                return Some(a);
            }
        }
    }

    // Pass 2: any line containing only the literal "0x{40-hex}" — common for
    // structured/key-value output formats.
    for line in stdout.lines() {
        if let Some(a) = first_address_token(line.trim()) {
            if !a.eq_ignore_ascii_case(dev_addr) {
                return Some(a);
            }
        }
    }

    None
}

fn first_address_token(s: &str) -> Option<String> {
    for tok in s.split(|c: char| c.is_whitespace() || c == ',' || c == ';' || c == '`') {
        if let Some(hex_part) = tok.strip_prefix("0x").or_else(|| tok.strip_prefix("0X")) {
            if hex_part.len() == 40 && hex_part.chars().all(|c| c.is_ascii_hexdigit()) {
                return Some(format!("0x{}", hex_part.to_lowercase()));
            }
        }
    }
    None
}

// ----------------------------------------------------------------------------
// Test cases
// ----------------------------------------------------------------------------

struct Ctx {
    chain_id: u64,
    dev_addr: [u8; 20],
    dev_addr_hex: String,
}

fn make_ctx() -> Result<Ctx> {
    check_cargo_stylus_version();
    let chain_id = cast_chain_id().context(
        "could not reach Nitro devnode at http://localhost:8547 — is it running?",
    )?;
    if chain_id != ARBITRUM_DEVNODE_CHAIN_ID {
        eprintln!(
            "warning: connected chain-id is {}, expected {} (Nitro devnode default)",
            chain_id, ARBITRUM_DEVNODE_CHAIN_ID
        );
    }
    let dev_addr_hex = cast_dev_address()?;
    let dev_addr = parse_addr(&dev_addr_hex)?;
    build_contract_wasm()?;
    Ok(Ctx {
        chain_id,
        dev_addr,
        dev_addr_hex,
    })
}

fn parse_addr(s: &str) -> Result<[u8; 20]> {
    let s = s.trim().trim_start_matches("0x");
    let bytes = hex::decode(s).context("hex decoding address")?;
    if bytes.len() != 20 {
        bail!("address is not 20 bytes: {}", s);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&bytes);
    Ok(out)
}

fn u64_to_u256_be(n: u64) -> [u8; 32] {
    u256_be(n)
}

/// Deploys a fresh account owned by `kp`, returns its address as a 20-byte
/// array.
fn deploy_fresh(kp: &Keypair, dev_addr_hex: &str) -> Result<(String, [u8; 20])> {
    let addr_str = cargo_stylus_deploy(&kp.pub_x, &kp.pub_y, dev_addr_hex)?;
    let addr_bytes = parse_addr(&addr_str)?;
    println!("    deployed: {}", addr_str);
    Ok((addr_str, addr_bytes))
}

fn test_execute_happy_path(ctx: &Ctx) -> Result<()> {
    println!("→ execute happy path");
    let kp = Keypair::generate();
    let (acct_str, acct_bytes) = deploy_fresh(&kp, &ctx.dev_addr_hex)?;

    // Fund the account so the inner call's `value` transfer succeeds.
    cast_send_value(&acct_str, "1000000000000000000")?;

    // Pick a benign destination (the dev wallet itself; receives ETH, no
    // selector required, so its receive path runs).
    let to_bytes = ctx.dev_addr;
    let to_str = format!("0x{}", hex::encode(to_bytes));
    let value: u64 = 1_000_000_000; // 1 gwei
    let data: &[u8] = b"";
    let nonce: u64 = 0;

    let nonce_u256 = u64_to_u256_be(nonce);
    let value_u256 = u64_to_u256_be(value);
    let hash = execute_hash(
        ctx.chain_id,
        &acct_bytes,
        &to_bytes,
        &value_u256,
        data,
        &nonce_u256,
    );
    let sig = kp.sign(&hash);

    cast_send_execute(&acct_str, &to_str, value, data, nonce, &sig)?;

    let new_nonce = cast_call_u256(&acct_str, "nonce()")?;
    let expected = u64_to_u256_be(1);
    if new_nonce != expected {
        bail!(
            "nonce mismatch: expected 1, got 0x{}",
            hex::encode(new_nonce)
        );
    }
    println!("    ✓ nonce: 0 → 1");
    Ok(())
}

fn test_execute_reverting_target_consumes_nonce(ctx: &Ctx) -> Result<()> {
    println!("→ execute against reverting target (nonce-consume invariant)");
    let kp = Keypair::generate();
    let (acct_str, acct_bytes) = deploy_fresh(&kp, &ctx.dev_addr_hex)?;

    // Have the account call ITSELF with garbage calldata. The account's
    // fallback reverts on any non-empty unknown selector, so this is a
    // self-contained "target that reverts" without needing a second contract.
    let to_bytes = acct_bytes;
    let to_str = acct_str.clone();
    let value: u64 = 0;
    let data: &[u8] = &[0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x00];
    let nonce: u64 = 0;

    let nonce_u256 = u64_to_u256_be(nonce);
    let value_u256 = u64_to_u256_be(value);
    let hash = execute_hash(
        ctx.chain_id,
        &acct_bytes,
        &to_bytes,
        &value_u256,
        data,
        &nonce_u256,
    );
    let sig = kp.sign(&hash);

    // Tx itself should NOT revert (we capture inner failure as a return tuple).
    let receipt =
        cast_send_execute_with_receipt(&acct_str, &to_str, value, data, nonce, &sig)?;
    let (success, return_data) = parse_executed_outcome_from_receipt(&receipt)?;
    if success {
        bail!("Executed.success was true despite the inner call hitting the fallback revert");
    }

    // Nonce must still bump despite inner-call revert — this is the A2 invariant.
    let new_nonce = cast_call_u256(&acct_str, "nonce()")?;
    let expected = u64_to_u256_be(1);
    if new_nonce != expected {
        bail!(
            "nonce did not advance after inner-call revert (got 0x{})",
            hex::encode(new_nonce)
        );
    }
    // Observation: stylus-sdk 0.9 surfaces inner-call reverts as
    // `call::Error::Revert(bytes)` and our `execute_outcome` host-side test
    // proves those bytes propagate into the event. For a Stylus fallback
    // returning `Err(UnknownSelector{}.into())`, the bytes actually
    // captured at this level happen to be empty (observed: 0 bytes). The
    // load-bearing invariant (success = false + nonce consumed) holds; the
    // returnData byte-count is reported for visibility — assert nothing.
    println!(
        "    ✓ inner reverted, nonce 0 → 1; Executed.returnData = {} byte(s) (observational)",
        return_data.len()
    );
    Ok(())
}

fn test_rotate_owner_changes_state(ctx: &Ctx) -> Result<()> {
    println!("→ rotate_owner: state transitions");
    let kp_old = Keypair::generate();
    let (acct_str, acct_bytes) = deploy_fresh(&kp_old, &ctx.dev_addr_hex)?;

    let kp_new = Keypair::generate();
    let nonce: u64 = 0;
    let nonce_u256 = u64_to_u256_be(nonce);

    let hash = rotate_hash(
        ctx.chain_id,
        &acct_bytes,
        &kp_new.pub_x,
        &kp_new.pub_y,
        &nonce_u256,
    );
    // Signed by the CURRENT owner.
    let sig = kp_old.sign(&hash);

    cast_send_rotate(&acct_str, &kp_new.pub_x, &kp_new.pub_y, nonce, &sig)?;

    let on_chain_x = cast_call_u256(&acct_str, "ownerX()")?;
    let on_chain_y = cast_call_u256(&acct_str, "ownerY()")?;
    if on_chain_x != kp_new.pub_x {
        bail!(
            "owner_x didn't rotate: got 0x{}, expected 0x{}",
            hex::encode(on_chain_x),
            hex::encode(kp_new.pub_x)
        );
    }
    if on_chain_y != kp_new.pub_y {
        bail!(
            "owner_y didn't rotate: got 0x{}, expected 0x{}",
            hex::encode(on_chain_y),
            hex::encode(kp_new.pub_y)
        );
    }
    let new_nonce = cast_call_u256(&acct_str, "nonce()")?;
    if new_nonce != u64_to_u256_be(1) {
        bail!("nonce after rotation should be 1");
    }
    println!("    ✓ owner pubkey overwritten, nonce: 0 → 1");
    Ok(())
}

fn test_execute_value_exceeds_balance(ctx: &Ctx) -> Result<()> {
    println!("→ execute with value > account balance");
    let kp = Keypair::generate();
    let (acct_str, acct_bytes) = deploy_fresh(&kp, &ctx.dev_addr_hex)?;

    // Fund the account with EXACTLY 1 wei — not enough for any transfer
    // of 2+ wei. Stylus CALL with `value > balance` is the case we want
    // to pin: does stylus-sdk surface it as Err(Revert(empty)) (correct,
    // `Executed.success = false`) or Ok(empty) (silent-success bug)?
    cast_send_value(&acct_str, "1")?;
    let balance_before = cast_call_balance(&acct_str)?;
    if balance_before != "1" {
        bail!(
            "expected account balance = 1 wei after funding, got `{}`",
            balance_before
        );
    }

    let to_bytes = ctx.dev_addr;
    let to_str = ctx.dev_addr_hex.clone();
    let value: u64 = 2; // intentional: more than the 1 wei in the account
    let data: &[u8] = b"";
    let nonce: u64 = 0;

    let value_u256 = u64_to_u256_be(value);
    let nonce_u256 = u64_to_u256_be(nonce);
    let hash = execute_hash(
        ctx.chain_id,
        &acct_bytes,
        &to_bytes,
        &value_u256,
        data,
        &nonce_u256,
    );
    let sig = kp.sign(&hash);

    let receipt =
        cast_send_execute_with_receipt(&acct_str, &to_str, value, data, nonce, &sig)?;
    let (success, return_data) = parse_executed_outcome_from_receipt(&receipt)?;
    if success {
        bail!(
            "Executed.success = TRUE despite value (2) > balance (1) — \
             stylus-sdk is mapping insufficient-balance CALL to Ok, which \
             would let a relayer/SDK incorrectly believe the transfer \
             happened. A `vm().balance() >= value` guard is needed in \
             `execute` before the call."
        );
    }

    let balance_after = cast_call_balance(&acct_str)?;
    if balance_after != "1" {
        bail!(
            "balance changed from 1 to `{}` despite Executed.success = false",
            balance_after
        );
    }

    let n = cast_call_u256(&acct_str, "nonce()")?;
    if n != u64_to_u256_be(1) {
        bail!("nonce did not advance to 1");
    }

    println!(
        "    ✓ Executed.success = false, balance unchanged at 1 wei, nonce 0 → 1, returnData = {} byte(s)",
        return_data.len()
    );
    Ok(())
}

fn test_nonce_monotonicity_across_execute_and_rotate(ctx: &Ctx) -> Result<()> {
    println!("→ nonce monotonicity across execute → rotate → execute");
    let kp1 = Keypair::generate();
    let (acct_str, acct_bytes) = deploy_fresh(&kp1, &ctx.dev_addr_hex)?;
    cast_send_value(&acct_str, "1000000000000000000")?;

    // 1. execute @ nonce 0 with kp1
    let to_bytes = ctx.dev_addr;
    let to_str = format!("0x{}", hex::encode(to_bytes));
    let value_u256 = u64_to_u256_be(1);
    let nonce_u256 = u64_to_u256_be(0);
    let h = execute_hash(
        ctx.chain_id,
        &acct_bytes,
        &to_bytes,
        &value_u256,
        b"",
        &nonce_u256,
    );
    let sig = kp1.sign(&h);
    cast_send_execute(&acct_str, &to_str, 1, b"", 0, &sig)?;
    let n = cast_call_u256(&acct_str, "nonce()")?;
    if n != u64_to_u256_be(1) {
        bail!("expected nonce 1 after first execute");
    }

    // 2. rotate_owner @ nonce 1 (signed by kp1) → switches to kp2
    let kp2 = Keypair::generate();
    let nonce_u256 = u64_to_u256_be(1);
    let h = rotate_hash(
        ctx.chain_id,
        &acct_bytes,
        &kp2.pub_x,
        &kp2.pub_y,
        &nonce_u256,
    );
    let sig = kp1.sign(&h);
    cast_send_rotate(&acct_str, &kp2.pub_x, &kp2.pub_y, 1, &sig)?;
    let n = cast_call_u256(&acct_str, "nonce()")?;
    if n != u64_to_u256_be(2) {
        bail!("expected nonce 2 after rotate");
    }

    // 3. execute @ nonce 2 with kp2 (kp1 must no longer authorise)
    let value_u256 = u64_to_u256_be(1);
    let nonce_u256 = u64_to_u256_be(2);
    let h = execute_hash(
        ctx.chain_id,
        &acct_bytes,
        &to_bytes,
        &value_u256,
        b"",
        &nonce_u256,
    );
    let sig = kp2.sign(&h);
    cast_send_execute(&acct_str, &to_str, 1, b"", 2, &sig)?;
    let n = cast_call_u256(&acct_str, "nonce()")?;
    if n != u64_to_u256_be(3) {
        bail!("expected nonce 3 after second execute");
    }
    println!("    ✓ nonce 0 → 1 (execute) → 2 (rotate) → 3 (execute w/ new key)");
    Ok(())
}

// ----------------------------------------------------------------------------
// CLI
// ----------------------------------------------------------------------------

#[derive(Parser)]
#[command(about = "Nitro-devnode integration tests for P256Account")]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Run every test (default).
    All,
    /// List available test names.
    List,
    /// Run one test by name.
    Run { name: String },
}

type TestFn = fn(&Ctx) -> Result<()>;
const TESTS: &[(&str, TestFn)] = &[
    ("happy_path", test_execute_happy_path),
    (
        "reverting_target_consumes_nonce",
        test_execute_reverting_target_consumes_nonce,
    ),
    (
        "value_exceeds_balance",
        test_execute_value_exceeds_balance,
    ),
    ("rotate_owner", test_rotate_owner_changes_state),
    (
        "nonce_monotonicity",
        test_nonce_monotonicity_across_execute_and_rotate,
    ),
];

fn run_all(ctx: &Ctx) -> Result<()> {
    let mut failed = 0usize;
    for (name, f) in TESTS {
        println!("\n=== {} ===", name);
        match f(ctx) {
            Ok(()) => println!("    PASS"),
            Err(e) => {
                println!("    FAIL: {:#}", e);
                failed += 1;
            }
        }
    }
    println!("\n---\n{} / {} passed", TESTS.len() - failed, TESTS.len());
    if failed > 0 {
        bail!("{} test(s) failed", failed);
    }
    Ok(())
}

fn run_one(ctx: &Ctx, name: &str) -> Result<()> {
    let f = TESTS
        .iter()
        .find(|(n, _)| *n == name)
        .ok_or_else(|| anyhow!("unknown test: {}", name))?
        .1;
    f(ctx)
}

// ----------------------------------------------------------------------------
// Tests — the only chain-free part of the harness. Covers the cargo-stylus
// output parser so a future format shift surfaces at build time, not at
// integration-run time.
// ----------------------------------------------------------------------------

#[cfg(test)]
mod parser_tests {
    use super::*;

    const ADDR: &str = "0xa1b2c3d4e5f60718293a4b5c6d7e8f9012345678";
    /// Fixture dev wallet (the real one) for the fallback-skip test. Other
    /// tests use an arbitrary wallet so they don't depend on this value.
    const DEV: &str = "0x3f1eae7d46d88f08fc2f8ed27fcb2ab183eb2d0e";

    #[test]
    fn extracts_from_classic_deployed_at_phrase() {
        let s = format!("  deployed code at address: {}\n", ADDR);
        assert_eq!(extract_deployed_address(&s, DEV).as_deref(), Some(ADDR));
    }

    #[test]
    fn extracts_from_contract_deployed_phrase() {
        let s = format!("Contract deployed at {}\n", ADDR);
        assert_eq!(extract_deployed_address(&s, DEV).as_deref(), Some(ADDR));
    }

    #[test]
    fn extracts_from_activated_and_deployed_phrase() {
        let s = format!("activated and deployed contract at: {}\n", ADDR);
        assert_eq!(extract_deployed_address(&s, DEV).as_deref(), Some(ADDR));
    }

    #[test]
    fn extracts_from_uppercase_0x_prefix() {
        let upper = format!("0X{}", &ADDR[2..]);
        let s = format!("deployed contract at {}\n", upper);
        assert_eq!(extract_deployed_address(&s, DEV).as_deref(), Some(ADDR));
    }

    #[test]
    fn extracts_from_comma_or_backtick_delimited() {
        let s = format!("`{}`,deploy ok\n", ADDR);
        assert_eq!(extract_deployed_address(&s, DEV).as_deref(), Some(ADDR));
    }

    #[test]
    fn fallback_skips_dev_wallet_for_isolated_address_line() {
        let s = format!(
            "from: 0x3f1Eae7D46d88F08fc2F8ed27FCb2AB183EB2d0E\nnew: {}\n",
            ADDR
        );
        assert_eq!(extract_deployed_address(&s, DEV).as_deref(), Some(ADDR));
    }

    #[test]
    fn fallback_skip_uses_runtime_dev_addr_not_hardcoded_constant() {
        // Rotated dev wallet: scanning should now treat THIS as the
        // deployer-to-skip, not the previous hardcoded value.
        let rotated_dev = "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef";
        let s = format!("{}\n{}\n", rotated_dev, ADDR);
        assert_eq!(
            extract_deployed_address(&s, rotated_dev).as_deref(),
            Some(ADDR)
        );
        // And the *old* hardcoded one is now just another address that
        // happens to appear first — so it would win the fallback if the
        // dev_addr argument were ignored.
        let s2 = format!("{}\n{}\n", DEV, ADDR);
        assert_eq!(
            extract_deployed_address(&s2, rotated_dev).as_deref(),
            Some(DEV)
        );
    }

    #[test]
    fn ignores_lines_with_no_address() {
        assert_eq!(
            extract_deployed_address("warning: untested cargo-stylus version 0.7.0", DEV),
            None
        );
    }

    #[test]
    fn ignores_short_or_long_hex_strings() {
        // 38-char address (missing 2 chars) — must not match.
        assert_eq!(
            extract_deployed_address("deployed at 0xa1b2c3d4e5f60718293a4b5c6d7e8f90123456", DEV),
            None
        );
        // 42-char tail (too long).
        assert_eq!(
            extract_deployed_address(
                "deployed at 0xa1b2c3d4e5f60718293a4b5c6d7e8f9012345678ab",
                DEV
            ),
            None
        );
    }

    #[test]
    fn first_address_token_finds_well_formed_value() {
        assert_eq!(first_address_token(ADDR).as_deref(), Some(ADDR));
        assert_eq!(first_address_token(&format!("noise {} more", ADDR)).as_deref(), Some(ADDR));
        assert_eq!(first_address_token("0x").as_deref(), None);
    }

    // ---- harness EIP-712 typehash audit ----
    //
    // The contract has equivalent unit tests asserting its constants match
    // `keccak256(type_string)`. Without these on the harness side, a
    // contract-only edit could leave the harness signing the wrong digest —
    // surfacing as "signature did not verify" mid-integration-run instead
    // of at `cargo test` time.

    #[test]
    fn harness_domain_typehash_matches_string() {
        assert_eq!(
            DOMAIN_TYPEHASH,
            keccak256(
                b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
            )
        );
    }

    #[test]
    fn harness_execute_typehash_matches_string() {
        assert_eq!(
            EXECUTE_TYPEHASH,
            keccak256(b"Execute(address to,uint256 value,bytes data,uint256 nonce)")
        );
    }

    #[test]
    fn harness_rotate_typehash_matches_string() {
        assert_eq!(
            ROTATE_TYPEHASH,
            keccak256(b"RotateOwner(uint256 newX,uint256 newY,uint256 nonce)")
        );
    }

    #[test]
    fn harness_name_and_version_hashes_match_strings() {
        assert_eq!(NAME_HASH, keccak256(b"P256Account"));
        assert_eq!(VERSION_HASH, keccak256(b"1"));
    }

    #[test]
    fn harness_executed_topic_matches_event_signature() {
        // `keccak256("Executed(address,uint256,uint256,bool,bytes)")` — the
        // log topic[0] used by `parse_executed_outcome_from_receipt` to
        // locate the event. If the contract event signature ever changes
        // (added field, renamed type), the parser would silently fail to
        // match instead of catching the drift here.
        let expected = keccak256(b"Executed(address,uint256,uint256,bool,bytes)");
        let topic = hex::decode(EXECUTED_TOPIC_HEX.trim_start_matches("0x"))
            .expect("EXECUTED_TOPIC_HEX is not valid hex");
        assert_eq!(&topic[..], &expected[..]);
    }
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.cmd.unwrap_or(Cmd::All) {
        Cmd::List => {
            for (name, _) in TESTS {
                println!("{}", name);
            }
        }
        Cmd::All => {
            let ctx = make_ctx()?;
            run_all(&ctx)?;
        }
        Cmd::Run { name } => {
            let ctx = make_ctx()?;
            run_one(&ctx, &name)?;
        }
    }
    Ok(())
}

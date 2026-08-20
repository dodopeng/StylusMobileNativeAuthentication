#!/usr/bin/env bash
# Milestone 1 KPI — "test suite coverage of ≥90% of authentication functions".
#
# Overall file coverage is the wrong metric here and will read low (~83%): the
# `#[public]` entry points (execute, rotate_owner, constructor, is_valid_signature,
# fallback, receive) and the stylus-sdk generated glue (Router, StorageType,
# error From impls) cannot execute under `cargo test` at all — they need a Stylus
# VM. Those are covered by contracts/stylus/devnode-tests against a real Nitro
# node, not by host unit tests.
#
# What this script measures is the set that CAN and MUST be exhaustively unit
# tested: the pure authentication logic — signature validation, the EIP-712
# digest construction, and the state-machine validators.
#
# Requires: cargo-llvm-cov (`cargo install cargo-llvm-cov --locked`).
#   contracts/stylus/coverage.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
cd "$here"

command -v cargo-llvm-cov >/dev/null || {
  echo "cargo-llvm-cov not found — cargo install cargo-llvm-cov --locked"; exit 1; }

THRESHOLD=${THRESHOLD:-90}
json="$(mktemp)"
trap 'rm -f "$json"' EXIT

echo "running host-side tests under llvm-cov …"
cargo llvm-cov --lib -p p256-account --json --quiet >"$json" 2>/dev/null

THRESHOLD="$THRESHOLD" python3 - "$json" <<'PY'
import json, os, sys

# The authentication surface: every function implementing signature checking,
# EIP-712 digest construction, or request validation. Keep this list in sync
# with lib.rs — a new auth helper that isn't listed here isn't being measured.
AUTH = [
    "validate_p256_signature", "verify_p256_precompile", "precompile_staticcall",
    "validate_execute_request", "validate_rotation_request", "validate_constructor_args",
    "is_low_s", "is_valid_scalar", "is_valid_pubkey_component",
    # Curve membership decides which public key can ever authorise anything —
    # an off-curve owner permanently bricks the account. Range-checking the
    # components alone (is_valid_pubkey_component) is not the same check.
    "is_on_curve", "is_valid_pubkey",
    "compute_domain_separator", "compute_execute_hash", "compute_rotate_hash",
    "eip712_envelope", "eip1271_response", "execute_outcome",
    "validate_batch_shape", "validate_authorised_hash", "compute_batch_hash",
    # Carries the EIP-1271 security boundary: verifying the raw hash instead of
    # this wrapper was the exploit. Omitting it from this list left the KPI
    # total unchanged across the fix, which is exactly the signal the comment
    # above warns about.
    "compute_personal_sign_hash",
]

data = json.load(open(sys.argv[1]))["data"][0]["functions"]

found, rows = {}, []
for f in data:
    name = f["name"]
    if "::tests::" in name or "test_precompile" in name:
        continue
    for a in AUTH:
        # Rust v0 symbol mangling embeds the name with a length prefix.
        if name.endswith(a) or f"{len(a)}{a}" in name:
            regions = f["regions"]
            covered = sum(1 for r in regions if r[4] > 0)
            found[a] = (covered, len(regions))
            break

missing = [a for a in AUTH if a not in found]
cov = sum(c for c, _ in found.values())
tot = sum(t for _, t in found.values())
pct = 100.0 * cov / tot if tot else 0.0

print(f"\n{'authentication function':<32} {'regions':>9}   cover")
print("-" * 56)
for a in AUTH:
    if a in found:
        c, t = found[a]
        p = 100.0 * c / t if t else 0.0
        flag = "" if p == 100.0 else "   <-- partial"
        print(f"{a:<32} {c:>4}/{t:<4} {p:6.1f}%{flag}")
    else:
        print(f"{a:<32} {'—':>9}   NOT FOUND")
print("-" * 56)
print(f"{'AUTHENTICATION TOTAL':<32} {cov:>4}/{tot:<4} {pct:6.1f}%")

threshold = float(os.environ["THRESHOLD"])
if missing:
    print(f"\nFAIL: not found in coverage data: {', '.join(missing)}")
    print("(renamed or removed? update the AUTH list in coverage.sh)")
    sys.exit(1)
if pct < threshold:
    print(f"\nFAIL: {pct:.1f}% < {threshold:.0f}% threshold")
    sys.exit(1)
print(f"\nPASS: {pct:.1f}% >= {threshold:.0f}% (Milestone 1 KPI)")
PY

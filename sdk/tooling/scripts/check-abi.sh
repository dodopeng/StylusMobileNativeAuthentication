#!/usr/bin/env bash
# Golden ABI check (SDK ⇄ contract). The SDKs hard-depend on stylus-sdk renaming
# Rust snake_case methods to camelCase Solidity selectors (rotate_owner →
# rotateOwner, etc., see sdk/SPEC.md §3). If that mapping ever changes — a method
# rename, a stylus-sdk behaviour shift — every SDK call would hit the contract's
# fallback and revert with UnknownSelector. This asserts the exported ABI still
# carries the exact camelCase names + selectors the SDKs encode.
#
# Requires: cargo-stylus (0.6.x) and foundry's `cast`. Run in CI:
#   sdk/tooling/scripts/check-abi.sh
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
crate="$here/../../../contracts/stylus/p256-account"

echo "exporting ABI from $crate …"
abi="$(cd "$crate" && cargo stylus export-abi 2>/dev/null)"

# signature -> expected 4-byte selector (golden; matches the SDK constants).
sigs=(
  "execute(address,uint256,bytes,uint256,bytes)=0xd2c88a7c"
  "rotateOwner(uint256,uint256,uint256,bytes)=0x82bed5b3"
  "nonce()=0xaffed0e0"
  "ownerX()=0xdbecca6f"
  "ownerY()=0xa2d57acf"
  "isValidSignature(bytes32,bytes)=0x1626ba7e"
)

fail=0
for pair in "${sigs[@]}"; do
  sig="${pair%%=*}"; want="${pair##*=}"; name="${sig%%(*}"

  # 1. the camelCase method must still be present in the exported interface.
  if ! grep -qE "function[[:space:]]+$name[[:space:]]*\(" <<<"$abi"; then
    echo "FAIL  '$name' missing from exported ABI — was it renamed? (would revert as UnknownSelector)"
    fail=1; continue
  fi
  # 2. its canonical selector must match the SDK's golden value.
  got="$(cast sig "$sig")"
  if [ "$got" != "$want" ]; then
    echo "FAIL  selector drift for $sig: got $got want $want"
    fail=1; continue
  fi
  echo "OK    $name  $want"
done

[ "$fail" -eq 0 ] && echo "ABI matches SDK selectors." || { echo "ABI/SDK selector mismatch."; exit 1; }

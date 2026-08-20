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
# Capture stderr and the exit status explicitly. `set -e` would otherwise kill
# the script mid-assignment with no message when export-abi fails to build, so a
# broken export looked identical to a clean run.
if ! abi="$(cd "$crate" && cargo stylus export-abi 2>&1)"; then
  echo "FAIL  cargo stylus export-abi failed — cannot check for drift:"
  sed 's/^/      /' <<<"$abi" | tail -20
  exit 1
fi
if ! grep -q "interface" <<<"$abi"; then
  echo "FAIL  export-abi produced no interface; got:"
  sed 's/^/      /' <<<"$abi" | tail -20
  exit 1
fi

# signature -> expected 4-byte selector (golden; matches the SDK constants).
#
# NOTE: a selector covers the function NAME and ARGUMENT TYPES only. It does not
# cover state mutability or return types, so `execute` flipping between payable
# and nonpayable — which changes whether a relayer may attach value — would not
# move the selector and used to slip through here. The mutability table below
# closes that.
sigs=(
  "execute(address,uint256,bytes,uint256,bytes)=0xd2c88a7c"
  "rotateOwner(uint256,uint256,uint256,bytes)=0x82bed5b3"
  "nonce()=0xaffed0e0"
  "ownerX()=0xdbecca6f"
  "ownerY()=0xa2d57acf"
  "isValidSignature(bytes32,bytes)=0x1626ba7e"
  "executeBatch(address[],uint256[],bytes[],uint256,bytes)=0xa428824f"
  "onERC721Received(address,address,uint256,bytes)=0x150b7a02"
  "onERC1155Received(address,address,uint256,uint256,bytes)=0xf23a6e61"
  "onERC1155BatchReceived(address,address,uint256[],uint256[],bytes)=0xbc197c81"
  "supportsInterface(bytes4)=0x01ffc9a7"
)

fail=0
for pair in "${sigs[@]}"; do
  sig="${pair%%=*}"; want="${pair##*=}"; name="${sig%%(*}"

  # 1. the camelCase method must still be present in the exported interface.
  if ! grep -qE "function[[:space:]]+$name[[:space:]]*\(" <<<"$abi"; then
    echo "FAIL  '$name' missing from exported ABI — was it renamed? (would revert as UnknownSelector)"
    fail=1; continue
  fi
  # 2. Rebuild the canonical signature from the EXPORTED interface and check
  #     THAT against the golden selector.
  #
  #     `cast sig "$sig"` alone is a tautology: it hashes the same string the
  #     golden was derived from, so it can never disagree. If `execute`'s
  #     `uint256 value` became `uint128`, the name grep still matched and the
  #     self-hash still agreed — the drift was invisible. Deriving the argument
  #     types from the exported ABI is what actually detects it.
  decl="$(grep -E "function[[:space:]]+$name[[:space:]]*\(" <<<"$abi" | head -1)"
  # "function foo(uint256 a, bytes calldata b) external ..." -> "foo(uint256,bytes)"
  argstr="$(sed -E 's/.*function[[:space:]]+[A-Za-z0-9_]+[[:space:]]*\((.*)\)[[:space:]]*external.*/\1/' <<<"$decl")"
  canon="$(python3 - "$name" "$argstr" <<'PYEOF'
import re, sys
name, argstr = sys.argv[1], sys.argv[2].strip()
types = []
if argstr:
    for part in argstr.split(','):
        tok = part.strip().split()
        if not tok:
            continue
        ty = tok[0]
        # Solidity memory/calldata/storage locations are not part of the selector.
        ty = re.sub(r'\b(memory|calldata|storage)\b', '', ty).strip()
        types.append(ty)
print(f"{name}({','.join(types)})")
PYEOF
)"
  got="$(cast sig "$canon")"
  if [ "$got" != "$want" ]; then
    echo "FAIL  selector drift for $name: exported '$canon' -> $got, SDK expects $want"
    echo "      (declared: $decl)"
    fail=1; continue
  fi
  if [ "$canon" != "$sig" ]; then
    echo "FAIL  signature drift for $name: exported '$canon' but SDK encodes '$sig'"
    fail=1; continue
  fi
  echo "OK    $name  $want  ($canon)"
done

# --- state mutability -----------------------------------------------------
# name -> expected mutability in the exported Solidity interface.
# `execute` and `executeBatch` are deliberately NON-payable: inner-call value
# comes from the account balance and IS signed, whereas an attached msg.value
# would not be. `receive` is payable so the account can be funded.
muts=(
  "execute=nonpayable"
  "executeBatch=nonpayable"
  "rotateOwner=nonpayable"
  "nonce=view"
  "ownerX=view"
  "ownerY=view"
  "isValidSignature=view"
  "supportsInterface=view"
)

for pair in "${muts[@]}"; do
  name="${pair%%=*}"; want="${pair##*=}"
  line="$(grep -E "function[[:space:]]+$name[[:space:]]*\(" <<<"$abi" | head -1)"
  if [ -z "$line" ]; then
    echo "FAIL  '$name' missing from exported ABI"
    fail=1; continue
  fi
  case "$want" in
    view)       got=$(grep -qE '\bview\b|\bpure\b' <<<"$line" && echo view || echo nonpayable) ;;
    payable)    got=$(grep -qE '\bpayable\b' <<<"$line" && echo payable || echo nonpayable) ;;
    nonpayable) got=$(grep -qE '\bpayable\b' <<<"$line" && echo payable || echo nonpayable) ;;
  esac
  if [ "$got" != "$want" ]; then
    echo "FAIL  mutability drift for $name: got $got want $want"
    echo "      ($line)"
    fail=1; continue
  fi
  echo "OK    $name  $want"
done

# --- EIP-712 typehashes ---------------------------------------------------
# The SDKs hardcode these; a change to any type string silently invalidates
# every signature all three produce, and no selector would move.
typehashes=(
  "Execute(address to,uint256 value,bytes data,uint256 nonce)=0x5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c"
  "RotateOwner(uint256 newX,uint256 newY,uint256 nonce)=0x8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a"
  "BatchExecute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)=0xe4c4e9c11a8826c10f239085bcd6b1f837ac8891ef69510451fb4e86df1ff4fb"
  "Call(address to,uint256 value,bytes data)=0x9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483"
  "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)=0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f"
  # The EIP-1271 wrapper. Four implementations hardcode this; if it drifts in
  # any one of them, 1271 verification silently stops matching — and this is the
  # typehash that exists specifically to close an exploit.
  "PersonalSign(bytes32 hash)=0x2431bd832cbb131f8882ef79f68ed6ae065cca9270f5bce0f2e4f75a9cd814b7"
)
for pair in "${typehashes[@]}"; do
  typestr="${pair%%=*}"; want="${pair##*=}"
  got="$(cast keccak "$typestr")"
  if [ "$got" != "$want" ]; then
    echo "FAIL  typehash drift for '$typestr': got $got want $want"
    fail=1; continue
  fi
  echo "OK    typehash  ${typestr%%(*}  $want"
done

# --- the contract's own constants match those typehashes -------------------
lib="$here/../../../contracts/stylus/p256-account/src/lib.rs"
for pair in "EXECUTE_TYPEHASH=5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c" \
            "ROTATE_TYPEHASH=8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a" \
            "BATCH_TYPEHASH=e4c4e9c11a8826c10f239085bcd6b1f837ac8891ef69510451fb4e86df1ff4fb" \
            "CALL_TYPEHASH=9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483" \
            "PERSONAL_SIGN_TYPEHASH=2431bd832cbb131f8882ef79f68ed6ae065cca9270f5bce0f2e4f75a9cd814b7"; do
  name="${pair%%=*}"; want="${pair##*=}"
  if ! grep -qF "$want" <<<"$(grep -A2 "const $name" "$lib")"; then
    echo "FAIL  contract constant $name does not match the golden typehash $want"
    fail=1; continue
  fi
  echo "OK    contract $name"
done

[ "$fail" -eq 0 ] && echo "ABI, mutability and typehashes all match the SDKs." \
  || { echo "ABI/SDK drift detected."; exit 1; }

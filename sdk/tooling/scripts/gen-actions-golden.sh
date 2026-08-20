#!/usr/bin/env bash
# Generates sdk/actions.golden.json — the single source of truth for what every
# Milestone 4 action template must encode.
#
# The point of this script is INDEPENDENCE. The goldens are produced by foundry's
# `cast`, which shares no code with any of the three SDK implementations. The
# Kotlin, Swift, and TypeScript test suites then all assert against this file, so
# "the three SDKs agree" is never satisfied by three copies of the same bug — it
# is checked against an external, widely-audited ABI encoder.
#
# Requires: foundry's `cast` on PATH. Run from anywhere:
#   sdk/tooling/scripts/gen-actions-golden.sh
#
# Regenerate whenever a template is added or a fixture value changes, then run
# the three suites — any that still carry stale goldens will fail loudly.
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
out="$here/../../actions.golden.json"

command -v cast >/dev/null || { echo "cast not found — install foundry"; exit 1; }

# Fixtures. MUST stay in sync with tooling/src/reference/fixtures.ts,
# ActionsInteropTest.kt, and ActionsInteropTests.swift.
ALICE=0x1111111111111111111111111111111111111111
BOB=0x2222222222222222222222222222222222222222
TOKEN=0x3333333333333333333333333333333333333333
TOKEN2=0x4444444444444444444444444444444444444444
ROUTER=0x5555555555555555555555555555555555555555
POOL=0x6666666666666666666666666666666666666666
NFT=0x7777777777777777777777777777777777777777
WETH=0x8888888888888888888888888888888888888888
AMOUNT=1000000                    # 1 USDC @ 6dp
AMOUNT_MIN=990000                 # 1% slippage floor
WEI=500000000000000000            # 0.5 ETH
TOKEN_ID=42
DEADLINE=1893456000               # 2030-01-01T00:00:00Z
VARIABLE=2                        # Aave interestRateMode: 2 = variable

entries=()
batch_entries=()

# add <id> <to> <value> <signature> [args…]
add() {
  local id="$1" to="$2" value="$3" sig="$4"; shift 4
  local data
  if [ -z "$sig" ]; then data="0x"; else data="$(cast calldata "$sig" "$@")"; fi
  entries+=("$(printf '  {"id":"%s","to":"%s","value":"%s","signature":"%s","data":"%s"}' \
    "$id" "$to" "$value" "$sig" "$data")")
  printf '  %-32s %s\n' "$id" "${data:0:10}" >&2
}

# Contract-derived limits. Read from lib.rs so the SDK constants have a single
# source of truth instead of three hardcoded 32s.
lib="$here/../../../contracts/stylus/p256-account/src/lib.rs"
MAX_BATCH_CALLS="$(grep -oE 'const MAX_BATCH_CALLS: usize = [0-9]+' "$lib" | grep -oE '[0-9]+$')"
[ -n "$MAX_BATCH_CALLS" ] || { echo "could not read MAX_BATCH_CALLS from $lib"; exit 1; }

echo "generating action-template goldens with $(cast --version | head -1) …" >&2
echo "  contract MAX_BATCH_CALLS = $MAX_BATCH_CALLS" >&2

add native.transfer                 "$BOB"    "$WEI" ""
add erc20.transfer                  "$TOKEN"  0      "transfer(address,uint256)" "$BOB" "$AMOUNT"
add erc20.approve                   "$TOKEN"  0      "approve(address,uint256)" "$ROUTER" "$AMOUNT"
add erc20.transferFrom              "$TOKEN"  0      "transferFrom(address,address,uint256)" "$ALICE" "$BOB" "$AMOUNT"
add erc721.safeTransferFrom         "$NFT"    0      "safeTransferFrom(address,address,uint256)" "$ALICE" "$BOB" "$TOKEN_ID"
add erc721.approve                  "$NFT"    0      "approve(address,uint256)" "$BOB" "$TOKEN_ID"
add erc721.setApprovalForAll        "$NFT"    0      "setApprovalForAll(address,bool)" "$BOB" true
add weth.deposit                    "$WETH"   "$WEI" "deposit()"
add weth.withdraw                   "$WETH"   0      "withdraw(uint256)" "$AMOUNT"
add univ2.swapExactTokensForTokens  "$ROUTER" 0      "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)" "$AMOUNT" "$AMOUNT_MIN" "[$TOKEN,$TOKEN2]" "$ALICE" "$DEADLINE"
add univ2.swapExactETHForTokens     "$ROUTER" "$WEI" "swapExactETHForTokens(uint256,address[],address,uint256)" "$AMOUNT_MIN" "[$WETH,$TOKEN]" "$ALICE" "$DEADLINE"
add univ2.swapExactTokensForETH     "$ROUTER" 0      "swapExactTokensForETH(uint256,uint256,address[],address,uint256)" "$AMOUNT" "$AMOUNT_MIN" "[$TOKEN,$WETH]" "$ALICE" "$DEADLINE"
add aave.supply                     "$POOL"   0      "supply(address,uint256,address,uint16)" "$TOKEN" "$AMOUNT" "$ALICE" 0
add aave.borrow                     "$POOL"   0      "borrow(address,uint256,uint256,uint16,address)" "$TOKEN" "$AMOUNT" "$VARIABLE" 0 "$ALICE"
add aave.repay                      "$POOL"   0      "repay(address,uint256,uint256,address)" "$TOKEN" "$AMOUNT" "$VARIABLE" "$ALICE"
add aave.withdraw                   "$POOL"   0      "withdraw(address,uint256,address)" "$TOKEN" "$AMOUNT" "$ALICE"

# --- executeBatch: the account-level calldata, not a template ---------------
# `bytes[]` is doubly dynamic (offset table -> length-prefixed padded elements)
# and every SDK hand-rolls it. Pin it against cast.
BATCH_APPROVE="$(cast calldata "approve(address,uint256)" "$ROUTER" "$AMOUNT")"
BATCH_SWAP="$(cast calldata "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)" "$AMOUNT" "$AMOUNT_MIN" "[$TOKEN,$TOKEN2]" "$ALICE" "$DEADLINE")"
BATCH_SIG="0x$(printf '11%.0s' $(seq 64))"
BATCH_DATA="$(cast calldata "executeBatch(address[],uint256[],bytes[],uint256,bytes)" \
  "[$TOKEN,$ROUTER]" "[0,0]" "[$BATCH_APPROVE,$BATCH_SWAP]" 0 "$BATCH_SIG")"
# The EIP-712 batch DIGEST, built here with cast rather than by any SDK, so the
# digest is pinned independently and not just the calldata. Mirrors
# compute_batch_hash in lib.rs.
BATCH_CHAIN=42161
BATCH_ACCOUNT=0x00000000000000000000000000000000000000aa
DOMAIN_SEP="$(cast keccak "$(cast abi-encode 'f(bytes32,bytes32,bytes32,uint256,address)' \
  "$(cast keccak 'EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)')" \
  "$(cast keccak 'P256Account')" "$(cast keccak '1')" "$BATCH_CHAIN" "$BATCH_ACCOUNT")")"
call_hash() { # <to> <value> <data>
  cast keccak "$(cast abi-encode 'f(bytes32,address,uint256,bytes32)' \
    "$(cast keccak 'Call(address to,uint256 value,bytes data)')" "$1" "$2" "$(cast keccak "$3")")"
}
CH0="$(call_hash "$TOKEN" 0 "$BATCH_APPROVE")"
CH1="$(call_hash "$ROUTER" 0 "$BATCH_SWAP")"
CALLS_HASH="$(cast keccak "${CH0}$(echo "$CH1" | cut -c3-)")"
BATCH_STRUCT="$(cast keccak "$(cast abi-encode 'f(bytes32,bytes32,uint256)' \
  "$(cast keccak 'BatchExecute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)')" \
  "$CALLS_HASH" 0)")"
BATCH_DIGEST="$(cast keccak "0x1901$(echo "$DOMAIN_SEP" | cut -c3-)$(echo "$BATCH_STRUCT" | cut -c3-)")"
printf '  %-32s %s\n' "batch.digest" "${BATCH_DIGEST:0:10}" >&2

# --- PersonalSign(bytes32 hash): the EIP-1271 wrapper -----------------------
# Deliberately wraps an *Execute digest*: that is the exact value an attacker
# would present as a "login challenge", so the golden pins the case that matters.
EXEC_STRUCT="$(cast keccak "$(cast abi-encode 'f(bytes32,address,uint256,bytes32,uint256)' \
  "$(cast keccak 'Execute(address to,uint256 value,bytes data,uint256 nonce)')" \
  "$BOB" 1000000000000000000 "$(cast keccak 0x)" 0)")"
EXEC_DIGEST="$(cast keccak "0x1901$(echo "$DOMAIN_SEP" | cut -c3-)$(echo "$EXEC_STRUCT" | cut -c3-)")"
PS_STRUCT="$(cast keccak "$(cast abi-encode 'f(bytes32,bytes32)' \
  "$(cast keccak 'PersonalSign(bytes32 hash)')" "$EXEC_DIGEST")")"
PS_DIGEST="$(cast keccak "0x1901$(echo "$DOMAIN_SEP" | cut -c3-)$(echo "$PS_STRUCT" | cut -c3-)")"
printf '  %-32s %s\n' "personalSign.digest" "${PS_DIGEST:0:10}" >&2

personal_sign_entry="$(printf '    {"chainId":"%s","account":"%s","hash":"%s","digest":"%s"}' \
  "$BATCH_CHAIN" "$BATCH_ACCOUNT" "$EXEC_DIGEST" "$PS_DIGEST")"

batch_entries+=("$(printf '    {"id":"approveThenSwap","chainId":"%s","account":"%s","to":["%s","%s"],"value":["0","0"],"calldata":["%s","%s"],"nonce":"0","signature":"%s","encoded":"%s","digest":"%s"}' \
  "$BATCH_CHAIN" "$BATCH_ACCOUNT" "$TOKEN" "$ROUTER" "$BATCH_APPROVE" "$BATCH_SWAP" "$BATCH_SIG" "$BATCH_DATA" "$BATCH_DIGEST")")
printf '  %-32s %s\n' "batch.executeBatch" "${BATCH_DATA:0:10}" >&2

{
  echo '{'
  echo '  "_comment": "GENERATED by sdk/tooling/scripts/gen-actions-golden.sh via foundry cast. Do not edit by hand.",'
  echo '  "fixtures": {'
  printf '    "alice": "%s", "bob": "%s", "token": "%s", "token2": "%s",\n' "$ALICE" "$BOB" "$TOKEN" "$TOKEN2"
  printf '    "router": "%s", "pool": "%s", "nft": "%s", "weth": "%s",\n' "$ROUTER" "$POOL" "$NFT" "$WETH"
  printf '    "amount": "%s", "amountMin": "%s", "wei": "%s", "tokenId": "%s",\n' "$AMOUNT" "$AMOUNT_MIN" "$WEI" "$TOKEN_ID"
  printf '    "deadline": "%s", "interestRateModeVariable": "%s"\n' "$DEADLINE" "$VARIABLE"
  echo '  },'
  printf '  "limits": { "maxBatchCalls": %s },\n' "$MAX_BATCH_CALLS"
  echo '  "templates": ['
  # macOS ships bash 3.2 — no negative subscripts, no ${a[@]::n-1}.
  i=0
  while [ "$i" -lt "${#entries[@]}" ]; do
    if [ "$i" -lt "$(( ${#entries[@]} - 1 ))" ]; then
      printf '%s,\n' "${entries[$i]}"
    else
      printf '%s\n' "${entries[$i]}"
    fi
    i=$(( i + 1 ))
  done
  echo '  ],'
  echo '  "batch": ['
  j=0
  while [ "$j" -lt "${#batch_entries[@]}" ]; do
    if [ "$j" -lt "$(( ${#batch_entries[@]} - 1 ))" ]; then
      printf '%s,\n' "${batch_entries[$j]}"
    else
      printf '%s\n' "${batch_entries[$j]}"
    fi
    j=$(( j + 1 ))
  done
  echo '  ],'
  echo '  "personalSign": ['
  printf '%s\n' "$personal_sign_entry"
  echo '  ]'
  echo '}'
} > "$out"

echo "wrote $(cd "$(dirname "$out")" && pwd)/$(basename "$out") (${#entries[@]} templates)" >&2

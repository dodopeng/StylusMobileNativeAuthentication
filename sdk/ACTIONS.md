# Action Templates — Milestone 4

Pre-built, ready-to-execute calls for the most common Arbitrum operations,
available identically in the **Android**, **iOS**, and **TypeScript reference**
SDKs. 16 templates across 6 families.

Every template is a **pure function**. No network, no state, no signer:

```
Erc20.transfer(token, to, amount)  ──▶  Call(to, value, data)  ──▶  account.execute(call)
       (this document)                                                (SPEC.md §2–§4)
```

`execute` wraps the `Call` in the EIP-712 envelope, has the hardware key sign the
digest behind a biometric, and hands the result to a relayer. Templates add no
new trust, no new signing path, and no new failure mode — they only build
calldata. Composing actions is just calling `execute` more than once.

---

## Catalog

| Template | Solidity signature | Selector |
|---|---|---|
| `Native.transfer` | *(no calldata — value only)* | — |
| `Erc20.transfer` | `transfer(address,uint256)` | `0xa9059cbb` |
| `Erc20.approve` | `approve(address,uint256)` | `0x095ea7b3` |
| `Erc20.transferFrom` | `transferFrom(address,address,uint256)` | `0x23b872dd` |
| `Erc721.safeTransferFrom` | `safeTransferFrom(address,address,uint256)` | `0x42842e0e` |
| `Erc721.approve` | `approve(address,uint256)` | `0x095ea7b3` |
| `Erc721.setApprovalForAll` | `setApprovalForAll(address,bool)` | `0xa22cb465` |
| `Weth.deposit` | `deposit()` | `0xd0e30db0` |
| `Weth.withdraw` | `withdraw(uint256)` | `0x2e1a7d4d` |
| `UniswapV2.swapExactTokensForTokens` | `swapExactTokensForTokens(uint256,uint256,address[],address,uint256)` | `0x38ed1739` |
| `UniswapV2.swapExactETHForTokens` | `swapExactETHForTokens(uint256,address[],address,uint256)` | `0x7ff36ab5` |
| `UniswapV2.swapExactTokensForETH` | `swapExactTokensForETH(uint256,uint256,address[],address,uint256)` | `0x18cbafe5` |
| `AaveV3.supply` | `supply(address,uint256,address,uint16)` | `0x617ba037` |
| `AaveV3.borrow` | `borrow(address,uint256,uint256,uint16,address)` | `0xa415bcad` |
| `AaveV3.repay` | `repay(address,uint256,uint256,address)` | `0x573ade81` |
| `AaveV3.withdraw` | `withdraw(address,uint256,address)` | `0x69328dec` |

Grant KPI mapping — swap → `UniswapV2.*`, borrow/lend → `AaveV3.*`,
ERC-20 transfer → `Erc20.*`, NFT interaction → `Erc721.*`, plus native ETH and
WETH wrapping, which every real mobile flow needs.

The `UniswapV2` family targets the Uniswap-V2 router interface, which Camelot
and SushiSwap on Arbitrum implement; `AaveV3` targets the Aave-V3 `IPool`
interface, which Radiant also implements. Pass the appropriate router/pool
address — the templates are interface-shaped, not protocol-locked.

---

## Usage

### Native ETH

```kotlin
val call = Native.transfer(to = recipient, amountWei = BigInteger("500000000000000000"))
account.execute(call, auth)
```
```swift
let call = Native.transfer(to: recipient, amountWei: U256(decimal: "500000000000000000")!)
try await client.execute(call)
```

### ERC-20

```kotlin
Erc20.transfer(token = usdc, to = recipient, amount = BigInteger.valueOf(1_000_000))  // 1 USDC (6dp)
Erc20.approve(token = usdc, spender = router, amount = BigInteger.valueOf(1_000_000))
Erc20.transferFrom(token = usdc, from = owner, to = recipient, amount = amount)
```
```swift
Erc20.transfer(token: usdc, to: recipient, amount: U256(1_000_000))
Erc20.approve(token: usdc, spender: router, amount: U256(1_000_000))
Erc20.transferFrom(token: usdc, from: owner, to: recipient, amount: amount)
```

> **Allowance race.** Tokens that enforce it (USDT-style) reject a non-zero →
> non-zero `approve`. Approve `0` first, then the new amount — two separate
> `execute` calls.

### ERC-721

```kotlin
Erc721.safeTransferFrom(nft = collection, from = account.address, to = recipient, tokenId = id)
Erc721.approve(nft = collection, to = marketplace, tokenId = id)
Erc721.setApprovalForAll(nft = collection, operator = marketplace, approved = true)
```
```swift
Erc721.safeTransferFrom(nft: collection, from: client.address, to: recipient, tokenId: id)
Erc721.approve(nft: collection, to: marketplace, tokenId: id)
Erc721.setApprovalForAll(nft: collection, operator: marketplace, approved: true)
```

> `safeTransferFrom` reverts if a contract recipient does not implement
> `onERC721Received`. The account records that as `Executed.success = false`
> **and still consumes the nonce** — see [Checking the result](#checking-the-result).

### WETH

> Both of these, and `swapExactTokensForETH`, send ETH **back** to the account,
> invoking its `receive()` while `execute` is still on the stack. The contract is
> built with re-entrancy enabled precisely so those callbacks succeed; nested
> `execute`/`executeBatch`/`rotateOwner` are blocked separately by an explicit
> guard. Under the earlier blanket-non-reentrant build these templates always
> reverted.

```kotlin
Weth.deposit(weth = wethAddress, amountWei = oneEth)   // payable: value rides on the call
Weth.withdraw(weth = wethAddress, amount = oneEth)
```
```swift
Weth.deposit(weth: wethAddress, amountWei: oneEth)
Weth.withdraw(weth: wethAddress, amount: oneEth)
```

### Swaps (Uniswap V2 interface)

> **Use `executeBatch` for this.** Two separate `execute` calls means two
> biometric prompts *and* a nonce race: the client reads `nonce()` at latest for
> both, so both get signed against the same value and the second reverts unless
> the user waits for the first to confirm. One batch is one signature, one
> nonce, one prompt — see [Batching](#batching).

```kotlin
// Legacy two-call form, shown for contrast. Prefer executeBatch.
account.execute(Erc20.approve(usdc, router, amountIn), auth)
account.execute(
    UniswapV2.swapExactTokensForTokens(
        router = router,
        amountIn = amountIn,
        amountOutMin = minOut,           // slippage floor — never pass 0 in production
        path = listOf(usdc, weth),
        to = account.address,
        deadline = chainTimeSeconds + 600,
    ),
    auth,
)
```
```swift
try await client.execute(Erc20.approve(token: usdc, spender: router, amount: amountIn))
try await client.execute(UniswapV2.swapExactTokensForTokens(
    router: router, amountIn: amountIn, amountOutMin: minOut,
    path: [usdc, weth], to: client.address, deadline: chainTime + 600))
```

ETH-in and ETH-out variants avoid the wrap/unwrap round trip:

```kotlin
UniswapV2.swapExactETHForTokens(router, amountInWei = halfEth, amountOutMin = minOut,
                                path = listOf(weth, usdc), to = account.address, deadline = dl)
UniswapV2.swapExactTokensForETH(router, amountIn = amount, amountOutMin = minOut,
                                path = listOf(usdc, weth), to = account.address, deadline = dl)
```

> **`deadline` must come from chain time**, not the device clock. A phone
> running fast will produce swaps the router rejects as expired. Read it from
> the latest block timestamp.
>
> **`amountOutMin` is the only sandwich protection.** Compute it from a quote
> with an explicit slippage tolerance; `0` means "accept any output".

### Lending (Aave V3 interface)

The full cycle, in the order a lending UI drives it:

```kotlin
account.execute(Erc20.approve(usdc, pool, amount), auth)
account.execute(AaveV3.supply(pool, asset = usdc, amount = amount, onBehalfOf = account.address), auth)
account.execute(AaveV3.borrow(pool, asset = weth, amount = borrowAmount,
                              interestRateMode = AaveV3.INTEREST_RATE_MODE_VARIABLE,
                              onBehalfOf = account.address), auth)
account.execute(Erc20.approve(weth, pool, borrowAmount), auth)
account.execute(AaveV3.repay(pool, asset = weth, amount = borrowAmount,
                             interestRateMode = AaveV3.INTEREST_RATE_MODE_VARIABLE,
                             onBehalfOf = account.address), auth)
account.execute(AaveV3.withdraw(pool, asset = usdc, amount = amount, to = account.address), auth)
```
```swift
try await client.execute(AaveV3.supply(pool: pool, asset: usdc, amount: amount, onBehalfOf: client.address))
try await client.execute(AaveV3.borrow(pool: pool, asset: weth, amount: borrowAmount,
                                       interestRateMode: AaveV3.InterestRateMode.variable,
                                       onBehalfOf: client.address))
try await client.execute(AaveV3.repay(pool: pool, asset: weth, amount: borrowAmount,
                                      interestRateMode: AaveV3.InterestRateMode.variable,
                                      onBehalfOf: client.address))
try await client.execute(AaveV3.withdraw(pool: pool, asset: usdc, amount: amount, to: client.address))
```

> **`interestRateMode` must be `2` (variable) on Arbitrum.** Stable-rate
> borrowing is disabled in Aave V3 on Arbitrum (deprecated protocol-wide after
> the 2023 stable-rate exploits) — mode `1` reverts. The SDKs still expose a
> `stable` constant, marked deprecated, so ported code produces a compiler
> warning rather than an on-chain failure.
>
> Pass `amount = 2^256 - 1` to `repay` or `withdraw` for "the full balance".
>
> Note Aave's argument order: `borrow` places `referralCode` **before**
> `onBehalfOf`, unlike `supply`. The templates encode the correct order; this is
> called out because it is a common hand-rolling bug.

---

## Batching

`executeBatch` runs an ordered list of calls under **one signature and one
nonce**. It is the fix for the multi-step flows above, not an optimisation:

```kotlin
account.executeBatch(
    listOf(
        Erc20.approve(usdc, router, amountIn),
        UniswapV2.swapExactTokensForTokens(
            router = router, amountIn = amountIn, amountOutMin = minOut,
            path = listOf(usdc, weth), to = account.address, deadline = dl,
        ),
    ),
    auth,
)
```
```swift
try await client.executeBatch([
    Erc20.approve(token: usdc, spender: router, amount: amountIn),
    UniswapV2.swapExactTokensForTokens(
        router: router, amountIn: amountIn, amountOutMin: minOut,
        path: [usdc, weth], to: client.address, deadline: dl),
])
```

- **All-or-nothing.** If any call reverts the whole transaction reverts and the
  nonce is not consumed. You never end up with a dangling approval and no swap.
  (Single `execute` behaves differently — it records the failure and *does*
  consume the nonce.)
- **Order is signed.** The EIP-712 hash covers the calls in sequence, so a
  relayer cannot reorder them.
- **Max 32 calls.**

## Checking the result

The account **does not revert when the inner call fails.** It consumes the nonce
and reports the failure in the `Executed` event. A transaction hash alone does
not mean the swap happened.

```kotlin
val txHash = account.execute(call, auth)
val result = account.awaitExecuted(txHash)
if (!result.success) {
    // result.returnData carries the target's revert payload
}
```
```swift
let txHash = try await client.execute(call)
let result = try await client.awaitExecuted(txHash: txHash)
if !result.success {
    // result.returnData carries the target's revert payload
}
```

This matters more for templates than for bare transfers: an expired deadline, a
breached `amountOutMin`, or insufficient allowance all surface here rather than
as a failed transaction.

---

## How these are verified

The three implementations are hand-written per language for idiomatic APIs, and
kept honest by **golden vectors generated outside all of them**:

```
sdk/tooling/scripts/gen-actions-golden.sh   ──(foundry cast)──▶  sdk/actions.golden.json
                                                                        │
                        ┌───────────────────────────────┬───────────────┘
                        ▼                               ▼               ▼
        ActionsInteropTest.kt          ActionsInteropTests.swift    actions.test.ts
             (Android)                          (iOS)                (TS reference)
```

`cast` shares no code with any SDK, so "the three SDKs agree" can never be
satisfied by three copies of the same bug. Each suite asserts the full
`(to, value, data)` triple, that no template is missing a golden, and that the
payable set (`Native.transfer`, `Weth.deposit`, `UniswapV2.swapExactETHForTokens`)
carries `value` while nothing else does.

Beyond encoding, `tooling/src/e2e/actions.e2e.test.ts` drives every template
through the **full account pipeline** against the contract simulator — EIP-712
digest, P-256 signature, on-chain-equivalent verification, nonce advance — plus
an approve→swap→supply→borrow session on one account, and two attacks:
post-signature calldata tampering and inflating a payable template's `value`.
Both are rejected without consuming a nonce.

```bash
cd sdk/tooling && npm test          # 55 tests: 19 golden, 19 template e2e, + existing
sdk/tooling/scripts/gen-actions-golden.sh   # regenerate goldens after adding a template
```

### Verifying on a live chain

`npm run e2e:actions` runs the same catalog against a **deployed** account. By
default it is a dry run: each template's digest is signed and verified on-chain
through the account's EIP-1271 `isValidSignature`, exercising the real RIP-7212
precompile with no gas and no state change.

`OWNER_KEY` is **required** — it must be the P-256 private key of the account's
current owner, or no signature can verify. The harness reads `ownerX()`/`ownerY()`
and aborts up front if the key doesn't match, so a wrong key is reported once
rather than as 16 template failures.

```bash
# dry run — verifies every template's signature against the real precompile
RPC_URL=https://arb1.arbitrum.io/rpc ACCOUNT=0x… OWNER_KEY=0x… npm run e2e:actions

# actually submit, against real protocol addresses
RPC_URL=… ACCOUNT=0x… OWNER_KEY=0x… RELAYER_URL=http://localhost:8080 \
TOKEN=0x… ROUTER=0x… POOL=0x… WETH=0x… \
npm run e2e:actions -- --broadcast
```

Templates whose target is still a fixture placeholder are skipped under
`--broadcast` rather than sent to a nonexistent contract.

### What this harness does and does not prove

Be precise about this when reporting against the M4 KPI:

- **Dry run** proves the *authorisation* path: a real RIP-7212 precompile
  accepts an SDK-produced P-256 signature over this template's exact EIP-712
  digest. It does **not** prove the calldata is valid for the target protocol —
  a swap with a malformed path passes the dry run and would revert on-chain.
- **`--broadcast`** currently marks only the templates with a directly supplied
  target as live (`native.transfer`, `erc20.approve`, `weth.deposit`,
  `weth.withdraw`). The swap and Aave templates stay dry-run because a
  meaningful execution needs funded positions — token balances, approvals,
  supplied collateral — which this harness does not set up. **Closing the M4 KPI
  in full requires that fixture work in addition to a deployment.**
- The offline simulator suite proves encoding survives the account's auth path.
  It does **not** model target contracts: `SimulatedAccount` accepts any
  non-`REVERTER` target, so "success" there means the account executed the call,
  not that Uniswap would have accepted it.

**Status:** offline suites green (55 TypeScript, 12 Kotlin, 16 Swift conformance).
The live path is written but **has never been executed** — there is no deployed
account yet. Treat it as untested code until M1 lands on-chain.

---

## Adding a template

1. Add the function to all three: `Actions.kt`, `Actions.swift`, `actions.ts`.
2. Add an `add …` line to `gen-actions-golden.sh` and re-run it.
3. Add the entry to the `built()` map in each of the three test suites — the
   "every template is covered by a golden" test fails if you miss one.
4. Add it to `CATALOG` in `actions.e2e.test.ts` and `actions-live.ts`.
5. Document it here.

If the template needs an ABI type the encoders don't have yet, extend
`AbiValue` in `Abi.kt` and `ABI.swift` together — they must stay in step.

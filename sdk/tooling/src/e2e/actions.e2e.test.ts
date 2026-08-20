// Milestone 4 end-to-end — every action template driven through the FULL account
// pipeline against the in-memory contract simulator:
//
//   template → Call(to, value, data) → EIP-712 digest → P-256 sign
//            → encodeExecute → SimulatedAccount.submit → Executed receipt
//
// The golden tests in ../reference/actions.test.ts prove each template *encodes*
// correctly. These prove the encoding survives the account's authorisation path:
// the digest commits to the template's exact `(to, value, data)`, the signature
// verifies the way RIP-7212 does, the nonce advances, and tampering with a
// template's calldata after signing is rejected.
//
// This is the offline stand-in for the M4 KPI "each template tested end-to-end".
// The same sequence runs against a live chain via `npm run e2e:actions` once an
// account is deployed — see ../../ACTIONS.md § Verifying on a live chain.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { type Address } from 'viem'
import { ReferenceSigner } from '../reference/signer.ts'
import { executeDigest, encodeExecute } from '../reference/eip712.ts'
import { SimulatedAccount, ContractRevert } from './simulator.ts'
import { Native, Erc20, Erc721, Weth, UniswapV2, AaveV3, InterestRateMode, type Call } from '../reference/actions.ts'
import * as f from '../reference/fixtures.ts'

const CHAIN = 412346n
const ACCOUNT: Address = '0x00000000000000000000000000000000000000aa'

/** Every template, in the order a real mobile session would fire them. */
const CATALOG: Array<{ id: string; call: Call }> = [
  { id: 'native.transfer', call: Native.transfer(f.BOB, f.WEI) },

  { id: 'erc20.approve', call: Erc20.approve(f.TOKEN, f.ROUTER, f.AMOUNT) },
  { id: 'erc20.transfer', call: Erc20.transfer(f.TOKEN, f.BOB, f.AMOUNT) },
  { id: 'erc20.transferFrom', call: Erc20.transferFrom(f.TOKEN, f.ALICE, f.BOB, f.AMOUNT) },

  { id: 'erc721.approve', call: Erc721.approve(f.NFT, f.BOB, f.TOKEN_ID) },
  { id: 'erc721.setApprovalForAll', call: Erc721.setApprovalForAll(f.NFT, f.BOB, true) },
  { id: 'erc721.safeTransferFrom', call: Erc721.safeTransferFrom(f.NFT, f.ALICE, f.BOB, f.TOKEN_ID) },

  { id: 'weth.deposit', call: Weth.deposit(f.WETH, f.WEI) },
  { id: 'weth.withdraw', call: Weth.withdraw(f.WETH, f.AMOUNT) },

  { id: 'univ2.swapExactTokensForTokens', call: UniswapV2.swapExactTokensForTokens(
      f.ROUTER, f.AMOUNT, f.AMOUNT_MIN, [f.TOKEN, f.TOKEN2], f.ALICE, f.DEADLINE) },
  { id: 'univ2.swapExactETHForTokens', call: UniswapV2.swapExactETHForTokens(
      f.ROUTER, f.WEI, f.AMOUNT_MIN, [f.WETH, f.TOKEN], f.ALICE, f.DEADLINE) },
  { id: 'univ2.swapExactTokensForETH', call: UniswapV2.swapExactTokensForETH(
      f.ROUTER, f.AMOUNT, f.AMOUNT_MIN, [f.TOKEN, f.WETH], f.ALICE, f.DEADLINE) },

  { id: 'aave.supply', call: AaveV3.supply(f.POOL, f.TOKEN, f.AMOUNT, f.ALICE) },
  { id: 'aave.borrow', call: AaveV3.borrow(f.POOL, f.TOKEN, f.AMOUNT, InterestRateMode.Variable, f.ALICE) },
  { id: 'aave.repay', call: AaveV3.repay(f.POOL, f.TOKEN, f.AMOUNT, InterestRateMode.Variable, f.ALICE) },
  { id: 'aave.withdraw', call: AaveV3.withdraw(f.POOL, f.TOKEN, f.AMOUNT, f.ALICE) },
]

function freshAccount(signer: ReferenceSigner) {
  return new SimulatedAccount(ACCOUNT, CHAIN, signer.publicKey())
}

/** Sign a template's Call exactly as the mobile SDKs do. */
function sign(signer: ReferenceSigner, acct: SimulatedAccount, call: Call) {
  const nonce = acct.nonce
  const digest = executeDigest({
    chainId: CHAIN, account: acct.address,
    to: call.to, value: call.value, data: call.data, nonce,
  })
  return encodeExecute(call.to, call.value, call.data, nonce, signer.sign(digest))
}

for (const { id, call } of CATALOG) {
  test(`${id}: signs, verifies, and executes through the account`, () => {
    const signer = ReferenceSigner.random()
    const acct = freshAccount(signer)

    const txHash = acct.submit(sign(signer, acct, call))
    const receipt = acct.receipt(txHash)

    assert.ok(receipt, `${id}: no Executed receipt`)
    assert.equal(receipt.success, true, `${id}: inner call did not succeed`)
    assert.equal(receipt.nonce, 0n, `${id}: Executed must report the consumed nonce`)
    assert.equal(acct.nonce, 1n, `${id}: nonce must advance exactly once`)
  })
}

test('a full approve → swap session runs on one account with monotonic nonces', () => {
  // The realistic mobile flow: one hardware key, one account, several actions.
  // Each needs its own signature over its own nonce — proving the templates
  // compose without any extra machinery.
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)

  const session: Call[] = [
    Erc20.approve(f.TOKEN, f.ROUTER, f.AMOUNT),
    UniswapV2.swapExactTokensForTokens(f.ROUTER, f.AMOUNT, f.AMOUNT_MIN, [f.TOKEN, f.TOKEN2], f.ALICE, f.DEADLINE),
    Erc20.approve(f.TOKEN2, f.POOL, f.AMOUNT_MIN),
    AaveV3.supply(f.POOL, f.TOKEN2, f.AMOUNT_MIN, f.ALICE),
    AaveV3.borrow(f.POOL, f.TOKEN, f.AMOUNT, InterestRateMode.Variable, f.ALICE),
  ]

  session.forEach((call, i) => {
    const txHash = acct.submit(sign(signer, acct, call))
    assert.equal(acct.receipt(txHash)?.success, true, `step ${i} failed`)
    assert.equal(acct.nonce, BigInt(i + 1), `nonce after step ${i}`)
  })
})

test('tampering with a template’s calldata after signing is rejected', () => {
  // The digest commits to `data`, so swapping the swap path (or any argument)
  // post-signature must fail signature verification rather than execute.
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)

  const honest = UniswapV2.swapExactTokensForTokens(
    f.ROUTER, f.AMOUNT, f.AMOUNT_MIN, [f.TOKEN, f.TOKEN2], f.ALICE, f.DEADLINE)
  const attacker = UniswapV2.swapExactTokensForTokens(
    f.ROUTER, f.AMOUNT, 0n, [f.TOKEN, f.TOKEN2], f.BOB, f.DEADLINE) // drained slippage + redirected

  const nonce = acct.nonce
  const digest = executeDigest({
    chainId: CHAIN, account: acct.address,
    to: honest.to, value: honest.value, data: honest.data, nonce,
  })
  const signature = signer.sign(digest)

  // Same signature, attacker's calldata.
  const forged = encodeExecute(attacker.to, attacker.value, attacker.data, nonce, signature)
  assert.throws(
    () => acct.submit(forged),
    (e) => e instanceof ContractRevert && /InvalidSignature/.test(e.reason),
  )
  assert.equal(acct.nonce, 0n, 'a rejected call must not consume a nonce')
})

test('a payable template’s value is committed to by the signature', () => {
  // `weth.deposit` is only correct if `value` reaches the contract. Re-signing
  // with a different value must not validate against the original digest.
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)

  const call = Weth.deposit(f.WETH, f.WEI)
  const nonce = acct.nonce
  const digest = executeDigest({
    chainId: CHAIN, account: acct.address,
    to: call.to, value: call.value, data: call.data, nonce,
  })
  const signature = signer.sign(digest)

  const inflated = encodeExecute(call.to, call.value * 2n, call.data, nonce, signature)
  assert.throws(
    () => acct.submit(inflated),
    (e) => e instanceof ContractRevert && /InvalidSignature/.test(e.reason),
  )
})

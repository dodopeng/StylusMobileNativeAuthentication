// Milestone 4 — the TypeScript reference must reproduce every golden in
// sdk/actions.golden.json, which was generated independently by foundry's
// `cast`. The Android (ActionsInteropTest.kt) and iOS (ActionsInteropTests.swift)
// suites assert against the SAME file, so all three SDKs are pinned to an
// external ABI encoder rather than to each other.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { executeDigest } from './eip712.ts'
import { Native, Erc20, Erc721, Weth, UniswapV2, AaveV3, InterestRateMode, type Call } from './actions.ts'
import * as f from './fixtures.ts'

interface Golden {
  id: string
  to: string
  value: string
  signature: string
  data: string
}

const goldens: { templates: Golden[]; fixtures: Record<string, string> } = JSON.parse(
  readFileSync(fileURLToPath(new URL('../../../actions.golden.json', import.meta.url)), 'utf8'),
)

const TOKEN_PATH = [f.TOKEN, f.TOKEN2] as const
const ETH_IN_PATH = [f.WETH, f.TOKEN] as const
const ETH_OUT_PATH = [f.TOKEN, f.WETH] as const

/** Every template the SDKs expose, built with the fixture values. */
const built: Record<string, Call> = {
  'native.transfer': Native.transfer(f.BOB, f.WEI),

  'erc20.transfer': Erc20.transfer(f.TOKEN, f.BOB, f.AMOUNT),
  'erc20.approve': Erc20.approve(f.TOKEN, f.ROUTER, f.AMOUNT),
  'erc20.transferFrom': Erc20.transferFrom(f.TOKEN, f.ALICE, f.BOB, f.AMOUNT),

  'erc721.safeTransferFrom': Erc721.safeTransferFrom(f.NFT, f.ALICE, f.BOB, f.TOKEN_ID),
  'erc721.approve': Erc721.approve(f.NFT, f.BOB, f.TOKEN_ID),
  'erc721.setApprovalForAll': Erc721.setApprovalForAll(f.NFT, f.BOB, true),

  'weth.deposit': Weth.deposit(f.WETH, f.WEI),
  'weth.withdraw': Weth.withdraw(f.WETH, f.AMOUNT),

  'univ2.swapExactTokensForTokens': UniswapV2.swapExactTokensForTokens(
    f.ROUTER, f.AMOUNT, f.AMOUNT_MIN, TOKEN_PATH, f.ALICE, f.DEADLINE),
  'univ2.swapExactETHForTokens': UniswapV2.swapExactETHForTokens(
    f.ROUTER, f.WEI, f.AMOUNT_MIN, ETH_IN_PATH, f.ALICE, f.DEADLINE),
  'univ2.swapExactTokensForETH': UniswapV2.swapExactTokensForETH(
    f.ROUTER, f.AMOUNT, f.AMOUNT_MIN, ETH_OUT_PATH, f.ALICE, f.DEADLINE),

  'aave.supply': AaveV3.supply(f.POOL, f.TOKEN, f.AMOUNT, f.ALICE),
  'aave.borrow': AaveV3.borrow(f.POOL, f.TOKEN, f.AMOUNT, InterestRateMode.Variable, f.ALICE),
  'aave.repay': AaveV3.repay(f.POOL, f.TOKEN, f.AMOUNT, InterestRateMode.Variable, f.ALICE),
  'aave.withdraw': AaveV3.withdraw(f.POOL, f.TOKEN, f.AMOUNT, f.ALICE),
}

for (const g of goldens.templates) {
  test(`${g.id} matches the cast-generated golden`, () => {
    const call = built[g.id]
    assert.ok(call, `no TS reference implementation for template '${g.id}'`)
    assert.equal(call.to.toLowerCase(), g.to.toLowerCase(), 'target address')
    assert.equal(call.value, BigInt(g.value), 'call value (wei)')
    assert.equal(call.data.toLowerCase(), g.data.toLowerCase(), 'calldata')
  })
}

test('every TS template is covered by a golden — no untested surface', () => {
  const goldenIds = new Set(goldens.templates.map((g) => g.id))
  const uncovered = Object.keys(built).filter((id) => !goldenIds.has(id))
  assert.deepEqual(uncovered, [], 'templates missing from actions.golden.json')
})

test('the golden fixtures match fixtures.ts — a drifted fixture invalidates every vector', () => {
  const fx = goldens.fixtures
  assert.equal(fx.alice.toLowerCase(), f.ALICE.toLowerCase())
  assert.equal(fx.bob.toLowerCase(), f.BOB.toLowerCase())
  assert.equal(fx.token.toLowerCase(), f.TOKEN.toLowerCase())
  assert.equal(fx.token2.toLowerCase(), f.TOKEN2.toLowerCase())
  assert.equal(fx.router.toLowerCase(), f.ROUTER.toLowerCase())
  assert.equal(fx.pool.toLowerCase(), f.POOL.toLowerCase())
  assert.equal(fx.nft.toLowerCase(), f.NFT.toLowerCase())
  assert.equal(fx.weth.toLowerCase(), f.WETH.toLowerCase())
  assert.equal(BigInt(fx.amount), f.AMOUNT)
  assert.equal(BigInt(fx.amountMin), f.AMOUNT_MIN)
  assert.equal(BigInt(fx.wei), f.WEI)
  assert.equal(BigInt(fx.tokenId), f.TOKEN_ID)
  assert.equal(BigInt(fx.deadline), f.DEADLINE)
  assert.equal(BigInt(fx.interestRateModeVariable), InterestRateMode.Variable)
})

test('payable templates carry value, non-payable ones do not', () => {
  // A template that silently drops `value` would encode correctly and still
  // fail on-chain, so pin the payable set explicitly.
  const payable = new Set(['native.transfer', 'weth.deposit', 'univ2.swapExactETHForTokens'])
  for (const [id, call] of Object.entries(built)) {
    if (payable.has(id)) assert.ok(call.value > 0n, `${id} must carry ETH value`)
    else assert.equal(call.value, 0n, `${id} must not carry ETH value`)
  }
})

// --- batch: digest + calldata, both pinned against cast ---------------------
// Both, not just the calldata: the EIP-712 batch digest is what the signature
// actually covers, so a change there would silently invalidate every batch
// signature with nothing failing.
import { batchDigest, encodeExecuteBatch, personalSignDigest } from './eip712.ts'
import type { Address, Hex } from 'viem'

interface BatchGolden {
  id: string; chainId: string; account: string
  to: string[]; value: string[]; calldata: string[]
  nonce: string; signature: string; encoded: string; digest: string
}

const batches: BatchGolden[] = (goldens as unknown as { batch: BatchGolden[] }).batch ?? []

for (const b of batches) {
  test(`batch ${b.id}: EIP-712 digest matches the cast-derived golden`, () => {
    const calls = b.to.map((to, i) => ({
      to: to as Address, value: BigInt(b.value[i]), data: b.calldata[i] as Hex,
    }))
    const got = batchDigest({
      chainId: BigInt(b.chainId), account: b.account as Address,
      calls, nonce: BigInt(b.nonce),
    })
    assert.equal(got.toLowerCase(), b.digest.toLowerCase())
  })

  test(`batch ${b.id}: calldata matches the cast-generated golden`, () => {
    const calls = b.to.map((to, i) => ({
      to: to as Address, value: BigInt(b.value[i]), data: b.calldata[i] as Hex,
    }))
    const got = encodeExecuteBatch(calls, BigInt(b.nonce), b.signature as Hex)
    assert.equal(got.toLowerCase(), b.encoded.toLowerCase())
  })

  test(`batch ${b.id}: reordering the calls changes the digest`, () => {
    const calls = b.to.map((to, i) => ({
      to: to as Address, value: BigInt(b.value[i]), data: b.calldata[i] as Hex,
    }))
    const forward = batchDigest({
      chainId: BigInt(b.chainId), account: b.account as Address, calls, nonce: BigInt(b.nonce),
    })
    const reversed = batchDigest({
      chainId: BigInt(b.chainId), account: b.account as Address,
      calls: [...calls].reverse(), nonce: BigInt(b.nonce),
    })
    assert.notEqual(forward, reversed, 'a relayer must not be able to reorder a signed batch')
  })
}

interface PersonalSignGolden { chainId: string; account: string; hash: string; digest: string }
const personalSigns: PersonalSignGolden[] =
  (goldens as unknown as { personalSign?: PersonalSignGolden[] }).personalSign ?? []

for (const ps of personalSigns) {
  test('personalSign digest matches the cast-derived golden', () => {
    // Asserting only "wrapped != raw" proves the wrapper changes the value, not
    // that it produces the RIGHT value. This pins the actual digest.
    const got = personalSignDigest({
      chainId: BigInt(ps.chainId), account: ps.account as Address, hash: ps.hash as Hex,
    })
    assert.equal(got.toLowerCase(), ps.digest.toLowerCase())
    assert.notEqual(got.toLowerCase(), ps.hash.toLowerCase(),
      'the 1271 path must not return the raw hash — that is the exploit')
  })
}

test('an execute digest wrapped as a 1271 challenge is a different message', () => {
  // The vulnerability the PersonalSign wrapper closes: signing a raw hash on the
  // 1271 path turned an attacker-supplied "login challenge" into a valid
  // execute authorisation.
  const chainId = 42161n
  const account = '0x00000000000000000000000000000000000000aa' as Address
  const evil = executeDigest({
    chainId, account, to: '0x000000000000000000000000000000000000dEaD' as Address,
    value: 10n ** 18n, data: '0x', nonce: 0n,
  })
  const wrapped = personalSignDigest({ chainId, account, hash: evil })
  assert.notEqual(wrapped, evil, 'the 1271 path must not sign the raw execute digest')
})

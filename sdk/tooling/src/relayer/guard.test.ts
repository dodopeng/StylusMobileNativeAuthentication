import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validateRelayRequest, SpendController, DEFAULT_POLICY } from './guard.ts'
import type { Address } from 'viem'

const ACCT = '0x000000000000000000000000000000000000aAaA'
const EXECUTE = '0xd2c88a7c' + '00'.repeat(64)
const ROTATE = '0x82bed5b3' + '00'.repeat(64)
const ERC20_TRANSFER = '0xa9059cbb' + '00'.repeat(64) // must be rejected

test('accepts execute', () => {
  const r = validateRelayRequest(ACCT, EXECUTE)
  assert.equal(r.ok, true)
})

test('accepts rotateOwner', () => {
  assert.equal(validateRelayRequest(ACCT, ROTATE).ok, true)
})

test('rejects non-account selector (no arbitrary-calldata oracle)', () => {
  const r = validateRelayRequest(ACCT, ERC20_TRANSFER)
  assert.equal(r.ok, false)
  if (!r.ok) assert.equal(r.status, 403)
})

test('rejects bad address', () => {
  const r = validateRelayRequest('0xnope', EXECUTE)
  assert.equal(r.ok, false)
  if (!r.ok) assert.equal(r.status, 400)
})

test('rejects short/non-hex data', () => {
  assert.equal(validateRelayRequest(ACCT, '0x12').ok, false)
  assert.equal(validateRelayRequest(ACCT, 'nothex').ok, false)
})

// --- spend control ---------------------------------------------------------
// The selector allowlist never was the security boundary: anyone can deploy
// their own P256Account and sign valid `execute` calls, so a relayer that pays
// gas for any well-formed request is a free-gas faucet. These pin the controls
// that actually stop that.


const SPONSORED: Address = '0x1111111111111111111111111111111111111111'
const OTHER: Address = '0x2222222222222222222222222222222222222222'

function controller(overrides: Record<string, unknown> = {}, now = () => 1_000_000) {
  return new SpendController(
    { allowlist: new Set([SPONSORED.toLowerCase()]), ...DEFAULT_POLICY, ...overrides } as any,
    now,
  )
}

test('an account that is not allowlisted is refused', () => {
  const c = controller()
  const r = c.admit(OTHER, 1n)
  assert.equal(r.ok, false)
  assert.equal(r.ok === false && r.status, 403)
})

test('allowlisting is case-insensitive', () => {
  const c = controller()
  assert.equal(c.admit(SPONSORED.toUpperCase() as Address, 1n).ok, true)
})

test('per-account budget is enforced', () => {
  const c = controller({ perAccountBudgetWei: 100n })
  assert.equal(c.admit(SPONSORED, 60n).ok, true)  // admit() now also reserves
  const r = c.admit(SPONSORED, 60n)
  assert.equal(r.ok, false)
  assert.equal(r.ok === false && r.status, 429)
})

test('global budget is enforced even when the per-account budget has room', () => {
  const c = new SpendController(
    { allowlist: new Set([SPONSORED.toLowerCase(), OTHER.toLowerCase()]),
      ...DEFAULT_POLICY, perAccountBudgetWei: 1000n, globalBudgetWei: 100n },
    () => 1_000_000,
  )
  c.admit(SPONSORED, 80n)
  const r = c.admit(OTHER, 40n)
  assert.equal(r.ok, false)
  assert.equal(r.ok === false && r.status, 503)
})

test('request rate limit is enforced independently of spend', () => {
  const c = controller({ perAccountRequests: 2 })
  c.admit(SPONSORED, 0n)
  c.admit(SPONSORED, 0n)
  const r = c.admit(SPONSORED, 0n)
  assert.equal(r.ok, false)
  assert.equal(r.ok === false && r.status, 429)
})

test('spend outside the window no longer counts', () => {
  let now = 1_000_000
  const c = controller({ perAccountBudgetWei: 100n, windowMs: 1000 }, () => now)
  c.admit(SPONSORED, 90n)
  assert.equal(c.admit(SPONSORED, 50n).ok, false, 'inside the window it is over budget')
  now += 2000
  assert.equal(c.admit(SPONSORED, 50n).ok, true, 'outside the window it is forgotten')
})

test('executeBatch selector is relayable, arbitrary selectors are not', () => {
  const batch = '0xa428824f' + '00'.repeat(32)
  assert.equal(validateRelayRequest(SPONSORED, batch).ok, true)
  const evil = '0xdeadbeef' + '00'.repeat(32)
  const r = validateRelayRequest(SPONSORED, evil)
  assert.equal(r.ok, false)
  assert.equal(r.ok === false && r.status, 403)
})

test('admit reserves, so concurrent requests cannot all pass the same budget', () => {
  // The TOCTOU this replaced: check-then-record let N concurrent requests all
  // read the same totals and all pass, overshooting by up to N x estimate.
  const c = controller({ perAccountBudgetWei: 100n })
  const results = [40n, 40n, 40n].map((wei) => c.admit(SPONSORED, wei))
  assert.deepEqual(results.map((r) => r.ok), [true, true, false],
    'the third must be refused because the first two already reserved')
})

test('a released reservation frees its budget again', () => {
  const c = controller({ perAccountBudgetWei: 100n })
  const first = c.admit(SPONSORED, 80n)
  assert.equal(first.ok, true)
  assert.equal(c.admit(SPONSORED, 80n).ok, false)
  if (first.ok) c.release(SPONSORED, first.reservation)
  assert.equal(c.admit(SPONSORED, 80n).ok, true, 'released budget is reusable')
})

test('settle replaces the estimate with the actual cost', () => {
  const c = controller({ perAccountBudgetWei: 100n })
  const r = c.admit(SPONSORED, 90n)
  assert.equal(r.ok, true)
  if (r.ok) c.settle(r.reservation, 10n)   // actual cost far below the estimate
  assert.equal(c.admit(SPONSORED, 80n).ok, true, 'settling frees the over-estimate')
})

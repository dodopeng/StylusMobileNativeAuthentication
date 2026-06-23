import { test } from 'node:test'
import assert from 'node:assert/strict'
import { validateRelayRequest } from './guard.ts'

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

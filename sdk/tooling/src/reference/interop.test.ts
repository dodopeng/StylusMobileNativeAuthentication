// Parity tests: the TS reference must reproduce the SAME golden vectors as the
// Android (InteropTest.kt) and iOS (InteropTests.swift) SDKs, AND a signature it
// produces must verify under P-256 — proving the full SDK signing path is sound.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { keccak256, toBytes, toHex } from 'viem'
import { executeDigest, encodeErc20Transfer } from './eip712.ts'
import { ReferenceSigner } from './signer.ts'

test('keccak known vectors', () => {
  assert.equal(
    keccak256(new Uint8Array(0)),
    '0xc5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470',
  )
  assert.equal(
    keccak256(toBytes('P256Account')),
    '0x0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d',
  )
})

test('execute digest matches contract + both SDKs', () => {
  const digest = executeDigest({
    chainId: 42161n,
    account: '0x1111111111111111111111111111111111111111',
    to: '0x2222222222222222222222222222222222222222',
    value: 1000n,
    data: toHex(toBytes('hello')),
    nonce: 0n,
  })
  assert.equal(digest, '0x4e71705df943b3848269d8a661320fca963cd2392a7cc0ee2e9028ff7983f854')
})

test('erc20 transfer encoding matches both SDKs', () => {
  const data = encodeErc20Transfer('0x2222222222222222222222222222222222222222', 1_000_000n)
  assert.equal(
    data,
    '0xa9059cbb0000000000000000000000002222222222222222222222222222222222222222' +
      '00000000000000000000000000000000000000000000000000000000000f4240',
  )
})

test('an SDK-equivalent P-256 signature verifies over the execute digest', () => {
  const signer = ReferenceSigner.random()
  const { x, y } = signer.publicKey()
  // x,y are valid field elements and the point is on-curve (noble guarantees it).
  assert.ok(x > 0n && y > 0n)

  const digest = executeDigest({
    chainId: 412346n, // Nitro devnode
    account: '0x00000000000000000000000000000000000000aa',
    to: '0x000000000000000000000000000000000000dead',
    value: 0n,
    data: '0x',
    nonce: 0n,
  })
  const sig = signer.sign(digest)
  assert.equal((sig.length - 2) / 2, 64, 'signature is 64 bytes r‖s')
  assert.ok(signer.verify(digest, sig), 'signature must verify under P-256 (== on-chain RIP-7212)')

  // low-S: s must be in (0, n/2].
  const HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8n
  const s = BigInt('0x' + sig.slice(2 + 64))
  assert.ok(s > 0n && s <= HALF_N, 'signature must be low-S')
})

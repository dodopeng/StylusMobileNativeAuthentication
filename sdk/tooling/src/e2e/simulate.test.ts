// Full SDK pipeline against the in-memory contract simulator — runs anywhere,
// no devnode. Drives the *real* reference signer + EIP-712 + ABI encoding the
// mobile SDKs use, and asserts the contract's security properties hold.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { type Address, type Hex } from 'viem'
import { ReferenceSigner } from '../reference/signer.ts'
import { executeDigest, rotateDigest, encodeExecute, encodeRotateOwner } from '../reference/eip712.ts'
import { SimulatedAccount, ContractRevert, REVERTER } from './simulator.ts'

const CHAIN = 412346n
const ACCOUNT: Address = '0x00000000000000000000000000000000000000aa'
const TO: Address = '0x1111111111111111111111111111111111111111'

function freshAccount(signer: ReferenceSigner) {
  return new SimulatedAccount(ACCOUNT, CHAIN, signer.publicKey())
}

/** Build a signed `execute` exactly as the SDK does. */
function signedExecute(signer: ReferenceSigner, acct: SimulatedAccount, to: Address, value = 0n, data: Hex = '0x') {
  const nonce = acct.nonce
  const digest = executeDigest({ chainId: CHAIN, account: acct.address, to, value, data, nonce })
  const signature = signer.sign(digest)
  return encodeExecute(to, value, data, nonce, signature)
}

test('happy path: execute verifies, nonce 0 → 1, success', () => {
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)
  const txHash = acct.submit(signedExecute(signer, acct, TO))
  assert.equal(acct.nonce, 1n)
  assert.deepEqual(acct.receipt(txHash)?.success, true)
})

test('replay of the same signed calldata is rejected (NonceMismatch)', () => {
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)
  const callData = signedExecute(signer, acct, TO)
  acct.submit(callData) // nonce now 1
  assert.throws(() => acct.submit(callData), (e) => e instanceof ContractRevert && /NonceMismatch/.test(e.reason))
})

test('signing the wrong nonce is rejected', () => {
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)
  const digest = executeDigest({ chainId: CHAIN, account: acct.address, to: TO, value: 0n, data: '0x', nonce: 5n })
  const callData = encodeExecute(TO, 0n, '0x', 5n, signer.sign(digest))
  assert.throws(() => acct.submit(callData), (e) => e instanceof ContractRevert && /NonceMismatch/.test(e.reason))
})

test('tampering with the call after signing breaks verification', () => {
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)
  // sign for TO, then submit calldata addressed elsewhere with the same sig.
  const nonce = acct.nonce
  const digest = executeDigest({ chainId: CHAIN, account: acct.address, to: TO, value: 0n, data: '0x', nonce })
  const sig = signer.sign(digest)
  const tampered = encodeExecute('0x2222222222222222222222222222222222222222', 0n, '0x', nonce, sig)
  assert.throws(() => acct.submit(tampered), (e) => e instanceof ContractRevert && /InvalidSignature/.test(e.reason))
})

test('a high-S signature is rejected (malleability)', () => {
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)
  const nonce = acct.nonce
  const digest = executeDigest({ chainId: CHAIN, account: acct.address, to: TO, value: 0n, data: '0x', nonce })
  const sig = signer.sign(digest)
  // Flip s to its high-S counterpart n - s.
  const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
  const r = sig.slice(2, 66)
  const s = BigInt('0x' + sig.slice(66, 130))
  const highSig = ('0x' + r + (N - s).toString(16).padStart(64, '0')) as Hex
  const callData = encodeExecute(TO, 0n, '0x', nonce, highSig)
  assert.throws(() => acct.submit(callData), (e) => e instanceof ContractRevert && /HighS/.test(e.reason))
})

test('rotateOwner: new key takes over, old key is rejected', () => {
  const k1 = ReferenceSigner.random()
  const k2 = ReferenceSigner.random()
  const acct = freshAccount(k1)

  // Rotate to k2, signed by the CURRENT owner k1.
  const rNonce = acct.nonce
  const newOwner = k2.publicKey()
  const rDigest = rotateDigest({ chainId: CHAIN, account: acct.address, newX: newOwner.x, newY: newOwner.y, nonce: rNonce })
  acct.submit(encodeRotateOwner(newOwner.x, newOwner.y, rNonce, k1.sign(rDigest)))
  assert.equal(acct.nonce, 1n)
  assert.deepEqual(acct.owner(), newOwner)

  // k2 can now execute…
  acct.submit(signedExecute(k2, acct, TO))
  assert.equal(acct.nonce, 2n)

  // …and the old key k1 can no longer execute.
  assert.throws(() => acct.submit(signedExecute(k1, acct, TO)),
    (e) => e instanceof ContractRevert && /InvalidSignature/.test(e.reason))
})

test('rotating to an off-curve key is rejected (anti-brick)', () => {
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)
  const owner = signer.publicKey()
  const badX = owner.x
  const badY = owner.y + 1n // almost certainly off-curve
  const nonce = acct.nonce
  const digest = rotateDigest({ chainId: CHAIN, account: acct.address, newX: badX, newY: badY, nonce })
  const callData = encodeRotateOwner(badX, badY, nonce, signer.sign(digest))
  assert.throws(() => acct.submit(callData), (e) => e instanceof ContractRevert && /InvalidPublicKey/.test(e.reason))
})

test('reverting inner call still consumes the nonce (nonce-before-call, SPEC.md §5)', () => {
  const signer = ReferenceSigner.random()
  const acct = freshAccount(signer)
  const txHash = acct.submit(signedExecute(signer, acct, REVERTER))
  const r = acct.receipt(txHash)
  assert.equal(r?.success, false)        // inner call failed…
  assert.equal(r?.returnData, '0xdeadbeef')
  assert.equal(acct.nonce, 1n)           // …but the nonce still bumped
})

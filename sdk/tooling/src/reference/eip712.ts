// EIP-712 digest + ABI encoding for P256Account, in TypeScript. This is the
// authoritative reference the mobile SDKs (Kotlin/Swift) are validated against:
// it uses viem's audited keccak/ABI primitives, and its golden outputs match the
// Android `InteropTest` and iOS `InteropTests`. See ../../SPEC.md.
import {
  concatHex,
  encodeAbiParameters,
  encodeFunctionData,
  keccak256,
  pad,
  toHex,
  type Address,
  type Hex,
} from 'viem'

// Typehashes — verified against the contract (SPEC.md §2).
const DOMAIN_TYPEHASH =
  '0x8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f' as const
const NAME_HASH =
  '0x0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d' as const
const VERSION_HASH =
  '0xc89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6' as const
const EXECUTE_TYPEHASH =
  '0x5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c' as const
const ROTATE_TYPEHASH =
  '0x8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a' as const

const word = (v: bigint | number): Hex => pad(toHex(v), { size: 32 })

export function domainSeparator(chainId: bigint, account: Address): Hex {
  return keccak256(
    concatHex([DOMAIN_TYPEHASH, NAME_HASH, VERSION_HASH, word(chainId), pad(account, { size: 32 })]),
  )
}

function envelope(chainId: bigint, account: Address, structHash: Hex): Hex {
  return keccak256(concatHex(['0x1901', domainSeparator(chainId, account), structHash]))
}

export function executeDigest(args: {
  chainId: bigint
  account: Address
  to: Address
  value: bigint
  data: Hex
  nonce: bigint
}): Hex {
  const structHash = keccak256(
    concatHex([
      EXECUTE_TYPEHASH,
      pad(args.to, { size: 32 }),
      word(args.value),
      keccak256(args.data),
      word(args.nonce),
    ]),
  )
  return envelope(args.chainId, args.account, structHash)
}

const BATCH_TYPEHASH =
  '0xe4c4e9c11a8826c10f239085bcd6b1f837ac8891ef69510451fb4e86df1ff4fb' as const
const CALL_TYPEHASH =
  '0x9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483' as const
const PERSONAL_SIGN_TYPEHASH =
  '0x2431bd832cbb131f8882ef79f68ed6ae065cca9270f5bce0f2e4f75a9cd814b7' as const

export interface BatchCall { to: Address; value: bigint; data: Hex }

/** EIP-712 digest for `executeBatch`. Order is part of the hash. */
export function batchDigest(args: {
  chainId: bigint
  account: Address
  calls: readonly BatchCall[]
  nonce: bigint
}): Hex {
  const callHashes = args.calls.map((c) =>
    keccak256(concatHex([CALL_TYPEHASH, pad(c.to, { size: 32 }), word(c.value), keccak256(c.data)])),
  )
  const callsHash = keccak256(concatHex(callHashes))
  const structHash = keccak256(concatHex([BATCH_TYPEHASH, callsHash, word(args.nonce)]))
  return envelope(args.chainId, args.account, structHash)
}

/**
 * EIP-712 digest for an EIP-1271 challenge: `PersonalSign(bytes32 hash)`.
 *
 * The 1271 path must NOT sign the raw hash — an `Execute` digest is itself a
 * 32-byte hash computable from public inputs, so raw signing turns a login
 * prompt into a transfer authorisation.
 */
export function personalSignDigest(args: {
  chainId: bigint
  account: Address
  hash: Hex
}): Hex {
  const structHash = keccak256(concatHex([PERSONAL_SIGN_TYPEHASH, args.hash]))
  return envelope(args.chainId, args.account, structHash)
}

export function encodeExecuteBatch(
  calls: readonly BatchCall[], nonce: bigint, signature: Hex,
): Hex {
  return encodeFunctionData({
    abi: ACCOUNT_ABI,
    functionName: 'executeBatch',
    args: [calls.map((c) => c.to), calls.map((c) => c.value), calls.map((c) => c.data), nonce, signature],
  })
}

export function rotateDigest(args: {
  chainId: bigint
  account: Address
  newX: bigint
  newY: bigint
  nonce: bigint
}): Hex {
  const structHash = keccak256(
    concatHex([ROTATE_TYPEHASH, word(args.newX), word(args.newY), word(args.nonce)]),
  )
  return envelope(args.chainId, args.account, structHash)
}

// --- Calldata for the account methods (authoritative ABI via viem) ---

export function encodeExecute(to: Address, value: bigint, data: Hex, nonce: bigint, signature: Hex): Hex {
  return encodeFunctionData({
    abi: ACCOUNT_ABI,
    functionName: 'execute',
    args: [to, value, data, nonce, signature],
  })
}

export function encodeRotateOwner(newX: bigint, newY: bigint, nonce: bigint, signature: Hex): Hex {
  return encodeFunctionData({
    abi: ACCOUNT_ABI,
    functionName: 'rotateOwner',
    args: [newX, newY, nonce, signature],
  })
}

export function encodeErc20Transfer(to: Address, amount: bigint): Hex {
  return encodeFunctionData({
    abi: [
      { type: 'function', name: 'transfer', stateMutability: 'nonpayable', inputs: [
        { name: 'to', type: 'address' }, { name: 'amount', type: 'uint256' },
      ], outputs: [{ type: 'bool' }] },
    ],
    functionName: 'transfer',
    args: [to, amount],
  })
}

export { encodeAbiParameters }

export const ACCOUNT_ABI = [
  { type: 'constructor', stateMutability: 'nonpayable', inputs: [
    { name: 'x', type: 'uint256' }, { name: 'y', type: 'uint256' } ] },
  // NOT payable — the contract deliberately isn't, and check-abi.sh asserts it.
  // This said 'payable' and directly contradicted that assertion.
  { type: 'function', name: 'execute', stateMutability: 'nonpayable', inputs: [
    { name: 'to', type: 'address' }, { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' }, { name: 'nonce', type: 'uint256' },
    { name: 'signature', type: 'bytes' } ],
    outputs: [{ type: 'bool' }, { type: 'bytes' }] },
  { type: 'function', name: 'rotateOwner', stateMutability: 'nonpayable', inputs: [
    { name: 'newX', type: 'uint256' }, { name: 'newY', type: 'uint256' },
    { name: 'nonce', type: 'uint256' }, { name: 'signature', type: 'bytes' } ], outputs: [] },
  { type: 'function', name: 'nonce', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'ownerX', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'ownerY', stateMutability: 'view', inputs: [], outputs: [{ type: 'uint256' }] },
  { type: 'function', name: 'isValidSignature', stateMutability: 'view', inputs: [
    { name: 'hash', type: 'bytes32' }, { name: 'signature', type: 'bytes' } ], outputs: [{ type: 'bytes4' }] },
  { type: 'function', name: 'executeBatch', stateMutability: 'nonpayable', inputs: [
    { name: 'to', type: 'address[]' }, { name: 'value', type: 'uint256[]' },
    { name: 'data', type: 'bytes[]' }, { name: 'nonce', type: 'uint256' },
    { name: 'signature', type: 'bytes' } ], outputs: [] },
  { type: 'function', name: 'supportsInterface', stateMutability: 'view', inputs: [
    { name: 'interfaceId', type: 'bytes4' } ], outputs: [{ type: 'bool' }] },
  { type: 'function', name: 'onERC721Received', stateMutability: 'nonpayable', inputs: [
    { name: 'operator', type: 'address' }, { name: 'from', type: 'address' },
    { name: 'tokenId', type: 'uint256' }, { name: 'data', type: 'bytes' } ],
    outputs: [{ type: 'bytes4' }] },
  { type: 'function', name: 'onERC1155Received', stateMutability: 'nonpayable', inputs: [
    { name: 'operator', type: 'address' }, { name: 'from', type: 'address' },
    { name: 'id', type: 'uint256' }, { name: 'value', type: 'uint256' },
    { name: 'data', type: 'bytes' } ], outputs: [{ type: 'bytes4' }] },
  { type: 'function', name: 'onERC1155BatchReceived', stateMutability: 'nonpayable', inputs: [
    { name: 'operator', type: 'address' }, { name: 'from', type: 'address' },
    { name: 'ids', type: 'uint256[]' }, { name: 'values', type: 'uint256[]' },
    { name: 'data', type: 'bytes' } ], outputs: [{ type: 'bytes4' }] },
] as const

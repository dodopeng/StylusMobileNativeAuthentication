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
  { type: 'function', name: 'execute', stateMutability: 'payable', inputs: [
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
] as const

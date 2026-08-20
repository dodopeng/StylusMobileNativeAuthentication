// In-memory simulator of the on-chain P256Account, standing in for a real Nitro
// devnode where one can't run (CI, offline). It is a FAITHFUL mock: it decodes
// the SDK's actual `execute`/`rotateOwner` calldata, recomputes the EIP-712
// digest exactly as the contract does, verifies the P-256 signature the way the
// RIP-7212 precompile does (message hash = digest, no re-hash, strict low-S),
// and reproduces the contract's nonce/replay/revert semantics.
//
// What it proves: the SDK's encode → sign → digest → verify → nonce pipeline is
// internally consistent and enforces the contract's security properties. What it
// does NOT prove: the real Stylus contract bytecode or the precompile itself —
// those are covered by contracts/stylus tests + the live devnode harness.
import { p256 } from '@noble/curves/p256'
import {
  decodeFunctionData,
  hexToBytes,
  pad,
  toHex,
  keccak256,
  concatHex,
  type Address,
  type Hex,
} from 'viem'
import { ACCOUNT_ABI, executeDigest, rotateDigest, batchDigest } from '../reference/eip712.ts'

const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n
const HALF_N = N >> 1n
const P = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn

/** A `to` address the simulator treats as a reverting inner call (for the
 *  contract's "revert still consumes the nonce" invariant). */
export const REVERTER: Address = '0x000000000000000000000000000000000000dead'

/** Mirrors the contract's MAX_BATCH_CALLS. */
export const MAX_BATCH_CALLS = 32

export interface ExecutedResult {
  success: boolean
  returnData: Hex
  nonce: bigint
}

/** Thrown for every rejection the contract would revert on, with the matching name. */
export class ContractRevert extends Error {
  constructor(public reason: string) {
    super(reason)
  }
}

export class SimulatedAccount {
  private ownerX: bigint
  private ownerY: bigint
  private _nonce = 0n
  private receipts = new Map<string, ExecutedResult>()

  constructor(
    public readonly address: Address,
    public readonly chainId: bigint,
    owner: { x: bigint; y: bigint },
  ) {
    this.assertValidOwner(owner.x, owner.y)
    this.ownerX = owner.x
    this.ownerY = owner.y
  }

  get nonce(): bigint {
    return this._nonce
  }
  owner(): { x: bigint; y: bigint } {
    return { x: this.ownerX, y: this.ownerY }
  }

  /** Apply pre-built account calldata (what the relayer broadcasts). Returns a
   *  fake tx hash; the decoded outcome is retrievable via `receipt()`. */
  submit(callData: Hex): Hex {
    const { functionName, args } = decodeFunctionData({ abi: ACCOUNT_ABI, data: callData })
    let result: ExecutedResult
    if (functionName === 'execute') {
      result = this.execute(args as readonly [Address, bigint, Hex, bigint, Hex])
    } else if (functionName === 'executeBatch') {
      result = this.executeBatch(
        args as readonly [readonly Address[], readonly bigint[], readonly Hex[], bigint, Hex],
      )
    } else if (functionName === 'rotateOwner') {
      result = this.rotateOwner(args as readonly [bigint, bigint, bigint, Hex])
    } else {
      throw new ContractRevert(`UnknownSelector(${functionName})`)
    }
    const txHash = keccak256(concatHex([callData, toHex(this._nonce, { size: 32 })]))
    this.receipts.set(txHash, result)
    return txHash
  }

  receipt(txHash: Hex): ExecutedResult | undefined {
    return this.receipts.get(txHash)
  }

  // --- contract logic mirrors ---

  private execute(args: readonly [Address, bigint, Hex, bigint, Hex]): ExecutedResult {
    const [to, value, data, nonce, signature] = args
    if (nonce !== this._nonce) throw new ContractRevert(`NonceMismatch(expected ${this._nonce}, got ${nonce})`)
    const digest = executeDigest({ chainId: this.chainId, account: this.address, to, value, data, nonce })
    this.verify(digest, signature) // reverts on bad sig BEFORE consuming the nonce

    // CEI: nonce committed before the (simulated) outbound call.
    this._nonce += 1n
    // Inner-call outcome: a revert still consumes the nonce and returns
    // (success=false, revertBytes) rather than reverting the whole tx.
    if (to.toLowerCase() === REVERTER.toLowerCase()) {
      return { success: false, returnData: '0xdeadbeef', nonce }
    }
    return { success: true, returnData: '0x', nonce }
  }

  /**
   * Mirror of `execute_batch`. Unlike `execute`, a batch is ALL-OR-NOTHING: a
   * failing inner call reverts the whole transaction and the nonce is NOT
   * consumed, so no partial state (e.g. a dangling approval) survives.
   */
  private executeBatch(
    args: readonly [readonly Address[], readonly bigint[], readonly Hex[], bigint, Hex],
  ): ExecutedResult {
    const [to, value, data, nonce, signature] = args
    if (to.length === 0 || to.length !== value.length || to.length !== data.length) {
      throw new ContractRevert(`InvalidBatch(${to.length}, ${value.length}, ${data.length})`)
    }
    if (to.length > MAX_BATCH_CALLS) {
      throw new ContractRevert(`InvalidBatch(${to.length}, ${value.length}, ${data.length})`)
    }
    if (nonce !== this._nonce) {
      throw new ContractRevert(`NonceMismatch(expected ${this._nonce}, got ${nonce})`)
    }
    const calls = to.map((t, i) => ({ to: t, value: value[i], data: data[i] }))
    const digest = batchDigest({ chainId: this.chainId, account: this.address, calls, nonce })
    this.verify(digest, signature)

    this._nonce += 1n
    for (let i = 0; i < to.length; i++) {
      if (to[i].toLowerCase() === REVERTER.toLowerCase()) {
        // All-or-nothing: undo the nonce bump, as an on-chain revert would.
        this._nonce -= 1n
        throw new ContractRevert(`BatchCallFailed(${i})`)
      }
    }
    return { success: true, returnData: '0x', nonce }
  }

  private rotateOwner(args: readonly [bigint, bigint, bigint, Hex]): ExecutedResult {
    const [newX, newY, nonce, signature] = args
    if (nonce !== this._nonce) throw new ContractRevert(`NonceMismatch(expected ${this._nonce}, got ${nonce})`)
    this.assertValidOwner(newX, newY) // off-curve / out-of-range rotation is rejected (anti-brick)
    const digest = rotateDigest({ chainId: this.chainId, account: this.address, newX, newY, nonce })
    this.verify(digest, signature) // signed by the CURRENT owner

    this._nonce += 1n
    this.ownerX = newX
    this.ownerY = newY
    return { success: true, returnData: '0x', nonce }
  }

  /** Mirror of validate_p256_signature: length, r/s range, strict low-S, then
   *  precompile verification (here: noble) against the current owner key. */
  private verify(digest: Hex, signature: Hex) {
    const sig = hexToBytes(signature)
    if (sig.length !== 64) throw new ContractRevert(`InvalidSignatureLength(${sig.length})`)
    const r = BigInt('0x' + signature.slice(2, 66))
    const s = BigInt('0x' + signature.slice(66, 130))
    if (r <= 0n || r >= N) throw new ContractRevert('InvalidR')
    if (s <= 0n || s >= N) throw new ContractRevert('InvalidS')
    if (s > HALF_N) throw new ContractRevert('HighS')

    const pub = hexToBytes(
      concatHex(['0x04', pad(toHex(this.ownerX), { size: 32 }), pad(toHex(this.ownerY), { size: 32 })]),
    )
    const ok = p256.verify(sig, hexToBytes(digest), pub, { lowS: true, prehash: false })
    if (!ok) throw new ContractRevert('InvalidSignature')
  }

  private assertValidOwner(x: bigint, y: bigint) {
    if (x <= 0n || x >= P || y <= 0n || y >= P) throw new ContractRevert('InvalidPublicKey(range)')
    // On-curve membership (the SDK's job per SPEC §6; the simulator enforces it
    // so an off-curve rotation can't "succeed" and brick the account).
    try {
      const uncompressed = concatHex(['0x04', pad(toHex(x), { size: 32 }), pad(toHex(y), { size: 32 })])
      p256.ProjectivePoint.fromHex(uncompressed.slice(2))
    } catch {
      throw new ContractRevert('InvalidPublicKey(off-curve)')
    }
  }
}

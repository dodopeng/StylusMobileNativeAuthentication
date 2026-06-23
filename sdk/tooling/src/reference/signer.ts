// Software P-256 signer — a faithful stand-in for the hardware signers in the
// Android (StrongBox/TEE) and iOS (Secure Enclave) SDKs. It produces the exact
// same artefact: a public key (x, y) and a canonical 64-byte `r‖s` low-S
// signature over a 32-byte digest, signing the digest *directly* (raw ECDSA,
// no inner hash) — which is what the RIP-7212 precompile verifies.
//
// Hardware keys can't run headless, so this is what the e2e harness uses to
// drive a real sign → relay → on-chain round trip. The on-chain verification is
// identical regardless of where the key physically lives.
import { p256 } from '@noble/curves/p256'
import { bytesToHex, hexToBytes, type Hex } from 'viem'

export interface P256Owner {
  x: bigint
  y: bigint
}

export class ReferenceSigner {
  private constructor(private readonly privateKey: Uint8Array) {}

  /** Generate a fresh key (mirrors `signer.create()` on device). */
  static random(): ReferenceSigner {
    return new ReferenceSigner(p256.utils.randomPrivateKey())
  }

  /** Restore from a raw 32-byte private key (tests / fixtures only). */
  static fromPrivateKey(pk: Hex | Uint8Array): ReferenceSigner {
    return new ReferenceSigner(typeof pk === 'string' ? hexToBytes(pk) : pk)
  }

  /** The on-chain owner coordinates `(x, y)` — constructor / rotation args. */
  publicKey(): P256Owner {
    const point = p256.ProjectivePoint.fromPrivateKey(this.privateKey).toAffine()
    return { x: point.x, y: point.y }
  }

  /**
   * Sign a 32-byte digest, returning canonical 64-byte `r‖s` as hex. noble
   * applies low-S by default and signs the prehashed digest directly (no extra
   * SHA-256), matching the contract's RIP-7212 expectation exactly.
   */
  sign(digest: Hex | Uint8Array): Hex {
    const msg = typeof digest === 'string' ? hexToBytes(digest) : digest
    if (msg.length !== 32) throw new Error('digest must be 32 bytes')
    const sig = p256.sign(msg, this.privateKey, { lowS: true, prehash: false })
    return bytesToHex(sig.toCompactRawBytes()) // r(32) || s(32)
  }

  /** Local verification (the precompile does this on-chain). */
  verify(digest: Hex | Uint8Array, signature: Hex): boolean {
    const msg = typeof digest === 'string' ? hexToBytes(digest) : digest
    return p256.verify(hexToBytes(signature), msg, p256.getPublicKey(this.privateKey, false), {
      lowS: true,
      prehash: false,
    })
  }
}

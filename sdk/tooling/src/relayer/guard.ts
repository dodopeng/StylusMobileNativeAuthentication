// Pure request validation for the relayer — kept separate so the security
// rules (address shape, selector allowlist) are unit-testable without a chain.
import { isAddress, isHex, type Hex } from 'viem'

/** Selectors the relayer will broadcast: execute, rotateOwner (SPEC.md §3). */
export const ALLOWED_SELECTORS = new Set<string>(['0xd2c88a7c', '0x82bed5b3'])

export type GuardResult = { ok: true; selector: string } | { ok: false; status: number; error: string }

export function validateRelayRequest(account: unknown, data: unknown): GuardResult {
  // strict:false — validate shape (0x + 40 hex), not EIP-55 checksum, since
  // clients may send lowercase addresses. The signature, not the casing, is auth.
  if (typeof account !== 'string' || !isAddress(account, { strict: false })) {
    return { ok: false, status: 400, error: 'invalid account address' }
  }
  if (typeof data !== 'string' || !isHex(data) || data.length < 10) {
    return { ok: false, status: 400, error: 'invalid data' }
  }
  const selector = (data as Hex).slice(0, 10).toLowerCase()
  if (!ALLOWED_SELECTORS.has(selector)) {
    return { ok: false, status: 403, error: `selector ${selector} not allowed (execute/rotateOwner only)` }
  }
  return { ok: true, selector }
}

// Request validation and spend control for the relayer.
//
// ## What the selector allowlist is NOT
//
// An earlier version of this file checked only the address shape and a
// two-selector allowlist, and claimed that made a leaked endpoint safe. It does
// not. The relayer pays gas for whatever it broadcasts, so the attack is not
// "send arbitrary calldata" — it is simply *spending the relayer's ETH*:
// deploy your own P256Account, sign your own valid `execute` calls with your own
// key, and every request is legitimately well-formed, passes the selector
// filter, and burns gas. There is no selector filter that fixes this, because
// the calls are genuinely valid.
//
// The boundary has to be **who the relayer is willing to pay for**, plus a cap
// on how much. Hence: an account allowlist (or a factory/registry membership
// check), a per-account and global spend budget, and a rate limit. The selector
// allowlist is kept because it still usefully constrains *shape* — it stops the
// endpoint doubling as a generic call proxy — but it is not the security
// boundary and is no longer described as one.
import { isAddress, isHex, type Address, type Hex } from 'viem'

/** Selectors the relayer will broadcast (SPEC.md §3). Shape control only. */
export const ALLOWED_SELECTORS = new Set<string>([
  '0xd2c88a7c', // execute(address,uint256,bytes,uint256,bytes)
  '0xa428824f', // executeBatch(address[],uint256[],bytes[],uint256,bytes)
  '0x82bed5b3', // rotateOwner(uint256,uint256,uint256,bytes)
])

export type GuardResult =
  | { ok: true; selector: string; account: Address; data: Hex }
  | { ok: false; status: number; error: string }

/** Shape validation only. Spend control is `SpendController` below. */
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
    return {
      ok: false,
      status: 403,
      error: `selector ${selector} not allowed (execute/executeBatch/rotateOwner only)`,
    }
  }
  return { ok: true, selector, account: account as Address, data: data as Hex }
}

export interface SpendPolicy {
  /** Accounts the relayer sponsors. Empty set = sponsor nobody (fail closed). */
  allowlist: Set<string>
  /** Max wei the relayer will spend on one account within `windowMs`. */
  perAccountBudgetWei: bigint
  /** Max wei across all accounts within `windowMs`. */
  globalBudgetWei: bigint
  /** Max requests per account within `windowMs`. */
  perAccountRequests: number
  /** Sliding-window length. */
  windowMs: number
}

export const DEFAULT_POLICY: Omit<SpendPolicy, 'allowlist'> = {
  perAccountBudgetWei: 10n ** 16n, // 0.01 ETH
  globalBudgetWei: 10n ** 17n, // 0.1 ETH
  perAccountRequests: 20,
  windowMs: 60 * 60 * 1000, // 1 hour
}

export interface Spend {
  at: number
  wei: bigint
}

export type AdmitResult =
  | { ok: true; reservation: Spend }
  | { ok: false; status: number; error: string }

/**
 * Sliding-window spend and rate control.
 *
 * In-memory on purpose: this is the reference relayer, and a single process is
 * the documented deployment. A multi-instance production relayer must move this
 * to shared storage — otherwise each instance enforces its own budget and the
 * effective cap is `instances × budget`. That limitation is stated here rather
 * than left for an operator to discover from a drained hot wallet.
 */
export class SpendController {
  private perAccount = new Map<string, Spend[]>()
  private global: Spend[] = []

  constructor(private policy: SpendPolicy, private now: () => number = Date.now) {}

  private prune(list: Spend[], cutoff: number): Spend[] {
    return list.filter((s) => s.at >= cutoff)
  }

  private total(list: Spend[]): bigint {
    return list.reduce((a, s) => a + s.wei, 0n)
  }

  /** Cheap allowlist test, callable before any RPC work is done. */
  isSponsored(account: Address): boolean {
    return this.policy.allowlist.has(account.toLowerCase())
  }

  /**
   * Reserve an intended spend BEFORE broadcasting, returning a handle that must
   * be settled with the real cost or released.
   *
   * Checking without reserving was a TOCTOU hole: N concurrent requests all read
   * the same totals, all passed, and `record()` only ran after the broadcast —
   * so both the budget and the rate limit could overshoot by up to N × estimate.
   * The reservation is written under the same synchronous step as the check, so
   * concurrent callers see each other immediately.
   */
  admit(account: Address, estimatedWei: bigint): AdmitResult {
    const key = account.toLowerCase()

    if (!this.policy.allowlist.has(key)) {
      return {
        ok: false,
        status: 403,
        error:
          'account is not sponsored by this relayer. ' +
          'A relayer pays gas, so it must know whose transactions it funds — ' +
          'set RELAYER_ALLOWLIST (see src/relayer/README or SPEC.md §4).',
      }
    }

    const cutoff = this.now() - this.policy.windowMs
    const mine = this.prune(this.perAccount.get(key) ?? [], cutoff)
    const all = this.prune(this.global, cutoff)

    if (mine.length >= this.policy.perAccountRequests) {
      return { ok: false, status: 429, error: `rate limit: ${this.policy.perAccountRequests} requests per window` }
    }
    if (this.total(mine) + estimatedWei > this.policy.perAccountBudgetWei) {
      return { ok: false, status: 429, error: 'per-account gas budget exhausted for this window' }
    }
    if (this.total(all) + estimatedWei > this.policy.globalBudgetWei) {
      return { ok: false, status: 503, error: 'relayer global gas budget exhausted for this window' }
    }

    // Reserve immediately — this is what closes the TOCTOU window.
    const entry: Spend = { at: this.now(), wei: estimatedWei }
    mine.push(entry)
    all.push(entry)
    this.perAccount.set(key, mine)
    this.global = all
    return { ok: true, reservation: entry }
  }

  /** Replace a reservation's estimate with the actual cost. */
  settle(reservation: Spend, actualWei: bigint): void {
    reservation.wei = actualWei
  }

  /** Release a reservation whose broadcast never happened. */
  release(account: Address, reservation: Spend): void {
    const key = account.toLowerCase()
    const mine = this.perAccount.get(key)
    if (mine) this.perAccount.set(key, mine.filter((s) => s !== reservation))
    this.global = this.global.filter((s) => s !== reservation)
  }

  /** Introspection for `/health`. */
  spentInWindow(): { global: bigint; accounts: number } {
    const cutoff = this.now() - this.policy.windowMs
    return { global: this.total(this.prune(this.global, cutoff)), accounts: this.perAccount.size }
  }
}

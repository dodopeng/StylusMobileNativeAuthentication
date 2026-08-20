// Shared fixture values for the Milestone 4 action-template golden vectors.
//
// These exact constants are mirrored in the Android (`ActionsInteropTest.kt`)
// and iOS (`ActionsInteropTests.swift`) suites and in ../../ACTIONS.md. Change
// them here and every golden in all three languages must be regenerated —
// that coupling is deliberate.
import type { Address } from 'viem'

export const ALICE: Address = '0x1111111111111111111111111111111111111111'
export const BOB: Address = '0x2222222222222222222222222222222222222222'
export const TOKEN: Address = '0x3333333333333333333333333333333333333333'
export const TOKEN2: Address = '0x4444444444444444444444444444444444444444'
export const ROUTER: Address = '0x5555555555555555555555555555555555555555'
export const POOL: Address = '0x6666666666666666666666666666666666666666'
export const NFT: Address = '0x7777777777777777777777777777777777777777'
export const WETH: Address = '0x8888888888888888888888888888888888888888'

/** 1 USDC at 6 decimals. */
export const AMOUNT = 1_000_000n
/** 0.99 USDC — a 1% slippage floor on AMOUNT. */
export const AMOUNT_MIN = 990_000n
/** 0.5 ETH in wei. */
export const WEI = 500_000_000_000_000_000n
export const TOKEN_ID = 42n
/** 2030-01-01T00:00:00Z — fixed so goldens stay stable. */
export const DEADLINE = 1_893_456_000n

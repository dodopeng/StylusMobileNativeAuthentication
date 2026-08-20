// Milestone 4 — action templates, TypeScript reference implementation.
//
// This is the third leg of the tri-language interop guarantee: the Kotlin
// (`action/Actions.kt`) and Swift (`Actions.swift`) templates must produce
// byte-identical `(to, value, data)` for the same inputs. This file builds its
// calldata with viem's audited `encodeFunctionData`, so the golden vectors in
// `actions.test.ts` are derived from an independent ABI encoder rather than
// from the SDKs' own hand-rolled ones — the SDKs are checked *against* it.
//
// See ../../ACTIONS.md for the catalog and ../../SPEC.md §3 for the call shape.
import { encodeFunctionData, parseAbi, type Address, type Hex } from 'viem'

/** An outbound call for `P256Account.execute(to, value, data)`. */
export interface Call {
  to: Address
  value: bigint
  data: Hex
}

const call = (to: Address, data: Hex, value = 0n): Call => ({ to, value, data })

// ---------------------------------------------------------------------------
// Native ETH
// ---------------------------------------------------------------------------

/** Plain value transfer — no calldata. The account itself is the sender. */
export const Native = {
  transfer(to: Address, amountWei: bigint): Call {
    return call(to, '0x', amountWei)
  },
}

// ---------------------------------------------------------------------------
// ERC-20
// ---------------------------------------------------------------------------

const ERC20_ABI = parseAbi([
  'function transfer(address to, uint256 amount)',
  'function approve(address spender, uint256 amount)',
  'function transferFrom(address from, address to, uint256 amount)',
])

export const Erc20 = {
  transfer(token: Address, to: Address, amount: bigint): Call {
    return call(token, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transfer', args: [to, amount] }))
  },
  approve(token: Address, spender: Address, amount: bigint): Call {
    return call(token, encodeFunctionData({ abi: ERC20_ABI, functionName: 'approve', args: [spender, amount] }))
  },
  transferFrom(token: Address, from: Address, to: Address, amount: bigint): Call {
    return call(token, encodeFunctionData({ abi: ERC20_ABI, functionName: 'transferFrom', args: [from, to, amount] }))
  },
}

// ---------------------------------------------------------------------------
// ERC-721
// ---------------------------------------------------------------------------

const ERC721_ABI = parseAbi([
  'function safeTransferFrom(address from, address to, uint256 tokenId)',
  'function approve(address to, uint256 tokenId)',
  'function setApprovalForAll(address operator, bool approved)',
])

export const Erc721 = {
  safeTransferFrom(nft: Address, from: Address, to: Address, tokenId: bigint): Call {
    return call(nft, encodeFunctionData({ abi: ERC721_ABI, functionName: 'safeTransferFrom', args: [from, to, tokenId] }))
  },
  approve(nft: Address, to: Address, tokenId: bigint): Call {
    return call(nft, encodeFunctionData({ abi: ERC721_ABI, functionName: 'approve', args: [to, tokenId] }))
  },
  setApprovalForAll(nft: Address, operator: Address, approved: boolean): Call {
    return call(nft, encodeFunctionData({ abi: ERC721_ABI, functionName: 'setApprovalForAll', args: [operator, approved] }))
  },
}

// ---------------------------------------------------------------------------
// WETH9 — the ETH ⇄ ERC-20 bridge every DEX path needs
// ---------------------------------------------------------------------------

const WETH_ABI = parseAbi(['function deposit()', 'function withdraw(uint256 wad)'])

export const Weth = {
  /** Wrap `amountWei` of native ETH. Payable — the value rides on the call. */
  deposit(weth: Address, amountWei: bigint): Call {
    return call(weth, encodeFunctionData({ abi: WETH_ABI, functionName: 'deposit' }), amountWei)
  },
  /** Unwrap `amount` WETH back to native ETH. */
  withdraw(weth: Address, amount: bigint): Call {
    return call(weth, encodeFunctionData({ abi: WETH_ABI, functionName: 'withdraw', args: [amount] }))
  },
}

// ---------------------------------------------------------------------------
// Uniswap V2-style routers (Camelot, SushiSwap, … on Arbitrum)
// ---------------------------------------------------------------------------

const UNIV2_ABI = parseAbi([
  'function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)',
  'function swapExactETHForTokens(uint256 amountOutMin, address[] path, address to, uint256 deadline)',
  'function swapExactTokensForETH(uint256 amountIn, uint256 amountOutMin, address[] path, address to, uint256 deadline)',
])

export const UniswapV2 = {
  swapExactTokensForTokens(
    router: Address, amountIn: bigint, amountOutMin: bigint,
    path: readonly Address[], to: Address, deadline: bigint,
  ): Call {
    return call(router, encodeFunctionData({
      abi: UNIV2_ABI, functionName: 'swapExactTokensForTokens',
      args: [amountIn, amountOutMin, path, to, deadline],
    }))
  },
  /** Payable — `amountInWei` of native ETH is sent with the call. */
  swapExactETHForTokens(
    router: Address, amountInWei: bigint, amountOutMin: bigint,
    path: readonly Address[], to: Address, deadline: bigint,
  ): Call {
    return call(router, encodeFunctionData({
      abi: UNIV2_ABI, functionName: 'swapExactETHForTokens',
      args: [amountOutMin, path, to, deadline],
    }), amountInWei)
  },
  swapExactTokensForETH(
    router: Address, amountIn: bigint, amountOutMin: bigint,
    path: readonly Address[], to: Address, deadline: bigint,
  ): Call {
    return call(router, encodeFunctionData({
      abi: UNIV2_ABI, functionName: 'swapExactTokensForETH',
      args: [amountIn, amountOutMin, path, to, deadline],
    }))
  },
}

// ---------------------------------------------------------------------------
// Aave V3-style lending pools (Aave, Radiant on Arbitrum)
// ---------------------------------------------------------------------------

const AAVE_ABI = parseAbi([
  'function supply(address asset, uint256 amount, address onBehalfOf, uint16 referralCode)',
  'function borrow(address asset, uint256 amount, uint256 interestRateMode, uint16 referralCode, address onBehalfOf)',
  'function repay(address asset, uint256 amount, uint256 interestRateMode, address onBehalfOf)',
  'function withdraw(address asset, uint256 amount, address to)',
])

/**
 * `interestRateMode` per Aave V3.
 *
 * `Stable` (1) is **disabled on Aave V3 on Arbitrum** — deprecated protocol-wide
 * after the 2023 stable-rate exploits — so borrowing or repaying with it reverts
 * on-chain. It is exported only so ported code fails loudly at review rather
 * than silently in production. Use `Variable`.
 *
 * @deprecated Stable — use `InterestRateMode.Variable`.
 */
export const InterestRateMode = { Stable: 1n, Variable: 2n } as const

export const AaveV3 = {
  supply(pool: Address, asset: Address, amount: bigint, onBehalfOf: Address, referralCode = 0): Call {
    return call(pool, encodeFunctionData({
      abi: AAVE_ABI, functionName: 'supply', args: [asset, amount, onBehalfOf, referralCode],
    }))
  },
  borrow(pool: Address, asset: Address, amount: bigint, interestRateMode: bigint, onBehalfOf: Address, referralCode = 0): Call {
    return call(pool, encodeFunctionData({
      abi: AAVE_ABI, functionName: 'borrow', args: [asset, amount, interestRateMode, referralCode, onBehalfOf],
    }))
  },
  repay(pool: Address, asset: Address, amount: bigint, interestRateMode: bigint, onBehalfOf: Address): Call {
    return call(pool, encodeFunctionData({
      abi: AAVE_ABI, functionName: 'repay', args: [asset, amount, interestRateMode, onBehalfOf],
    }))
  },
  withdraw(pool: Address, asset: Address, amount: bigint, to: Address): Call {
    return call(pool, encodeFunctionData({
      abi: AAVE_ABI, functionName: 'withdraw', args: [asset, amount, to],
    }))
  },
}

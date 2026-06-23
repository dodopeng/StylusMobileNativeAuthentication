package xyz.heavenlydev.p256account.action

import xyz.heavenlydev.p256account.abi.Abi
import xyz.heavenlydev.p256account.abi.AbiValue
import xyz.heavenlydev.p256account.account.Call
import java.math.BigInteger

/**
 * Milestone 4 — pre-built templates for the most common Arbitrum DeFi actions.
 * Each returns a [Call] `(to, value, data)` ready to pass to
 * `P256Account.execute(call)`. Selectors are derived from the function
 * signature at build time via keccak, so they cannot silently drift.
 */

/** ERC-20 token operations. */
object Erc20 {
    fun transfer(token: String, to: String, amount: BigInteger): Call = Call(
        to = token,
        data = Abi.encodeWithSelector(
            "transfer(address,uint256)",
            listOf(AbiValue.Address(to), AbiValue.Uint(amount)),
        ),
    )

    fun approve(token: String, spender: String, amount: BigInteger): Call = Call(
        to = token,
        data = Abi.encodeWithSelector(
            "approve(address,uint256)",
            listOf(AbiValue.Address(spender), AbiValue.Uint(amount)),
        ),
    )
}

/** ERC-721 NFT operations. */
object Erc721 {
    fun safeTransferFrom(nft: String, from: String, to: String, tokenId: BigInteger): Call = Call(
        to = nft,
        data = Abi.encodeWithSelector(
            "safeTransferFrom(address,address,uint256)",
            listOf(AbiValue.Address(from), AbiValue.Address(to), AbiValue.Uint(tokenId)),
        ),
    )
}

/** Uniswap V2-style router swaps (Camelot, SushiSwap, etc. on Arbitrum). */
object UniswapV2 {
    fun swapExactTokensForTokens(
        router: String,
        amountIn: BigInteger,
        amountOutMin: BigInteger,
        path: List<String>,
        to: String,
        deadline: BigInteger,
    ): Call = Call(
        to = router,
        data = Abi.encodeWithSelector(
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
            listOf(
                AbiValue.Uint(amountIn),
                AbiValue.Uint(amountOutMin),
                AbiValue.AddressArray(path),
                AbiValue.Address(to),
                AbiValue.Uint(deadline),
            ),
        ),
    )
}

/** Aave V3-style lending pool (Aave, Radiant on Arbitrum). */
object AaveV3 {
    fun supply(
        pool: String,
        asset: String,
        amount: BigInteger,
        onBehalfOf: String,
        referralCode: Int = 0,
    ): Call = Call(
        to = pool,
        data = Abi.encodeWithSelector(
            "supply(address,uint256,address,uint16)",
            listOf(
                AbiValue.Address(asset),
                AbiValue.Uint(amount),
                AbiValue.Address(onBehalfOf),
                AbiValue.Uint(BigInteger.valueOf(referralCode.toLong())),
            ),
        ),
    )

    fun borrow(
        pool: String,
        asset: String,
        amount: BigInteger,
        interestRateMode: BigInteger,
        onBehalfOf: String,
        referralCode: Int = 0,
    ): Call = Call(
        to = pool,
        data = Abi.encodeWithSelector(
            "borrow(address,uint256,uint256,uint16,address)",
            listOf(
                AbiValue.Address(asset),
                AbiValue.Uint(amount),
                AbiValue.Uint(interestRateMode),
                AbiValue.Uint(BigInteger.valueOf(referralCode.toLong())),
                AbiValue.Address(onBehalfOf),
            ),
        ),
    )
}

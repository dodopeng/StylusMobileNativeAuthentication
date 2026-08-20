package xyz.heavenlydev.p256account.action

import xyz.heavenlydev.p256account.abi.Abi
import xyz.heavenlydev.p256account.abi.AbiValue
import xyz.heavenlydev.p256account.account.Call
import java.math.BigInteger

/**
 * Milestone 4 — pre-built templates for the most common Arbitrum actions.
 *
 * Every template is a **pure function**: no network, no state, no signer. Each
 * returns a [Call] `(to, value, data)` ready to hand to
 * `P256Account.execute(call)`, which wraps it in the EIP-712 envelope, signs it
 * with the hardware key, and relays it. Composing actions (approve-then-swap)
 * is just two `execute` calls — no extra machinery.
 *
 * Selectors are derived from the function signature at runtime via keccak, so
 * they cannot silently drift. Every template here is pinned to a golden vector
 * in `sdk/actions.golden.json` — generated independently by foundry's `cast` —
 * and asserted by `ActionsInteropTest`, alongside the iOS and TypeScript suites.
 *
 * See `sdk/ACTIONS.md` for the catalog and usage examples.
 */

/** Native ETH. */
object Native {
    /**
     * Plain value transfer with no calldata. The account itself is the sender,
     * so the recipient sees the account address as `msg.sender`.
     */
    @JvmStatic
    fun transfer(to: String, amountWei: BigInteger): Call =
        Call(to = to, value = amountWei)
}

/** ERC-20 token operations. */
object Erc20 {
    @JvmStatic
    fun transfer(token: String, to: String, amount: BigInteger): Call = Call(
        to = token,
        data = Abi.encodeWithSelector(
            "transfer(address,uint256)",
            listOf(AbiValue.Address(to), AbiValue.Uint(amount)),
        ),
    )

    /**
     * Approve `spender` for `amount`. Note the classic ERC-20 race: to change a
     * non-zero allowance on tokens that enforce it (e.g. USDT), approve `0`
     * first, then the new amount — two separate `execute` calls.
     */
    @JvmStatic
    fun approve(token: String, spender: String, amount: BigInteger): Call = Call(
        to = token,
        data = Abi.encodeWithSelector(
            "approve(address,uint256)",
            listOf(AbiValue.Address(spender), AbiValue.Uint(amount)),
        ),
    )

    /** Requires `from` to have approved this account as spender. */
    @JvmStatic
    fun transferFrom(token: String, from: String, to: String, amount: BigInteger): Call = Call(
        to = token,
        data = Abi.encodeWithSelector(
            "transferFrom(address,address,uint256)",
            listOf(AbiValue.Address(from), AbiValue.Address(to), AbiValue.Uint(amount)),
        ),
    )
}

/** ERC-721 NFT operations. */
object Erc721 {
    /**
     * Safe transfer. The recipient, if a contract, must implement
     * `onERC721Received` or the inner call reverts — which the account records
     * as `Executed.success = false` while still consuming the nonce.
     */
    @JvmStatic
    fun safeTransferFrom(nft: String, from: String, to: String, tokenId: BigInteger): Call = Call(
        to = nft,
        data = Abi.encodeWithSelector(
            "safeTransferFrom(address,address,uint256)",
            listOf(AbiValue.Address(from), AbiValue.Address(to), AbiValue.Uint(tokenId)),
        ),
    )

    /** Approve a single token id — the usual precursor to a marketplace listing. */
    @JvmStatic
    fun approve(nft: String, to: String, tokenId: BigInteger): Call = Call(
        to = nft,
        data = Abi.encodeWithSelector(
            "approve(address,uint256)",
            listOf(AbiValue.Address(to), AbiValue.Uint(tokenId)),
        ),
    )

    /** Approve/revoke an operator for the whole collection. */
    @JvmStatic
    fun setApprovalForAll(nft: String, operator: String, approved: Boolean): Call = Call(
        to = nft,
        data = Abi.encodeWithSelector(
            "setApprovalForAll(address,bool)",
            listOf(AbiValue.Address(operator), AbiValue.Bool(approved)),
        ),
    )
}

/** WETH9 — the ETH ⇄ ERC-20 bridge every DEX path needs. */
object Weth {
    /** Wrap `amountWei` of native ETH. Payable: the value rides on the call. */
    @JvmStatic
    fun deposit(weth: String, amountWei: BigInteger): Call = Call(
        to = weth,
        value = amountWei,
        data = Abi.encodeWithSelector("deposit()", emptyList()),
    )

    /** Unwrap `amount` WETH back into native ETH held by the account. */
    @JvmStatic
    fun withdraw(weth: String, amount: BigInteger): Call = Call(
        to = weth,
        data = Abi.encodeWithSelector("withdraw(uint256)", listOf(AbiValue.Uint(amount))),
    )
}

/**
 * Uniswap V2-style router swaps (Camelot, SushiSwap, … on Arbitrum).
 *
 * All variants need `deadline` as a **unix timestamp in seconds** — take it
 * from chain time, not device time, since a device clock skewed fast will
 * produce swaps the router rejects as expired.
 */
object UniswapV2 {
    /** Token → token. Requires a prior [Erc20.approve] of `router` for `amountIn`. */
    @JvmStatic
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

    /**
     * Native ETH → token. Payable: `amountInWei` is sent with the call rather
     * than passed as an argument, and `path[0]` must be WETH.
     */
    @JvmStatic
    fun swapExactETHForTokens(
        router: String,
        amountInWei: BigInteger,
        amountOutMin: BigInteger,
        path: List<String>,
        to: String,
        deadline: BigInteger,
    ): Call = Call(
        to = router,
        value = amountInWei,
        data = Abi.encodeWithSelector(
            "swapExactETHForTokens(uint256,address[],address,uint256)",
            listOf(
                AbiValue.Uint(amountOutMin),
                AbiValue.AddressArray(path),
                AbiValue.Address(to),
                AbiValue.Uint(deadline),
            ),
        ),
    )

    /** Token → native ETH. `path.last()` must be WETH. */
    @JvmStatic
    fun swapExactTokensForETH(
        router: String,
        amountIn: BigInteger,
        amountOutMin: BigInteger,
        path: List<String>,
        to: String,
        deadline: BigInteger,
    ): Call = Call(
        to = router,
        data = Abi.encodeWithSelector(
            "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
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
    /**
     * `interestRateMode` = 1 (stable).
     *
     * **Stable-rate borrowing is disabled on Aave V3 on Arbitrum** (and was
     * deprecated protocol-wide after the 2023 stable-rate exploits). A `borrow`
     * or `repay` using this value reverts. It is kept only so integrators
     * porting existing code get a deprecation warning rather than a silent
     * on-chain failure; use [INTEREST_RATE_MODE_VARIABLE].
     */
    @Deprecated(
        message = "Aave V3 stable-rate borrowing is disabled on Arbitrum; borrowing with mode 1 reverts.",
        replaceWith = ReplaceWith("INTEREST_RATE_MODE_VARIABLE"),
        level = DeprecationLevel.WARNING,
    )
    @JvmField
    val INTEREST_RATE_MODE_STABLE: BigInteger = BigInteger.ONE

    @JvmField
    val INTEREST_RATE_MODE_VARIABLE: BigInteger = BigInteger.TWO

    /** Supply collateral. Requires a prior [Erc20.approve] of `pool`. */
    @JvmStatic
    @JvmOverloads
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

    /** Borrow against supplied collateral. Note: `referralCode` precedes `onBehalfOf`. */
    @JvmStatic
    @JvmOverloads
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

    /**
     * Repay debt. Requires a prior [Erc20.approve] of `pool`. Pass
     * `amount = 2^256 - 1` to repay the full outstanding balance.
     */
    @JvmStatic
    fun repay(
        pool: String,
        asset: String,
        amount: BigInteger,
        interestRateMode: BigInteger,
        onBehalfOf: String,
    ): Call = Call(
        to = pool,
        data = Abi.encodeWithSelector(
            "repay(address,uint256,uint256,address)",
            listOf(
                AbiValue.Address(asset),
                AbiValue.Uint(amount),
                AbiValue.Uint(interestRateMode),
                AbiValue.Address(onBehalfOf),
            ),
        ),
    )

    /**
     * Withdraw supplied collateral. Pass `amount = 2^256 - 1` to withdraw the
     * full balance.
     */
    @JvmStatic
    fun withdraw(pool: String, asset: String, amount: BigInteger, to: String): Call = Call(
        to = pool,
        data = Abi.encodeWithSelector(
            "withdraw(address,uint256,address)",
            listOf(
                AbiValue.Address(asset),
                AbiValue.Uint(amount),
                AbiValue.Address(to),
            ),
        ),
    )
}

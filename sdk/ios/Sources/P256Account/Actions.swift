import Foundation

/// Milestone 4 — pre-built templates for the most common Arbitrum actions.
///
/// Every template is a **pure function**: no network, no state, no signer. Each
/// returns a `Call (to, value, data)` ready for `client.execute(call)`, which
/// wraps it in the EIP-712 envelope, signs it with the Secure Enclave key, and
/// relays it. Composing actions (approve-then-swap) is just two `execute`
/// calls — no extra machinery.
///
/// Selectors are derived from the signature via keccak, so they cannot drift.
/// Every template is pinned to a golden vector in `sdk/actions.golden.json`,
/// generated independently by foundry's `cast`, and asserted by
/// `ActionsInteropTests` alongside the Android and TypeScript suites.
///
/// See `sdk/ACTIONS.md` for the catalog and usage examples.

/// Native ETH.
public enum Native {
    /// Plain value transfer with no calldata. The account itself is the sender,
    /// so the recipient sees the account address as `msg.sender`.
    public static func transfer(to: String, amountWei: U256) throws -> Call {
        Call(to: to, value: amountWei, data: [])
    }
}

/// ERC-20 token operations.
public enum Erc20 {
    public static func transfer(token: String, to: String, amount: U256) throws -> Call {
        Call(to: token, data: try ABI.encodeWithSelector(
            "transfer(address,uint256)", [.address(to), .uint(amount)]))
    }

    /// Approve `spender` for `amount`. Note the classic ERC-20 race: to change a
    /// non-zero allowance on tokens that enforce it (e.g. USDT), approve `0`
    /// first, then the new amount — two separate `execute` calls.
    public static func approve(token: String, spender: String, amount: U256) throws -> Call {
        Call(to: token, data: try ABI.encodeWithSelector(
            "approve(address,uint256)", [.address(spender), .uint(amount)]))
    }

    /// Requires `from` to have approved this account as spender.
    public static func transferFrom(token: String, from: String, to: String, amount: U256) throws -> Call {
        Call(to: token, data: try ABI.encodeWithSelector(
            "transferFrom(address,address,uint256)", [.address(from), .address(to), .uint(amount)]))
    }
}

/// ERC-721 NFT operations.
public enum Erc721 {
    /// Safe transfer. A contract recipient must implement `onERC721Received` or
    /// the inner call reverts — which the account records as
    /// `Executed.success = false` while still consuming the nonce.
    public static func safeTransferFrom(nft: String, from: String, to: String, tokenId: U256) throws -> Call {
        Call(to: nft, data: try ABI.encodeWithSelector(
            "safeTransferFrom(address,address,uint256)", [.address(from), .address(to), .uint(tokenId)]))
    }

    /// Approve a single token id — the usual precursor to a marketplace listing.
    public static func approve(nft: String, to: String, tokenId: U256) throws -> Call {
        Call(to: nft, data: try ABI.encodeWithSelector(
            "approve(address,uint256)", [.address(to), .uint(tokenId)]))
    }

    /// Approve/revoke an operator for the whole collection.
    public static func setApprovalForAll(nft: String, operator op: String, approved: Bool) throws -> Call {
        Call(to: nft, data: try ABI.encodeWithSelector(
            "setApprovalForAll(address,bool)", [.address(op), .bool(approved)]))
    }
}

/// WETH9 — the ETH ⇄ ERC-20 bridge every DEX path needs.
public enum Weth {
    /// Wrap `amountWei` of native ETH. Payable: the value rides on the call.
    public static func deposit(weth: String, amountWei: U256) throws -> Call {
        Call(to: weth, value: amountWei, data: try ABI.encodeWithSelector("deposit()", []))
    }

    /// Unwrap `amount` WETH back into native ETH held by the account.
    public static func withdraw(weth: String, amount: U256) throws -> Call {
        Call(to: weth, data: try ABI.encodeWithSelector("withdraw(uint256)", [.uint(amount)]))
    }
}

/// Uniswap V2-style router swaps (Camelot, SushiSwap, … on Arbitrum).
///
/// All variants take `deadline` as a **unix timestamp in seconds** — take it
/// from chain time, not device time: a device clock running fast will produce
/// swaps the router rejects as expired.
public enum UniswapV2 {
    /// Token → token. Requires a prior `Erc20.approve` of `router` for `amountIn`.
    public static func swapExactTokensForTokens(
        router: String, amountIn: U256, amountOutMin: U256,
        path: [String], to: String, deadline: U256
    ) throws -> Call {
        Call(to: router, data: try ABI.encodeWithSelector(
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
            [.uint(amountIn), .uint(amountOutMin), .addressArray(path), .address(to), .uint(deadline)]))
    }

    /// Native ETH → token. Payable: `amountInWei` is sent with the call rather
    /// than passed as an argument, and `path[0]` must be WETH.
    public static func swapExactETHForTokens(
        router: String, amountInWei: U256, amountOutMin: U256,
        path: [String], to: String, deadline: U256
    ) throws -> Call {
        Call(to: router, value: amountInWei, data: try ABI.encodeWithSelector(
            "swapExactETHForTokens(uint256,address[],address,uint256)",
            [.uint(amountOutMin), .addressArray(path), .address(to), .uint(deadline)]))
    }

    /// Token → native ETH. `path.last` must be WETH.
    public static func swapExactTokensForETH(
        router: String, amountIn: U256, amountOutMin: U256,
        path: [String], to: String, deadline: U256
    ) throws -> Call {
        Call(to: router, data: try ABI.encodeWithSelector(
            "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
            [.uint(amountIn), .uint(amountOutMin), .addressArray(path), .address(to), .uint(deadline)]))
    }
}

/// Aave V3-style lending pool (Aave, Radiant on Arbitrum).
public enum AaveV3 {
    /// `interestRateMode` per Aave V3.
    public enum InterestRateMode {
        /// Stable rate (mode 1).
        ///
        /// **Disabled on Aave V3 on Arbitrum** — deprecated protocol-wide after
        /// the 2023 stable-rate exploits. Borrowing or repaying with this value
        /// reverts on-chain. Kept so ported code gets a deprecation warning
        /// instead of a silent failure; use `variable`.
        @available(*, deprecated, message: "Aave V3 stable-rate borrowing is disabled on Arbitrum; mode 1 reverts. Use .variable.")
        public static let stable = U256(1)
        /// Variable rate (mode 2) — the only mode usable on Arbitrum.
        public static let variable = U256(2)
    }

    /// Supply collateral. Requires a prior `Erc20.approve` of `pool`.
    public static func supply(
        pool: String, asset: String, amount: U256, onBehalfOf: String, referralCode: UInt16 = 0
    ) throws -> Call {
        Call(to: pool, data: try ABI.encodeWithSelector(
            "supply(address,uint256,address,uint16)",
            [.address(asset), .uint(amount), .address(onBehalfOf), .uint(U256(UInt64(referralCode)))]))
    }

    /// Borrow against supplied collateral. Note: `referralCode` precedes `onBehalfOf`.
    public static func borrow(
        pool: String, asset: String, amount: U256, interestRateMode: U256,
        onBehalfOf: String, referralCode: UInt16 = 0
    ) throws -> Call {
        Call(to: pool, data: try ABI.encodeWithSelector(
            "borrow(address,uint256,uint256,uint16,address)",
            [.address(asset), .uint(amount), .uint(interestRateMode),
             .uint(U256(UInt64(referralCode))), .address(onBehalfOf)]))
    }

    /// Repay debt. Requires a prior `Erc20.approve` of `pool`. Pass
    /// `amount = 2^256 - 1` to repay the full outstanding balance.
    public static func repay(
        pool: String, asset: String, amount: U256, interestRateMode: U256, onBehalfOf: String
    ) throws -> Call {
        Call(to: pool, data: try ABI.encodeWithSelector(
            "repay(address,uint256,uint256,address)",
            [.address(asset), .uint(amount), .uint(interestRateMode), .address(onBehalfOf)]))
    }

    /// Withdraw supplied collateral. Pass `amount = 2^256 - 1` for the full balance.
    public static func withdraw(pool: String, asset: String, amount: U256, to: String) throws -> Call {
        Call(to: pool, data: try ABI.encodeWithSelector(
            "withdraw(address,uint256,address)",
            [.address(asset), .uint(amount), .address(to)]))
    }
}

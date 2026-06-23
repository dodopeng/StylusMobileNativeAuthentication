import Foundation

/// Milestone 4 — pre-built templates for the most common Arbitrum DeFi actions.
/// Each returns a `Call (to, value, data)` ready for `client.execute(call)`.
/// Selectors are derived from the signature via keccak, so they cannot drift.

/// ERC-20 token operations.
public enum Erc20 {
    public static func transfer(token: String, to: String, amount: U256) -> Call {
        Call(to: token, data: ABI.encodeWithSelector(
            "transfer(address,uint256)", [.address(to), .uint(amount)]))
    }
    public static func approve(token: String, spender: String, amount: U256) -> Call {
        Call(to: token, data: ABI.encodeWithSelector(
            "approve(address,uint256)", [.address(spender), .uint(amount)]))
    }
}

/// ERC-721 NFT operations.
public enum Erc721 {
    public static func safeTransferFrom(nft: String, from: String, to: String, tokenId: U256) -> Call {
        Call(to: nft, data: ABI.encodeWithSelector(
            "safeTransferFrom(address,address,uint256)", [.address(from), .address(to), .uint(tokenId)]))
    }
}

/// Uniswap V2-style router swaps (Camelot, SushiSwap, etc. on Arbitrum).
public enum UniswapV2 {
    public static func swapExactTokensForTokens(
        router: String, amountIn: U256, amountOutMin: U256,
        path: [String], to: String, deadline: U256
    ) -> Call {
        Call(to: router, data: ABI.encodeWithSelector(
            "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
            [.uint(amountIn), .uint(amountOutMin), .addressArray(path), .address(to), .uint(deadline)]))
    }
}

/// Aave V3-style lending pool (Aave, Radiant on Arbitrum).
public enum AaveV3 {
    public static func supply(pool: String, asset: String, amount: U256, onBehalfOf: String, referralCode: UInt16 = 0) -> Call {
        Call(to: pool, data: ABI.encodeWithSelector(
            "supply(address,uint256,address,uint16)",
            [.address(asset), .uint(amount), .address(onBehalfOf), .uint(U256(UInt64(referralCode)))]))
    }
    public static func borrow(pool: String, asset: String, amount: U256, interestRateMode: U256, onBehalfOf: String, referralCode: UInt16 = 0) -> Call {
        Call(to: pool, data: ABI.encodeWithSelector(
            "borrow(address,uint256,uint256,uint16,address)",
            [.address(asset), .uint(amount), .uint(interestRateMode), .uint(U256(UInt64(referralCode))), .address(onBehalfOf)]))
    }
}

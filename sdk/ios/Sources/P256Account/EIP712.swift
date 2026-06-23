import Foundation

/// EIP-712 digest construction matching the `P256Account` contract exactly.
/// Typehash constants verified against the contract (sdk/SPEC.md §2).
public enum EIP712 {
    private static let domainTypehash = Hex.toBytes("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f")!
    private static let nameHash = Hex.toBytes("0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d")!
    private static let versionHash = Hex.toBytes("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6")!
    private static let executeTypehash = Hex.toBytes("5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c")!
    private static let rotateTypehash = Hex.toBytes("8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a")!

    public static func domainSeparator(chainId: UInt64, account: String) -> [UInt8] {
        Keccak256.digest(
            domainTypehash + nameHash + versionHash
                + [UInt8](U256(chainId).data) + Hex.addressWord(account)
        )
    }

    public static func executeDigest(
        chainId: UInt64, account: String, to: String,
        value: U256, data: [UInt8], nonce: U256
    ) -> [UInt8] {
        let structHash = Keccak256.digest(
            executeTypehash + Hex.addressWord(to) + [UInt8](value.data)
                + Keccak256.digest(data) + [UInt8](nonce.data)
        )
        return envelope(chainId: chainId, account: account, structHash: structHash)
    }

    public static func rotateDigest(
        chainId: UInt64, account: String, newX: U256, newY: U256, nonce: U256
    ) -> [UInt8] {
        let structHash = Keccak256.digest(
            rotateTypehash + [UInt8](newX.data) + [UInt8](newY.data) + [UInt8](nonce.data)
        )
        return envelope(chainId: chainId, account: account, structHash: structHash)
    }

    private static func envelope(chainId: UInt64, account: String, structHash: [UInt8]) -> [UInt8] {
        let sep = domainSeparator(chainId: chainId, account: account)
        return Keccak256.digest([0x19, 0x01] + sep + structHash)
    }
}

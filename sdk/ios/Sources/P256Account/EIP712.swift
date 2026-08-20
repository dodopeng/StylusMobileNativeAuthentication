import Foundation

/// EIP-712 digest construction matching the `P256Account` contract exactly.
/// Typehash constants verified against the contract (sdk/SPEC.md §2).
public enum EIP712 {
    private static let domainTypehash = Hex.toBytes("8b73c3c69bb8fe3d512ecc4cf759cc79239f7b179b0ffacaa9a75d522b39400f")!
    private static let nameHash = Hex.toBytes("0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d")!
    private static let versionHash = Hex.toBytes("c89efdaa54c0f20c7adf612882df0950f5a951637e0307cdcb4c672f298b8bc6")!
    private static let executeTypehash = Hex.toBytes("5e61180c786157773cdb1e3aff8dd66149b93ea36e48bf5e28f0fcf3895a1c9c")!
    private static let rotateTypehash = Hex.toBytes("8f4436f69e71ad0ae17d640b65201039c4d90422d319e1151cf92d223086b47a")!
    /// keccak256("BatchExecute(Call[] calls,uint256 nonce)Call(address to,uint256 value,bytes data)")
    private static let batchTypehash = Hex.toBytes("e4c4e9c11a8826c10f239085bcd6b1f837ac8891ef69510451fb4e86df1ff4fb")!
    /// keccak256("PersonalSign(bytes32 hash)") — the EIP-1271 challenge wrapper.
    private static let personalSignTypehash = Hex.toBytes("2431bd832cbb131f8882ef79f68ed6ae065cca9270f5bce0f2e4f75a9cd814b7")!
    /// keccak256("Call(address to,uint256 value,bytes data)")
    private static let callTypehash = Hex.toBytes("9085b19ea56248c94d86174b3784cfaaa8673d1041d6441f61ff52752dac8483")!

    public static func domainSeparator(chainId: UInt64, account: String) throws -> [UInt8] {
        let accountWord = try Hex.addressWord(account)
        return Keccak256.digest(
            domainTypehash + nameHash + versionHash + [UInt8](U256(chainId).data) + accountWord
        )
    }

    public static func executeDigest(
        chainId: UInt64, account: String, to: String,
        value: U256, data: [UInt8], nonce: U256
    ) throws -> [UInt8] {
        let toWord = try Hex.addressWord(to)
        let structHash = Keccak256.digest(
            executeTypehash + toWord + [UInt8](value.data)
                + Keccak256.digest(data) + [UInt8](nonce.data)
        )
        return try envelope(chainId: chainId, account: account, structHash: structHash)
    }

    public static func rotateDigest(
        chainId: UInt64, account: String, newX: U256, newY: U256, nonce: U256
    ) throws -> [UInt8] {
        let structHash = Keccak256.digest(
            rotateTypehash + [UInt8](newX.data) + [UInt8](newY.data) + [UInt8](nonce.data)
        )
        return try envelope(chainId: chainId, account: account, structHash: structHash)
    }

    /// Digest for `executeBatch` — one signature authorising an ordered list of
    /// calls under a single nonce.
    ///
    /// Per EIP-712 an array member hashes to `keccak256` of the concatenated
    /// `hashStruct` of each element. Order is part of the hash, so a relayer
    /// cannot reorder a signed batch.
    public static func batchDigest(
        chainId: UInt64, account: String, calls: [Call], nonce: U256
    ) throws -> [UInt8] {
        var concatenated = [UInt8]()
        concatenated.reserveCapacity(calls.count * 32)
        for call in calls {
            let toWord = try Hex.addressWord(call.to)
            let callHash = Keccak256.digest(
                callTypehash + toWord + [UInt8](call.value.data) + Keccak256.digest(call.data)
            )
            concatenated += callHash
        }
        let callsHash = Keccak256.digest(concatenated)
        let structHash = Keccak256.digest(batchTypehash + callsHash + [UInt8](nonce.data))
        return try envelope(chainId: chainId, account: account, structHash: structHash)
    }

    /// Digest for an EIP-1271 challenge: `PersonalSign(bytes32 hash)`.
    ///
    /// The 1271 path MUST NOT sign the raw hash. An `Execute` digest is itself a
    /// 32-byte hash an attacker can compute from public inputs; presented as a
    /// "login challenge" and signed raw, the result is a valid transfer
    /// authorisation. Wrapping puts the two in disjoint typed domains.
    public static func personalSignDigest(
        chainId: UInt64, account: String, hash: [UInt8]
    ) throws -> [UInt8] {
        let structHash = Keccak256.digest(personalSignTypehash + hash)
        return try envelope(chainId: chainId, account: account, structHash: structHash)
    }

    private static func envelope(chainId: UInt64, account: String, structHash: [UInt8]) throws -> [UInt8] {
        let sep = try domainSeparator(chainId: chainId, account: account)
        return Keccak256.digest([0x19, 0x01] + sep + structHash)
    }
}

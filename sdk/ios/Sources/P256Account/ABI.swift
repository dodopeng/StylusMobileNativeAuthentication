import Foundation

/// A single ABI argument.
public enum AbiValue {
    case address(String)
    case uint(U256)
    case dynBytes([UInt8])
    case addressArray([String])
    /// `bool`, encoded as a right-aligned 0/1 word (ERC-721 `setApprovalForAll`).
    case bool(Bool)
    /// `uint256[]` — batch call values.
    case uintArray([U256])
    /// `bytes[]` — batch calldata. Doubly dynamic: an offset table into
    /// individually length-prefixed, right-padded elements.
    case bytesArray([[UInt8]])
}

/// Minimal Solidity ABI encoder (head/tail) + keccak-derived 4-byte selectors —
/// covers `address`, `uint256`, `bytes`, `address[]`, which is everything the
/// account methods and action templates need.
public enum ABI {
    /// `bytes4(keccak256(signature))`, e.g. `selector("transfer(address,uint256)")`.
    public static func selector(_ signature: String) -> [UInt8] {
        Array(Keccak256.digest(Array(signature.utf8))[0..<4])
    }

    public static func encodeWithSelector(_ signature: String, _ args: [AbiValue]) throws -> [UInt8] {
        try encode(selector(signature), args)
    }

    public static func encode(_ selector: [UInt8], _ args: [AbiValue]) throws -> [UInt8] {
        var head = [[UInt8]]()
        var tail = [[UInt8]]()
        let headSize = args.count * 32
        var tailOffset = headSize

        for arg in args {
            switch arg {
            case .address(let a):
                head.append(try Hex.addressWord(a))
            case .uint(let u):
                head.append([UInt8](u.data))
            case .bool(let b):
                head.append([UInt8](U256(b ? 1 : 0).data))
            case .dynBytes(let b):
                head.append([UInt8](U256(UInt64(tailOffset)).data))
                let enc = encodeDynBytes(b)
                tail.append(enc); tailOffset += enc.count
            case .addressArray(let arr):
                head.append([UInt8](U256(UInt64(tailOffset)).data))
                let enc = try encodeAddressArray(arr)
                tail.append(enc); tailOffset += enc.count
            case .uintArray(let arr):
                head.append([UInt8](U256(UInt64(tailOffset)).data))
                let enc = encodeUintArray(arr)
                tail.append(enc); tailOffset += enc.count
            case .bytesArray(let arr):
                head.append([UInt8](U256(UInt64(tailOffset)).data))
                let enc = encodeBytesArray(arr)
                tail.append(enc); tailOffset += enc.count
            }
        }

        var out = selector
        for h in head { out += h }
        for t in tail { out += t }
        return out
    }

    private static func encodeDynBytes(_ value: [UInt8]) -> [UInt8] {
        let padded = ((value.count + 31) / 32) * 32
        var out = [UInt8](U256(UInt64(value.count)).data)
        out += value
        out += [UInt8](repeating: 0, count: padded - value.count)
        return out
    }

    private static func encodeUintArray(_ values: [U256]) -> [UInt8] {
        var out = [UInt8](U256(UInt64(values.count)).data)
        for v in values { out += [UInt8](v.data) }
        return out
    }

    /// `bytes[]`: count, then a word-offset per element (relative to the start
    /// of the offset table), then each element length-prefixed and padded.
    private static func encodeBytesArray(_ values: [[UInt8]]) -> [UInt8] {
        var offsets = [UInt8]()
        var bodies = [UInt8]()
        var cursor = values.count * 32
        for v in values {
            offsets += [UInt8](U256(UInt64(cursor)).data)
            let enc = encodeDynBytes(v)
            bodies += enc
            cursor += enc.count
        }
        return [UInt8](U256(UInt64(values.count)).data) + offsets + bodies
    }

    private static func encodeAddressArray(_ values: [String]) throws -> [UInt8] {
        var out = [UInt8](U256(UInt64(values.count)).data)
        for a in values { out += try Hex.addressWord(a) }
        return out
    }
}

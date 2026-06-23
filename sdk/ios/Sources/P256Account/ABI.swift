import Foundation

/// A single ABI argument.
public enum AbiValue {
    case address(String)
    case uint(U256)
    case dynBytes([UInt8])
    case addressArray([String])
}

/// Minimal Solidity ABI encoder (head/tail) + keccak-derived 4-byte selectors —
/// covers `address`, `uint256`, `bytes`, `address[]`, which is everything the
/// account methods and action templates need.
public enum ABI {
    /// `bytes4(keccak256(signature))`, e.g. `selector("transfer(address,uint256)")`.
    public static func selector(_ signature: String) -> [UInt8] {
        Array(Keccak256.digest(Array(signature.utf8))[0..<4])
    }

    public static func encodeWithSelector(_ signature: String, _ args: [AbiValue]) -> [UInt8] {
        encode(selector(signature), args)
    }

    public static func encode(_ selector: [UInt8], _ args: [AbiValue]) -> [UInt8] {
        var head = [[UInt8]]()
        var tail = [[UInt8]]()
        let headSize = args.count * 32
        var tailOffset = headSize

        for arg in args {
            switch arg {
            case .address(let a):
                head.append(Hex.addressWord(a))
            case .uint(let u):
                head.append([UInt8](u.data))
            case .dynBytes(let b):
                head.append([UInt8](U256(UInt64(tailOffset)).data))
                let enc = encodeDynBytes(b)
                tail.append(enc); tailOffset += enc.count
            case .addressArray(let arr):
                head.append([UInt8](U256(UInt64(tailOffset)).data))
                let enc = encodeAddressArray(arr)
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

    private static func encodeAddressArray(_ values: [String]) -> [UInt8] {
        var out = [UInt8](U256(UInt64(values.count)).data)
        for a in values { out += Hex.addressWord(a) }
        return out
    }
}

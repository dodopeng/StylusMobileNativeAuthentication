import Foundation

/// Fixed-width 256-bit unsigned integer stored big-endian (32 bytes). Swift has
/// no native big integer; this provides exactly the operations the SDK needs:
/// parse from decimal/hex/UInt64, compare, and subtract (for low-S `n - s`).
/// All values on-chain are uint256, so 32 bytes is the natural width.
public struct U256: Comparable, Equatable {
    /// Big-endian, always exactly 32 bytes.
    public private(set) var bytes: [UInt8]

    public init() { bytes = [UInt8](repeating: 0, count: 32) }

    public init(_ value: UInt64) {
        bytes = [UInt8](repeating: 0, count: 32)
        for i in 0..<8 { bytes[31 - i] = UInt8((value >> (8 * UInt64(i))) & 0xff) }
    }

    /// Big-endian bytes, right-aligned into 32 bytes. Accepts ≤ 32 bytes.
    public init?(bigEndian raw: [UInt8]) {
        guard raw.count <= 32 else { return nil }
        var b = [UInt8](repeating: 0, count: 32)
        b.replaceSubrange((32 - raw.count)..<32, with: raw)
        bytes = b
    }

    public init?(hex: String) {
        var s = hex
        if s.hasPrefix("0x") || s.hasPrefix("0X") { s.removeFirst(2) }
        if s.count % 2 == 1 { s = "0" + s }
        guard let data = Hex.toBytes(s) else { return nil }
        self.init(bigEndian: data)
    }

    /// Decimal string → U256 via repeated `*10 + digit` (mod 2^256).
    public init?(decimal: String) {
        var acc = U256()
        for ch in decimal {
            guard let d = ch.wholeNumberValue, d >= 0, d <= 9 else { return nil }
            acc = acc.mulSmall(10).addSmall(UInt32(d))
        }
        self = acc
    }

    public var data: Data { Data(bytes) }

    public static func < (lhs: U256, rhs: U256) -> Bool {
        for i in 0..<32 {
            if lhs.bytes[i] != rhs.bytes[i] { return lhs.bytes[i] < rhs.bytes[i] }
        }
        return false
    }

    /// `self - other`, assuming `self >= other` (true for the `n - s` use).
    public func subtracting(_ other: U256) -> U256 {
        var out = [UInt8](repeating: 0, count: 32)
        var borrow = 0
        for i in stride(from: 31, through: 0, by: -1) {
            var diff = Int(bytes[i]) - Int(other.bytes[i]) - borrow
            if diff < 0 { diff += 256; borrow = 1 } else { borrow = 0 }
            out[i] = UInt8(diff)
        }
        return U256(bigEndian: out)!
    }

    func mulSmall(_ m: UInt32) -> U256 {
        var out = [UInt8](repeating: 0, count: 32)
        var carry: UInt32 = 0
        for i in stride(from: 31, through: 0, by: -1) {
            let v = UInt32(bytes[i]) * m + carry
            out[i] = UInt8(v & 0xff)
            carry = v >> 8
        }
        return U256(bigEndian: out)!
    }

    func addSmall(_ a: UInt32) -> U256 {
        var out = bytes
        var carry = Int(a)
        for i in stride(from: 31, through: 0, by: -1) {
            let v = Int(out[i]) + carry
            out[i] = UInt8(v & 0xff)
            carry = v >> 8
            if carry == 0 { break }
        }
        return U256(bigEndian: out)!
    }
}

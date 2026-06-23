import Foundation

/// Hex <-> bytes helpers and EVM 32-byte word builders.
public enum Hex {
    public static func toBytes(_ hex: String) -> [UInt8]? {
        var s = hex
        if s.hasPrefix("0x") || s.hasPrefix("0X") { s.removeFirst(2) }
        if s.count % 2 == 1 { s = "0" + s }
        var out = [UInt8](); out.reserveCapacity(s.count / 2)
        var idx = s.startIndex
        while idx < s.endIndex {
            let next = s.index(idx, offsetBy: 2)
            guard let b = UInt8(s[idx..<next], radix: 16) else { return nil }
            out.append(b); idx = next
        }
        return out
    }

    public static func toString(_ bytes: [UInt8], prefix: Bool = true) -> String {
        (prefix ? "0x" : "") + bytes.map { String(format: "%02x", $0) }.joined()
    }

    public static func toString(_ data: Data, prefix: Bool = true) -> String {
        toString([UInt8](data), prefix: prefix)
    }

    /// 20-byte address → left-padded 32-byte word.
    public static func addressWord(_ address: String) -> [UInt8] {
        let a = toBytes(address) ?? []
        precondition(a.count == 20, "address must be 20 bytes: \(address)")
        return [UInt8](repeating: 0, count: 12) + a
    }
}

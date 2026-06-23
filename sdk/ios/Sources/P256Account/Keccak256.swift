import Foundation

/// Keccak-256 (Ethereum variant: 0x01 padding, 136-byte rate) in pure Swift —
/// no CryptoKit/CommonCrypto (neither ships Keccak). Faithful port of the
/// reference verified against `cast keccak`. See sdk/SPEC.md.
public enum Keccak256 {
    private static let RHO: [UInt64] = [
        1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14,
        27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
    ]
    private static let PI: [Int] = [
        10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4,
        15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
    ]
    private static let RC: [UInt64] = [
        0x0000000000000001, 0x0000000000008082, 0x800000000000808a, 0x8000000080008000,
        0x000000000000808b, 0x0000000080000001, 0x8000000080008081, 0x8000000000008009,
        0x000000000000008a, 0x0000000000000088, 0x0000000080008009, 0x000000008000000a,
        0x000000008000808b, 0x800000000000008b, 0x8000000000008089, 0x8000000000008003,
        0x8000000000008002, 0x8000000000000080, 0x000000000000800a, 0x800000008000000a,
        0x8000000080008081, 0x8000000000008080, 0x0000000080000001, 0x8000000080008008,
    ]
    private static let rate = 136

    public static func digest(_ input: [UInt8]) -> [UInt8] {
        var state = [UInt64](repeating: 0, count: 25)
        let padLen = rate - (input.count % rate)
        var padded = input + [UInt8](repeating: 0, count: padLen)
        padded[input.count] = 0x01
        padded[padded.count - 1] |= 0x80

        var off = 0
        while off < padded.count {
            for i in 0..<(rate / 8) {
                state[i] ^= leLoad(padded, off + i * 8)
            }
            keccakF(&state)
            off += rate
        }

        var out = [UInt8](repeating: 0, count: 32)
        for i in 0..<4 { leStore(state[i], &out, i * 8) }
        return out
    }

    public static func digest(_ data: Data) -> [UInt8] { digest([UInt8](data)) }

    private static func keccakF(_ a: inout [UInt64]) {
        for round in 0..<24 {
            var c = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { c[x] = a[x] ^ a[x + 5] ^ a[x + 10] ^ a[x + 15] ^ a[x + 20] }
            var d = [UInt64](repeating: 0, count: 5)
            for x in 0..<5 { d[x] = c[(x + 4) % 5] ^ rotl(c[(x + 1) % 5], 1) }
            for x in 0..<5 {
                var y = 0
                while y < 25 { a[x + y] ^= d[x]; y += 5 }
            }
            // rho + pi
            var t = a[1]
            for i in 0..<24 {
                let j = PI[i]
                let tmp = a[j]
                a[j] = rotl(t, RHO[i])
                t = tmp
            }
            // chi
            var y = 0
            while y < 25 {
                let r0 = a[y], r1 = a[y + 1], r2 = a[y + 2], r3 = a[y + 3], r4 = a[y + 4]
                a[y]     = r0 ^ (~r1 & r2)
                a[y + 1] = r1 ^ (~r2 & r3)
                a[y + 2] = r2 ^ (~r3 & r4)
                a[y + 3] = r3 ^ (~r4 & r0)
                a[y + 4] = r4 ^ (~r0 & r1)
                y += 5
            }
            a[0] ^= RC[round]
        }
    }

    private static func rotl(_ x: UInt64, _ n: UInt64) -> UInt64 {
        n == 0 ? x : (x << n) | (x >> (64 - n))
    }

    private static func leLoad(_ b: [UInt8], _ off: Int) -> UInt64 {
        var v: UInt64 = 0
        for i in 0..<8 { v |= UInt64(b[off + i]) << (8 * UInt64(i)) }
        return v
    }

    private static func leStore(_ v: UInt64, _ out: inout [UInt8], _ off: Int) {
        for i in 0..<8 { out[off + i] = UInt8((v >> (8 * UInt64(i))) & 0xff) }
    }
}

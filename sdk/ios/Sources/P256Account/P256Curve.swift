import Foundation
import CryptoKit

/// A P-256 public key as the on-chain owner `(x, y)`.
///
/// The initializer **validates that `(x, y)` is on the P-256 curve** (SPEC.md
/// §6). The contract only range-checks `0 < x,y < p`, so an off-curve point
/// would deploy/rotate successfully and then permanently brick the account —
/// no signature could ever verify. Keys from the Secure Enclave are always
/// on-curve; this guard protects the public surface (`rotateOwner(to:)` and any
/// integrator-supplied coordinates) from the footgun.
public struct PublicKeyP256: Equatable {
    public let x: U256
    public let y: U256

    /// - Throws: `P256Error.badPublicKey` if `(x, y)` is not on the curve.
    public init(x: U256, y: U256) throws {
        guard P256Curve.isOnCurve(x: x, y: y) else {
            throw P256Error.badPublicKey("(x, y) is not on the P-256 curve — would brick the account")
        }
        self.x = x
        self.y = y
    }
}

/// P-256 / secp256r1 parameters plus DER → raw `r‖s` with strict low-S, which
/// the contract mandates (`s ∈ (0, n/2]`). On-curve membership is guaranteed by
/// provenance: every public key here comes from the Secure Enclave, which never
/// emits an off-curve point (see sdk/SPEC.md §6).
public enum P256Curve {
    /// Group order n.
    public static let N = U256(hex: "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551")!
    /// floor(n/2): low-S boundary.
    public static let halfN = U256(hex: "7FFFFFFF800000007FFFFFFFFFFFFFFFDE737D56D38BCF4279DCE5617E3192A8")!

    /// On-curve membership check, delegated to CryptoKit: constructing a
    /// `P256.Signing.PublicKey` from the uncompressed X9.63 encoding succeeds
    /// only for a valid curve point (and rejects the point at infinity / bad
    /// field elements). Avoids hand-rolling 256-bit modular arithmetic.
    public static func isOnCurve(x: U256, y: U256) -> Bool {
        var rep = [UInt8]()
        rep.reserveCapacity(65)
        rep.append(0x04)
        rep.append(contentsOf: x.bytes)
        rep.append(contentsOf: y.bytes)
        return (try? P256.Signing.PublicKey(x963Representation: Data(rep))) != nil
    }

    /// Convert a DER `SEQUENCE { INTEGER r, INTEGER s }` (what
    /// `SecKeyCreateSignature` returns) to canonical 64-byte `r‖s`, low-S applied.
    public static func derToRawLowS(_ der: [UInt8]) throws -> [UInt8] {
        let (rBytes, sBytes) = try decodeDER(der)
        guard let r = U256(bigEndian: rBytes), let sRaw = U256(bigEndian: sBytes) else {
            throw P256Error.badSignature("scalar exceeds 32 bytes")
        }
        guard r > U256(0), r < N else { throw P256Error.badSignature("r out of range") }
        guard sRaw > U256(0), sRaw < N else { throw P256Error.badSignature("s out of range") }
        let s = sRaw > halfN ? N.subtracting(sRaw) : sRaw
        return [UInt8](r.data) + [UInt8](s.data)
    }

    private static func decodeDER(_ der: [UInt8]) throws -> ([UInt8], [UInt8]) {
        var i = 0
        guard i < der.count, der[i] == 0x30 else { throw P256Error.badSignature("no SEQUENCE") }
        i += 1
        i = skipLength(der, i)
        guard i < der.count, der[i] == 0x02 else { throw P256Error.badSignature("no INTEGER r") }
        i += 1
        let rLen = Int(der[i]); i += 1
        let r = stripSign(Array(der[i..<i + rLen])); i += rLen
        guard i < der.count, der[i] == 0x02 else { throw P256Error.badSignature("no INTEGER s") }
        i += 1
        let sLen = Int(der[i]); i += 1
        let s = stripSign(Array(der[i..<i + sLen]))
        return (r, s)
    }

    private static func skipLength(_ der: [UInt8], _ start: Int) -> Int {
        var i = start
        let first = Int(der[i]); i += 1
        if first & 0x80 != 0 { i += first & 0x7f } // long form
        return i
    }

    /// Drop a leading 0x00 sign byte that DER adds when the high bit is set.
    private static func stripSign(_ b: [UInt8]) -> [UInt8] {
        var b = b
        while b.count > 1 && b.first == 0 { b.removeFirst() }
        return b
    }
}

public enum P256Error: Error, Equatable {
    case badSignature(String)
    case badPublicKey(String)
    case keystore(String)
    case rpc(String)
}

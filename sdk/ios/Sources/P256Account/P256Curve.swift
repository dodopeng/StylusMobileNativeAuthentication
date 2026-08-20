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

    /// DER `SEQUENCE { INTEGER r, INTEGER s }` → `(r, s)`.
    ///
    /// Every read is bounds-checked. This parses bytes that arrive from outside
    /// the SDK (a hardware signer, but also anything an integrator passes in),
    /// and in Swift an out-of-range slice is a **fatal trap, not a throw** — it
    /// kills the host app. Nothing in here may index without checking first.
    private static func decodeDER(_ der: [UInt8]) throws -> ([UInt8], [UInt8]) {
        var i = 0

        func byte() throws -> UInt8 {
            guard i < der.count else { throw P256Error.badSignature("truncated DER") }
            defer { i += 1 }
            return der[i]
        }

        func take(_ n: Int) throws -> [UInt8] {
            guard n >= 0, i + n <= der.count else { throw P256Error.badSignature("truncated DER") }
            defer { i += n }
            return Array(der[i..<i + n])
        }

        /// DER length: short form, or long form with a 1–4 byte big-endian count.
        func length() throws -> Int {
            let first = Int(try byte())
            if first & 0x80 == 0 { return first }
            let count = first & 0x7f
            guard count >= 1, count <= 4 else { throw P256Error.badSignature("bad DER length") }
            var value = 0
            for _ in 0..<count { value = (value << 8) | Int(try byte()) }
            guard value >= 0 else { throw P256Error.badSignature("bad DER length") }
            return value
        }

        func integer() throws -> [UInt8] {
            guard try byte() == 0x02 else { throw P256Error.badSignature("expected INTEGER") }
            let len = try length()
            guard len > 0 else { throw P256Error.badSignature("empty INTEGER") }
            return stripSign(try take(len))
        }

        guard try byte() == 0x30 else { throw P256Error.badSignature("no SEQUENCE") }
        let seqLen = try length()
        guard i + seqLen <= der.count else { throw P256Error.badSignature("SEQUENCE overruns buffer") }

        let r = try integer()
        let s = try integer()
        return (r, s)
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
    /// A malformed address reached an encoder. Recoverable — the Swift SDK
    /// used to `precondition` here, which killed the host app.
    case badAddress(String)
    /// A receipt or log payload could not be decoded.
    case badReceipt(String)
    case keystore(String)
    case rpc(String)
}

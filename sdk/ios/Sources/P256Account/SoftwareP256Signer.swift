import Foundation
import Security

/// **Testing / development only — NOT hardware-backed.**
///
/// A drop-in `SignProvider` that behaves exactly like ``SecureEnclaveSigner``
/// but with a *software* P-256 key (no `kSecAttrTokenIDSecureEnclave`, no
/// biometric gate). It uses the **identical** signing algorithm —
/// `.ecdsaSignatureDigestX962SHA256`, which signs the supplied 32-byte digest
/// as-is — so signatures are byte-compatible with what the enclave produces and
/// verify the same way on-chain via RIP-7212.
///
/// Use it to run the SDK on the iOS Simulator (which has no Secure Enclave) and
/// in unit tests. Swap in ``SecureEnclaveSigner`` for production. The key lives
/// only in memory and is never persisted.
public final class SoftwareP256Signer: SignProvider {
    private let privateKey: SecKey

    public init() throws {
        let attrs: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            // No token id → software key; no kSecAttrIsPermanent → in-memory only.
        ]
        var error: Unmanaged<CFError>?
        guard let key = SecKeyCreateRandomKey(attrs as CFDictionary, &error) else {
            throw P256Error.keystore("software key gen: \(Self.cfError(error))")
        }
        self.privateKey = key
    }

    public func publicKey() throws -> PublicKeyP256 {
        guard let pub = SecKeyCopyPublicKey(privateKey) else {
            throw P256Error.keystore("no public key")
        }
        var error: Unmanaged<CFError>?
        guard let ext = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw P256Error.keystore("export public key: \(Self.cfError(error))")
        }
        let bytes = [UInt8](ext) // 0x04 ‖ X(32) ‖ Y(32)
        guard bytes.count == 65, bytes[0] == 0x04,
              let x = U256(bigEndian: Array(bytes[1..<33])),
              let y = U256(bigEndian: Array(bytes[33..<65])) else {
            throw P256Error.keystore("unexpected public key format")
        }
        return try PublicKeyP256(x: x, y: y)
    }

    public func sign(digest: [UInt8]) async throws -> [UInt8] {
        precondition(digest.count == 32, "digest must be 32 bytes")
        var error: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(
            privateKey, .ecdsaSignatureDigestX962SHA256, Data(digest) as CFData, &error
        ) as Data? else {
            throw P256Error.keystore("sign: \(Self.cfError(error))")
        }
        return try P256Curve.derToRawLowS([UInt8](sig))
    }

    private static func cfError(_ e: Unmanaged<CFError>?) -> String {
        guard let e = e?.takeRetainedValue() else { return "unknown" }
        return CFErrorCopyDescription(e) as String? ?? "unknown"
    }
}

import Foundation
import Security
import LocalAuthentication

/// Produces a canonical 64-byte `r‖s` (low-S) signature over a 32-byte digest.
public protocol SignProvider {
    func publicKey() throws -> PublicKeyP256
    func sign(digest: [UInt8]) async throws -> [UInt8]
}

/// Hardware-backed P-256 signer using the **Secure Enclave**. The private key
/// is generated inside the enclave, is non-exportable, and every signature is
/// gated by Face ID / Touch ID through the key's access control. We only read
/// out the public key `(x, y)` — which becomes the on-chain account owner.
///
/// Signing uses `.ecdsaSignatureDigestX962SHA256`, the *digest* variant, which
/// signs the supplied 32-byte digest **as-is** (no second hash). That makes the
/// ECDSA message hash `e` equal to the keccak EIP-712 digest — exactly what the
/// RIP-7212 precompile verifies (see sdk/SPEC.md §2).
public final class SecureEnclaveSigner: SignProvider {
    private let tag: Data
    private let requireBiometric: Bool
    private let invalidateOnEnrollment: Bool

    /// - Parameters:
    ///   - requireBiometric: gate every signature behind Face ID / Touch ID.
    ///   - invalidateOnEnrollment: when `true` the key is bound to the *current*
    ///     biometric set (`.biometryCurrentSet`) and is destroyed if the user
    ///     adds/removes a fingerprint or face. This is more tamper-resistant but
    ///     **permanently bricks a sole-owner account** on re-enrollment (the
    ///     rotation that would save it needs the now-dead key). Defaults to
    ///     `false` (`.biometryAny`) so re-enrollment is survivable; set `true`
    ///     only if you also maintain a recovery/rotation path.
    public init(tag: String, requireBiometric: Bool = true, invalidateOnEnrollment: Bool = false) {
        self.tag = Data(tag.utf8)
        self.requireBiometric = requireBiometric
        self.invalidateOnEnrollment = invalidateOnEnrollment
    }

    public func exists() -> Bool { (try? loadPrivateKey(context: nil)) != nil }

    /// Generate a new Secure Enclave key. Returns the public key to register
    /// on-chain (constructor args, or a rotation target).
    @discardableResult
    public func create() throws -> PublicKeyP256 {
        var acError: Unmanaged<CFError>?
        let biometryFlag: SecAccessControlCreateFlags = invalidateOnEnrollment ? .biometryCurrentSet : .biometryAny
        let flags: SecAccessControlCreateFlags = requireBiometric
            ? [.privateKeyUsage, biometryFlag]
            : [.privateKeyUsage]
        guard let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            flags,
            &acError
        ) else {
            throw P256Error.keystore("access control: \(cfError(acError))")
        }

        let attributes: [String: Any] = [
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecAttrKeySizeInBits as String: 256,
            kSecAttrTokenID as String: kSecAttrTokenIDSecureEnclave,
            kSecPrivateKeyAttrs as String: [
                kSecAttrIsPermanent as String: true,
                kSecAttrApplicationTag as String: tag,
                kSecAttrAccessControl as String: access,
            ],
        ]

        var error: Unmanaged<CFError>?
        guard let privateKey = SecKeyCreateRandomKey(attributes as CFDictionary, &error) else {
            throw P256Error.keystore("key generation: \(cfError(error))")
        }
        return try publicKey(from: privateKey)
    }

    public func publicKey() throws -> PublicKeyP256 {
        try publicKey(from: try loadPrivateKey(context: nil))
    }

    /// Sign a 32-byte EIP-712 [digest]. The Secure Enclave triggers the
    /// system biometric prompt automatically via the key's access control;
    /// pass a configured [context] to customise the prompt copy.
    public func sign(digest: [UInt8], context: LAContext) async throws -> [UInt8] {
        precondition(digest.count == 32, "digest must be 32 bytes")
        let key = try loadPrivateKey(context: context)
        // SecKeyCreateSignature blocks on the biometric UI; hop off the main actor.
        return try await Task.detached { () -> [UInt8] in
            var error: Unmanaged<CFError>?
            guard let sig = SecKeyCreateSignature(
                key,
                .ecdsaSignatureDigestX962SHA256,
                Data(digest) as CFData,
                &error
            ) as Data? else {
                throw P256Error.keystore("sign: \(Self.cfError(error))")
            }
            return try P256Curve.derToRawLowS([UInt8](sig))
        }.value
    }

    /// `SignProvider` conformance with a default `LAContext`.
    public func sign(digest: [UInt8]) async throws -> [UInt8] {
        try await sign(digest: digest, context: LAContext())
    }

    // MARK: - Internals

    private func loadPrivateKey(context: LAContext?) throws -> SecKey {
        var query: [String: Any] = [
            kSecClass as String: kSecClassKey,
            kSecAttrApplicationTag as String: tag,
            kSecAttrKeyType as String: kSecAttrKeyTypeECSECPrimeRandom,
            kSecReturnRef as String: true,
        ]
        if let context { query[kSecUseAuthenticationContext as String] = context }
        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        guard status == errSecSuccess, let item else {
            throw P256Error.keystore("no key for tag (status \(status))")
        }
        return (item as! SecKey)
    }

    private func publicKey(from privateKey: SecKey) throws -> PublicKeyP256 {
        guard let pub = SecKeyCopyPublicKey(privateKey) else {
            throw P256Error.keystore("no public key")
        }
        var error: Unmanaged<CFError>?
        guard let ext = SecKeyCopyExternalRepresentation(pub, &error) as Data? else {
            throw P256Error.keystore("export public key: \(Self.cfError(error))")
        }
        // X9.63 uncompressed point: 0x04 ‖ X(32) ‖ Y(32).
        let bytes = [UInt8](ext)
        guard bytes.count == 65, bytes[0] == 0x04 else {
            throw P256Error.keystore("unexpected public key format")
        }
        guard let x = U256(bigEndian: Array(bytes[1..<33])),
              let y = U256(bigEndian: Array(bytes[33..<65])) else {
            throw P256Error.keystore("bad public key coordinates")
        }
        return try PublicKeyP256(x: x, y: y) // enclave keys are on-curve; validates defensively

    }

    private static func cfError(_ e: Unmanaged<CFError>?) -> String {
        guard let e = e?.takeRetainedValue() else { return "unknown" }
        return CFErrorCopyDescription(e) as String? ?? "unknown"
    }
    private func cfError(_ e: Unmanaged<CFError>?) -> String { Self.cfError(e) }
}

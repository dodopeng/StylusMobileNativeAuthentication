import XCTest
import CryptoKit
@testable import P256Account

/// Pure-Swift interop tests. Golden values match the Android `InteropTest` and
/// were computed with the Keccak reference verified against `cast` and the
/// contract's EIP-712 type strings. A regression here means the SDK would
/// produce signatures the on-chain `execute` rejects.
final class InteropTests: XCTestCase {

    func testKeccakKnownVectors() {
        XCTAssertEqual(
            Hex.toString(Keccak256.digest([UInt8]()), prefix: false),
            "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470")
        XCTAssertEqual(
            Hex.toString(Keccak256.digest(Array("P256Account".utf8)), prefix: false),
            "0b72970e1618929986bf5a7d529c51922dac77346c4b37b8a99a57436d812f1d")
    }

    func testExecuteDigestMatchesContract() {
        let digest = EIP712.executeDigest(
            chainId: 42161,
            account: "0x1111111111111111111111111111111111111111",
            to: "0x2222222222222222222222222222222222222222",
            value: U256(1000),
            data: Array("hello".utf8),
            nonce: U256(0))
        XCTAssertEqual(
            Hex.toString(digest, prefix: false),
            "4e71705df943b3848269d8a661320fca963cd2392a7cc0ee2e9028ff7983f854")
    }

    func testErc20TransferEncoding() {
        let call = Erc20.transfer(
            token: "0x000000000000000000000000000000000000dead",
            to: "0x2222222222222222222222222222222222222222",
            amount: U256(1_000_000))
        XCTAssertEqual(
            Hex.toString(call.data),
            "0xa9059cbb0000000000000000000000002222222222222222222222222222222222222222"
                + "00000000000000000000000000000000000000000000000000000000000f4240")
    }

    func testSelectorsMatchAbi() {
        XCTAssertEqual(Hex.toString(ABI.selector("execute(address,uint256,bytes,uint256,bytes)")), "0xd2c88a7c")
        XCTAssertEqual(Hex.toString(ABI.selector("rotateOwner(uint256,uint256,uint256,bytes)")), "0x82bed5b3")
        XCTAssertEqual(Hex.toString(ABI.selector("nonce()")), "0xaffed0e0")
    }

    func testLowSNormalisation() throws {
        // DER sig with s in the upper half must be flipped to n - s.
        let r = U256(0x1234)
        let highS = P256Curve.N.subtracting(U256(0x5678)) // > n/2
        let der = makeDER(r: r, s: highS)
        let raw = try P256Curve.derToRawLowS(der)
        let s = U256(bigEndian: Array(raw[32..<64]))!
        XCTAssertTrue(s <= P256Curve.halfN)
        XCTAssertEqual(s, U256(0x5678))
    }

    func testU256Decimal() {
        XCTAssertEqual(U256(decimal: "1000000")!, U256(1_000_000))
        XCTAssertEqual(U256(decimal: "0")!, U256(0))
    }

    func testOnCurveValidationGuardsAgainstBricking() throws {
        // A real Secure-Enclave-equivalent key (CryptoKit P-256) is on-curve.
        let key = P256.Signing.PrivateKey()
        let rep = [UInt8](key.publicKey.x963Representation) // 0x04 ‖ X ‖ Y
        let x = U256(bigEndian: Array(rep[1..<33]))!
        let y = U256(bigEndian: Array(rep[33..<65]))!
        XCTAssertTrue(P256Curve.isOnCurve(x: x, y: y))
        XCTAssertNoThrow(try PublicKeyP256(x: x, y: y))

        // Perturbing Y moves off-curve → init must throw (would brick the account).
        let yBad = y.addSmall(1)
        XCTAssertFalse(P256Curve.isOnCurve(x: x, y: yBad))
        XCTAssertThrowsError(try PublicKeyP256(x: x, y: yBad))
    }

    private func makeDER(r: U256, s: U256) -> [UInt8] {
        func intDER(_ v: U256) -> [UInt8] {
            var b = Array(v.bytes.drop(while: { $0 == 0 }))
            if b.isEmpty { b = [0] }
            if b[0] & 0x80 != 0 { b = [0] + b } // DER sign byte
            return [0x02, UInt8(b.count)] + b
        }
        let body = intDER(r) + intDER(s)
        return [0x30, UInt8(body.count)] + body
    }
}

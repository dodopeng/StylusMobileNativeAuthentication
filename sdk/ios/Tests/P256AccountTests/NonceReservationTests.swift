import XCTest
@testable import Conformance

/// Client-side nonce reservation — see `Conformance/NonceReservation.swift`.
///
/// As with the template checks, the logic lives in the `Conformance` target so
/// it stays runnable via `swift run p256account-conformance` on a machine with
/// only the Swift toolchain. This file is the XCTest wrapper.
final class NonceReservationTests: XCTestCase {

    func testReservationCoversEverySigningEntryPoint() async throws {
        let report = try await NonceReservation.run()
        for failure in report.failures {
            XCTFail(failure)
        }
        XCTAssertGreaterThan(report.checked, 0, "no nonce checks ran")
    }
}

import XCTest
@testable import Conformance

/// Milestone 4 — action templates vs. the `cast`-generated golden vectors in
/// `sdk/actions.golden.json`.
///
/// The checks themselves live in the `Conformance` target, NOT here. That target
/// is a plain library compiled by `swift build` and runnable via
/// `swift run p256account-conformance`, so the iOS templates stay verifiable on
/// a machine with only the Swift toolchain — XCTest requires Xcode, and when it
/// is missing this file cannot even be compiled. Keeping the logic out of the
/// test file means "no Xcode" costs you this thin wrapper, not the verification.
final class ActionsInteropTests: XCTestCase {

    func testEveryTemplateMatchesItsCastGeneratedGolden() throws {
        let report = try Conformance.run()
        for failure in report.failures {
            XCTFail(failure.description)
        }
        XCTAssertGreaterThan(report.checked, 0, "golden file contained no templates")
    }
}

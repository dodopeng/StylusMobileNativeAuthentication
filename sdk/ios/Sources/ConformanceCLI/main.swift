import Foundation
import Conformance

// `swift run p256account-conformance [path/to/actions.golden.json]`
//
// Verifies every iOS action template against the cast-generated golden vectors
// without needing Xcode/XCTest. Exits non-zero on any mismatch so CI can gate
// on it.
let explicit = CommandLine.arguments.count > 1 ? CommandLine.arguments[1] : nil

do {
    let report = try Conformance.run(goldenPath: explicit)
    for f in report.failures { print("FAIL  \(f)") }
    if report.passed {
        print("iOS conformance: \(report.checked)/\(report.checked) action templates match the cast goldens")
    } else {
        print("\niOS conformance: \(report.failures.count) failure(s) across \(report.checked) templates")
        exit(1)
    }

    // Client-side nonce reservation. Not a golden-vector check — it drives the
    // account against a fake relay and a pinned chain nonce.
    let nonce = try await NonceReservation.run()
    for f in nonce.failures { print("FAIL  \(f)") }
    if nonce.passed {
        print("iOS nonce reservation: \(nonce.checked)/\(nonce.checked) checks pass")
        exit(0)
    }
    print("\niOS nonce reservation: \(nonce.failures.count) failure(s) across \(nonce.checked) checks")
    exit(1)
} catch {
    print("iOS conformance: could not run — \(error)")
    exit(2)
}

// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "P256Account",
    platforms: [
        .iOS(.v16),   // Secure Enclave P-256 + async/await; matches the M3 KPI (iOS 16+)
        .macOS(.v12), // so the interop checks run on a Mac host (CI / `swift test`)
    ],
    products: [
        .library(name: "P256Account", targets: ["P256Account"]),
        // Runs the golden-vector conformance checks WITHOUT XCTest, so the SDK
        // can be verified on a machine with only the Swift toolchain (no Xcode).
        // See Sources/Conformance/Conformance.swift.
        .executable(name: "p256account-conformance", targets: ["ConformanceCLI"]),
    ],
    targets: [
        .target(name: "P256Account"),
        // Plain library: compiled by `swift build`, so the check logic is
        // type-checked even where XCTest is unavailable.
        .target(name: "Conformance", dependencies: ["P256Account"]),
        .executableTarget(name: "ConformanceCLI", dependencies: ["Conformance"]),
        // Thin XCTest wrapper over the same logic — needs Xcode.
        .testTarget(name: "P256AccountTests", dependencies: ["P256Account", "Conformance"]),
    ]
)

// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "P256Account",
    platforms: [
        .iOS(.v16),   // Secure Enclave P-256 + async/await; matches the M3 KPI (iOS 16+)
        .macOS(.v12), // so the interop tests run on a Mac host (CI / `swift test`)
    ],
    products: [
        .library(name: "P256Account", targets: ["P256Account"]),
    ],
    targets: [
        .target(name: "P256Account"),
        .testTarget(name: "P256AccountTests", dependencies: ["P256Account"]),
    ]
)

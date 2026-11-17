// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "Herald",
    platforms: [.macOS(.v13)],
    targets: [.executableTarget(name: "Herald", path: "Sources/Herald")]
)

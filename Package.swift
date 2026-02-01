// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "TorClient",
    platforms: [
        .iOS(.v18)
    ],
    products: [
        // Main library product exposing the Swift wrapper
        // Product name matches target name for consistent import statements
        .library(
            name: "TorClientWrapper",
            targets: ["TorClientWrapper"]
        )
    ],
    targets: [
        // Binary target containing libTorClient.a with C API (module name: TorClientC from modulemap)
        // This library bundles: Tor + OpenSSL + libevent + zlib (all statically linked)
        .binaryTarget(
            name: "TorClientC",
            path: "TorClientC.xcframework"
        ),
        // Swift wrapper providing TorService, TorConfiguration, etc.
        .target(
            name: "TorClientWrapper",
            dependencies: ["TorClientC"],
            path: "Sources/TorClientWrapper",
            linkerSettings: [
                // Force load ensures all object files from the static library are included
                // Without this, linker strips "unused" internal symbols (OpenSSL, libevent internals)
                // that are called by Tor but not directly referenced from Swift
                .unsafeFlags(["-ObjC", "-all_load"])
            ]
        )
    ]
)

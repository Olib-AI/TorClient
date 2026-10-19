// swift-tools-version: 6.4
import PackageDescription

// Swift 7 upcoming features adopted early; compile-time only (no runtime change).
let upcomingFeatures: [SwiftSetting] = [
    .enableUpcomingFeature("MemberImportVisibility"),
    .enableUpcomingFeature("ImmutableWeakCaptures"),
]

let package = Package(
    name: "TorClient",
    platforms: [
        .iOS(.v18)
    ],
    products: [
        // Main library product exposing the Swift wrapper. Product name matches
        // the target name for consistent import statements.
        //
        // Dynamic on purpose: Tor, OpenSSL, libevent and zlib keep process-wide
        // global state (subsystem tables, OpenSSL's library context, the siphash
        // key, thread pools). They must exist exactly once per process, so they
        // live in this one image and every client (app, frameworks, test bundles)
        // binds to it. A static product would be copied into every image that
        // links it, each copy with its own globals.
        .library(
            name: "TorClientWrapper",
            type: .dynamic,
            targets: ["TorClientWrapper"]
        )
    ],
    targets: [
        // Binary target containing libTorClient.a with C API (module name: TorClientC from modulemap)
        // This library bundles: Tor + OpenSSL + libevent + zlib (all statically linked)
        //
        // No linker flags here: package linker settings propagate to every
        // target that links the product, and the former `-all_load` made each
        // of those targets force-load the whole archive (17 copies of Tor in
        // the app). The archive needs no force-loading: every object Tor uses
        // is reached by symbol reference from the tor_api.h entry points, and
        // the only static initializers (OpenSSL's libcrypto-lib-armcap.o and
        // libcrypto-lib-init.o) sit in objects that are referenced anyway.
        // It contains no Objective-C, so `-ObjC` had nothing to load either.
        .binaryTarget(
            name: "TorClientC",
            path: "TorClientC.xcframework"
        ),
        // Swift wrapper providing TorService, TorConfiguration, etc.
        .target(
            name: "TorClientWrapper",
            dependencies: ["TorClientC"],
            path: "Sources/TorClientWrapper",
            swiftSettings: upcomingFeatures
        )
    ]
)

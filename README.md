# TorClient

**A lightweight embedded Tor client for iOS/macOS by [Olib AI](https://www.olib.ai)**

Used in [StealthOS](https://www.stealthos.app) - The privacy-focused operating environment.

---

This package provides a native Swift wrapper around the Tor C library, enabling anonymous network access directly within your app without external dependencies.

## Why We Built Our Own Tor Client

Because we can. We wanted a clean, slim Tor client that we fully control — from source compilation to the final binary. No bloated wrappers, no outdated dependencies dragged in from abandoned repos, no guessing what's inside the black box. Just Tor compiled from official sources, statically linked, with a modern Swift API on top. Full transparency, full control, minimal footprint.

## Features

- **Embedded Tor Daemon**: Full Tor implementation compiled as a static library - no external processes or dependencies
- **Client-Only Mode**: Optimized build with relay functionality disabled for smaller footprint
- **Auto Port Selection**: Automatic SOCKS5 port assignment to avoid conflicts with other Tor instances
- **Connection Status Monitoring**: Real-time bootstrap progress tracking via stdout parsing
- **Swift Concurrency**: Modern async/await API with strict Swift 6 concurrency compliance
- **Actor Isolation**: Thread-safe `TorService` actor ensures data race prevention
- **Circuit Management**: Extended circuit lifetime settings for stable long-running connections
- **New Circuit on Demand**: Request new Tor identity (SIGNAL NEWNYM) via in-process control socket
- **Real Disconnect / Reconnect**: `disconnect()` / `reconnect()` toggle `DisableNetwork` over the control socket - all circuits, connections and the SOCKS listener close; reconnect re-bootstraps in seconds, any number of times
- **In-Process Restart**: `stop()` lets `tor_run_main()` return and clean up; `start()` can launch it again in the same process (with the patches in `Scripts/patches/`)
- **Validated Control Protocol**: replies are parsed per control-spec (status codes, multi-line, data blocks, size limits), commands are built from validated input only (no CR/LF injection)

## Requirements

- iOS 18.0+
- Swift 6.0+
- Xcode 16+

### Build Requirements (only if building from source)

To build the XCFramework from source, you also need:

- macOS with Apple Silicon (arm64) or Intel Mac
- Xcode Command Line Tools (`xcode-select --install`)
- [Homebrew](https://brew.sh) packages:

```bash
brew install autoconf automake libtool pkg-config gnupg
```

## Building from Source

The `TorClientC.xcframework` is included pre-built for convenience. If you want to build it yourself (to verify, modify, or update versions):

```bash
# From the TorClient package directory:
./Scripts/build-xcframework.sh

# Or clean and rebuild:
./Scripts/build-xcframework.sh --clean

# Only download + verify the pinned tarballs:
./Scripts/build-xcframework.sh --sources-only
```

The build script will:

1. Download source tarballs from official mirrors (zlib, OpenSSL, libevent, Tor) and **verify them before use** (cached copies included): the SHA-256 pinned in `Scripts/supply-chain/sources.lock`, plus the upstream OpenPGP signature checked against the pinned keyrings in `Scripts/supply-chain/keys/` (Tor's signed `.sha256sum`, OpenSSL, zlib and libevent detached signatures in `Scripts/supply-chain/signatures/`). Any mismatch aborts the build; nothing is re-downloaded over a bad file
2. Apply the local Tor patches in `Scripts/patches/` (each has a header explaining the bug; they are upstream candidates). A cached Tor build is redone automatically when the patch set changes
3. Cross-compile each library for iOS device **arm64 and arm64e** (pointer authentication) and simulator (arm64 + x86_64 stub), with hardening on every C file: `-ftrivial-auto-var-init=zero`, typed allocator support (`-ftyped-memory-operations`) and Apple's security warning set. Warning counts land in `.build-tor/logs/warnings-summary.txt`
4. Combine all libraries into a single `libTorClient.a` per platform; the device library is one fat arm64 + arm64e archive (xcframework identifier `ios-arm64_arm64e`)
5. Package everything into `TorClientC.xcframework` and record every file's SHA-256 in `TorClientC.xcframework.sha256`

The build is **reproducible**: two builds from different directories produce
byte-identical xcframeworks (fixed `SOURCE_DATE_EPOCH`, `ZERO_AR_DATE`,
`-ffile-prefix-map`, neutral install prefixes, so no build-machine path ends up in the
binary). To check, build twice and compare the manifests:

```bash
TORCLIENT_BUILD_DIR=/tmp/tc-a TORCLIENT_OUTPUT_DIR=/tmp/tc-a ./Scripts/build-xcframework.sh
diff <(grep -v '^#' TorClientC.xcframework.sha256) <(grep -v '^#' /tmp/tc-a/TorClientC.xcframework.sha256)
```

StealthOS's `Scripts/verify-release.sh` checks the shipped xcframework against
`TorClientC.xcframework.sha256` before every release.

`./Scripts/test-supply-chain.sh` proves the checks fail closed: tampered cached
tarballs, unpinned files, edited pins, corrupted signatures, the wrong key, a forged
Tor checksum file, and an end-to-end build run on a tampered tarball must all abort.

**Bumping a version:** download the new tarball and its signature, verify the
signature by hand against the fingerprints the project publishes, then update the
line in `sources.lock` and the file in `signatures/` (see the comments in
`sources.lock`). Never copy a hash from a tarball you have not verified.

| Patch | Fixes |
|-------|-------|
| `0001-workqueue-per-pool-worker-accounting.patch` | Function-level statics in `worker_thread_main()` survive `threadpool_free()`; the second `tor_run_main()` in a process then frees its CPU-worker pool while workers still run and aborts with "Error unlocking a mutex" |
| `0002-tor-api-owning-controller-socket-double-close.patch` | `tor_main_configuration_free()` closed the owning-controller descriptor that `tor_run_main()` had already closed, which can close an unrelated descriptor in the embedding app |
| `0003-dispatch-naming-reset-on-shutdown.patch` | The pubsub name maps (message/subsystem/channel/type name to ID) survive `tor_run_main()`, but their hashes use a siphash key that every run re-randomizes; after a few in-process restarts one name resolves to two IDs and `pubsub_install()` aborts |

| Library | Version | Source |
|---------|---------|--------|
| Tor | 0.4.9.14 | https://dist.torproject.org/ |
| OpenSSL | 4.0.3 | https://github.com/openssl/openssl |
| libevent | 2.1.13-stable | https://github.com/libevent/libevent |
| zlib | 1.3.2 | https://zlib.net/ |

**Build time**: ~10-30 minutes depending on CPU. OpenSSL is the longest step.

Downloaded source tarballs are cached in `.build-tor/` and reused on subsequent runs.

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/Olib-AI/TorClient.git", from: "1.2.8")
]
```

Then add the dependency to your target:

```swift
targets: [
    .target(
        name: "YourApp",
        dependencies: [
            .product(name: "TorClientWrapper", package: "TorClient")
        ]
    )
]
```

### Local Package (XcodeGen)

If using XcodeGen, add to your `project.yml`:

```yaml
packages:
  TorClient:
    path: LocalPackages/TorClient

targets:
  YourApp:
    dependencies:
      - package: TorClient
        product: TorClientWrapper
```

Then regenerate: `xcodegen generate`

## Quick Start

```swift
import TorClientWrapper

// Get the shared TorService instance
let torService = TorService.shared

// Configure Tor
let dataDirectory = FileManager.default.temporaryDirectory.appendingPathComponent("tor")
let config = TorConfiguration(
    dataDirectory: dataDirectory,
    // App-private Unix socket: no other app on the device can reach it (a TCP port on
    // 127.0.0.1 is reachable by every app). Must fit sun_path (103 bytes).
    socksPort: .unix(path: TorSocksSocketLocation.plan()!),
    clientOnly: true,     // No relay functionality
    avoidDiskWrites: true // Minimize disk I/O
)

do {
    // Configure and start Tor
    try await torService.configure(config)
    try await torService.start()
    
    // Wait for Tor to bootstrap (connect to the network)
    try await torService.waitForBootstrap(timeout: 120)
    
    // Get the SOCKS5 proxy URL
    if let proxyURL = await torService.socksProxyURL {
        print("Tor SOCKS5 proxy: \(proxyURL)")
        // Use with URLSession or other networking
    }
    
    // The listener Tor actually opened (re-read after every reconnect)
    let listener = await torService.actualSocksListener
    print("Tor SOCKS listener: \(String(describing: listener))")
    
} catch {
    print("Tor error: \(error)")
}
```

### Using with URLSession

URLSession cannot address a Unix-socket SOCKS proxy; with `.unix` route URLSession
traffic through an in-app HTTP CONNECT proxy that speaks SOCKS5 to the socket (as
StealthOS's LocalProxyServer does). With `.auto` / `.fixed` (TCP):

```swift
let port = await torService.actualSocksPort

let sessionConfig = URLSessionConfiguration.ephemeral
sessionConfig.connectionProxyDictionary = [
    kCFProxyTypeKey as String: kCFProxyTypeSOCKS,
    kCFStreamPropertySOCKSProxyHost as String: "127.0.0.1",
    kCFStreamPropertySOCKSProxyPort as String: port
]

let session = URLSession(configuration: sessionConfig)
let (data, response) = try await session.data(from: url)
```

## Configuration Options

### TorConfiguration

| Property | Type | Default | Description |
|----------|------|---------|-------------|
| `dataDirectory` | `URL` | Required | Directory for Tor state files (keys, consensus, etc.) |
| `socksPortMode` | `PortMode` | `.auto` | SOCKS5 listener: `.auto`, `.fixed(port)` or `.unix(path:)` (app-private socket, directory created 0700, not group/world writable) |
| `bridges` | `[String]` | `[]` | Bridge relay addresses for censored networks |
| `clientOnly` | `Bool` | `true` | Disable relay/exit functionality |
| `avoidDiskWrites` | `Bool` | `true` | Minimize disk I/O for privacy |
| `geoIPFile` | `URL?` | `nil` | Path to GeoIP database file |
| `geoIP6File` | `URL?` | `nil` | Path to GeoIPv6 database file |

### PortMode

```swift
public enum PortMode: Sendable, Equatable {
    case auto              // Let Tor select an available port
    case fixed(UInt16)     // Use a specific port number
}
```

**Recommendation**: Use `.auto` to avoid port conflicts with other Tor instances or services.

## API Reference

### TorService

`TorService` is the main interface for controlling the Tor daemon. It is implemented as a Swift actor for thread safety.

#### Properties

```swift
/// Shared singleton instance
public static let shared: TorService

/// Whether Tor daemon is currently running
public var isRunning: Bool { get async }

/// Whether Tor is ready to accept connections (running and bootstrapped)
public var isReady: Bool { get async }

/// The actual SOCKS port Tor bound to (0 if not yet discovered, or a Unix socket)
public var actualSocksPort: UInt16 { get async }

/// The SOCKS listener Tor opened, TCP or Unix socket (nil while disconnected)
public var actualSocksListener: TorSocksListener? { get async }

/// Current Tor status
public var status: TorStatus { get async }

/// SOCKS5 proxy URL (nil if not running)
public var socksProxyURL: URL? { get async }
```

#### Methods

```swift
/// Configure Tor with the specified settings
/// Must be called before start(). Cannot reconfigure while running.
public func configure(_ config: TorConfiguration) async throws

/// Start the Tor daemon
/// If already running, returns immediately without error.
public func start() async throws

/// Stop the Tor daemon: SIGNAL HALT, then wait for tor_run_main() to return
/// (tor_cleanup() runs). start() may launch Tor again afterwards when
/// TorService.supportsInProcessRestart is true. Throws .shutdownFailed if
/// Tor does not exit in time (start() then refuses a second instance).
public func stop() async throws

/// Wait for Tor to fully bootstrap
/// - Parameter timeout: Maximum time to wait (default: 120 seconds)
public func waitForBootstrap(timeout: TimeInterval = 120) async throws

/// Real network disconnect without stopping the daemon: SETCONF DisableNetwork=1,
/// verified with GETCONF/GETINFO. Closes all circuits, connections and the SOCKS
/// listener. Throws TorControlError on any failure - never assumes success.
public func disconnect(timeout: Duration = .seconds(15)) async throws

/// SETCONF DisableNetwork=0, then waits for an established circuit and an open
/// SOCKS listener. The SOCKS port usually changes (SocksPort auto): re-read
/// actualSocksPort. Time suspended in the background does not use up `timeout`.
public func reconnect(timeout: Duration = .seconds(120),
                      onProgress: (@Sendable (Int) -> Void)? = nil) async throws

/// .stopped / .enabled / .disabled (soft-disconnected)
public var networkState: TorNetworkState { get async }

/// One GETINFO round trip: circuit-established, network-liveness,
/// bootstrap-phase, SOCKS listeners.
public func networkSnapshot(timeout: Duration = .seconds(10)) async throws -> TorNetworkSnapshot

/// Send any validated command (TorControlCommand.getInfo / getConf / setConf / signal).
public func sendControlCommand(_ command: TorControlCommand,
                               timeout: Duration = .seconds(10)) async throws -> TorControlReply

/// Request a new Tor circuit (new identity / exit node)
/// Sends SIGNAL NEWNYM via the in-process control socket.
/// Throws TorControlError.networkDisabled while disconnected.
public func sendNewnym() async throws

/// Whether the control socket is available for sending commands
public var hasControlSocket: Bool { get }

/// Get current bootstrap progress (0-100)
public func getBootstrapProgress() async -> Int?

/// Stream of status updates
public var statusStream: AsyncStream<TorStatus> { get async }
```

### TorStatus

```swift
public enum TorStatus: Sendable, Equatable {
    case idle                           // Not started
    case starting                       // Starting up
    case connecting                     // Connecting to network
    case bootstrapping(progress: Int)   // Bootstrap in progress (0-100%)
    case ready                          // Fully connected and ready
    case stopping                       // Shutting down
    case error(TorError)                // Error occurred
}
```

### TorError

```swift
public enum TorError: Error, Sendable {
    case configurationFailed(String)  // Configuration issue
    case startFailed(String)          // Failed to start daemon
    case alreadyRunning               // Tor already running (configure error)
    case notRunning                   // Tor not running (operation error)
    case bootstrapTimeout             // Bootstrap took too long
    case connectionFailed             // Network connection failed
    case shutdownFailed               // Failed to shut down cleanly
    case controlSocketFailed          // Control socket error
}
```

## Important Limitations

### One Instance at a Time; Restart Needs the Patches

Only one `tor_run_main()` may run at a time: Tor's globals are per process. The old "assertion in `hs_circuitmap_init()` on restart" was a second instance started while the first had never returned. `stop()` now waits for `tor_run_main()` to return; with `Scripts/patches/0001` a following `start()` works (exercised 10x per process in the StealthOS test suite, including under AddressSanitizer). Without the patch the second shutdown aborts.

**Best Practice**: for a user-facing "disconnect", prefer `disconnect()` / `reconnect()`: no thread restart, cached consensus, reconnects in seconds.

### In-Process Control Socket (No TCP Control Port)

This implementation uses `tor_main_configuration_setup_control_socket()` to obtain a pre-authenticated in-process control socket instead of a TCP control port. Status monitoring is done by parsing Tor's stdout. This approach:
- Avoids TCP port conflicts
- Reduces attack surface: an anonymous `AF_UNIX` socketpair has no filesystem path and no TCP port, so no other app or process can connect to it; it needs no cookie or password because only this process holds the descriptor
- Works reliably on iOS where socket permissions may be restricted
- Enables `SIGNAL NEWNYM`, `DisableNetwork` and `GETINFO` at runtime
- Is the *owning* controller connection: closing it makes Tor exit
- Is protected against `SIGPIPE` (`SO_NOSIGPIPE`) and every wait on it is bounded by a timeout

### Thread Safety

`TorService` is an actor. All property access and method calls must use `await` from non-isolated contexts:

```swift
// Correct
let port = await TorService.shared.actualSocksPort

// Incorrect - will not compile
let port = TorService.shared.actualSocksPort
```

## Architecture

### Package Structure

```
TorClient/
├── Package.swift                  # Swift Package manifest
├── Scripts/
│   ├── build-xcframework.sh      # Build Tor + deps from source (hardened, reproducible)
│   ├── test-supply-chain.sh      # Proves tarball verification fails closed
│   ├── openssl/ios64e.conf       # OpenSSL target for the arm64e slice
│   ├── supply-chain/             # sources.lock (pinned SHA-256), keys/, signatures/, verify.sh
│   └── patches/                   # Local Tor patches (upstream candidates)
├── Sources/
│   └── TorClientWrapper/
│       ├── TorService.swift       # Swift actor wrapping Tor C API
│       ├── TorControlProtocol.swift # Pure reply parser, command builder, value helpers
│       └── TorControlChannel.swift  # Bounded, serialized control-socket I/O
├── TorClientC.xcframework.sha256  # SHA-256 of every xcframework file (reproducible build)
└── TorClientC.xcframework/        # Pre-built static libraries
    ├── ios-arm64_arm64e/          # iOS Device: one fat archive, arm64 + arm64e
    │   ├── Headers/
    │   │   ├── tor_api.h          # Tor C API
    │   │   ├── module.modulemap
    │   │   └── openssl/           # OpenSSL headers
    │   └── libTorClient.a         # Combined static library (~13MB per architecture)
    └── ios-arm64_x86_64-simulator/
        └── ...                    # Simulator libraries (arm64 real + x86_64 stub)
```

An app that links TorClient for a device builds both architectures when it enables
pointer authentication (`ENABLE_POINTER_AUTHENTICATION`); the linker takes the
matching half of the fat archive. Apps that build arm64 only are unaffected.

### Library Contents

`libTorClient.a` is a combined static library containing:
- **Tor 0.4.9.14**: The Onion Router (client-only build)
- **OpenSSL 4.0.3**: Cryptographic library
- **libevent 2.1.13**: Event notification library
- **zlib 1.3.2**: Compression library

All dependencies are statically linked into `libTorClient.a`, which is linked into
exactly one image: the `TorClientWrapper` product is a **dynamic** library, so the app
embeds `TorClientWrapper.framework` once and every framework, extension or test bundle
that uses Tor binds to that single copy. Tor and OpenSSL keep process-wide globals;
they must not be copied into several images. For the same reason the package declares
no linker flags (they would propagate to every client) and the module map carries no
`link` directive (it would ask every importing module's linker for the archive).

### How It Works

1. **Initialization**: `TorService.configure()` creates the data directory and stores configuration
2. **Startup**: `TorService.start()` launches `tor_run_main()` in a background thread
3. **Port Discovery**: stdout is parsed to find the auto-assigned SOCKS5 port
4. **Bootstrap Monitoring**: stdout is parsed for bootstrap progress (0-100%)
5. **Control Socket**: `tor_main_configuration_setup_control_socket()` provides a pre-authenticated control connection for runtime commands
6. **SOCKS5 Proxy**: Applications route traffic through `127.0.0.1:<port>`
7. **New Circuit**: `sendNewnym()` writes `SIGNAL NEWNYM` to the control socket, forcing Tor to build new circuits with a different exit node
8. **Disconnect / Reconnect**: `disconnect()` / `reconnect()` toggle `DisableNetwork`; the result is verified via `GETCONF` / `GETINFO` (note: `network-liveness` only flips to "down" after circuit timeouts, so `status/circuit-established` and `net/listeners/socks` are what prove a disconnect)
9. **Stop / Restart**: `stop()` sends `SIGNAL HALT` and waits for `tor_run_main()` to return; `start()` can launch a new instance afterwards

### Tor Configuration Flags

The Swift wrapper sets these Tor options automatically:

```
--DataDirectory /path/to/tor        # State storage
--SocksPort unix:/path | auto       # Unix socket (StealthOS) or auto port selection
--ControlPort 0                     # Disable TCP control port (uses in-process socket instead)
--ClientOnly 1                      # No relay functionality
--DirCache 0                        # Disable directory cache
--HiddenServiceStatistics 0         # Disable HS stats
--AvoidDiskWrites 1                 # Minimize disk I/O
--Log notice stdout                 # Log to stdout for parsing
--MaxCircuitDirtiness 1800          # 30 min circuit lifetime
--NewCircuitPeriod 60               # Less aggressive circuit building
--CircuitBuildTimeout 90            # Patient circuit building
--SocksTimeout 120                  # Generous SOCKS timeout
```

## Troubleshooting

### "Tor exited with code X"

Check the console logs for Tor's error messages. Common causes:
- Invalid data directory permissions
- Missing GeoIP files (optional, but Tor may warn)
- Network connectivity issues

### Bootstrap Timeout

Tor may take 1-2 minutes to bootstrap on slow networks. Consider:
- Increasing the timeout: `try await tor.waitForBootstrap(timeout: 180)`
- Using bridges if Tor is blocked: `TorConfiguration(bridges: [...])`

### Port Already in Use

Use `.auto` port mode (default) to let Tor find an available port.

### Restart After Stop Aborts ("Error unlocking a mutex")

The XCFramework was built without `Scripts/patches/0001-workqueue-per-pool-worker-accounting.patch`. Rebuild with `./Scripts/build-xcframework.sh` (it applies the patches), or use `disconnect()` / `reconnect()` instead of `stop()` / `start()`.

### `start()` Throws "Previous Tor instance is still shutting down"

`stop()` timed out (it threw `.shutdownFailed`). A second `tor_run_main()` must not run alongside the first, so `start()` refuses until the old one has returned.

## License

MIT License

Copyright (c) 2025 Olib AI

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.

## Credits

- [Olib AI](https://www.olib.ai) - Package maintainer and [StealthOS](https://www.stealthos.app) developer
- [The Tor Project](https://www.torproject.org/) - Tor software and anonymity network
- [OpenSSL Project](https://www.openssl.org/) - Cryptographic library
- [libevent](https://libevent.org/) - Event notification library
- [zlib](https://zlib.net/) - Compression library

## Contributing

Contributions are welcome! Please ensure:

1. Code compiles under Swift 6 strict concurrency
2. All public APIs are documented
3. Actor isolation is maintained for thread safety
4. No use of `@preconcurrency` escape hatches

## Security

If you discover a security vulnerability, please report it privately to security@olib.ai rather than opening a public issue.

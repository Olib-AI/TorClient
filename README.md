# TorClient

**A lightweight embedded Tor client for iOS/macOS by [Olib AI](https://www.olib.ai)**

Used in [StealthOS](https://www.stealthos.app) - The privacy-focused operating environment.

---

This package provides a native Swift wrapper around the Tor C library, enabling anonymous network access directly within your app without external dependencies.

## Features

- **Embedded Tor Daemon**: Full Tor implementation compiled as a static library - no external processes or dependencies
- **Client-Only Mode**: Optimized build with relay functionality disabled for smaller footprint
- **Auto Port Selection**: Automatic SOCKS5 port assignment to avoid conflicts with other Tor instances
- **Connection Status Monitoring**: Real-time bootstrap progress tracking via stdout parsing
- **Swift Concurrency**: Modern async/await API with strict Swift 6 concurrency compliance
- **Actor Isolation**: Thread-safe `TorService` actor ensures data race prevention
- **Circuit Management**: Extended circuit lifetime settings for stable long-running connections

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
brew install autoconf automake libtool pkg-config
```

## Building from Source

The `TorClientC.xcframework` is included pre-built for convenience. If you want to build it yourself (to verify, modify, or update versions):

```bash
# From the TorClient package directory:
./Scripts/build-xcframework.sh

# Or clean and rebuild:
./Scripts/build-xcframework.sh --clean
```

The build script will:

1. Download source tarballs from official mirrors (zlib, OpenSSL, libevent, Tor)
2. Cross-compile each library for iOS device (arm64) and simulator (arm64 + x86_64 stub)
3. Combine all libraries into a single `libTorClient.a` per platform
4. Package everything into `TorClientC.xcframework`

| Library | Version | Source |
|---------|---------|--------|
| Tor | 0.4.9.5 | https://dist.torproject.org/ |
| OpenSSL | 3.6.1 | https://github.com/openssl/openssl |
| libevent | 2.1.12-stable | https://github.com/libevent/libevent |
| zlib | 1.3.1 | https://zlib.net/ |

**Build time**: ~10-30 minutes depending on CPU. OpenSSL is the longest step.

Downloaded source tarballs are cached in `.build-tor/` and reused on subsequent runs.

## Installation

### Swift Package Manager

Add to your `Package.swift`:

```swift
dependencies: [
    .package(url: "https://github.com/Olib-AI/TorClient.git", from: "1.0.0")
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
    socksPort: .auto,     // Let Tor pick an available port
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
    
    // Get the actual port Tor bound to
    let port = await torService.actualSocksPort
    print("Tor running on port: \(port)")
    
} catch {
    print("Tor error: \(error)")
}
```

### Using with URLSession

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
| `socksPortMode` | `PortMode` | `.auto` | SOCKS5 port configuration |
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

/// The actual SOCKS port Tor bound to (0 if not yet discovered)
public var actualSocksPort: UInt16 { get async }

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

/// Stop the Tor daemon
/// WARNING: Tor C library has global state - cannot restart after stop!
public func stop() async throws

/// Wait for Tor to fully bootstrap
/// - Parameter timeout: Maximum time to wait (default: 120 seconds)
public func waitForBootstrap(timeout: TimeInterval = 120) async throws

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

### Single Instance Per Process

**CRITICAL**: The Tor C library (`tor_run_main()`) can only be called once per process. The library uses global state that is not reset between calls. Attempting to restart Tor after stopping will cause an assertion failure.

**Best Practice**: Keep Tor running for the lifetime of your application. If you need to "disconnect," simply stop routing traffic through the SOCKS5 proxy rather than stopping the daemon.

### No Control Port

This implementation parses Tor's stdout for status monitoring instead of using the control port. This approach:
- Avoids potential port conflicts
- Reduces attack surface
- Works reliably on iOS where socket permissions may be restricted

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
│   └── build-xcframework.sh      # Build Tor + deps from source
├── Sources/
│   └── TorClientWrapper/
│       └── TorService.swift       # Swift actor wrapping Tor C API
└── TorClientC.xcframework/        # Pre-built static libraries
    ├── ios-arm64/                 # iOS Device
    │   ├── Headers/
    │   │   ├── tor_api.h          # Tor C API
    │   │   ├── module.modulemap
    │   │   └── openssl/           # OpenSSL headers
    │   └── libTorClient.a         # Combined static library (~13MB)
    └── ios-arm64_x86_64-simulator/
        └── ...                    # Simulator libraries (arm64 real + x86_64 stub)
```

### Library Contents

`libTorClient.a` is a combined static library containing:
- **Tor 0.4.9.5**: The Onion Router (client-only build)
- **OpenSSL 3.6.1**: Cryptographic library
- **libevent 2.1.12**: Event notification library
- **zlib 1.3.1**: Compression library

All dependencies are statically linked - no dynamic frameworks required.

### How It Works

1. **Initialization**: `TorService.configure()` creates the data directory and stores configuration
2. **Startup**: `TorService.start()` launches `tor_run_main()` in a background thread
3. **Port Discovery**: stdout is parsed to find the auto-assigned SOCKS5 port
4. **Bootstrap Monitoring**: stdout is parsed for bootstrap progress (0-100%)
5. **SOCKS5 Proxy**: Applications route traffic through `127.0.0.1:<port>`
6. **Persistence**: Tor daemon runs until app termination (no restart capability)

### Tor Configuration Flags

The Swift wrapper sets these Tor options automatically:

```
--DataDirectory /path/to/tor        # State storage
--SocksPort auto                    # Auto port selection
--ControlPort 0                     # Disable control port
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

### Cannot Restart After Stop

This is a known limitation of the Tor C library. Design your app to:
1. Start Tor once at launch
2. Keep it running until app termination
3. "Disconnect" by routing traffic directly instead of through SOCKS5

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

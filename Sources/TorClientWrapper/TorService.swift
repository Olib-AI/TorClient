// TorService.swift
// Swift wrapper for embedded Tor daemon
// StealthOS - stealthos.app

import Foundation
import TorClientC
import os

// MARK: - Tor Configuration

public struct TorConfiguration: Sendable {
    public var dataDirectory: URL
    public var socksPortMode: PortMode
    public var bridges: [String]
    public var clientOnly: Bool
    public var avoidDiskWrites: Bool
    public var geoIPFile: URL?
    public var geoIP6File: URL?
    /// The proxy Tor's own connections (to guards and bridges) go through, when the user
    /// has one configured. Nil: Tor connects directly.
    public var upstreamProxy: UpstreamProxy?

    /// An outbound proxy for Tor itself (torrc `HTTPSProxy` / `Socks5Proxy` / `Socks4Proxy`).
    public enum UpstreamProxy: Sendable, Equatable {
        /// An HTTP proxy that supports CONNECT (`HTTPSProxy`; Tor speaks plain HTTP to it).
        case httpConnect(host: String, port: UInt16, username: String?, password: String?)
        case socks5(host: String, port: UInt16, username: String?, password: String?)
        case socks4(host: String, port: UInt16)

        /// `host:port` with IPv6 literals bracketed. Nil when the host could break a torrc
        /// value (empty, whitespace, quotes, brackets inside a name).
        var address: String? {
            let (host, port): (String, UInt16) = switch self {
            case .httpConnect(let host, let port, _, _), .socks5(let host, let port, _, _): (host, port)
            case .socks4(let host, let port): (host, port)
            }
            guard port > 0, !host.isEmpty, host.utf8.count <= 255,
                  host.utf8.allSatisfy({ $0 > 0x20 && $0 < 0x7F && $0 != 0x22 && $0 != 0x5C && $0 != 0x5B && $0 != 0x5D }) else {
                return nil
            }
            return host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)"
        }

        /// Every torrc option that selects an upstream proxy, set for this one and reset
        /// (nil) for the others, so a change never leaves a stale proxy behind. Nil when
        /// the proxy cannot be expressed.
        public var settings: [TorConfigSetting]? {
            guard let address else { return nil }
            var values: [String: String?] = [
                "HTTPSProxy": nil, "HTTPSProxyAuthenticator": nil,
                "Socks5Proxy": nil, "Socks5ProxyUsername": nil, "Socks5ProxyPassword": nil,
                "Socks4Proxy": nil,
            ]
            switch self {
            case .httpConnect(_, _, let username, let password):
                values["HTTPSProxy"] = address
                if let username, !username.isEmpty {
                    guard !username.contains(":"), username.utf8.count <= 255, (password ?? "").utf8.count <= 255 else { return nil }
                    values["HTTPSProxyAuthenticator"] = "\(username):\(password ?? "")"
                }
            case .socks5(_, _, let username, let password):
                values["Socks5Proxy"] = address
                if let username, !username.isEmpty {
                    guard let password, !password.isEmpty, username.utf8.count <= 255, password.utf8.count <= 255 else { return nil }
                    values["Socks5ProxyUsername"] = username
                    values["Socks5ProxyPassword"] = password
                }
            case .socks4:
                values["Socks4Proxy"] = address
            }
            return values.keys.sorted().map { TorConfigSetting($0, values[$0] ?? nil) }
        }
    }

    /// No upstream proxy: every proxy option reset.
    public static let noUpstreamProxySettings: [TorConfigSetting] = [
        "HTTPSProxy", "HTTPSProxyAuthenticator", "Socks4Proxy", "Socks5Proxy", "Socks5ProxyPassword", "Socks5ProxyUsername",
    ].map { TorConfigSetting($0, nil) }

    /// Port configuration mode
    public enum PortMode: Sendable, Equatable {
        /// Let Tor automatically select an available port
        case auto
        /// Use a specific port number
        case fixed(UInt16)
        /// Listen on a Unix-domain socket at this absolute path instead of TCP, so no
        /// other app on the device can reach the SOCKS port. The parent directory is
        /// created with mode 0700 (Tor refuses a socket in a group/world-accessible
        /// directory) and the socket is neither group- nor world-writable.
        case unix(path: String)

        var torArgument: String {
            switch self {
            case .auto:
                return "auto"
            case .fixed(let port):
                return "\(port)"
            case .unix(let path):
                return "unix:\(path)"
            }
        }
    }

    /// Longest usable AF_UNIX path on Darwin: `sun_path` is 104 bytes including the NUL.
    public static let maxUnixSocketPathLength = 103

    /// Whether `path` can be bound as a Unix socket and passed to Tor unquoted.
    public static func isUsableUnixSocketPath(_ path: String) -> Bool {
        path.hasPrefix("/")
            && path.utf8.count <= maxUnixSocketPathLength
            && !path.utf8.contains(where: { $0 <= 0x20 || $0 == 0x22 || $0 == 0x5C || $0 >= 0x7F })
    }

    public init(
        dataDirectory: URL,
        socksPort: PortMode = .auto,
        bridges: [String] = [],
        clientOnly: Bool = true,
        avoidDiskWrites: Bool = true,
        geoIPFile: URL? = nil,
        geoIP6File: URL? = nil,
        upstreamProxy: UpstreamProxy? = nil
    ) {
        self.dataDirectory = dataDirectory
        self.socksPortMode = socksPort
        self.bridges = bridges
        self.clientOnly = clientOnly
        self.avoidDiskWrites = avoidDiskWrites
        self.geoIPFile = geoIPFile
        self.geoIP6File = geoIP6File
        self.upstreamProxy = upstreamProxy
    }

    /// Convenience initializer for fixed port (backwards compatibility)
    public init(
        dataDirectory: URL,
        socksPort: UInt16,
        controlPort: UInt16? = nil,
        bridges: [String] = [],
        clientOnly: Bool = true,
        avoidDiskWrites: Bool = true,
        geoIPFile: URL? = nil,
        geoIP6File: URL? = nil
    ) {
        self.dataDirectory = dataDirectory
        self.socksPortMode = .fixed(socksPort)
        self.bridges = bridges
        self.clientOnly = clientOnly
        self.avoidDiskWrites = avoidDiskWrites
        self.geoIPFile = geoIPFile
        self.geoIP6File = geoIP6File
        // Note: controlPort is ignored - we disable it to avoid port conflicts
    }
}

// MARK: - SOCKS Socket Location

/// Where the embedded Tor's SOCKS Unix socket lives.
///
/// The natural home, `<container>/Library/Caches/tor/socks.sock`, is 114 bytes on a
/// device (`/private/var/mobile/Containers/Data/Application/<UUID>/` is 85), over the
/// 103-byte `sun_path` limit. The app's own `tmp/` keeps the socket inside the sandbox
/// (no other app can open it) and `<tmp>/tor/socks.sock` is 103 bytes: it fits. A
/// shorter `<tmp>/t/s.sock` is the fallback should the container path ever grow.
/// Simulator containers live under the Mac user's home and are far longer than any
/// limit; there, and only there, a private 0700 directory under the host's /tmp is
/// used (development only; the simulator has no app sandbox to protect anyway).
public enum TorSocksSocketLocation {

    /// Candidate socket paths in preference order.
    public static func candidates(temporaryDirectory: URL) -> [String] {
        let tmp = temporaryDirectory.standardizedFileURL.path
        let base = tmp.hasSuffix("/") ? String(tmp.dropLast()) : tmp
        var paths = ["\(base)/tor/socks.sock", "\(base)/t/s.sock"]
        #if targetEnvironment(simulator)
        paths.append("/tmp/sos-\(shortHash(base))/s.sock")
        #endif
        return paths
    }

    /// The first candidate that fits `sun_path`, or nil.
    public static func plan(temporaryDirectory: URL = FileManager.default.temporaryDirectory) -> String? {
        candidates(temporaryDirectory: temporaryDirectory).first(where: TorConfiguration.isUsableUnixSocketPath)
    }

    /// FNV-1a, 48 bits, hex: a stable per-container directory name.
    static func shortHash(_ text: String) -> String {
        var hash: UInt64 = 0xcbf2_9ce4_8422_2325
        for byte in text.utf8 {
            hash ^= UInt64(byte)
            hash = hash &* 0x0000_0100_0000_01B3
        }
        return String(hash & 0xFFFF_FFFF_FFFF, radix: 16)
    }

    /// Creates the socket's directory as 0700 (fixing the mode if it exists) and removes
    /// a stale socket file left by a crash. Throws if the directory is not ours.
    public static func prepare(socketPath: String) throws {
        let fileManager = FileManager.default
        let directory = (socketPath as NSString).deletingLastPathComponent
        if !fileManager.fileExists(atPath: directory) {
            try fileManager.createDirectory(
                atPath: directory,
                withIntermediateDirectories: true,
                attributes: [.posixPermissions: 0o700]
            )
        }
        try fileManager.setAttributes([.posixPermissions: 0o700], ofItemAtPath: directory)
        let attributes = try fileManager.attributesOfItem(atPath: directory)
        if let owner = attributes[.ownerAccountID] as? NSNumber, owner.uint32Value != getuid() {
            throw TorError.configurationFailed("SOCKS socket directory is not owned by this app")
        }
        if fileManager.fileExists(atPath: socketPath) {
            try fileManager.removeItem(atPath: socketPath)
        }
    }
}

// MARK: - Tor Status

public enum TorStatus: Sendable, Equatable {
    case idle
    case starting
    case connecting
    case bootstrapping(progress: Int)
    case ready
    case stopping
    case error(TorError)

    public static func == (lhs: TorStatus, rhs: TorStatus) -> Bool {
        switch (lhs, rhs) {
        case (.idle, .idle), (.starting, .starting), (.connecting, .connecting),
             (.ready, .ready), (.stopping, .stopping):
            return true
        case (.bootstrapping(let l), .bootstrapping(let r)):
            return l == r
        case (.error(let l), .error(let r)):
            return l.localizedDescription == r.localizedDescription
        default:
            return false
        }
    }
}

// MARK: - Tor Error

public enum TorError: Error, Sendable {
    case configurationFailed(String)
    case startFailed(String)
    case alreadyRunning
    case notRunning
    case bootstrapTimeout
    case connectionFailed
    case shutdownFailed
    case controlSocketFailed

    public var localizedDescription: String {
        switch self {
        case .configurationFailed(let reason):
            return "Tor configuration failed: \(reason)"
        case .startFailed(let reason):
            return "Failed to start Tor: \(reason)"
        case .alreadyRunning:
            return "Tor is already running"
        case .notRunning:
            return "Tor is not running"
        case .bootstrapTimeout:
            return "Tor bootstrap timed out"
        case .connectionFailed:
            return "Tor connection failed"
        case .shutdownFailed:
            return "Failed to shutdown Tor"
        case .controlSocketFailed:
            return "Failed to create control socket"
        }
    }
}

// MARK: - Tor Output Parser State

/// Thread-safe state for parsing Tor stdout output
/// Uses OSAllocatedUnfairLock for Sendable compliance
private final class TorOutputParserState: @unchecked Sendable {
    private struct State {
        var socksListener: TorSocksListener?
        var bootstrapProgress: Int = 0
        var isReady: Bool = false
        var errorMessage: String?
    }

    private let lock = NSLock()
    private var state = State()

    var socksListener: TorSocksListener? {
        lock.lock()
        defer { lock.unlock() }
        return state.socksListener
    }

    var bootstrapProgress: Int {
        lock.lock()
        defer { lock.unlock() }
        return state.bootstrapProgress
    }

    var isReady: Bool {
        lock.lock()
        defer { lock.unlock() }
        return state.isReady
    }

    var errorMessage: String? {
        lock.lock()
        defer { lock.unlock() }
        return state.errorMessage
    }

    func setSocksListener(_ listener: TorSocksListener) {
        lock.lock()
        defer { lock.unlock() }
        state.socksListener = listener
    }

    func setBootstrapProgress(_ progress: Int) {
        lock.lock()
        defer { lock.unlock() }
        state.bootstrapProgress = progress
        if progress >= 100 {
            state.isReady = true
        }
    }

    func setError(_ message: String) {
        lock.lock()
        defer { lock.unlock() }
        state.errorMessage = message
    }

    func setReady(_ ready: Bool) {
        lock.lock()
        defer { lock.unlock() }
        state.isReady = ready
    }

    /// Reset all state for a fresh Tor start
    func reset() {
        lock.lock()
        defer { lock.unlock() }
        state = State()
    }
}

// MARK: - Tor Network State

/// Whether Tor's network is enabled (`DisableNetwork=0`) while the daemon runs.
public enum TorNetworkState: Sendable, Equatable {
    /// Tor is not running.
    case stopped
    /// Running with network enabled (connecting or connected).
    case enabled
    /// Running with `DisableNetwork=1`: no circuits, no SOCKS listener, no
    /// network traffic. `reconnect()` brings it back without a restart.
    case disabled
}

// MARK: - Tor Run Handle

/// Tracks one `tor_run_main()` invocation so `stop()` can wait for it to
/// return (which runs `tor_cleanup()`), instead of abandoning the thread.
private final class TorRunHandle: @unchecked Sendable {
    private let lock = NSLock()
    private var exitCode: Int32?

    var hasExited: Bool { lock.withLock { exitCode != nil } }

    func markExited(_ code: Int32) {
        lock.withLock { exitCode = code }
    }

    /// Waits until `tor_run_main()` returned or `timeout` elapsed. Not
    /// cancellable on purpose: a shutdown must not be abandoned half way.
    func waitForExit(timeout: Duration) async -> Bool {
        let deadline = ContinuousClock.now + timeout
        while ContinuousClock.now < deadline {
            if hasExited { return true }
            await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
                DispatchQueue.global(qos: .userInitiated).asyncAfter(deadline: .now() + .milliseconds(50)) {
                    continuation.resume()
                }
            }
        }
        return hasExited
    }
}

// MARK: - Tor Service Actor

/// TorService provides a Swift actor interface to the embedded Tor daemon.
///
/// The Tor C API is blocking - tor_run_main() does not return until Tor exits.
/// This implementation uses auto-assigned ports to avoid conflicts with other
/// Tor instances. The actual SOCKS port is discovered by parsing Tor's stdout
/// and, after a reconnect, from the control port.
///
/// Lifecycle:
/// - `start()` / `waitForBootstrap()` launch the daemon on a dedicated thread.
/// - `disconnect()` / `reconnect()` toggle `DisableNetwork` over the control
///   socket: a real network disconnect (all circuits and connections closed,
///   SOCKS listener closed) without stopping the daemon. Any number of cycles.
/// - `stop()` asks Tor to exit (`SIGNAL HALT`), waits for `tor_run_main()` to
///   return and run `tor_cleanup()`; `start()` may then launch it again in the
///   same process when `supportsInProcessRestart` is true.
///
/// Usage:
/// ```swift
/// let tor = TorService.shared
/// try await tor.configure(TorConfiguration(
///     dataDirectory: FileManager.default.temporaryDirectory.appendingPathComponent("tor")
/// ))
/// try await tor.start()
/// // Wait for port discovery
/// try await tor.waitForBootstrap(timeout: 120)
/// // Use tor.actualSocksPort for connections
/// ```
@available(iOS 18.0, *)
public actor TorService {

    // MARK: - Properties

    private var configuration: TorConfiguration?
    private var torThread: Thread?
    private var _isRunning = false
    private let parserState = TorOutputParserState()

    /// Pre-authenticated control connection (our end of the socketpair from
    /// tor_main_configuration_setup_control_socket()). Attached from the Tor
    /// thread in runTorMain(); used for NEWNYM, DisableNetwork, GETINFO, HALT.
    private let control = TorControlChannel()

    /// The current/last tor_run_main() invocation.
    private var runHandle: TorRunHandle?

    /// True while `DisableNetwork=1` is applied (soft-disconnected).
    private var networkDisabled = false

    /// Incremented by every disconnect/reconnect/stop so an older in-flight
    /// reconnect stops waiting and reports `.superseded`.
    private var networkTransitionGeneration = 0

    private var statusContinuation: AsyncStream<TorStatus>.Continuation?
    private lazy var _statusStream: AsyncStream<TorStatus> = {
        AsyncStream { continuation in
            self.statusContinuation = continuation
        }
    }()
    public private(set) var status: TorStatus = .idle

    // Pipe for capturing Tor stdout
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?

    // MARK: - Singleton

    public static let shared = TorService()

    private init() {}

    // MARK: - Public API

    /// Whether `start()` may launch Tor again after `stop()` in the same
    /// process. True for TorClientC builds that carry
    /// Scripts/patches/0001-workqueue-per-pool-worker-accounting.patch (stale
    /// thread-pool statics made the second shutdown abort),
    /// 0002-tor-api-owning-controller-socket-double-close.patch and
    /// 0003-dispatch-naming-reset-on-shutdown.patch (stale pubsub name maps
    /// made pubsub_install() abort after a few restarts).
    public static let supportsInProcessRestart = true

    /// Whether Tor is currently running
    public var isRunning: Bool {
        _isRunning
    }

    /// Whether Tor is ready to accept connections (running, network enabled, bootstrapped)
    public var isReady: Bool {
        _isRunning && !networkDisabled && parserState.isReady
    }

    /// Network state of the running daemon.
    public var networkState: TorNetworkState {
        guard _isRunning else { return .stopped }
        return networkDisabled ? .disabled : .enabled
    }

    /// The actual SOCKS port Tor bound to (discovered from stdout, refreshed
    /// from the control port by `reconnect()`). Returns 0 if not yet
    /// discovered, while the network is disabled (the listener is closed), or
    /// when Tor listens on a Unix socket (see `actualSocksListener`).
    public var actualSocksPort: UInt16 {
        networkDisabled ? 0 : (parserState.socksListener?.tcpPort ?? 0)
    }

    /// The SOCKS listener Tor opened (TCP or Unix socket), re-read from
    /// `GETINFO net/listeners/socks` by `reconnect()`. nil if not yet
    /// discovered or while the network is disabled.
    public var actualSocksListener: TorSocksListener? {
        networkDisabled ? nil : parserState.socksListener
    }

    /// Configure Tor with the specified settings
    ///
    /// Note: If Tor is already running, this will throw TorError.alreadyRunning.
    /// Configuration can only change between `stop()` and `start()`.
    public func configure(_ config: TorConfiguration) async throws {
        guard !_isRunning else {
            throw TorError.alreadyRunning
        }

        // Start every configured run from an empty data directory (the app's
        // existing privacy behaviour: no state carried over between runs).
        // Note: this was once believed to prevent the hs_circuitmap_init()
        // assertion on a second tor_run_main(); it does not - that assertion
        // came from running a second instance while the first had never
        // returned. See Scripts/patches/ for what in-process restart needs.
        let fileManager = FileManager.default
        if fileManager.fileExists(atPath: config.dataDirectory.path) {
            try fileManager.removeItem(at: config.dataDirectory)
        }

        // Recreate data directory
        try fileManager.createDirectory(
            at: config.dataDirectory,
            withIntermediateDirectories: true
        )

        self.configuration = config
    }

    /// Start Tor daemon
    ///
    /// - If Tor is already running, returns immediately without error.
    /// - After a completed `stop()`, launches a new tor_run_main() in this
    ///   process (requires `supportsInProcessRestart`).
    /// - Throws if a previous instance has not finished shutting down;
    ///   two concurrent tor_run_main() calls share global state and abort.
    ///
    /// The actual SOCKS port is discovered by parsing Tor's stdout output.
    /// Use `actualSocksPort` to get the port once Tor has started.
    public func start() async throws {
        guard !_isRunning else {
            return
        }

        guard let config = configuration else {
            throw TorError.configurationFailed("Tor not configured")
        }

        if let previous = runHandle {
            guard previous.hasExited else {
                throw TorError.startFailed("Previous Tor instance is still shutting down")
            }
            guard Self.supportsInProcessRestart else {
                throw TorError.startFailed("Tor cannot be restarted in this process; relaunch the app")
            }
        }

        // A Unix-socket SOCKS listener needs a private (0700) directory and no stale
        // socket file from a previous run.
        if case .unix(let path) = config.socksPortMode {
            guard TorConfiguration.isUsableUnixSocketPath(path) else {
                throw TorError.configurationFailed("SOCKS socket path does not fit sun_path: \(path.utf8.count) bytes")
            }
            try TorSocksSocketLocation.prepare(socketPath: path)
        }

        // Reset parser state for fresh start (prevents stale state from previous runs)
        parserState.reset()
        networkDisabled = false
        networkTransitionGeneration += 1

        updateStatus(.starting)

        // Build command line arguments
        let args = buildArguments(from: config)

        // Create pipes for stdout/stderr capture
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        self.stdoutPipe = stdoutPipe
        self.stderrPipe = stderrPipe

        // Start monitoring stdout for port discovery
        startOutputMonitoring(stdoutPipe: stdoutPipe, stderrPipe: stderrPipe)

        // Start Tor in background thread
        _isRunning = true

        let handle = TorRunHandle()
        runHandle = handle
        let parserStateRef = parserState
        let controlRef = control
        torThread = Thread {
            TorService.runTorMain(
                arguments: args,
                stdoutPipe: stdoutPipe,
                stderrPipe: stderrPipe,
                parserState: parserStateRef,
                control: controlRef,
                handle: handle
            )
        }
        torThread?.name = "ai.olib.stealthos.tor"
        torThread?.qualityOfService = .userInitiated
        torThread?.start()

        // Wait for port discovery (up to 10 seconds for initial startup)
        var attempts = 0
        while parserState.socksListener == nil && attempts < 100 {
            try await Task.sleep(nanoseconds: 100_000_000) // 0.1 seconds
            attempts += 1

            // Check if there was an error
            if let errorMsg = parserState.errorMessage {
                await abandonFailedStart(handle)
                throw TorError.startFailed(errorMsg)
            }

            // Check if thread exited
            if handle.hasExited {
                await abandonFailedStart(handle)
                throw TorError.startFailed("Tor thread exited before binding port")
            }
        }

        if parserState.socksListener == nil {
            await abandonFailedStart(handle)
            throw TorError.startFailed("Timeout waiting for Tor to bind SOCKS port")
        }

        updateStatus(.connecting)
    }

    /// Stop the Tor daemon and wait for tor_run_main() to return.
    ///
    /// Sends `SIGNAL HALT` (if the control socket is unusable, closes it: it
    /// is the owning controller connection, so Tor exits), then waits for the
    /// Tor thread to finish `tor_cleanup()`. Throws `TorError.shutdownFailed`
    /// if Tor does not exit in time; `start()` then refuses to launch a second
    /// instance.
    ///
    /// For a user-facing "disconnect" prefer `disconnect()`: it is faster to
    /// undo (cached consensus, no thread restart) and stops all traffic too.
    public func stop() async throws {
        guard _isRunning, let handle = runHandle else {
            return
        }

        updateStatus(.stopping)
        networkTransitionGeneration += 1

        var haltAccepted = false
        if control.isAttached, !handle.hasExited {
            if let reply = try? await control.execute(.signal(.halt), timeout: .seconds(5)) {
                haltAccepted = reply.isSuccess
            }
        }
        if !haltAccepted {
            await control.close()
        }

        let exited = await handle.waitForExit(timeout: .seconds(30))
        await control.close()
        releaseOutputPipes()
        networkDisabled = false
        _isRunning = false
        torThread = nil

        guard exited else {
            updateStatus(.error(.shutdownFailed))
            throw TorError.shutdownFailed
        }
        parserState.reset()
        updateStatus(.idle)
    }

    /// Get SOCKS proxy URL using the auto-discovered port (TCP listeners only)
    public var socksProxyURL: URL? {
        let port = actualSocksPort
        guard port > 0, _isRunning else { return nil }
        return URL(string: "socks5h://127.0.0.1:\(port)")
    }

    /// Status update stream
    public var statusStream: AsyncStream<TorStatus> {
        _statusStream
    }

    /// Get bootstrap progress from parsed stdout (0-100)
    public func getBootstrapProgress() async -> Int? {
        guard _isRunning else { return nil }
        let progress = parserState.bootstrapProgress
        return progress > 0 ? progress : nil
    }

    /// Wait for Tor to fully bootstrap
    public func waitForBootstrap(timeout: TimeInterval = 120) async throws {
        let startTime = Date()

        while Date().timeIntervalSince(startTime) < timeout {
            // A disconnect() while waiting means bootstrap will not finish.
            if networkDisabled {
                throw TorControlError.networkDisabled
            }

            let progress = parserState.bootstrapProgress

            if parserState.isReady || progress >= 100 {
                updateStatus(.ready)
                return
            } else if progress > 0 {
                updateStatus(.bootstrapping(progress: progress))
            }

            // Check for errors
            if let errorMsg = parserState.errorMessage {
                throw TorError.startFailed(errorMsg)
            }

            // Check if thread is still running
            if runHandle?.hasExited != false {
                throw TorError.startFailed("Tor process exited unexpectedly")
            }

            try await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
        }

        throw TorError.bootstrapTimeout
    }

    /// Whether the control socket is available for sending commands
    public nonisolated var hasControlSocket: Bool {
        control.isAttached
    }

    // MARK: - Network Disconnect / Reconnect

    /// Soft disconnect: `SETCONF DisableNetwork=1`.
    ///
    /// Tor closes every circuit and OR connection, closes its SOCKS listener
    /// (new SOCKS connections are refused immediately) and makes no network
    /// traffic until `reconnect()`. The daemon, its consensus and the control
    /// socket stay alive. Idempotent.
    ///
    /// The result is verified with `GETCONF DisableNetwork` and
    /// `GETINFO status/circuit-established net/listeners/socks ...`; any
    /// mismatch, non-`2xx` reply, timeout or dead control socket throws a
    /// `TorControlError` - success is never assumed.
    public func disconnect(timeout: Duration = .seconds(15)) async throws {
        guard _isRunning else { throw TorError.notRunning }
        networkTransitionGeneration += 1
        try await waitForControlSocket(timeout: timeout)

        try await setDisableNetwork(true, timeout: timeout)
        networkDisabled = true
        parserState.setReady(false)
        parserState.setBootstrapProgress(0)
        updateStatus(.idle)

        let disabled = try await getConfBool("DisableNetwork", timeout: timeout)
        guard disabled == true else {
            throw TorControlError.verificationFailed("DisableNetwork reads back as \(String(describing: disabled))")
        }
        let snapshot = try await networkSnapshot(timeout: timeout)
        guard snapshot.isOffline else {
            throw TorControlError.verificationFailed(
                "circuit-established=\(snapshot.circuitEstablished), socks listeners=\(snapshot.socksPorts)"
            )
        }
    }

    /// Re-enables the network (`SETCONF DisableNetwork=0`) and waits until
    /// Tor has an established circuit and an open SOCKS listener.
    ///
    /// `onProgress` receives 0-99 while waiting (Tor's bootstrap percentage
    /// while it is below 100, otherwise milestone-based) and 100 once usable.
    /// The SOCKS port usually changes (`SocksPort auto`): read
    /// `actualSocksPort` afterwards. Time spent suspended in the background
    /// does not count against `timeout` (see `TorWaitBudget`).
    ///
    /// Throws `TorControlError` for control-port failures, `.superseded` if
    /// `disconnect()`/`stop()` was called meanwhile, `TorError.bootstrapTimeout`
    /// if no circuit was built in time (the network stays enabled and Tor
    /// keeps trying), or `CancellationError`.
    public func reconnect(
        timeout: Duration = .seconds(120),
        onProgress: (@Sendable (Int) -> Void)? = nil
    ) async throws {
        guard _isRunning else { throw TorError.notRunning }
        networkTransitionGeneration += 1
        let generation = networkTransitionGeneration
        let commandTimeout = Duration.seconds(10)
        try await waitForControlSocket(timeout: commandTimeout)

        try await setDisableNetwork(false, timeout: commandTimeout)
        networkDisabled = false
        let disabled = try await getConfBool("DisableNetwork", timeout: commandTimeout)
        guard disabled == false else {
            throw TorControlError.verificationFailed("DisableNetwork reads back as \(String(describing: disabled))")
        }
        updateStatus(.connecting)

        let pollInterval = Duration.milliseconds(500)
        var budget = TorWaitBudget(total: timeout, maxChargePerStep: pollInterval * 4)
        var lastProgress = -1
        while true {
            try Task.checkCancellation()
            guard generation == networkTransitionGeneration, _isRunning else {
                throw TorControlError.superseded
            }
            if runHandle?.hasExited != false {
                throw TorError.startFailed("Tor process exited unexpectedly")
            }

            let stepStart = ContinuousClock.now
            let snapshot = try await networkSnapshot(timeout: commandTimeout)
            guard generation == networkTransitionGeneration else { throw TorControlError.superseded }

            let progress = snapshot.reconnectProgress
            if progress != lastProgress {
                lastProgress = progress
                onProgress?(progress)
                if progress < 100 { updateStatus(.bootstrapping(progress: progress)) }
            }
            if snapshot.isOnline, let listener = snapshot.socksListeners.first {
                parserState.setSocksListener(listener)
                parserState.setBootstrapProgress(100)
                parserState.setReady(true)
                updateStatus(.ready)
                return
            }

            try await Task.sleep(for: pollInterval)
            budget.charge(stepStart.duration(to: .now))
            if budget.isExhausted { throw TorError.bootstrapTimeout }
        }
    }

    /// One GETINFO round trip describing Tor's network state.
    public func networkSnapshot(timeout: Duration = .seconds(10)) async throws -> TorNetworkSnapshot {
        let reply = try await sendControlCommand(
            try Self.build { () throws(TorControlCommandError) in try .getInfo(TorNetworkSnapshot.getInfoKeys) },
            timeout: timeout
        )
        guard let snapshot = TorNetworkSnapshot(reply: reply) else {
            throw TorControlError.verificationFailed("Unexpected GETINFO answer")
        }
        return snapshot
    }

    /// Sends a validated control command and returns Tor's `2xx` reply.
    /// Non-`2xx` answers throw `TorControlError.rejected`.
    public func sendControlCommand(
        _ command: TorControlCommand,
        timeout: Duration = .seconds(10)
    ) async throws -> TorControlReply {
        guard _isRunning else { throw TorError.notRunning }
        let reply = try await control.execute(command, timeout: timeout)
        guard reply.isSuccess else {
            throw TorControlError.rejected(command: command.verb, statusCode: reply.statusCode, message: reply.message)
        }
        return reply
    }

    // MARK: - Upstream Proxy

    /// Switches the proxy Tor itself uses, on the running daemon (SETCONF). Nil removes it.
    /// Throws `TorError.configurationFailed`-style errors when the proxy cannot be
    /// expressed, `TorError.notRunning` when Tor is not running.
    public func applyUpstreamProxy(_ proxy: TorConfiguration.UpstreamProxy?) async throws {
        let settings: [TorConfigSetting]
        if let proxy {
            guard let proxySettings = proxy.settings else { throw TorControlError.verificationFailed("Unusable upstream proxy") }
            settings = proxySettings
        } else {
            settings = TorConfiguration.noUpstreamProxySettings
        }
        _ = try await sendControlCommand(try TorControlCommand.setConf(settings))
        configuration?.upstreamProxy = proxy
    }

    // MARK: - Circuit Control

    /// Send SIGNAL NEWNYM to Tor via the control socket to request a new circuit (new identity).
    ///
    /// Throws `TorError.notRunning` / `TorError.controlSocketFailed` as before,
    /// and `TorControlError.networkDisabled` while soft-disconnected: a new
    /// identity cannot be built without network, so it fails instead of
    /// pretending.
    public func sendNewnym() async throws {
        guard _isRunning else {
            throw TorError.notRunning
        }
        guard control.isAttached else {
            throw TorError.controlSocketFailed
        }
        guard !networkDisabled else {
            throw TorControlError.networkDisabled
        }

        do {
            let reply = try await control.execute(.signal(.newnym), timeout: .seconds(10))
            guard reply.isSuccess else {
                TorLog.service.error("NEWNYM rejected: \(reply.statusCode, privacy: .public) \(reply.message, privacy: .private)")
                throw TorError.controlSocketFailed
            }
            TorLog.service.info("NEWNYM accepted: \(reply.statusCode, privacy: .public)")
            TorLog.service.debug("NEWNYM reply: \(reply.message, privacy: .private)")
        } catch let error as TorControlError {
            TorLog.service.error("NEWNYM failed: \(error.localizedDescription, privacy: .private)")
            throw TorError.controlSocketFailed
        }
    }

    // MARK: - Control Helpers

    /// Lets builders with typed throws be used where `TorControlError` is expected.
    private static func build(
        _ make: () throws(TorControlCommandError) -> TorControlCommand
    ) throws(TorControlError) -> TorControlCommand {
        do {
            return try make()
        } catch {
            throw .invalidCommand(error)
        }
    }

    private func setDisableNetwork(_ disabled: Bool, timeout: Duration) async throws {
        let command = try Self.build { () throws(TorControlCommandError) in
            try .setConf([TorConfigSetting("DisableNetwork", disabled ? "1" : "0")])
        }
        _ = try await sendControlCommand(command, timeout: timeout)
    }

    private func getConfBool(_ key: String, timeout: Duration) async throws -> Bool? {
        let command = try Self.build { () throws(TorControlCommandError) in try .getConf([key]) }
        let reply = try await sendControlCommand(command, timeout: timeout)
        return TorControlValue.bool(reply.keyValues[key])
    }

    /// The control socket is attached from the Tor thread shortly after
    /// `start()`; a disconnect during early startup waits for it.
    private func waitForControlSocket(timeout: Duration) async throws {
        let deadline = ContinuousClock.now + timeout
        while !control.isAttached {
            if runHandle?.hasExited != false || ContinuousClock.now >= deadline {
                throw TorControlError.notConnected
            }
            try await Task.sleep(for: .milliseconds(50))
        }
    }

    /// Cleans up after start() gave up: stop the instance if it is still
    /// running so a later start() does not race a live tor_run_main().
    private func abandonFailedStart(_ handle: TorRunHandle) async {
        if !handle.hasExited {
            if control.isAttached {
                _ = try? await control.execute(.signal(.halt), timeout: .seconds(5))
            }
            await control.close()
            _ = await handle.waitForExit(timeout: .seconds(30))
        }
        await control.close()
        releaseOutputPipes()
        _isRunning = false
        torThread = nil
    }

    private func releaseOutputPipes() {
        stdoutPipe?.fileHandleForReading.readabilityHandler = nil
        stderrPipe?.fileHandleForReading.readabilityHandler = nil
        stdoutPipe = nil
        stderrPipe = nil
    }

    // MARK: - Private Methods

    private func updateStatus(_ newStatus: TorStatus) {
        status = newStatus
        statusContinuation?.yield(newStatus)
    }

    private func buildArguments(from config: TorConfiguration) -> [String] {
        Self.arguments(for: config)
    }

    /// Tor's command line for `config`. Carries proxy credentials: never log it.
    public static func arguments(for config: TorConfiguration) -> [String] {
        var args: [String] = ["tor"] // argv[0]

        args.append("--DataDirectory")
        args.append(config.dataDirectory.path)

        // Use auto port or fixed port based on configuration
        args.append("--SocksPort")
        args.append(config.socksPortMode.torArgument)

        // Disable TCP control port — we use the in-process control socket instead
        // (set up via tor_main_configuration_setup_control_socket in runTorMain)
        args.append("--ControlPort")
        args.append("0")

        if config.clientOnly {
            args.append("--ClientOnly")
            args.append("1")

            // CRITICAL: For client-only builds (--disable-module-relay), DirCache
            // defaults to 1 but relay functionality is disabled. We MUST explicitly
            // disable DirCache to prevent the config validation error:
            // "This tor was built with relay mode disabled. It can not be configured
            // with an ORPort, a DirPort, DirCache 1, or BridgeRelay 1."
            args.append("--DirCache")
            args.append("0")

            // CRITICAL FIX: Disable HiddenServiceStatistics to prevent hs_circuitmap_init crash
            // Even for clients, Tor may try to initialize HS statistics structures. When built
            // with --disable-module-relay, this can cause assertion failures on restart due to
            // global state not being properly reset. Explicitly disabling prevents the init path.
            args.append("--HiddenServiceStatistics")
            args.append("0")
        }

        if config.avoidDiskWrites {
            args.append("--AvoidDiskWrites")
            args.append("1")
        }

        if !config.bridges.isEmpty {
            args.append("--UseBridges")
            args.append("1")
            for bridge in config.bridges {
                args.append("--Bridge")
                args.append(bridge)
            }
        }

        // The user's own proxy, for Tor's connections to its guards / bridges.
        if let settings = config.upstreamProxy?.settings {
            for setting in settings {
                guard let value = setting.value else { continue }
                args.append("--\(setting.key)")
                args.append(value)
            }
        }

        if let geoIP = config.geoIPFile {
            args.append("--GeoIPFile")
            args.append(geoIP.path)
        }

        if let geoIP6 = config.geoIP6File {
            args.append("--GeoIPv6File")
            args.append(geoIP6.path)
        }

        // Log to stdout for parsing (no log file)
        args.append("--Log")
        args.append("notice stdout")

        // CRITICAL FIX: Prevent premature circuit disconnects (3-4 minute timeout issue)
        //
        // Default Tor settings cause circuits to become stale after ~3-5 minutes of low traffic.
        // The keepalive mechanism was only checking SOCKS5 port availability, not actually
        // using the circuits, causing them to expire. These settings extend circuit lifetime:
        //
        // MaxCircuitDirtiness: How long a circuit can be used before being marked "dirty"
        // Default is 600s (10 min), but circuits can close earlier if idle
        args.append("--MaxCircuitDirtiness")
        args.append("1800")  // 30 minutes - keep circuits usable longer

        // NewCircuitPeriod: Minimum time before building a new circuit for new streams
        // Default is 30s. Setting higher prevents circuit churn.
        args.append("--NewCircuitPeriod")
        args.append("60")  // 1 minute - less aggressive circuit building

        // LearnCircuitBuildTimeout: Disable adaptive timeouts that can cause instability
        // When Tor "learns" from failed circuits, it can become overly aggressive
        args.append("--LearnCircuitBuildTimeout")
        args.append("0")  // Disable learning (use default 60s timeout)

        // CircuitBuildTimeout: How long to wait for a circuit to build
        args.append("--CircuitBuildTimeout")
        args.append("90")  // 90 seconds - more patient for slow networks

        // SocksTimeout: How long to wait for a SOCKS connection
        args.append("--SocksTimeout")
        args.append("120")  // 2 minutes - longer timeout for slow circuits

        return args
    }

    private func startOutputMonitoring(stdoutPipe: Pipe, stderrPipe: Pipe) {
        let parserStateRef = parserState

        // Monitor stdout for port binding and bootstrap messages
        stdoutPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty, let output = String(data: data, encoding: .utf8) else { return }

            // Parse each line
            for line in output.components(separatedBy: .newlines) {
                Self.parseTorOutput(line: line, state: parserStateRef)
            }
        }

        // Monitor stderr for errors
        stderrPipe.fileHandleForReading.readabilityHandler = { handle in
            let data = handle.availableData
            guard !data.isEmpty, let output = String(data: data, encoding: .utf8) else { return }

            // Check for critical errors
            if output.contains("[warn]") || output.contains("[err]") {
                if output.contains("Could not bind") || output.contains("Address already in use") {
                    parserStateRef.setError("Port binding failed: \(output)")
                }
            }
        }
    }

    /// The listener announced by an "Opened Socks listener ... (ready) on X" log line.
    static func socksListener(fromLogLine line: String) -> TorSocksListener? {
        guard line.contains("Opened Socks listener"), line.contains("ready"),
              let on = line.range(of: " on ", options: .backwards) else { return nil }
        let address = line[on.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        return TorSocksListener(listenerAddress: address)
    }

    /// Parse Tor log output to extract port and bootstrap status
    private static func parseTorOutput(line: String, state: TorOutputParserState) {
        // Parse SOCKS listener binding. Formats:
        // "[notice] Opened Socks listener connection (ready) on 127.0.0.1:XXXXX"
        // "[notice] Opened Socks listener connection (ready) on /path/to/socks.sock"
        if let listener = socksListener(fromLogLine: line) {
            state.setSocksListener(listener)
        }

        // Parse bootstrap progress
        // Format: "Bootstrapped XX% (phase): description"
        if line.contains("Bootstrapped") {
            if let percentRange = line.range(of: "Bootstrapped ") {
                let afterBootstrapped = line[percentRange.upperBound...]
                if let percentEnd = afterBootstrapped.firstIndex(of: "%") {
                    let percentStr = String(afterBootstrapped[..<percentEnd])
                    if let progress = Int(percentStr) {
                        state.setBootstrapProgress(progress)
                    }
                }
            }
        }

        // Detect errors
        if line.contains("[warn]") {
            if line.contains("Could not bind") {
                state.setError("Port binding failed")
            }
        }
        if line.contains("[err]") {
            state.setError(line)
        }
    }

    /// Body of the Tor thread: one complete tor_run_main() invocation.
    /// `handle.markExited` runs last, after the configuration is freed and
    /// stdout/stderr are restored, so `stop()` returning means the thread is
    /// done with every resource it touched.
    private static func runTorMain(
        arguments: [String],
        stdoutPipe: Pipe,
        stderrPipe: Pipe,
        parserState: TorOutputParserState,
        control: TorControlChannel,
        handle: TorRunHandle
    ) {
        var exitCode: Int32 = -1
        defer { handle.markExited(exitCode) }

        TorLog.thread.debug("Tor thread starting: \(Thread.current.name ?? "unnamed", privacy: .public)")

        guard let cfg = tor_main_configuration_new() else {
            parserState.setError("Failed to create Tor configuration")
            TorLog.thread.error("Failed to create the Tor configuration")
            return
        }

        // tor_api.h: argv must stay valid and unchanged until tor_run_main()
        // returns, so it lives in manually managed memory (not an Array
        // buffer whose pointer would escape withUnsafeMutableBufferPointer).
        let argc = arguments.count
        let argv = UnsafeMutablePointer<UnsafeMutablePointer<CChar>?>.allocate(capacity: argc + 1)
        for (index, argument) in arguments.enumerated() {
            argv[index] = strdup(argument)
        }
        argv[argc] = nil

        defer {
            // Freed after tor_run_main() returned. With
            // Scripts/patches/0002 this closes each control descriptor once.
            tor_main_configuration_free(cfg)
            for index in 0..<argc { free(argv[index]) }
            argv.deallocate()
            TorLog.thread.debug("Tor thread exiting: configuration freed")
        }

        // Redirect stdout/stderr to our pipes
        let originalStdout = dup(STDOUT_FILENO)
        let originalStderr = dup(STDERR_FILENO)

        dup2(stdoutPipe.fileHandleForWriting.fileDescriptor, STDOUT_FILENO)
        dup2(stderrPipe.fileHandleForWriting.fileDescriptor, STDERR_FILENO)

        defer {
            // Restore original stdout/stderr
            dup2(originalStdout, STDOUT_FILENO)
            dup2(originalStderr, STDERR_FILENO)
            close(originalStdout)
            close(originalStderr)
        }

        // Set up control socket BEFORE tor_run_main(): an anonymous AF_UNIX
        // socketpair, passed to Tor as __OwningControllerFD. It is
        // pre-authenticated, reachable by nobody else (no path, no TCP port),
        // and closing our end makes Tor exit.
        let controlFD = tor_main_configuration_setup_control_socket(cfg)
        if controlFD != INVALID_TOR_CONTROL_SOCKET {
            TorLog.thread.debug("Control socket created: fd=\(controlFD, privacy: .public)")
            control.attach(controlFD)
        } else {
            TorLog.thread.error("Failed to create the control socket: NEWNYM and disconnect will not work")
        }

        _ = tor_main_configuration_set_command_line(cfg, Int32(argc), argv)

        // Never log `arguments`/argv: they can carry proxy credentials.
        TorLog.thread.debug("Calling tor_run_main()")

        // This blocks until Tor exits
        let result = tor_run_main(cfg)
        exitCode = result

        TorLog.thread.debug("tor_run_main() returned \(result, privacy: .public)")

        if result != 0 {
            parserState.setError("Tor exited with code \(result)")
            TorLog.thread.error("Tor exited with code \(result, privacy: .public)")
        }
    }
}

// MARK: - Redacted Descriptions

/// An upstream proxy carries the user's proxy host and credentials. Its
/// description, debug description and mirror (what `print`, `dump`,
/// `String(describing:)` and the description of an enclosing
/// `TorConfiguration` use) name only the proxy kind and whether it
/// authenticates, so an accidental log line cannot leak them.
extension TorConfiguration.UpstreamProxy: CustomStringConvertible, CustomDebugStringConvertible, CustomReflectable {
    public var description: String {
        switch self {
        case .httpConnect(_, _, let username, _):
            return "UpstreamProxy.httpConnect(<redacted>, authenticated: \(!(username ?? "").isEmpty))"
        case .socks5(_, _, let username, _):
            return "UpstreamProxy.socks5(<redacted>, authenticated: \(!(username ?? "").isEmpty))"
        case .socks4:
            return "UpstreamProxy.socks4(<redacted>)"
        }
    }

    public var debugDescription: String { description }

    public var customMirror: Mirror { Mirror(self, children: [Mirror.Child](), displayStyle: .enum) }
}

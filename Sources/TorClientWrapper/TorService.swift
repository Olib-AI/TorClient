// TorService.swift
// Swift wrapper for embedded Tor daemon
// StealthOS - stealthos.app

import Foundation
import TorClientC

// MARK: - Tor Configuration

public struct TorConfiguration: Sendable {
    public var dataDirectory: URL
    public var socksPortMode: PortMode
    public var bridges: [String]
    public var clientOnly: Bool
    public var avoidDiskWrites: Bool
    public var geoIPFile: URL?
    public var geoIP6File: URL?

    /// Port configuration mode
    public enum PortMode: Sendable, Equatable {
        /// Let Tor automatically select an available port
        case auto
        /// Use a specific port number
        case fixed(UInt16)

        var torArgument: String {
            switch self {
            case .auto:
                return "auto"
            case .fixed(let port):
                return "\(port)"
            }
        }
    }

    public init(
        dataDirectory: URL,
        socksPort: PortMode = .auto,
        bridges: [String] = [],
        clientOnly: Bool = true,
        avoidDiskWrites: Bool = true,
        geoIPFile: URL? = nil,
        geoIP6File: URL? = nil
    ) {
        self.dataDirectory = dataDirectory
        self.socksPortMode = socksPort
        self.bridges = bridges
        self.clientOnly = clientOnly
        self.avoidDiskWrites = avoidDiskWrites
        self.geoIPFile = geoIPFile
        self.geoIP6File = geoIP6File
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
        var socksPort: UInt16 = 0
        var bootstrapProgress: Int = 0
        var isReady: Bool = false
        var errorMessage: String?
    }

    private let lock = NSLock()
    private var state = State()

    var socksPort: UInt16 {
        lock.lock()
        defer { lock.unlock() }
        return state.socksPort
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

    func setSocksPort(_ port: UInt16) {
        lock.lock()
        defer { lock.unlock() }
        state.socksPort = port
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

// MARK: - Tor Service Actor

/// TorService provides a Swift actor interface to the embedded Tor daemon.
///
/// The Tor C API is blocking - tor_run_main() does not return until Tor exits.
/// This implementation uses auto-assigned ports to avoid conflicts with other
/// Tor instances. The actual SOCKS port is discovered by parsing Tor's stdout.
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

    private var statusContinuation: AsyncStream<TorStatus>.Continuation?
    public private(set) var status: TorStatus = .idle

    // Pipe for capturing Tor stdout
    private var stdoutPipe: Pipe?
    private var stderrPipe: Pipe?

    // MARK: - Singleton

    public static let shared = TorService()

    private init() {}

    // MARK: - Public API

    /// Whether Tor is currently running
    public var isRunning: Bool {
        _isRunning
    }

    /// Whether Tor is ready to accept connections (running and bootstrapped)
    public var isReady: Bool {
        _isRunning && parserState.isReady
    }

    /// The actual SOCKS port Tor bound to (discovered from stdout)
    /// Returns 0 if not yet discovered
    public var actualSocksPort: UInt16 {
        parserState.socksPort
    }

    /// Configure Tor with the specified settings
    ///
    /// Note: If Tor is already running, this will throw TorError.alreadyRunning.
    /// This is intentional - configuration can only happen before start.
    /// To change configuration, the app must be restarted.
    public func configure(_ config: TorConfiguration) async throws {
        guard !_isRunning else {
            throw TorError.alreadyRunning
        }

        // CRITICAL FIX: Clear data directory before starting to prevent hs_circuitmap_init crash
        // The Tor library uses global state that is not reset between runs. When tor_run_main()
        // is called a second time, hs_circuitmap_init() asserts because the hash table is already
        // initialized. Clearing the data directory ensures a clean slate.
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
    /// CRITICAL: Due to Tor C library limitations, tor_run_main() can only be called
    /// once per process. The library uses global state that is not reset between calls.
    /// Calling it a second time causes an assertion failure in hs_circuitmap_init().
    ///
    /// This method handles the limitation by:
    /// - If Tor is already running, returns immediately without error
    /// - If Tor is not running, starts it in a background thread
    ///
    /// The actual SOCKS port is discovered by parsing Tor's stdout output.
    /// Use `actualSocksPort` to get the port once Tor has started.
    public func start() async throws {
        // If already running, return silently - this is expected behavior
        // when reconnecting after a disconnect (Tor daemon kept running)
        guard !_isRunning else {
            // Already running - this is not an error, just return
            return
        }

        guard let config = configuration else {
            throw TorError.configurationFailed("Tor not configured")
        }

        // Reset parser state for fresh start (prevents stale state from previous runs)
        parserState.reset()

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

        let parserStateRef = parserState
        torThread = Thread { [weak self] in
            self?.runTorMain(
                arguments: args,
                stdoutPipe: stdoutPipe,
                stderrPipe: stderrPipe,
                parserState: parserStateRef
            )
        }
        torThread?.name = "ai.olib.stealthos.tor"
        torThread?.qualityOfService = .userInitiated
        torThread?.start()

        // Wait for port discovery (up to 10 seconds for initial startup)
        var attempts = 0
        while parserState.socksPort == 0 && attempts < 100 {
            try await Task.sleep(nanoseconds: 100_000_000) // 0.1 seconds
            attempts += 1

            // Check if there was an error
            if let errorMsg = parserState.errorMessage {
                _isRunning = false
                throw TorError.startFailed(errorMsg)
            }

            // Check if thread exited
            if torThread?.isExecuting != true {
                _isRunning = false
                throw TorError.startFailed("Tor thread exited before binding port")
            }
        }

        if parserState.socksPort == 0 {
            _isRunning = false
            throw TorError.startFailed("Timeout waiting for Tor to bind SOCKS port")
        }

        updateStatus(.connecting)
    }

    /// Stop Tor daemon
    ///
    /// WARNING: DO NOT call this method during normal operation!
    ///
    /// Due to Tor C library limitations, tor_run_main() can only be called once per
    /// process. If you stop Tor, it CANNOT be restarted - the app must be terminated.
    /// The library uses global state (hs_circuitmap) that asserts on second initialization.
    ///
    /// This method exists only for:
    /// - App termination cleanup
    /// - Extreme error recovery (knowing restart requires app relaunch)
    ///
    /// For normal "disconnect" operations, use TorManager.disconnect() which keeps
    /// the Tor daemon running and only disconnects the proxy layer.
    public func stop() async throws {
        guard _isRunning else {
            // Not running - just return, don't throw
            return
        }

        updateStatus(.stopping)

        // Close pipes to signal EOF
        stdoutPipe?.fileHandleForWriting.closeFile()
        stderrPipe?.fileHandleForWriting.closeFile()

        // Cancel the thread
        torThread?.cancel()

        // Wait for thread to finish (up to 10 seconds)
        var waitCount = 0
        while torThread?.isExecuting == true && waitCount < 100 {
            try await Task.sleep(nanoseconds: 100_000_000) // 0.1 seconds
            waitCount += 1
        }

        _isRunning = false
        torThread = nil
        stdoutPipe = nil
        stderrPipe = nil
        updateStatus(.idle)
    }

    /// Get SOCKS proxy URL using the auto-discovered port
    public var socksProxyURL: URL? {
        let port = parserState.socksPort
        guard port > 0, _isRunning else { return nil }
        return URL(string: "socks5h://127.0.0.1:\(port)")
    }

    /// Status update stream
    public var statusStream: AsyncStream<TorStatus> {
        AsyncStream { continuation in
            self.statusContinuation = continuation
        }
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
            if torThread?.isExecuting != true {
                throw TorError.startFailed("Tor process exited unexpectedly")
            }

            try await Task.sleep(nanoseconds: 500_000_000) // 0.5 seconds
        }

        throw TorError.bootstrapTimeout
    }

    // MARK: - Private Methods

    private func updateStatus(_ newStatus: TorStatus) {
        status = newStatus
        statusContinuation?.yield(newStatus)
    }

    private func buildArguments(from config: TorConfiguration) -> [String] {
        var args: [String] = ["tor"] // argv[0]

        args.append("--DataDirectory")
        args.append(config.dataDirectory.path)

        // Use auto port or fixed port based on configuration
        args.append("--SocksPort")
        args.append(config.socksPortMode.torArgument)

        // IMPORTANT: Disable control port to avoid binding conflicts
        // We parse stdout instead for status monitoring
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

    /// Parse Tor log output to extract port and bootstrap status
    private static func parseTorOutput(line: String, state: TorOutputParserState) {
        // Parse SOCKS port binding
        // Format: "[notice] Opened Socks listener connection (ready) on 127.0.0.1:XXXXX"
        if line.contains("Opened Socks listener") && line.contains("ready") {
            if let range = line.range(of: "127.0.0.1:") {
                let portSubstring = line[range.upperBound...]
                // Extract just the port number (stop at any non-digit)
                let portStr = portSubstring.prefix(while: { $0.isNumber })
                if let port = UInt16(portStr), port > 0 {
                    state.setSocksPort(port)
                }
            }
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

    private nonisolated func runTorMain(
        arguments: [String],
        stdoutPipe: Pipe,
        stderrPipe: Pipe,
        parserState: TorOutputParserState
    ) {
        // DIAGNOSTIC: Log thread start
        print("[TorService] TOR THREAD STARTING - thread: \(Thread.current.name ?? "unnamed")")

        guard let cfg = tor_main_configuration_new() else {
            parserState.setError("Failed to create Tor configuration")
            print("[TorService] TOR THREAD ERROR - failed to create configuration")
            return
        }

        defer {
            tor_main_configuration_free(cfg)
            // DIAGNOSTIC: Log thread exit
            print("[TorService] TOR THREAD EXITING - configuration freed")
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

        // Convert Swift strings to C strings
        var cStrings = arguments.map { strdup($0) }
        defer { cStrings.forEach { free($0) } }

        let argc = Int32(cStrings.count)
        cStrings.withUnsafeMutableBufferPointer { buffer in
            _ = tor_main_configuration_set_command_line(cfg, argc, buffer.baseAddress)
        }

        // DIAGNOSTIC: Log before tor_run_main
        print("[TorService] TOR THREAD - calling tor_run_main()")

        // This blocks until Tor exits
        let result = tor_run_main(cfg)

        // DIAGNOSTIC: Log tor_run_main exit
        print("[TorService] TOR THREAD - tor_run_main() returned with code \(result)")

        if result != 0 {
            parserState.setError("Tor exited with code \(result)")
            print("[TorService] TOR THREAD ERROR - Tor exited with code \(result)")
        }
    }
}

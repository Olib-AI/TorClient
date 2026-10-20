// LoggingHygieneTests.swift
// Guards against logging that could leak Tor's command line or proxy credentials.
// StealthOS - stealthos.app

import Foundation
import Testing
@testable import TorClientWrapper

@Suite("Logging hygiene")
struct LoggingHygieneTests {
    // MARK: - Source scan

    /// `Sources/` of this package, found from this file's path (the simulator
    /// runs tests with access to the host file system).
    private static let sourcesDirectory: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent() // TorClientWrapperTests
        .deletingLastPathComponent() // Tests
        .deletingLastPathComponent() // package root
        .appendingPathComponent("Sources", isDirectory: true)

    private struct SourceLine: CustomStringConvertible {
        let file: String
        let number: Int
        let text: String
        var description: String { "\(file):\(number): \(text.trimmingCharacters(in: .whitespaces))" }
    }

    /// Every non-comment line of every Swift file under `Sources/`.
    private static func sourceLines() throws -> [SourceLine] {
        let enumerator = try #require(FileManager.default.enumerator(
            at: sourcesDirectory, includingPropertiesForKeys: nil
        ))
        var lines: [SourceLine] = []
        for case let url as URL in enumerator where url.pathExtension == "swift" {
            let text = try String(contentsOf: url, encoding: .utf8)
            for (index, line) in text.components(separatedBy: .newlines).enumerated() {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                if trimmed.hasPrefix("//") { continue }
                lines.append(SourceLine(file: url.lastPathComponent, number: index + 1, text: line))
            }
        }
        return lines
    }

    @Test("The scan actually sees the package sources")
    func scanFindsSources() throws {
        let files = Set(try Self.sourceLines().map(\.file))
        #expect(files.contains("TorService.swift"))
        #expect(files.contains("TorControlChannel.swift"))
        #expect(files.contains("TorLog.swift"))
    }

    @Test("Sources never print to stdout/stderr")
    func noPrintInSources() throws {
        // `print` bypasses unified-logging privacy, and while Tor runs stdout
        // is redirected into Tor's output parser.
        let forbidden = try NSRegularExpression(pattern: #"(?<![A-Za-z0-9_.])(print|debugPrint|dump|NSLog)\s*\("#)
        let offenders = try Self.sourceLines().filter { line in
            forbidden.firstMatch(in: line.text, range: NSRange(line.text.startIndex..., in: line.text)) != nil
        }
        #expect(offenders.isEmpty, "Use TorLog instead of: \(offenders)")
    }

    @Test("Log statements never interpolate the command line or control command lines")
    func logsNeverCarryCommandLine() throws {
        let logCall = try NSRegularExpression(pattern: #"TorLog\.\w+\.\w+\("#)
        let secretBearing = ["arguments", "argv", "args", ".line", "wireBytes", "upstreamProxy", "settings", "bridges", "password", "username"]
        let offenders = try Self.sourceLines().filter { line in
            guard logCall.firstMatch(in: line.text, range: NSRange(line.text.startIndex..., in: line.text)) != nil else { return false }
            return secretBearing.contains { line.text.contains($0) }
        }
        #expect(offenders.isEmpty, "Log line may carry credentials: \(offenders)")
    }

    // MARK: - Redacted descriptions

    private static let secrets = ["proxy.example.net", "8443", "alice", "s3cr3t-pass"]

    private static let proxies: [TorConfiguration.UpstreamProxy] = [
        .httpConnect(host: "proxy.example.net", port: 8443, username: "alice", password: "s3cr3t-pass"),
        .socks5(host: "proxy.example.net", port: 8443, username: "alice", password: "s3cr3t-pass"),
        .socks4(host: "proxy.example.net", port: 8443),
    ]

    private static func renderings(of value: Any) -> [String] {
        var dumped = ""
        dump(value, to: &dumped)
        return [String(describing: value), String(reflecting: value), "\(value)", dumped]
    }

    @Test("Upstream proxy descriptions hide host, port and credentials", arguments: proxies)
    func upstreamProxyIsRedacted(proxy: TorConfiguration.UpstreamProxy) {
        for rendering in Self.renderings(of: proxy) {
            for secret in Self.secrets {
                #expect(!rendering.contains(secret), "\(secret) leaked in \(rendering)")
            }
        }
    }

    @Test("A configuration's description hides its upstream proxy")
    func configurationIsRedacted() {
        let config = TorConfiguration(
            dataDirectory: URL(fileURLWithPath: "/tmp/tor"),
            upstreamProxy: Self.proxies[1]
        )
        for rendering in Self.renderings(of: config) {
            for secret in Self.secrets {
                #expect(!rendering.contains(secret), "\(secret) leaked in \(rendering)")
            }
        }
        // The command line itself does carry them, which is why it is never logged.
        let arguments = TorService.arguments(for: config)
        #expect(arguments.contains("s3cr3t-pass"))
    }

    @Test("Config settings and control commands describe keys and verbs only")
    func settingsAndCommandsAreRedacted() throws {
        let settings = try #require(Self.proxies[0].settings)
        let command = try TorControlCommand.setConf(settings)
        #expect(command.line.contains("s3cr3t-pass"))
        for value in [settings as Any, command as Any] {
            for rendering in Self.renderings(of: value) {
                for secret in Self.secrets {
                    #expect(!rendering.contains(secret), "\(secret) leaked in \(rendering)")
                }
            }
        }
        #expect(String(describing: command) == "SETCONF")
        #expect(TorConfigSetting("HTTPSProxy", nil).description == "HTTPSProxy (reset)")
        #expect(TorConfigSetting("HTTPSProxy", "h:1").description == "HTTPSProxy=<redacted>")
    }
}

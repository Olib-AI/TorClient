// TorControlProtocol.swift
// Pure (I/O-free) pieces of the Tor control protocol: reply parsing, command
// building with input validation, and helpers that interpret GETINFO/GETCONF
// answers. Everything here is deterministic so it can be unit tested without
// a running Tor. Grammar: tor control-spec, "Replies" / "Commands".
// StealthOS - stealthos.app

import Foundation

// MARK: - Reply Model

/// One line of a control-port reply.
public struct TorControlReplyLine: Sendable, Equatable {
    /// `-` (more lines follow), `+` (a dot-terminated data block follows) or
    /// ` ` (final line of the reply).
    public enum Kind: Sendable, Equatable {
        case mid
        case data
        case end
    }

    public let statusCode: Int
    public let kind: Kind
    /// Text after the separator, e.g. `version=0.4.9.14` or `OK`.
    public let text: String
    /// Lines of the data block for `.data` lines (dot-unstuffed, terminator
    /// removed). Always empty for `.mid` and `.end`.
    public let data: [String]

    public init(statusCode: Int, kind: Kind, text: String, data: [String] = []) {
        self.statusCode = statusCode
        self.kind = kind
        self.text = text
        self.data = data
    }
}

/// A complete control-port reply (synchronous answer or asynchronous event).
public struct TorControlReply: Sendable, Equatable {
    public let statusCode: Int
    /// Every line of the reply; the last one is always `.end`.
    public let lines: [TorControlReplyLine]

    public init(statusCode: Int, lines: [TorControlReplyLine]) {
        self.statusCode = statusCode
        self.lines = lines
    }

    /// `2xx`: the command was accepted.
    public var isSuccess: Bool { (200..<300).contains(statusCode) }

    /// `6xx`: an asynchronous event, not the answer to a command.
    public var isAsynchronousEvent: Bool { (600..<700).contains(statusCode) }

    /// Text of the final line (e.g. `OK`, or Tor's error message for `5xx`).
    public var message: String { lines.last?.text ?? "" }

    /// `keyword=value` pairs of a GETINFO / GETCONF reply. Data-block values
    /// (`250+key=` followed by lines) are joined with `\n`. A bare keyword
    /// without `=` (GETCONF for an option at its default) maps to `""`.
    /// The terminating `250 OK` of GETINFO is not a pair and is skipped.
    public var keyValues: [String: String] {
        var result: [String: String] = [:]
        for line in lines {
            guard let separator = line.text.firstIndex(of: "=") else {
                let isTerminator = line.kind == .end && line.text == "OK"
                if !isTerminator, !line.text.isEmpty { result[line.text] = "" }
                continue
            }
            let key = String(line.text[..<separator])
            let inlineValue = String(line.text[line.text.index(after: separator)...])
            result[key] = line.kind == .data ? line.data.joined(separator: "\n") : inlineValue
        }
        return result
    }
}

// MARK: - Parser

/// Why a byte stream is not a valid control-port reply. Once the parser
/// reports one of these the stream position is unknown, so the connection
/// must be treated as desynchronized.
public enum TorControlProtocolError: Error, Sendable, Equatable {
    /// A line does not start with a 3-digit status code and a valid separator.
    case malformedLine(String)
    /// A single line exceeded `Limits.maxLineBytes` (with or without its LF).
    case lineTooLong(limit: Int)
    /// A reply exceeded `Limits.maxReplyBytes` before it was complete.
    case replyTooLarge(limit: Int)
    /// Lines inside one reply carried different status codes (control-spec
    /// guarantees they share one).
    case inconsistentStatusCodes(expected: Int, found: Int)
    /// A line was not valid UTF-8.
    case invalidEncoding
}

public enum TorControlReplyParser {
    public struct Limits: Sendable, Equatable {
        public var maxLineBytes: Int
        public var maxReplyBytes: Int

        public init(maxLineBytes: Int = 64 * 1024, maxReplyBytes: Int = 1024 * 1024) {
            self.maxLineBytes = maxLineBytes
            self.maxReplyBytes = maxReplyBytes
        }

        public static let `default` = Limits()
    }

    public enum Outcome: Sendable, Equatable {
        /// The buffer holds only the beginning of a reply.
        case incomplete
        /// A full reply was parsed from the first `consumedBytes` bytes.
        case reply(TorControlReply, consumedBytes: Int)
        /// The buffer cannot be a valid reply.
        case failure(TorControlProtocolError)
    }

    private static let lf: UInt8 = 0x0A
    private static let cr: UInt8 = 0x0D
    private static let dot: UInt8 = 0x2E

    /// Parses the first reply at the start of `buffer`. Pure: the same input
    /// always produces the same outcome; nothing is consumed or retained.
    /// Lines end in CRLF (a bare LF is tolerated).
    public static func parse(_ buffer: ArraySlice<UInt8>, limits: Limits = .default) -> Outcome {
        let start = buffer.startIndex
        var cursor = start
        var lines: [TorControlReplyLine] = []
        var replyCode: Int?
        var dataHeader: (code: Int, text: String)?
        var dataLines: [String] = []

        while true {
            guard let newline = buffer[cursor...].firstIndex(of: lf) else {
                let pending = buffer.endIndex - cursor
                if pending > limits.maxLineBytes { return .failure(.lineTooLong(limit: limits.maxLineBytes)) }
                if buffer.endIndex - start > limits.maxReplyBytes { return .failure(.replyTooLarge(limit: limits.maxReplyBytes)) }
                return .incomplete
            }
            var lineEnd = newline
            if lineEnd > cursor, buffer[lineEnd - 1] == cr { lineEnd -= 1 }
            let lineBytes = buffer[cursor..<lineEnd]
            if lineBytes.count > limits.maxLineBytes { return .failure(.lineTooLong(limit: limits.maxLineBytes)) }
            cursor = newline + 1
            if cursor - start > limits.maxReplyBytes { return .failure(.replyTooLarge(limit: limits.maxReplyBytes)) }

            if let header = dataHeader {
                if lineBytes.count == 1, lineBytes.first == dot {
                    lines.append(TorControlReplyLine(statusCode: header.code, kind: .data, text: header.text, data: dataLines))
                    dataHeader = nil
                    dataLines = []
                    continue
                }
                // Dot-stuffing: a data line starting with "." was sent as "..".
                let unstuffed = lineBytes.first == dot ? lineBytes.dropFirst() : lineBytes
                guard let text = String(validating: unstuffed, as: UTF8.self) else { return .failure(.invalidEncoding) }
                dataLines.append(text)
                continue
            }

            guard lineBytes.count >= 4 else { return .failure(.malformedLine(preview(lineBytes))) }
            let codeBytes = lineBytes.prefix(3)
            guard codeBytes.allSatisfy({ (0x30...0x39).contains($0) }) else {
                return .failure(.malformedLine(preview(lineBytes)))
            }
            let code = codeBytes.reduce(0) { $0 * 10 + Int($1 - 0x30) }
            guard (100...699).contains(code) else { return .failure(.malformedLine(preview(lineBytes))) }
            if let expected = replyCode, expected != code {
                return .failure(.inconsistentStatusCodes(expected: expected, found: code))
            }
            replyCode = code
            let separator = lineBytes[lineBytes.startIndex + 3]
            guard let text = String(validating: lineBytes.dropFirst(4), as: UTF8.self) else {
                return .failure(.invalidEncoding)
            }
            switch separator {
            case 0x2D: // "-"
                lines.append(TorControlReplyLine(statusCode: code, kind: .mid, text: text))
            case 0x2B: // "+"
                dataHeader = (code, text)
            case 0x20: // " "
                lines.append(TorControlReplyLine(statusCode: code, kind: .end, text: text))
                return .reply(TorControlReply(statusCode: code, lines: lines), consumedBytes: cursor - start)
            default:
                return .failure(.malformedLine(preview(lineBytes)))
            }
        }
    }

    /// Short, printable excerpt of an offending line for error messages.
    private static func preview(_ bytes: ArraySlice<UInt8>) -> String {
        let printable = bytes.prefix(48).map { (0x20..<0x7F).contains($0) ? Character(UnicodeScalar($0)) : "?" }
        return String(printable)
    }
}

/// Incremental reader over a control-socket byte stream: append bytes as they
/// arrive (in any chunking), then pull complete replies. After a protocol
/// error the reader stays failed, because the stream position is lost.
public struct TorControlReplyReader: Sendable {
    private var buffer: [UInt8] = []
    private var failure: TorControlProtocolError?
    public let limits: TorControlReplyParser.Limits

    public init(limits: TorControlReplyParser.Limits = .default) {
        self.limits = limits
    }

    /// Bytes received but not yet returned as part of a reply.
    public var bufferedByteCount: Int { buffer.count }

    public mutating func append(_ bytes: some Sequence<UInt8>) {
        buffer.append(contentsOf: bytes)
    }

    /// The next complete reply, `nil` if more bytes are needed.
    public mutating func nextReply() throws(TorControlProtocolError) -> TorControlReply? {
        if let failure { throw failure }
        switch TorControlReplyParser.parse(buffer[...], limits: limits) {
        case .incomplete:
            return nil
        case .reply(let reply, let consumed):
            buffer.removeFirst(consumed)
            return reply
        case .failure(let error):
            failure = error
            buffer.removeAll()
            throw error
        }
    }
}

// MARK: - Commands

/// Why a command could not be built. Commands are never sent when building
/// fails, so nothing reaches Tor.
public enum TorControlCommandError: Error, Sendable, Equatable {
    case emptyKeyList
    /// The keyword contains characters outside `[A-Za-z0-9_./:-]` or is too long.
    case invalidKeyword(String)
    /// The value contains a control character (CR, LF, NUL, ...) that could
    /// terminate or corrupt the command line.
    case invalidValue(key: String)
    case commandTooLong(limit: Int)
}

/// Signals accepted by `SIGNAL`.
public enum TorControlSignal: String, Sendable, CaseIterable {
    case newnym = "NEWNYM"
    case halt = "HALT"
    case shutdown = "SHUTDOWN"
    case reload = "RELOAD"
    case dormant = "DORMANT"
    case active = "ACTIVE"
    case clearDNSCache = "CLEARDNSCACHE"
    case heartbeat = "HEARTBEAT"
}

/// One `key=value` assignment for SETCONF. A `nil` value resets the option
/// to its default.
public struct TorConfigSetting: Sendable, Equatable {
    public let key: String
    public let value: String?

    public init(_ key: String, _ value: String?) {
        self.key = key
        self.value = value
    }
}

/// A single, validated control-port command line. Instances can only be
/// created through the factory methods, which reject any input that could
/// smuggle a second command (CR/LF) or otherwise corrupt the line.
public struct TorControlCommand: Sendable, Equatable, CustomStringConvertible {
    /// The command line without its CRLF terminator.
    public let line: String
    /// The command verb (e.g. `SETCONF`), safe to log.
    public let verb: String

    public static let maxLineBytes = 4096
    static let maxKeywordLength = 256

    private init(verb: String, line: String) throws(TorControlCommandError) {
        guard line.utf8.count + 2 <= Self.maxLineBytes else { throw .commandTooLong(limit: Self.maxLineBytes) }
        self.verb = verb
        self.line = line
    }

    /// Bytes to write on the socket.
    public var wireBytes: [UInt8] { Array(line.utf8) + [0x0D, 0x0A] }

    /// Verb only: argument values (config paths, bridge lines) stay out of logs.
    public var description: String { verb }

    public static func signal(_ signal: TorControlSignal) -> TorControlCommand {
        // Fixed uppercase alphabet from the enum: nothing to validate.
        TorControlCommand(uncheckedVerb: "SIGNAL", line: "SIGNAL \(signal.rawValue)")
    }

    public static func getInfo(_ keys: [String]) throws(TorControlCommandError) -> TorControlCommand {
        try keywordCommand(verb: "GETINFO", keys: keys)
    }

    public static func getConf(_ keys: [String]) throws(TorControlCommandError) -> TorControlCommand {
        try keywordCommand(verb: "GETCONF", keys: keys)
    }

    public static func setConf(_ settings: [TorConfigSetting]) throws(TorControlCommandError) -> TorControlCommand {
        guard !settings.isEmpty else { throw .emptyKeyList }
        var parts = ["SETCONF"]
        for setting in settings {
            try validateKeyword(setting.key)
            if let value = setting.value {
                parts.append("\(setting.key)=\(try quoted(value, key: setting.key))")
            } else {
                parts.append(setting.key)
            }
        }
        return try TorControlCommand(verb: "SETCONF", line: parts.joined(separator: " "))
    }

    private init(uncheckedVerb: String, line: String) {
        self.verb = uncheckedVerb
        self.line = line
    }

    private static func keywordCommand(verb: String, keys: [String]) throws(TorControlCommandError) -> TorControlCommand {
        guard !keys.isEmpty else { throw .emptyKeyList }
        for key in keys { try validateKeyword(key) }
        return try TorControlCommand(verb: verb, line: ([verb] + keys).joined(separator: " "))
    }

    static func validateKeyword(_ keyword: String) throws(TorControlCommandError) {
        let allowed = keyword.utf8.allSatisfy { byte in
            switch byte {
            case 0x30...0x39, 0x41...0x5A, 0x61...0x7A: return true // 0-9 A-Z a-z
            case 0x5F, 0x2E, 0x2F, 0x3A, 0x2D: return true          // _ . / : -
            default: return false
            }
        }
        guard !keyword.isEmpty, keyword.utf8.count <= maxKeywordLength, allowed else {
            throw .invalidKeyword(String(keyword.prefix(64)))
        }
    }

    /// QuotedString per control-spec: wrapped in `"`, with `\` and `"`
    /// escaped. Control characters are rejected rather than escaped so that a
    /// value can never span lines, whatever Tor's unescaping does.
    static func quoted(_ value: String, key: String) throws(TorControlCommandError) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            if scalar.value < 0x20 || scalar.value == 0x7F || (0x80...0x9F).contains(scalar.value)
                || scalar == "\u{2028}" || scalar == "\u{2029}" {
                throw .invalidValue(key: key)
            }
            if scalar == "\\" || scalar == "\"" { out.append("\\") }
            out.unicodeScalars.append(scalar)
        }
        out.append("\"")
        return out
    }
}

// MARK: - Answer Interpretation

public enum TorControlValue {
    /// Decodes a control-spec QuotedString (`"..."` with `\` escapes).
    /// Returns `nil` if `text` is not exactly one well-formed quoted string.
    public static func unquote(_ text: Substring) -> String? {
        var scanner = text.unicodeScalars[...]
        guard let value = takeQuoted(&scanner), scanner.isEmpty else { return nil }
        return value
    }

    /// Parses a GETINFO `net/listeners/socks` value: zero or more
    /// space-separated quoted `host:port` strings, e.g.
    /// `"127.0.0.1:9050" "[::1]:9050"`. `nil` on malformed input.
    public static func socksListeners(_ text: String) -> [(host: String, port: UInt16)]? {
        var scanner = text.unicodeScalars[...]
        var listeners: [(host: String, port: UInt16)] = []
        while true {
            while scanner.first == " " { scanner.removeFirst() }
            if scanner.isEmpty { return listeners }
            guard let entry = takeQuoted(&scanner) else { return nil }
            guard let colon = entry.lastIndex(of: ":"),
                  let port = UInt16(entry[entry.index(after: colon)...]), port > 0 else { return nil }
            var host = String(entry[..<colon])
            if host.hasPrefix("["), host.hasSuffix("]") { host = String(host.dropFirst().dropLast()) }
            guard !host.isEmpty else { return nil }
            listeners.append((host, port))
        }
    }

    /// `PROGRESS=` of a GETINFO `status/bootstrap-phase` value such as
    /// `NOTICE BOOTSTRAP PROGRESS=45 TAG=loading_descriptors SUMMARY="..."`.
    public static func bootstrapProgress(_ text: String) -> Int? {
        for token in text.split(separator: " ") where token.hasPrefix("PROGRESS=") {
            guard let value = Int(token.dropFirst("PROGRESS=".count)), (0...100).contains(value) else { return nil }
            return value
        }
        return nil
    }

    /// Strict `0` / `1` boolean as used by `status/circuit-established` and
    /// boolean GETCONF answers.
    public static func bool(_ text: String?) -> Bool? {
        switch text {
        case "1": return true
        case "0": return false
        default: return nil
        }
    }

    private static func takeQuoted(_ scanner: inout Substring.UnicodeScalarView) -> String? {
        guard scanner.first == "\"" else { return nil }
        scanner.removeFirst()
        var out = String.UnicodeScalarView()
        while let scalar = scanner.first {
            scanner.removeFirst()
            switch scalar {
            case "\"":
                return String(out)
            case "\\":
                guard let escaped = scanner.first else { return nil }
                scanner.removeFirst()
                switch escaped {
                case "n": out.append("\n")
                case "t": out.append("\t")
                case "r": out.append("\r")
                default: out.append(escaped)
                }
            default:
                out.append(scalar)
            }
        }
        return nil
    }
}

// MARK: - Network State Snapshot

/// What Tor reports about its network activity, gathered with one GETINFO.
public struct TorNetworkSnapshot: Sendable, Equatable {
    /// `status/circuit-established`: Tor has a working circuit. Reset to
    /// false the moment `DisableNetwork=1` is applied.
    public var circuitEstablished: Bool
    /// `network-liveness`. Only flips to "down" after circuit-build timeouts,
    /// so it stays "up" for a while after `DisableNetwork=1`; informational.
    public var networkLive: Bool
    /// `status/bootstrap-phase` PROGRESS. Stays 100 once Tor has bootstrapped
    /// once, even while the network is disabled.
    public var bootstrapProgress: Int?
    /// Open SOCKS listener ports (`net/listeners/socks`). `DisableNetwork=1`
    /// closes every SOCKS listener; with `SocksPort auto` re-enabling the
    /// network binds a NEW port.
    public var socksPorts: [UInt16]

    public static let getInfoKeys = [
        "status/circuit-established",
        "network-liveness",
        "status/bootstrap-phase",
        "net/listeners/socks",
    ]

    public init(circuitEstablished: Bool, networkLive: Bool, bootstrapProgress: Int?, socksPorts: [UInt16]) {
        self.circuitEstablished = circuitEstablished
        self.networkLive = networkLive
        self.bootstrapProgress = bootstrapProgress
        self.socksPorts = socksPorts
    }

    /// Interprets the GETINFO reply for `getInfoKeys`; `nil` if any value is
    /// missing or malformed.
    public init?(reply: TorControlReply) {
        guard reply.isSuccess else { return nil }
        let values = reply.keyValues
        guard let circuit = TorControlValue.bool(values["status/circuit-established"]),
              let liveness = values["network-liveness"], liveness == "up" || liveness == "down",
              let phase = values["status/bootstrap-phase"],
              let listenersText = values["net/listeners/socks"],
              let listeners = TorControlValue.socksListeners(listenersText) else { return nil }
        self.circuitEstablished = circuit
        self.networkLive = liveness == "up"
        self.bootstrapProgress = TorControlValue.bootstrapProgress(phase)
        self.socksPorts = listeners.map(\.port)
    }

    /// True when Tor is fully online and usable: a circuit exists and a SOCKS
    /// listener is open.
    public var isOnline: Bool { circuitEstablished && !socksPorts.isEmpty }

    /// True when the network is verifiably down from the client's point of
    /// view: no circuit and no SOCKS listener accepting connections.
    public var isOffline: Bool { !circuitEstablished && socksPorts.isEmpty }

    /// Progress to show while re-enabling the network. Tor's own bootstrap
    /// percentage is used while it is below 100; after a first successful
    /// bootstrap it stays at 100, so milestones are used instead. Never
    /// reports 100 until a circuit is actually established.
    public var reconnectProgress: Int {
        if isOnline { return 100 }
        if let progress = bootstrapProgress, progress < 100 { return max(5, min(progress, 99)) }
        if socksPorts.isEmpty { return 10 }
        return networkLive ? 75 : 50
    }
}

// MARK: - Reconnect Budget

/// Time budget for waiting on Tor that does not burn while the app is
/// suspended. On iOS a backgrounded app stops running; when it resumes, the
/// wall clock has jumped. Each poll interval is charged at most
/// `maxChargePerStep`, so a reconnect that was interrupted by backgrounding
/// keeps (almost) all of its remaining budget instead of timing out at once.
public struct TorWaitBudget: Sendable, Equatable {
    public let total: Duration
    public let maxChargePerStep: Duration
    public private(set) var consumed: Duration = .zero

    public init(total: Duration, maxChargePerStep: Duration) {
        self.total = total
        self.maxChargePerStep = maxChargePerStep
    }

    public var isExhausted: Bool { consumed >= total }

    /// Charges one step that took `elapsed` of wall-clock time.
    public mutating func charge(_ elapsed: Duration) {
        let step = min(max(elapsed, .zero), maxChargePerStep)
        consumed += step
    }
}

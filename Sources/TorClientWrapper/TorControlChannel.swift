// TorControlChannel.swift
// Request/response transport over the pre-authenticated, process-private
// control socket that tor_main_configuration_setup_control_socket() creates.
// StealthOS - stealthos.app

import Foundation

// MARK: - Errors

/// Failures of control-port operations. Every failure is reported; nothing
/// is ever treated as success without a `2xx` reply from Tor.
public enum TorControlError: Error, Sendable, Equatable, LocalizedError {
    /// No control socket (Tor not started, already stopped, or setup failed).
    case notConnected
    /// Tor closed its end of the control socket (Tor exited).
    case socketClosed
    /// No complete reply before the deadline.
    case timedOut(command: String)
    /// A socket call failed with `errno`.
    case io(command: String, errno: Int32)
    /// Tor sent bytes that are not a valid reply.
    case protocolViolation(TorControlProtocolError)
    /// An earlier protocol violation or partially written command left the
    /// stream position unknown; the channel refuses further commands.
    case desynchronized
    /// The command was refused before being sent (unsafe/invalid input).
    case invalidCommand(TorControlCommandError)
    /// Tor answered with a non-`2xx` status.
    case rejected(command: String, statusCode: Int, message: String)
    /// The operation needs Tor's network, which is disabled (soft disconnect).
    case networkDisabled
    /// Tor accepted the command but its reported state does not match.
    case verificationFailed(String)
    /// A newer disconnect/reconnect request replaced this one.
    case superseded

    public var errorDescription: String? {
        switch self {
        case .notConnected: return "Tor control socket is not available"
        case .socketClosed: return "Tor closed the control connection"
        case .timedOut(let command): return "Tor did not answer \(command) in time"
        case .io(let command, let code): return "Control socket error during \(command): \(String(cString: strerror(code)))"
        case .protocolViolation(let error): return "Malformed reply from Tor: \(error)"
        case .desynchronized: return "Tor control connection is out of sync"
        case .invalidCommand(let error): return "Refused to send unsafe control command: \(error)"
        case .rejected(let command, let code, let message): return "Tor rejected \(command) (\(code) \(message))"
        case .networkDisabled: return "Tor is disconnected"
        case .verificationFailed(let detail): return "Tor state verification failed: \(detail)"
        case .superseded: return "Cancelled by a newer connect/disconnect request"
        }
    }
}

// MARK: - Channel

/// Serializes commands on the control socket and pairs each with its reply.
///
/// Blocking socket I/O runs on a private serial queue, never on the Swift
/// cooperative pool, and every wait is bounded by `poll()` with a deadline.
/// Thread-safety follows the project's `NSLock` + `@unchecked Sendable`
/// pattern: `fd` is lock-protected (it is attached from Tor's thread);
/// `reader`, `pendingRepliesToDiscard` and `isDesynchronized` are confined to
/// `queue`.
final class TorControlChannel: @unchecked Sendable {
    private let queue = DispatchQueue(label: "ai.olib.stealthos.tor.control", qos: .userInitiated)
    private let lock = NSLock()
    private var fd: Int32 = -1

    private var reader = TorControlReplyReader()
    /// Replies still owed for commands that timed out; they are read and
    /// dropped before the next command's reply so pairing stays correct.
    private var pendingRepliesToDiscard = 0
    private var isDesynchronized = false

    var isAttached: Bool { lock.withLock { fd >= 0 } }

    var fileDescriptor: Int32 { lock.withLock { fd } }

    /// Takes ownership of `newFD` (our end of the socketpair).
    func attach(_ newFD: Int32) {
        guard newFD >= 0 else { return }
        var on: Int32 = 1
        // Writing after Tor exits must fail with EPIPE, not kill the app with SIGPIPE.
        _ = setsockopt(newFD, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        queue.sync {
            reader = TorControlReplyReader()
            pendingRepliesToDiscard = 0
            isDesynchronized = false
            let previous = lock.withLock { () -> Int32 in
                let old = fd
                fd = newFD
                return old
            }
            if previous >= 0, previous != newFD { Darwin.close(previous) }
        }
    }

    /// Closes our end. Because this is the owning controller connection,
    /// closing it makes a running Tor shut down. Runs after any in-flight
    /// command (each is bounded by its timeout).
    func close() async {
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            queue.async {
                let old = self.lock.withLock { () -> Int32 in
                    let value = self.fd
                    self.fd = -1
                    return value
                }
                if old >= 0 { Darwin.close(old) }
                self.reader = TorControlReplyReader()
                self.pendingRepliesToDiscard = 0
                self.isDesynchronized = false
                continuation.resume()
            }
        }
    }

    /// Sends `command` and returns Tor's reply (any status code; callers
    /// decide what a non-`2xx` means). Throws `TorControlError` only.
    func execute(_ command: TorControlCommand, timeout: Duration) async throws -> TorControlReply {
        try await withCheckedThrowingContinuation { (continuation: CheckedContinuation<TorControlReply, any Error>) in
            queue.async {
                continuation.resume(with: Result { try self.performBlocking(command, timeout: timeout) })
            }
        }
    }

    // MARK: Blocking I/O (queue-confined)

    private enum ReadOutcome {
        case data
        case timedOut
    }

    private func performBlocking(_ command: TorControlCommand, timeout: Duration) throws(TorControlError) -> TorControlReply {
        dispatchPrecondition(condition: .onQueue(queue))
        let fd = fileDescriptor
        guard fd >= 0 else { throw .notConnected }
        guard !isDesynchronized else { throw .desynchronized }

        let deadline = ContinuousClock.now + timeout
        try writeAll(command.wireBytes, to: fd, deadline: deadline, verb: command.verb)

        while true {
            let reply: TorControlReply?
            do {
                reply = try reader.nextReply()
            } catch {
                isDesynchronized = true
                throw .protocolViolation(error)
            }
            if let reply {
                // We never SETEVENTS, but an async event must not be mistaken for our reply.
                if reply.isAsynchronousEvent { continue }
                if pendingRepliesToDiscard > 0 {
                    pendingRepliesToDiscard -= 1
                    continue
                }
                return reply
            }
            switch try readAvailable(from: fd, deadline: deadline, verb: command.verb) {
            case .data:
                continue
            case .timedOut:
                // Our reply may still arrive later; drop it then.
                pendingRepliesToDiscard += 1
                throw .timedOut(command: command.verb)
            }
        }
    }

    private func writeAll(_ bytes: [UInt8], to fd: Int32, deadline: ContinuousClock.Instant, verb: String) throws(TorControlError) {
        var offset = 0
        while offset < bytes.count {
            var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
            let ready = poll(&pfd, 1, Self.remainingMilliseconds(until: deadline))
            if ready < 0 {
                if errno == EINTR { continue }
                throw .io(command: verb, errno: errno)
            }
            if ready == 0 {
                // A partially written line would corrupt the next command.
                if offset > 0 { isDesynchronized = true }
                throw .timedOut(command: verb)
            }
            let written = bytes.withUnsafeBufferPointer { buffer in
                Darwin.write(fd, buffer.baseAddress! + offset, buffer.count - offset)
            }
            if written < 0 {
                let code = errno
                if code == EINTR || code == EAGAIN { continue }
                if offset > 0 { isDesynchronized = true }
                if code == EPIPE || code == ECONNRESET || code == ENOTCONN { throw .socketClosed }
                throw .io(command: verb, errno: code)
            }
            offset += written
        }
    }

    private func readAvailable(from fd: Int32, deadline: ContinuousClock.Instant, verb: String) throws(TorControlError) -> ReadOutcome {
        while true {
            var pfd = pollfd(fd: fd, events: Int16(POLLIN), revents: 0)
            let ready = poll(&pfd, 1, Self.remainingMilliseconds(until: deadline))
            if ready < 0 {
                if errno == EINTR { continue }
                throw .io(command: verb, errno: errno)
            }
            if ready == 0 { return .timedOut }
            var chunk = [UInt8](repeating: 0, count: 16 * 1024)
            let count = chunk.withUnsafeMutableBufferPointer { buffer in
                Darwin.read(fd, buffer.baseAddress!, buffer.count)
            }
            if count > 0 {
                reader.append(chunk[0..<count])
                return .data
            }
            if count == 0 { throw .socketClosed }
            let code = errno
            if code == EINTR || code == EAGAIN { continue }
            if code == ECONNRESET || code == ENOTCONN { throw .socketClosed }
            throw .io(command: verb, errno: code)
        }
    }

    private static func remainingMilliseconds(until deadline: ContinuousClock.Instant) -> Int32 {
        let remaining = ContinuousClock.now.duration(to: deadline)
        guard remaining > .zero else { return 0 }
        let (seconds, attoseconds) = remaining.components
        let milliseconds = seconds * 1000 + attoseconds / 1_000_000_000_000_000 + 1
        return Int32(clamping: milliseconds)
    }
}

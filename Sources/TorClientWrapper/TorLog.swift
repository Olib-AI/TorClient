// TorLog.swift
// Unified logging for the Tor wrapper
// StealthOS - stealthos.app

import os

/// Loggers for the Tor wrapper. Never `print`: while Tor runs, the process's
/// stdout/stderr are redirected into Tor's output parser, and `print` output
/// is not subject to unified-logging privacy redaction.
///
/// Privacy rules for every call site:
/// - status codes, states and exit codes are `.public`;
/// - reply text, error descriptions, paths, hosts, ports and credentials are
///   `.private`;
/// - Tor's command line (`TorService.arguments(for:)`) and control command
///   lines are never logged at all: they can carry proxy credentials and
///   bridge lines.
enum TorLog {
    static let subsystem = "ai.olib.stealthos.torclient"

    /// `TorService` lifecycle and control-port operations.
    static let service = Logger(subsystem: subsystem, category: "TorService")
    /// The dedicated thread that runs `tor_run_main()`.
    static let thread = Logger(subsystem: subsystem, category: "TorThread")
}

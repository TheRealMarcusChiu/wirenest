import Foundation
import WireNestCore

/// Runs fixed executables with a fixed environment, no shell, and a hard deadline.
final class ProcessRunner: CommandRunning {
    private static let environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
    private static let settleAfterMarker: TimeInterval = 2

    private let outputDir: URL
    /// Commands that reported ready but kept running stay referenced so `Process` can reap them.
    private var detached: [Process] = []

    init(outputDir: URL) {
        self.outputDir = outputDir
    }

    func run(_ executable: String, _ args: [String], timeout: TimeInterval, readyMarker: String?) -> CommandResult {
        // A file rather than a pipe: a daemon that inherits a pipe would keep a reader blocked forever.
        let outputURL = outputDir.appendingPathComponent("output-\(UUID().uuidString)")
        guard FileManager.default.createFile(atPath: outputURL.path, contents: nil, attributes: [.posixPermissions: 0o600]),
              let sink = try? FileHandle(forWritingTo: outputURL) else {
            return CommandResult(status: 126, output: "Cannot capture command output.")
        }
        defer {
            try? sink.close()
            try? FileManager.default.removeItem(at: outputURL)
        }

        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = args
        process.environment = Self.environment
        process.currentDirectoryURL = URL(fileURLWithPath: "/")
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = sink
        process.standardError = sink
        let finished = DispatchSemaphore(value: 0)
        process.terminationHandler = { _ in finished.signal() }

        do {
            try process.run()
        } catch {
            return CommandResult(status: 126, output: "Cannot run \(URL(fileURLWithPath: executable).lastPathComponent).")
        }

        var deadline = Date().addingTimeInterval(timeout)
        var markerSeen = false
        while finished.wait(timeout: .now() + 0.1) == .timedOut {
            if let readyMarker, !markerSeen, readOutput(outputURL).contains(readyMarker) {
                markerSeen = true
                deadline = Date().addingTimeInterval(Self.settleAfterMarker)
            }
            if Date() >= deadline {
                if markerSeen {
                    detached.removeAll { !$0.isRunning }
                    detached.append(process)
                    return CommandResult(status: 0, output: readOutput(outputURL))
                }
                process.terminate()
                if finished.wait(timeout: .now() + 3) == .timedOut {
                    kill(process.processIdentifier, SIGKILL)
                    _ = finished.wait(timeout: .now() + 3)
                }
                return CommandResult(status: 124, output: readOutput(outputURL) + "\nTimed out after \(Int(timeout))s.")
            }
        }
        return CommandResult(status: process.terminationStatus, output: readOutput(outputURL))
    }

    private func readOutput(_ url: URL) -> String {
        guard let data = try? Data(contentsOf: url) else { return "" }
        return String(decoding: data.suffix(64 * 1024), as: UTF8.self)
    }
}

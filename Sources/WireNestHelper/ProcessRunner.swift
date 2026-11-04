import Foundation
import WireNestCore

/// Runs fixed executables with a fixed environment, no shell, a hard deadline, and each in a process
/// group of its own, so a whole command tree can be signalled without touching anything else.
final class ProcessRunner: CommandRunning {
    private static let environment = ["PATH=/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL=C"]

    private let outputDir: URL

    init(outputDir: URL) {
        self.outputDir = outputDir
        chdir("/")
    }

    func run(_ executable: String, _ args: [String], timeout: TimeInterval, readyMarker: String?) -> CommandResult {
        // A file rather than a pipe: a daemon that inherits a pipe would keep a reader blocked forever.
        let outputURL = outputDir.appendingPathComponent("output-\(UUID().uuidString)")
        let output = open(outputURL.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0o600)
        guard output >= 0 else { return CommandResult(status: 126, output: "Cannot capture command output.") }
        defer {
            close(output)
            unlink(outputURL.path)
        }

        let argv = [executable] + args
        guard let pid = spawn(argv, output: output) else {
            return CommandResult(status: 126, output: "Cannot run \(URL(fileURLWithPath: executable).lastPathComponent).")
        }

        let deadline = Date().addingTimeInterval(timeout)
        while true {
            var status: Int32 = 0
            if waitpid(pid, &status, WNOHANG) == pid {
                return CommandResult(status: exitCode(status), output: readOutput(outputURL))
            }
            // Under launchd, wg-quick's detect_launchd makes `up` block in `wait` for the monitor's whole
            // life. That fork existing is what "up" finished means in that case, and the engine then verifies it.
            if let readyMarker, readOutput(outputURL).contains(readyMarker), processes(matching: argv).count >= 2 {
                DispatchQueue.global().async {
                    var ignored: Int32 = 0
                    waitpid(pid, &ignored, 0)
                }
                return CommandResult(status: 0, output: readOutput(outputURL))
            }
            if Date() >= deadline {
                kill(-pid, SIGTERM)
                reap(pid, within: 3)
                kill(-pid, SIGKILL)
                reap(pid, within: 3)
                return CommandResult(status: 124, output: readOutput(outputURL) + "\nTimed out after \(Int(timeout))s.")
            }
            usleep(100_000)
        }
    }

    func liveProcessGroups(matching argv: [String]) -> [Int32] {
        Array(Set(processes(matching: argv).map { $0.pgid }))
    }

    func terminateProcessGroup(_ pgid: Int32) {
        // Group 0 and 1 mean "my own" and "everything". The caller only passes verified groups, but this is root.
        guard pgid > 1, pgid != getpgrp() else { return }
        kill(-pgid, SIGTERM)
    }

    func pause(_ seconds: TimeInterval) {
        Thread.sleep(forTimeInterval: seconds)
    }

    private func spawn(_ argv: [String], output: Int32) -> pid_t? {
        var attributes: posix_spawnattr_t?
        var actions: posix_spawn_file_actions_t?
        guard posix_spawnattr_init(&attributes) == 0 else { return nil }
        defer { posix_spawnattr_destroy(&attributes) }
        guard posix_spawn_file_actions_init(&actions) == 0 else { return nil }
        defer { posix_spawn_file_actions_destroy(&actions) }

        // Group 0 makes the child the leader of a new group. CLOEXEC_DEFAULT keeps root's descriptors out of the tools.
        guard posix_spawnattr_setpgroup(&attributes, 0) == 0,
              posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)) == 0,
              posix_spawn_file_actions_addopen(&actions, 0, "/dev/null", O_RDONLY, 0) == 0,
              posix_spawn_file_actions_adddup2(&actions, output, 1) == 0,
              posix_spawn_file_actions_adddup2(&actions, output, 2) == 0 else { return nil }

        let cArguments: [UnsafeMutablePointer<CChar>?] = argv.map { strdup($0) } + [nil]
        let cEnvironment: [UnsafeMutablePointer<CChar>?] = Self.environment.map { strdup($0) } + [nil]
        defer {
            cArguments.forEach { free($0) }
            cEnvironment.forEach { free($0) }
        }
        var pid: pid_t = 0
        guard posix_spawn(&pid, argv[0], &actions, &attributes, cArguments, cEnvironment) == 0 else { return nil }
        return pid
    }

    private func reap(_ pid: pid_t, within seconds: TimeInterval) {
        let deadline = Date().addingTimeInterval(seconds)
        var status: Int32 = 0
        while Date() < deadline {
            if waitpid(pid, &status, WNOHANG) == pid { return }
            usleep(100_000)
        }
    }

    /// `waitpid`'s status macros are not imported into Swift.
    private func exitCode(_ status: Int32) -> Int32 {
        status & 0x7F == 0 ? (status >> 8) & 0xFF : 128 + (status & 0x7F)
    }

    /// Root-owned processes whose whole argv matches. Requiring root stops another user's process from posing as ours.
    private func processes(matching argv: [String]) -> [(pid: pid_t, pgid: Int32)] {
        let capacity = proc_listallpids(nil, 0) + 64
        guard capacity > 64 else { return [] }
        var pids = [pid_t](repeating: 0, count: Int(capacity))
        let count = proc_listallpids(&pids, capacity * Int32(MemoryLayout<pid_t>.stride))
        guard count > 0 else { return [] }

        return pids.prefix(Int(count)).compactMap { pid in
            var info = proc_bsdinfo()
            let size = Int32(MemoryLayout<proc_bsdinfo>.stride)
            guard pid > 0, proc_pidinfo(pid, PROC_PIDTBSDINFO, 0, &info, size) == size,
                  info.pbi_ruid == 0, arguments(of: pid) == argv else { return nil }
            return (pid, Int32(info.pbi_pgid))
        }
    }

    /// KERN_PROCARGS2 is: argc as int32, the executable path, padding NULs, then each argv string.
    private func arguments(of pid: pid_t) -> [String]? {
        var mib: [Int32] = [CTL_KERN, KERN_PROCARGS2, pid]
        var size = 0
        guard sysctl(&mib, 3, nil, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }
        var buffer = [UInt8](repeating: 0, count: size)
        guard sysctl(&mib, 3, &buffer, &size, nil, 0) == 0, size > MemoryLayout<Int32>.size else { return nil }

        let argc = buffer.withUnsafeBytes { $0.load(as: Int32.self) }
        var index = MemoryLayout<Int32>.size
        while index < size, buffer[index] != 0 { index += 1 }
        while index < size, buffer[index] == 0 { index += 1 }
        var result: [String] = []
        while result.count < Int(argc), index < size {
            let start = index
            while index < size, buffer[index] != 0 { index += 1 }
            result.append(String(decoding: buffer[start..<index], as: UTF8.self))
            index += 1
        }
        return result
    }

    private func readOutput(_ url: URL) -> String {
        guard let data = try? Data(contentsOf: url) else { return "" }
        return String(decoding: data.suffix(64 * 1024), as: UTF8.self)
    }
}

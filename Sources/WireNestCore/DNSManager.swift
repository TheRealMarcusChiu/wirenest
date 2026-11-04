import Foundation

/// Connection-level DNS through `networksetup`. The original servers of every service are saved
/// to disk before the first change, because these settings survive a crash or reboot and tunnels do not.
/// An entry leaves the journal only once its service is confirmed restored.
final class DNSManager {
    private static let networksetup = "/usr/sbin/networksetup"

    private let runner: CommandRunning
    private let snapshotURL: URL

    init(runner: CommandRunning, snapshotURL: URL) {
        self.runner = runner
        self.snapshotURL = snapshotURL
    }

    /// True for an unreadable journal too: that is lost recovery information, not an absence of it.
    var isManaging: Bool { FileManager.default.fileExists(atPath: snapshotURL.path) }

    /// Services whose originals are still waiting to be restored.
    var pendingServices: [String] { (try? loadSnapshot())?.keys.sorted() ?? [] }

    /// Idempotent. Services that appeared since the last call are snapshotted first; a pending original is never replaced.
    func apply(_ servers: [String]) throws {
        var snapshot = try loadSnapshot() ?? [:]
        let services = try listServices().enabled
        var current: [String: [String]] = [:]
        for service in services {
            let existing = try getServers(service)
            current[service] = existing
            if snapshot[service] == nil { snapshot[service] = existing }
        }
        try saveSnapshot(snapshot)
        for service in services where current[service] != servers {
            try setServers(service, servers)
        }
    }

    /// Restores what it can now. A disabled service keeps its entry and is not an error: it is retried until
    /// it can be restored. Only a service that no longer exists at all is dropped, as nothing can hold its setting.
    func restore() throws {
        guard var snapshot = try loadSnapshot() else { return }
        let services = try listServices()
        var firstError: Error?
        for (service, servers) in snapshot.sorted(by: { $0.key < $1.key }) {
            if services.disabled.contains(service) { continue }
            guard services.enabled.contains(service) else {
                snapshot[service] = nil
                continue
            }
            do {
                try setServers(service, servers)
                guard try getServers(service) == servers else { throw SecureFileError("DNS servers of \(service) did not change.") }
                snapshot[service] = nil
            } catch {
                firstError = firstError ?? error
            }
        }
        if snapshot.isEmpty {
            try FileManager.default.removeItem(at: snapshotURL)
        } else {
            try saveSnapshot(snapshot)
        }
        if let firstError { throw firstError }
    }

    private func listServices() throws -> (enabled: [String], disabled: [String]) {
        let result = runner.run(Self.networksetup, ["-listallnetworkservices"], timeout: 15, readyMarker: nil)
        guard result.status == 0 else { throw SecureFileError("Cannot list network services.") }
        // The first line is an explanatory header; a leading * marks a disabled service.
        let lines = result.output.split(separator: "\n").dropFirst().map(String.init)
        return (lines.filter { !$0.hasPrefix("*") }, lines.filter { $0.hasPrefix("*") }.map { String($0.dropFirst()) })
    }

    private func getServers(_ service: String) throws -> [String] {
        let result = runner.run(Self.networksetup, ["-getdnsservers", service], timeout: 15, readyMarker: nil)
        guard result.status == 0 else { throw SecureFileError("Cannot read DNS servers of \(service).") }
        // The "there aren't any" sentence has no address in it, so filtering yields the right empty list.
        return result.output.split(separator: "\n").map(String.init).filter(isIPAddress)
    }

    private func setServers(_ service: String, _ servers: [String]) throws {
        let values = servers.isEmpty ? ["Empty"] : servers
        let result = runner.run(Self.networksetup, ["-setdnsservers", service] + values, timeout: 15, readyMarker: nil)
        guard result.status == 0 else { throw SecureFileError("Cannot set DNS servers of \(service).") }
    }

    /// Nil means no journal. An unreadable journal throws, so it is never mistaken for nothing to restore or overwritten.
    private func loadSnapshot() throws -> [String: [String]]? {
        guard isManaging else { return nil }
        do {
            return try JSONDecoder().decode([String: [String]].self, from: Data(contentsOf: snapshotURL))
        } catch {
            throw SecureFileError("The saved DNS settings at \(snapshotURL.path) cannot be read. Check your DNS settings, then remove that file.")
        }
    }

    private func saveSnapshot(_ snapshot: [String: [String]]) throws {
        try SecureFile.store(JSONEncoder().encode(snapshot), to: snapshotURL)
    }
}

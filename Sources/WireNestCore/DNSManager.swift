import Foundation

/// Connection-level DNS through `networksetup`. The original servers of every service are saved
/// to disk before the first change, because these settings survive a crash or reboot and tunnels do not.
final class DNSManager {
    private static let networksetup = "/usr/sbin/networksetup"

    private let runner: CommandRunning
    private let snapshotURL: URL

    init(runner: CommandRunning, snapshotURL: URL) {
        self.runner = runner
        self.snapshotURL = snapshotURL
    }

    var isManaging: Bool { FileManager.default.fileExists(atPath: snapshotURL.path) }

    /// Idempotent. Services that appeared since the last call are snapshotted first.
    func apply(_ servers: [String]) throws {
        var snapshot = loadSnapshot() ?? [:]
        let services = try listServices()
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

    /// Keeps the snapshot if any service could not be restored, so a later attempt can finish the job.
    func restore() throws {
        guard let snapshot = loadSnapshot() else { return }
        let existing = Set(try listServices())
        for (service, servers) in snapshot.sorted(by: { $0.key < $1.key }) where existing.contains(service) {
            try setServers(service, servers)
        }
        try FileManager.default.removeItem(at: snapshotURL)
    }

    private func listServices() throws -> [String] {
        let result = runner.run(Self.networksetup, ["-listallnetworkservices"], timeout: 15, readyMarker: nil)
        guard result.status == 0 else { throw SecureFileError("Cannot list network services.") }
        // The first line is an explanatory header; a leading * marks a disabled service.
        return result.output.split(separator: "\n").dropFirst().map(String.init).filter { !$0.hasPrefix("*") && !$0.isEmpty }
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

    private func loadSnapshot() -> [String: [String]]? {
        guard let data = try? Data(contentsOf: snapshotURL) else { return nil }
        return try? JSONDecoder().decode([String: [String]].self, from: data)
    }

    private func saveSnapshot(_ snapshot: [String: [String]]) throws {
        try SecureFile.store(JSONEncoder().encode(snapshot), to: snapshotURL)
    }
}

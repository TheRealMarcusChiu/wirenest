import Foundation

public struct CommandResult: Equatable {
    public let status: Int32
    public let output: String

    public init(status: Int32, output: String) {
        self.status = status
        self.output = output
    }
}

/// The subprocess edge. Executables are fixed paths chosen by the engine; nothing is run through a shell.
public protocol CommandRunning {
    /// `readyMarker`: treat the command as finished once its output contains this text. See `HelperEngine.up`.
    func run(_ executable: String, _ args: [String], timeout: TimeInterval, readyMarker: String?) -> CommandResult
}

public struct HelperPaths {
    public let runtimeDir: URL
    public let wireguardRunDir: URL
    public let toolsDir: URL
    public let durableDir: URL

    public init(runtimeDir: URL, wireguardRunDir: URL, toolsDir: URL, durableDir: URL) {
        self.runtimeDir = runtimeDir
        self.wireguardRunDir = wireguardRunDir
        self.toolsDir = toolsDir
        self.durableDir = durableDir
    }

    public static let production = HelperPaths(
        runtimeDir: URL(fileURLWithPath: "/var/run/com.marcuschiu.WireNest"),
        wireguardRunDir: URL(fileURLWithPath: "/var/run/wireguard"),
        toolsDir: URL(fileURLWithPath: HelperConstants.installedTools),
        durableDir: URL(fileURLWithPath: "/Library/Application Support/com.marcuschiu.WireNest")
    )

    var bash: String { toolsDir.appendingPathComponent("bash").path }
    var wgQuick: String { toolsDir.appendingPathComponent("wg-quick").path }
    var wg: String { toolsDir.appendingPathComponent("wg").path }
}

/// Everything root does for the app. All input is re-validated here, whatever the app already checked.
/// Not thread-safe: the daemon calls it from one serial queue.
public final class HelperEngine {
    private struct Session: Codable {
        var tunnels: [UUID: String] = [:]
    }

    /// wg-quick prints this after addresses, routes and the monitor are in place.
    private static let readyMarker = "Backgrounding route monitor"

    private let paths: HelperPaths
    private let runner: CommandRunning
    private let dns: DNSManager
    private var session = Session()

    private var sessionURL: URL { paths.runtimeDir.appendingPathComponent("session.json") }

    public init(paths: HelperPaths, runner: CommandRunning) throws {
        self.paths = paths
        self.runner = runner
        try SecureFile.ensurePrivateDirectory(paths.runtimeDir)
        try SecureFile.ensurePrivateDirectory(paths.durableDir)
        dns = DNSManager(runner: runner, snapshotURL: paths.durableDir.appendingPathComponent("dns-snapshot.json"))
    }

    public func handle(_ request: HelperRequest) -> HelperResponse {
        do {
            switch request {
            case .status:
                return HelperResponse(status: currentStatus())
            case .up(let id, let config):
                try up(id, configText: config)
            case .down(let id):
                try down(id)
            case .downAll:
                try downAll()
            case .setDNS(let primary, let secondary):
                try setDNS(primary: primary, secondary: secondary)
            }
            return HelperResponse(status: currentStatus())
        } catch {
            return HelperResponse(error: redactSecrets(error.localizedDescription), status: currentStatus())
        }
    }

    /// After a helper restart: re-adopt live tunnels. After a reboot none survive, so durable DNS changes are undone.
    public func recoverOnStart() {
        if let data = try? Data(contentsOf: sessionURL), let saved = try? JSONDecoder().decode(Session.self, from: data) {
            session = saved
        }
        for (id, name) in session.tunnels where realInterface(name).map(isInterfaceAlive) != true {
            forget(id, name: name)
        }
        saveSession()
        if session.tunnels.isEmpty { try? dns.restore() }
    }

    public func downAll() throws {
        var firstError: Error?
        for id in session.tunnels.keys.sorted(by: { $0.uuidString < $1.uuidString }) {
            do {
                try down(id)
            } catch {
                firstError = firstError ?? error
            }
        }
        if session.tunnels.isEmpty {
            do { try dns.restore() } catch { firstError = firstError ?? error }
        }
        if let firstError { throw firstError }
    }

    // MARK: Tunnels

    private func up(_ id: UUID, configText: String) throws {
        let config = try WireGuardConfig.parse(configText)
        if let name = session.tunnels[id] {
            let current = runningConfig(name)
            if current?.fingerprint == config.fingerprint, realInterface(name).map(isInterfaceAlive) == true { return }
            try down(id)
        }

        let others = session.tunnels.values.sorted().compactMap { name in
            runningConfig(name).map { NamedConfig(name: name, config: $0) }
        }
        let conflicts = findRouteConflicts(others + [NamedConfig(name: "new tunnel", config: config)])
        if !conflicts.isEmpty { throw RouteConflictError(conflicts: conflicts) }

        let used = Set(session.tunnels.values)
        guard let name = (0..<HelperConstants.maxTunnels).map({ "wn\($0)" }).first(where: { !used.contains($0) }) else {
            throw SecureFileError("At most \(HelperConstants.maxTunnels) tunnels can run at once.")
        }

        let conf = confURL(name)
        try? FileManager.default.removeItem(at: conf)
        try SecureFile.store(Data(config.runtimeText.utf8), to: conf)

        // Under launchd, wg-quick's detect_launchd can make `up` block in `wait` for the life of the
        // monitor. Readiness therefore comes from its output, not its exit, and a timeout means failure.
        let result = runner.run(paths.bash, [paths.wgQuick, "up", conf.path], timeout: 45, readyMarker: Self.readyMarker)
        guard result.status == 0 else {
            try? FileManager.default.removeItem(at: conf)
            if session.tunnels.isEmpty { try? dns.restore() }
            throw SecureFileError("wg-quick up failed: \(tail(result.output))")
        }
        session.tunnels[id] = name
        saveSession()
    }

    private func down(_ id: UUID) throws {
        guard let name = session.tunnels[id] else { return }
        let conf = confURL(name)
        let result = runner.run(paths.bash, [paths.wgQuick, "down", conf.path], timeout: 30, readyMarker: nil)
        if result.status != 0, realInterface(name).map(isInterfaceAlive) == true {
            throw SecureFileError("wg-quick down failed: \(tail(result.output))")
        }
        forget(id, name: name)
        saveSession()
        if session.tunnels.isEmpty { try dns.restore() }
    }

    private func forget(_ id: UUID, name: String) {
        session.tunnels[id] = nil
        try? FileManager.default.removeItem(at: confURL(name))
    }

    private func setDNS(primary: String, secondary: String) throws {
        try validateDNS(primary: primary, secondary: secondary)
        if primary.isEmpty {
            try dns.restore()
            return
        }
        guard !session.tunnels.isEmpty else { throw SecureFileError("DNS can only be managed while a tunnel is up.") }
        try dns.apply([primary, secondary].filter { !$0.isEmpty })
    }

    // MARK: Status

    private func currentStatus() -> HelperStatus {
        let tunnels = session.tunnels.sorted { $0.value < $1.value }.map { id, name -> HelperTunnelStatus in
            let fingerprint = runningConfig(name)?.fingerprint ?? ""
            guard let real = realInterface(name), let peers = peerStats(real) else {
                return HelperTunnelStatus(tunnelID: id, interface: "", fingerprint: fingerprint, alive: false, peers: [])
            }
            return HelperTunnelStatus(tunnelID: id, interface: real, fingerprint: fingerprint, alive: true, peers: peers)
        }
        return HelperStatus(protocolVersion: HelperConstants.protocolVersion, tunnels: tunnels, dnsManaged: dns.isManaging)
    }

    private func isInterfaceAlive(_ real: String) -> Bool {
        peerStats(real) != nil
    }

    /// Asks only for handshakes and counters: `wg show … dump` would print the private key.
    private func peerStats(_ real: String) -> [PeerStats]? {
        let handshakes = runner.run(paths.wg, ["show", real, "latest-handshakes"], timeout: 5, readyMarker: nil)
        let transfer = runner.run(paths.wg, ["show", real, "transfer"], timeout: 5, readyMarker: nil)
        guard handshakes.status == 0, transfer.status == 0 else { return nil }
        return parseWgShow(handshakes: handshakes.output, transfer: transfer.output)
    }

    private func realInterface(_ name: String) -> String? {
        let file = paths.wireguardRunDir.appendingPathComponent("\(name).name")
        guard let text = try? String(contentsOf: file, encoding: .utf8) else { return nil }
        let real = text.trimmingCharacters(in: .whitespacesAndNewlines)
        guard real.hasPrefix("utun"), real.count > 4, real.dropFirst(4).allSatisfy({ $0.isASCII && $0.isNumber }) else { return nil }
        return real
    }

    private func runningConfig(_ name: String) -> WireGuardConfig? {
        guard let text = try? String(contentsOf: confURL(name), encoding: .utf8) else { return nil }
        return try? WireGuardConfig.parse(text)
    }

    private func confURL(_ name: String) -> URL {
        paths.runtimeDir.appendingPathComponent("\(name).conf")
    }

    private func saveSession() {
        if let data = try? JSONEncoder().encode(session) {
            try? SecureFile.store(data, to: sessionURL)
        }
    }

    private func tail(_ output: String) -> String {
        redactSecrets(String(output.trimmingCharacters(in: .whitespacesAndNewlines).suffix(600)))
    }
}

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
    /// Each command runs in its own process group. `readyMarker`: once its output contains this text, the command
    /// also counts as finished if another process with its exact argv is alive, i.e. it has forked its daemon.
    func run(_ executable: String, _ args: [String], timeout: TimeInterval, readyMarker: String?) -> CommandResult
    /// Process groups of root-owned processes whose whole argv equals `argv`, which only this helper ever starts.
    func liveProcessGroups(matching argv: [String]) -> [Int32]
    func terminateProcessGroup(_ pgid: Int32)
    func pause(_ seconds: TimeInterval)
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
    /// The ownership journal. An entry is written before any root action on it and removed only after its
    /// resources are verified gone, so a crash at any point leaves enough to finish the job on the next start.
    private struct Entry: Codable {
        enum Phase: String, Codable { case starting, running, retiring }
        var name: String
        var phase: Phase
        var interface: String?
        /// Set when route enforcement is taking this tunnel down, so that cleanup keeps being retried and reported.
        var proofFailure: String?
    }

    /// A host route this helper added, keeping another tunnel's endpoint out of a default-route tunnel. Journaled before
    /// `route` runs and removed only once the row is verified gone or affirmatively someone else's.
    private struct EndpointRoute: Codable {
        /// `adding` is intent only: a matching row may be another writer's, so it is never promoted or deleted for matching.
        /// Only an exit 0 from our own `route add`, recorded as `installed`, makes the route ours. `removing` follows from that.
        enum Phase: String, Codable { case adding, installed, removing }
        let gateway: String
        let interface: String
        var phase: Phase
    }

    private struct Session: Codable {
        var tunnels: [UUID: Entry] = [:]
        var endpointRoutes: [String: EndpointRoute] = [:]

        private enum CodingKeys: String, CodingKey { case tunnels, endpointRoutes }

        init() {}

        /// A journal from before endpoint routes must still adopt its live tunnels.
        init(from decoder: Decoder) throws {
            let container = try decoder.container(keyedBy: CodingKeys.self)
            tunnels = try container.decode([UUID: Entry].self, forKey: .tunnels)
            endpointRoutes = try container.decodeIfPresent([String: EndpointRoute].self, forKey: .endpointRoutes) ?? [:]
        }
    }

    /// Who needs a protective route right now. Recomputed from the journal each time, so shared endpoints need no refcount.
    private struct EndpointDemand {
        /// Endpoints whose route must not be removed.
        var keep: Set<String> = []
        /// The part of `keep` this helper may add a route for. A default owner's own endpoint is wg-quick's.
        var addable: Set<String> = []
    }

    /// wg-quick prints this just before forking its route monitor.
    private static let readyMarker = "Backgrounding route monitor"
    private static let routeTool = "/sbin/route"
    private static let noRouteAdded = "No protective route was added."
    private static let routeUnconfirmed = "A protective route command ran, but its effect could not be confirmed."
    private static let routeDebtMessage = "A protective route to a tunnel's endpoint could not be confirmed or removed. It stays tracked and will be retried."
    private static let unconfirmedRouteMessage = "A route to a tunnel's endpoint may exist, but nothing shows WireNest created it, so it was not removed. A default-route tunnel cannot run beside the tunnel using that endpoint until the route is gone. Remove it by hand if nothing else needs it."
    private static let pollInterval: TimeInterval = 0.25
    private static let cleanupPolls = 80
    private static let retryCleanupPolls = 20
    private static let routeReadyPolls = 20

    private let paths: HelperPaths
    private let runner: CommandRunning
    private let dns: DNSManager
    private var session = Session()
    private var routeFailure: String?
    /// Why the last reconcile could not protect an endpoint, for the message that refusal ends in.
    private var endpointRouteProblems: [String: (reason: String, tail: String)] = [:]
    private var endpointRouteDebt: String?

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
                enforceRouteProofs()
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

    /// After a helper restart: re-adopt live running tunnels and finish anything interrupted. After a reboot
    /// none survive, so durable DNS changes are undone. What cannot be cleaned stays journaled for a retry.
    public func recoverOnStart() {
        if let data = try? Data(contentsOf: sessionURL), let saved = try? JSONDecoder().decode(Session.self, from: data) {
            session = saved
        }
        // A config with no journal entry is ours (only this helper writes this name here) but its owner was lost.
        let known = Set(session.tunnels.values.map(\.name))
        let files = (try? FileManager.default.contentsOfDirectory(atPath: paths.runtimeDir.path)) ?? []
        for name in HelperConstants.slotNames where files.contains("\(name).conf") && !known.contains(name) {
            session.tunnels[UUID()] = Entry(name: name, phase: .retiring, interface: nil)
        }
        for (id, entry) in session.tunnels {
            if entry.phase == .running, realInterface(entry.name).map(isInterfaceAlive) == true { continue }
            try? retire(id, polls: Self.cleanupPolls)
        }
        enforceRouteProofs()
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
            // Uninstall removes the journal after this, so nothing can be left for a later retry.
            reconcileEndpointRoutes()
            if let debt = endpointRouteDebt { firstError = firstError ?? SecureFileError(debt) }
        }
        if let firstError { throw firstError }
    }

    // MARK: Tunnels

    private func up(_ id: UUID, configText: String) throws {
        let config = try WireGuardConfig.parse(configText)
        if let entry = session.tunnels[id] {
            if entry.phase == .running, runningConfig(entry.name)?.fingerprint == config.fingerprint,
               realInterface(entry.name).map(isInterfaceAlive) == true {
                enforceRouteProofs()
                guard session.tunnels[id]?.phase == .running else {
                    throw SecureFileError(routeFailure ?? "This tunnel was stopped because its routes are no longer safe.")
                }
                return
            }
            try down(id)
        }

        // A monitor outliving its tunnel would act on any new tunnel that reuses its utun number
        // and delete that tunnel's routes when it exits, so nothing starts until all of them are gone.
        for (id, entry) in session.tunnels where entry.phase != .running {
            try retire(id, polls: Self.retryCleanupPolls)
        }

        let others = session.tunnels.values.map(\.name).sorted().compactMap { name in
            runningConfig(name).map { NamedConfig(name: name, config: $0) }
        }
        let newName = "new tunnel"
        let candidate = NamedConfig(name: newName, config: config)
        let assessment = assessRoutes(others + [candidate])
        if !assessment.conflicts.isEmpty { throw RouteConflictError(conflicts: assessment.conflicts) }

        let used = Set(session.tunnels.values.map(\.name))
        guard let name = HelperConstants.slotNames.first(where: { !used.contains($0) }) else {
            throw SecureFileError("At most \(HelperConstants.maxTunnels) tunnels can run at once.")
        }

        let exposures = assessment.exposures.filter { $0.tunnel == newName || $0.defaultOwner == newName }
        if !exposures.isEmpty {
            // Before any config or spawn, so the endpoint is already pinned when the capturing /1 routes appear.
            reconcileEndpointRoutes(candidate: candidate)
            // A new default owner's own endpoint only gets its route from wg-quick, so it is proved after the start.
            let managed = ownEndpoints(ofDefaultOwner: candidate) ?? []
            for exposure in exposures {
                if let failure = endpointProofFailure(exposure, deferring: exposure.defaultOwner == newName ? managed : []) {
                    reconcileEndpointRoutes()
                    throw SecureFileError(failure)
                }
            }
        }

        session.tunnels[id] = Entry(name: name, phase: .starting, interface: nil)
        do {
            try saveSession()
            let conf = confURL(name)
            try? FileManager.default.removeItem(at: conf)
            try SecureFile.store(Data(config.runtimeText.utf8), to: conf)
        } catch {
            // Nothing has run yet, so there is nothing to clean: failing here is what keeps every start tracked.
            session.tunnels[id] = nil
            try? FileManager.default.removeItem(at: confURL(name))
            try? saveSession()
            reconcileEndpointRoutes()
            throw error
        }

        let result = runner.run(paths.bash, upArguments(name), timeout: 45, readyMarker: Self.readyMarker)
        do {
            guard result.status == 0 else { throw SecureFileError("wg-quick up failed: \(tail(result.output))") }
            session.tunnels[id]?.interface = try verifiedInterface(name, config: config)
            try waitForSafeRoutes(of: name)
            session.tunnels[id]?.phase = .running
            try saveSession()
        } catch {
            do {
                try retire(id, polls: Self.cleanupPolls)
            } catch let cleanup {
                throw SecureFileError("\(error.localizedDescription) Its cleanup is also incomplete and will be retried: \(cleanup.localizedDescription)")
            }
            throw error
        }
    }

    /// The tool's own report is not proof: the device must answer with this config's peers, and its monitor must be running.
    private func verifiedInterface(_ name: String, config: WireGuardConfig) throws -> String {
        guard let real = realInterface(name),
              FileManager.default.fileExists(atPath: socketURL(real).path),
              let peers = peerStats(real) else {
            throw SecureFileError("wg-quick reported success, but its interface is not running.")
        }
        guard Set(peers.map(\.publicKey)) == Set(config.peers.map(\.publicKey)) else {
            throw SecureFileError("The started interface does not have the expected peers.")
        }
        guard !runner.liveProcessGroups(matching: quickArgv(name)).isEmpty else {
            throw SecureFileError("wg-quick reported success, but its route monitor is not running.")
        }
        return real
    }

    // MARK: Default-route safety

    /// A tunnel running beside a default-route tunnel is safe only while its endpoints are proven to stay outside it.
    private func endpointProofFailure(_ exposure: EndpointExposure, deferring: Set<String> = []) -> String? {
        guard let endpoints = currentEndpoints(of: exposure) else {
            return unsafeRouteMessage("a tunnel's endpoint", reason: "its current endpoint is unknown")
        }
        let owned = ownedInterfaces()
        for endpoint in endpoints where CIDR(endpoint)?.isIPv6 == exposure.isIPv6 {
            if exposure.isIPv6 {
                return unsafeRouteMessage(endpoint, reason: "IPv6 endpoints cannot be proved")
            }
            if deferring.contains(endpoint) { continue }
            if let reason = EndpointRouteProof.refusal(endpoint: endpoint, ownedInterfaces: owned, runner: runner) {
                if gatewayRouteProven(endpoint, ownedInterfaces: owned) { continue }
                return unsafeRouteMessage(endpoint, reason: endpointRouteProblems[endpoint]?.reason ?? reason)
            }
        }
        return nil
    }

    private func unsafeRouteMessage(_ endpoint: String, reason: String) -> String {
        let tail = endpointRouteProblems[endpoint]?.tail
            ?? (session.endpointRoutes.isEmpty ? Self.noRouteAdded : "Protective routes already added stay tracked until they can be removed.")
        return "Cannot safely run this tunnel beside the default-route tunnel: no proven physical-LAN, loopback or gateway route to \(endpoint) more specific than its /1 routes (\(reason)). \(tail)"
    }

    private func ownedInterfaces() -> Set<String> {
        Set(session.tunnels.values.compactMap { realInterface($0.name) ?? $0.interface })
    }

    /// What this device is really using. Empty only if it is really gone: failing to read it proves nothing, and its restart is checked on the way up.
    private func actualEndpoints(of entry: Entry) -> [String]? {
        guard let real = realInterface(entry.name) ?? entry.interface else { return nil }
        let result = runner.run(paths.wg, ["show", real, "endpoints"], timeout: 5, readyMarker: nil)
        if result.status == 0, let actual = parseWgEndpoints(result.output) { return actual }
        return isInterfaceAbsent(real) ? [] : nil
    }

    private func currentEndpoints(of exposure: EndpointExposure) -> [String]? {
        guard let entry = session.tunnels.values.first(where: { $0.name == exposure.tunnel }) else { return exposure.configuredEndpoints }
        return actualEndpoints(of: entry)
    }

    /// The endpoints wg-quick manages for a default-route tunnel, numeric only. Nil if a live device cannot be read.
    private func ownEndpoints(ofDefaultOwner owner: NamedConfig) -> Set<String>? {
        var hosts = Set(owner.config.peers.compactMap { peer -> String? in
            guard let host = peer.endpoint?.host, CIDR(host)?.isIPv6 == false else { return nil }
            return host
        })
        if let entry = session.tunnels.values.first(where: { $0.name == owner.name }) {
            guard let actual = actualEndpoints(of: entry) else { return nil }
            hosts.formUnion(actual)
        }
        return hosts
    }

    /// A row found exact counts only under the gateway the kernel uses now, and never while our own unconfirmed add is outstanding.
    private func gatewayRouteProven(_ endpoint: String, ownedInterfaces owned: Set<String>) -> Bool {
        guard session.endpointRoutes[endpoint]?.phase != .adding else { return false }
        let table = EndpointRouteProof.readRoutingTable(runner)
        guard let physical = EndpointRouteProof.physicalGateway(
            netstat: table,
            ifconfig: runner.run("/sbin/ifconfig", ["-a"], timeout: 5, readyMarker: nil),
            hardwarePorts: runner.run("/usr/sbin/networksetup", ["-listallhardwareports"], timeout: 15, readyMarker: nil),
            ownedInterfaces: owned
        ) else { return false }
        return EndpointRouteProof.gatewayRouteProven(
            endpoint: endpoint, via: physical, netstat: table,
            routeLookup: runner.run(Self.routeTool, ["-n", "get", "-inet", endpoint], timeout: 5, readyMarker: nil)
        )
    }

    // MARK: Endpoint routes

    /// Nil if anything needed to decide is unknown, which must never read as nobody needing a route.
    private func endpointDemand(candidate: NamedConfig?) -> EndpointDemand? {
        var named = candidate.map { [$0] } ?? []
        for entry in session.tunnels.values {
            guard let config = runningConfig(entry.name) else { return nil }
            named.append(NamedConfig(name: entry.name, config: config))
        }

        var demand = EndpointDemand()
        for exposure in assessRoutes(named).exposures where !exposure.isIPv6 {
            guard let endpoints = currentEndpoints(of: exposure)?.filter({ CIDR($0)?.isIPv6 == false }) else { return nil }
            guard !endpoints.isEmpty else { continue }
            guard let owner = named.first(where: { $0.name == exposure.defaultOwner }),
                  let managed = ownEndpoints(ofDefaultOwner: owner) else { return nil }
            demand.keep.formUnion(endpoints)
            demand.addable.formUnion(endpoints.filter { !managed.contains($0) })
        }

        // A default owner now using one of our routes would capture its own traffic if that route were removed.
        if !session.endpointRoutes.isEmpty {
            for owner in named where owner.config.table != .off && owner.config.peers.flatMap(\.allowedIPs).contains(where: { $0.isDefaultRoute && !$0.isIPv6 }) {
                guard let managed = ownEndpoints(ofDefaultOwner: owner) else { return nil }
                demand.keep.formUnion(managed.intersection(session.endpointRoutes.keys))
            }
        }
        return demand
    }

    /// The only code that changes endpoint routes. Records why it could not rather than throwing: the proof
    /// that follows every call decides what that means, and cleanup debt stays journaled and visible.
    private func reconcileEndpointRoutes(candidate: NamedConfig? = nil) {
        endpointRouteProblems = [:]
        guard let demand = endpointDemand(candidate: candidate) else {
            endpointRouteDebt = session.endpointRoutes.isEmpty ? nil : Self.routeDebtMessage
            return
        }
        if demand.addable.isEmpty && session.endpointRoutes.isEmpty {
            endpointRouteDebt = nil
            return
        }
        var settled = true
        for (endpoint, route) in session.endpointRoutes.sorted(by: { $0.key < $1.key }) where !demand.keep.contains(endpoint) {
            if !removeEndpointRoute(endpoint, route) { settled = false }
        }
        for endpoint in demand.addable.sorted() {
            if !ensureEndpointRoute(endpoint) { settled = false }
        }
        if session.endpointRoutes.values.contains(where: { $0.phase == .adding }) {
            endpointRouteDebt = Self.unconfirmedRouteMessage
        } else {
            endpointRouteDebt = settled ? nil : Self.routeDebtMessage
        }
    }

    private func recordEndpointRoute(_ endpoint: String, _ route: EndpointRoute?) -> Bool {
        let previous = session.endpointRoutes[endpoint]
        session.endpointRoutes[endpoint] = route
        do {
            try saveSession()
            return true
        } catch {
            session.endpointRoutes[endpoint] = previous
            return false
        }
    }

    /// False if a journaled route is left unsettled, as opposed to a refusal that leaves nothing behind.
    private func ensureEndpointRoute(_ endpoint: String) -> Bool {
        let problem: (String, String) -> Void = { reason, tail in self.endpointRouteProblems[endpoint] = (reason, tail) }
        let table = EndpointRouteProof.readRoutingTable(runner)
        let owned = ownedInterfaces()

        if let tracked = session.endpointRoutes[endpoint] {
            switch EndpointRouteProof.endpointRow(endpoint, gateway: tracked.gateway, interface: tracked.interface, netstat: table) {
            case .exact:
                if tracked.phase == .adding {
                    problem("a matching route exists, but nothing shows this helper created it", Self.routeUnconfirmed)
                    return false
                }
                // Left as it is even if the gateway has moved. The proof fails and stops the default first, and only then is it removed.
                if tracked.phase != .installed {
                    var installed = tracked
                    installed.phase = .installed
                    _ = recordEndpointRoute(endpoint, installed)
                }
                return true
            case .unknown:
                return false
            case .mixed:
                problem("another route to it exists beside the protective one", "Both routes were left in place.")
                return false
            case .foreign:
                // Someone else's row now, so ownership ends here and that row stays.
                _ = recordEndpointRoute(endpoint, nil)
                problem("another route to it replaced the protective one", "That route was left in place.")
                return true
            case .absent, .cloneOnly:
                guard recordEndpointRoute(endpoint, nil) else { return false }
            }
        }

        guard EndpointRouteProof.refusal(endpoint: endpoint, ownedInterfaces: owned, runner: runner) != nil else { return true }
        guard EndpointRouteProof.isProtectableEndpoint(endpoint) else {
            problem("only a numeric unicast IPv4 endpoint can get a protective route", Self.noRouteAdded)
            return true
        }
        let ifconfig = runner.run("/sbin/ifconfig", ["-a"], timeout: 5, readyMarker: nil)
        guard let physical = EndpointRouteProof.physicalGateway(
            netstat: table, ifconfig: ifconfig,
            hardwarePorts: runner.run("/usr/sbin/networksetup", ["-listallhardwareports"], timeout: 15, readyMarker: nil),
            ownedInterfaces: owned
        ) else {
            problem("the physical default gateway could not be proven", Self.noRouteAdded)
            return true
        }
        guard !EndpointRouteProof.isOnLink(endpoint, ifconfig: ifconfig) else {
            problem("it is on a connected network, which a gateway route cannot protect", Self.noRouteAdded)
            return true
        }
        guard !EndpointRouteProof.hasCoveringRoute(endpoint, netstat: table) else {
            problem("another route already covers it", Self.noRouteAdded)
            return true
        }
        switch EndpointRouteProof.endpointRow(endpoint, gateway: physical.gateway, interface: physical.interface, netstat: table) {
        case .exact:
            return true  // Not ours: the proof may rely on it, and nothing here ever deletes it.
        case .unknown:
            problem("the routing table could not be read", Self.noRouteAdded)
            return true
        case .foreign, .mixed:
            problem("a different route to it already exists", Self.noRouteAdded)
            return true
        case .absent, .cloneOnly:
            break
        }

        guard recordEndpointRoute(endpoint, EndpointRoute(gateway: physical.gateway, interface: physical.interface, phase: .adding)) else {
            problem("its intent could not be recorded", Self.noRouteAdded)
            return true
        }
        let added = runner.run(Self.routeTool, ["-q", "-n", "add", "-inet", endpoint, "-gateway", physical.gateway], timeout: 5, readyMarker: nil)
        if added.status != 0 {
            if added.status == 124 || added.status >= 128 {
                // It may or may not have happened, and an identical row could be someone else's, so only absence can settle this.
                problem("adding the route timed out", Self.routeUnconfirmed)
                return false
            }
            // A refused add leaves nothing of ours, and whatever made it fail is not ours to adopt or delete.
            _ = recordEndpointRoute(endpoint, nil)
            problem("the route could not be added", Self.noRouteAdded)
            return true
        }
        // The receipt comes before any read-back. If it cannot be recorded this stays `adding`, and no later poll upgrades it.
        guard recordEndpointRoute(endpoint, EndpointRoute(gateway: physical.gateway, interface: physical.interface, phase: .installed)) else {
            problem("creating the route could not be recorded", Self.routeUnconfirmed)
            return false
        }
        switch EndpointRouteProof.endpointRow(endpoint, gateway: physical.gateway, interface: physical.interface, netstat: EndpointRouteProof.readRoutingTable(runner)) {
        case .exact:
            return true
        case .unknown, .mixed:
            problem("the added route could not be read back unambiguously", Self.routeUnconfirmed)
            return false
        case .absent, .cloneOnly, .foreign:
            _ = recordEndpointRoute(endpoint, nil)
            problem("the added route did not take effect", Self.routeUnconfirmed)
            return true
        }
    }

    /// True once nothing of ours remains. Deletes only a row we confirmed creating, exactly as recorded and read immediately before.
    private func removeEndpointRoute(_ endpoint: String, _ route: EndpointRoute) -> Bool {
        guard EndpointRouteProof.isProtectableEndpoint(endpoint), CIDR(route.gateway)?.isIPv6 == false, !route.gateway.contains("/") else { return false }
        func rowNow() -> EndpointRowState {
            EndpointRouteProof.endpointRow(endpoint, gateway: route.gateway, interface: route.interface, netstat: EndpointRouteProof.readRoutingTable(runner))
        }
        switch rowNow() {
        case .unknown, .mixed:
            return false
        case .absent, .cloneOnly, .foreign:
            return recordEndpointRoute(endpoint, nil)
        case .exact:
            guard route.phase != .adding else { return false }
        }
        var removing = route
        removing.phase = .removing
        guard recordEndpointRoute(endpoint, removing) else { return false }
        // The verification below decides, not this exit status.
        _ = runner.run(Self.routeTool, ["-q", "-n", "delete", "-inet", endpoint, route.gateway], timeout: 5, readyMarker: nil)
        switch rowNow() {
        case .unknown, .exact, .mixed:
            return false
        case .absent, .cloneOnly, .foreign:
            return recordEndpointRoute(endpoint, nil)
        }
    }

    /// A running device and a ready marker say nothing about routes. A new tunnel of a pair runs only once
    /// the kernel shows its routes in effect and every endpoint is still proven with them in place.
    private func waitForSafeRoutes(of name: String) throws {
        let named = session.tunnels.values.filter { $0.phase != .retiring }.map(\.name).sorted().compactMap { name in
            runningConfig(name).map { NamedConfig(name: name, config: $0) }
        }
        let exposures = assessRoutes(named).exposures.filter { $0.tunnel == name || $0.defaultOwner == name }
        guard !exposures.isEmpty else { return }

        var failure: String?
        for poll in 0...Self.routeReadyPolls {
            failure = routeEffectFailure(exposures) ?? exposures.compactMap { endpointProofFailure($0) }.first
            if failure == nil { return }
            if poll < Self.routeReadyPolls { runner.pause(Self.pollInterval) }
        }
        throw SecureFileError(failure ?? "The new tunnel's routes could not be confirmed.")
    }

    private func routeEffectFailure(_ exposures: [EndpointExposure]) -> String? {
        let participants = Set(exposures.filter { !$0.isIPv6 }.flatMap { [$0.tunnel, $0.defaultOwner] })
        for name in participants.sorted() {
            guard let config = runningConfig(name), config.table != .off, let real = realInterface(name) else { continue }
            let routes = config.peers.flatMap(\.allowedIPs).filter { !$0.isIPv6 }
            if routes.contains(where: \.isDefaultRoute) {
                let table = EndpointRouteProof.readRoutingTable(runner)
                guard table.status == 0, EndpointRouteProof.defaultExpansionsInstalled(netstat: table.output, on: real) else {
                    return "The default-route tunnel's routes did not appear on \(real). It was stopped."
                }
            }
            let narrow = routes.filter { !$0.isDefaultRoute }
            guard !narrow.isEmpty else { continue }
            // A lookup alone is one address: a /32 or a wider route on this interface would answer it the same way.
            let table = EndpointRouteProof.readRoutingTable(runner)
            for route in narrow {
                guard table.status == 0, EndpointRouteProof.routeInstalled(netstat: table.output, address: route.address, prefix: route.prefix, on: real),
                      EndpointRouteProof.lookupInterface(route.address, runner: runner) == real else {
                    return "The route \(route) is not in effect on \(real). The tunnel was stopped."
                }
            }
        }
        return nil
    }

    /// Run on every status poll and helper start, so losing the protecting route stops the default-route tunnel while the
    /// other tunnel and DNS continue. The app then retries it with backoff, and each attempt is refused until safe again.
    private func enforceRouteProofs() {
        for (id, entry) in session.tunnels where entry.phase == .retiring && entry.proofFailure != nil {
            try? retire(id, polls: Self.retryCleanupPolls)
        }
        routeFailure = session.tunnels.values.compactMap(\.proofFailure).first
        reconcileEndpointRoutes()

        let running = session.tunnels.filter { $0.value.phase == .running }
        let named = running.values.map(\.name).sorted().compactMap { name in
            runningConfig(name).map { NamedConfig(name: name, config: $0) }
        }
        for exposure in assessRoutes(named).exposures {
            guard let ownerID = session.tunnels.first(where: { $0.value.name == exposure.defaultOwner && $0.value.phase == .running })?.key,
                  let failure = endpointProofFailure(exposure) else { continue }
            routeFailure = failure
            session.tunnels[ownerID]?.proofFailure = failure
            do {
                try retire(ownerID, polls: Self.cleanupPolls)
            } catch {
                routeFailure = "\(failure) Stopping the default-route tunnel is incomplete and will be retried: \(error.localizedDescription)"
            }
        }
        routeFailure = routeFailure ?? endpointRouteDebt
    }

    private func down(_ id: UUID) throws {
        guard let phase = session.tunnels[id]?.phase else { return }
        try retire(id, polls: phase == .retiring ? Self.retryCleanupPolls : Self.cleanupPolls)
    }

    /// Takes a tunnel fully down, or throws with it still journaled and its config kept for a retry.
    private func retire(_ id: UUID, polls: Int) throws {
        guard let entry = session.tunnels[id] else { return }
        let real = realInterface(entry.name) ?? entry.interface
        session.tunnels[id]?.phase = .retiring
        session.tunnels[id]?.interface = real
        do {
            try saveSession()
        } catch {
            session.tunnels[id] = entry
            throw error
        }

        // Only an interface known to be gone skips this: unreadable stats must not leave its routes installed.
        if let named = realInterface(entry.name), !isInterfaceAbsent(named) {
            let result = runner.run(paths.bash, [paths.wgQuick, "down", confURL(entry.name).path], timeout: 30, readyMarker: nil)
            if result.status != 0, isInterfaceAlive(named) {
                // wg-quick stops before touching anything when it fails like this, so a running tunnel simply stays running.
                if entry.phase == .running {
                    session.tunnels[id]?.phase = .running
                    try saveSession()
                }
                throw SecureFileError("wg-quick down failed: \(tail(result.output))")
            }
        }
        guard waitForCleanup(name: entry.name, real: real, polls: polls) else {
            throw SecureFileError("“\(entry.name)” is still shutting down. New tunnels wait until it is gone.")
        }

        session.tunnels[id] = nil
        try? FileManager.default.removeItem(at: confURL(entry.name))
        try saveSession()
        // Only now, so a tunnel's route outlives its traffic and the default's /1 routes. A route that stays is reported as debt, not thrown: this tunnel really is gone.
        reconcileEndpointRoutes()
        if session.tunnels.isEmpty { try dns.restore() }
    }

    /// wg-quick removes the socket and returns; wireguard-go and the utun go next, and only then does the
    /// route monitor notice, delete its routes and exit. Only that exit and the utun being gone prove cleanup.
    /// Anything less stays a failure, even if the utun might now be another app's: a utun number proves no owner.
    private func waitForCleanup(name: String, real: String?, polls: Int) -> Bool {
        let argv = quickArgv(name)
        for poll in 0...polls {
            let groups = runner.liveProcessGroups(matching: argv)
            let deviceGone = real.map { !isInterfaceAlive($0) && isInterfaceAbsent($0) } ?? true
            if groups.isEmpty, deviceGone {
                // Only our own slot's file. A socket is named by utun number, which another app may hold by now.
                try? FileManager.default.removeItem(at: nameURL(name))
                return true
            }
            // A monitor's group also holds its wireguard-go, and the monitor's trap deletes its routes.
            if poll == polls / 2 {
                for group in groups { runner.terminateProcessGroup(group) }
            }
            runner.pause(Self.pollInterval)
        }
        return false
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
        let tunnels = session.tunnels.sorted { $0.value.name < $1.value.name }.map { id, entry -> HelperTunnelStatus in
            let fingerprint = runningConfig(entry.name)?.fingerprint ?? ""
            guard let real = realInterface(entry.name), let peers = peerStats(real) else {
                return HelperTunnelStatus(tunnelID: id, interface: "", fingerprint: fingerprint, alive: false, peers: [])
            }
            return HelperTunnelStatus(tunnelID: id, interface: real, fingerprint: fingerprint, alive: true, peers: peers)
        }
        return HelperStatus(
            protocolVersion: HelperConstants.protocolVersion, tunnels: tunnels,
            dnsManaged: dns.isManaging, dnsPendingServices: dns.pendingServices, routeFailure: routeFailure
        )
    }

    /// True only on affirmative evidence. Present and unknown are treated alike by every caller: the interface may still hold routes.
    private func isInterfaceAbsent(_ real: String) -> Bool {
        EndpointRouteProof.interfacePresence(real, ifconfigAll: runner.run("/sbin/ifconfig", ["-a"], timeout: 5, readyMarker: nil)) == .absent
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
        guard let text = try? String(contentsOf: nameURL(name), encoding: .utf8) else { return nil }
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

    private func nameURL(_ name: String) -> URL {
        paths.wireguardRunDir.appendingPathComponent("\(name).name")
    }

    private func socketURL(_ real: String) -> URL {
        paths.wireguardRunDir.appendingPathComponent("\(real).sock")
    }

    private func upArguments(_ name: String) -> [String] {
        [paths.wgQuick, "up", confURL(name).path]
    }

    /// The route monitor is a fork of `wg-quick up`, so it keeps this argv after the original process has exited.
    private func quickArgv(_ name: String) -> [String] {
        [paths.bash] + upArguments(name)
    }

    private func saveSession() throws {
        try SecureFile.store(JSONEncoder().encode(session), to: sessionURL)
    }

    private func tail(_ output: String) -> String {
        redactSecrets(String(output.trimmingCharacters(in: .whitespacesAndNewlines).suffix(600)))
    }
}

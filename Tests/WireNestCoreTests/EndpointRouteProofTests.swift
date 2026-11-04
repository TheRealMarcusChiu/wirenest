import XCTest
@testable import WireNestCore

/// Verbatim outputs from GitHub-hosted macOS runners, B4 run 41761570609 at 03949ca. They are a CI host's network,
/// not the reported user's Mac, and prove only that the parser reads real Darwin output.
private enum ObservedARM64 {
    static let netstat = """
    Routing tables

    Internet:
    Destination        Gateway            Flags               Netif Expire
    default            192.168.64.1       UGScg                 en0
    127                127.0.0.1          UCS                   lo0
    127.0.0.1          127.0.0.1          UH                    lo0
    169.254            link#7             UCS                   en0      !
    192.168.64         link#7             UCS                   en0      !
    192.168.64.1/32    link#7             UCS                   en0      !
    192.168.64.1       a6:77:f3:20:33:64  UHLWIir               en0   1135
    192.168.64.8/32    link#7             UCS                   en0      !
    192.168.64.255     ff:ff:ff:ff:ff:ff  UHLWbI                en0      !
    224.0.0/4          link#7             UmCS                  en0      !
    224.0.0.251        1:0:5e:0:0:fb      UHmLWI                en0
    255.255.255.255/32 link#7             UCS                   en0      !

    """
    static let ifconfig = """
    lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
    \toptions=1203<RXCSUM,TXCSUM,TXSTATUS,SW_TIMESTAMP>
    \tinet 127.0.0.1 netmask 0xff000000
    \tinet6 ::1 prefixlen 128
    \tinet6 fe80::1%lo0 prefixlen 64 scopeid 0x1
    \tnd6 options=201<PERFORMNUD,DAD>
    gif0: flags=8010<POINTOPOINT,MULTICAST> mtu 1280
    stf0: flags=0<> mtu 1280
    anpi0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    \toptions=400<CHANNEL_IO>
    \tether 8e:54:67:ce:75:6a
    \tmedia: none
    \tstatus: inactive
    XHC12: flags=0<> mtu 0
    en1: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    \toptions=400<CHANNEL_IO>
    \tether 8e:54:67:ce:75:4a
    \tnd6 options=201<PERFORMNUD,DAD>
    \tmedia: none
    \tstatus: inactive
    en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    \toptions=400<CHANNEL_IO>
    \tether 56:ad:6e:98:31:b9
    \tinet6 fe80::10d7:af7c:9fea:758%en0 prefixlen 64 secured scopeid 0x7
    \tinet 192.168.64.8 netmask 0xffffff00 broadcast 192.168.64.255
    \tnd6 options=201<PERFORMNUD,DAD>
    \tmedia: autoselect <full-duplex,flow-control>
    \tstatus: active
    utun0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST> mtu 1380
    \tinet6 fe80::d94d:b1f9:60f8:d9dc%utun0 prefixlen 64 scopeid 0x8
    \tnd6 options=201<PERFORMNUD,DAD>

    """
    static let hardware = """

    Hardware Port: Ethernet
    Device: en0
    Ethernet Address: 56:ad:6e:98:31:b9

    Hardware Port: Ethernet Adapter (en1)
    Device: en1
    Ethernet Address: 8e:54:67:ce:75:4a

    VLAN Configurations
    ===================

    """
    static let neighbor = """
       route to: 192.168.64.2
    destination: 192.168.64.0
           mask: 255.255.255.0
      interface: en0
          flags: <UP,DONE,CLONING,STATIC>
     recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
           0         0         0         0         0         0      1500       -66

    """
    static let cachedGateway = """
       route to: 192.168.64.1
    destination: 192.168.64.1
      interface: en0
          flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFSCOPE,IFREF,ROUTER>
     recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
           0         0         0         0         0         0      1500      1135

    """
    static let loopbackNeighbor = """
       route to: 127.0.0.2
    destination: 127.0.0.0
           mask: 255.0.0.0
      interface: lo0
          flags: <UP,DONE,CLONING,STATIC>
     recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       49152     49152         0         0         0         0     16384         0

    """
    static let loopbackHost = """
       route to: 127.0.0.1
    destination: 127.0.0.1
      interface: lo0
          flags: <UP,HOST,DONE,LOCAL>
     recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
       49152     49152         0         0         0         0     16384         0

    """
    static let defaultRoute = """
       route to: default
    destination: default
           mask: default
        gateway: 192.168.64.1
      interface: en0
          flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
     recvpipe  sendpipe  ssthresh  rtt,msec    rttvar  hopcount      mtu     expire
           0         0         0         0         0         0      1500         0

    """
}

final class EndpointRouteProofReplayTests: XCTestCase {
    private func ok(_ text: String) -> CommandResult { CommandResult(status: 0, output: text) }

    private func refusal(
        _ endpoint: String, route: String, netstat: String = ObservedARM64.netstat, ifconfig: String = ObservedARM64.ifconfig,
        hardware: String = ObservedARM64.hardware, owned: Set<String> = []
    ) -> String? {
        EndpointRouteProof.refusal(
            endpoint: endpoint, routeLookup: ok(route), netstat: ok(netstat), ifconfig: ok(ifconfig), hardwarePorts: ok(hardware),
            ownedInterfaces: owned
        )
    }

    // MARK: actual observed outputs

    func testObservedConnectedParentIsProof() {
        XCTAssertNil(refusal("192.168.64.2", route: ObservedARM64.neighbor))
    }

    func testObservedCachedChildIsProofOnlyBecauseItsParentIsIndependentlyProven() {
        XCTAssertNil(refusal("192.168.64.1", route: ObservedARM64.cachedGateway))

        // Synthetic mutation of the observed table: the same child with its parent row gone.
        let withoutParent = ObservedARM64.netstat.replacingOccurrences(of: "192.168.64         link#7             UCS                   en0      !\n", with: "")
        XCTAssertNotNil(refusal("192.168.64.1", route: ObservedARM64.cachedGateway, netstat: withoutParent))
    }

    func testObservedLoopbackParentAndLocalHostAreProof() {
        XCTAssertNil(refusal("127.0.0.2", route: ObservedARM64.loopbackNeighbor))
        XCTAssertNil(refusal("127.0.0.1", route: ObservedARM64.loopbackHost))
    }

    func testObservedDefaultGatewayRouteIsNotProof() {
        XCTAssertNotNil(refusal("8.8.8.8", route: ObservedARM64.defaultRoute))
    }

    func testObservedSlash32RowIsNeverAParent() {
        // Synthetic mutation: only the observed /32 cache row of the gateway remains on en0.
        let onlyCache = ObservedARM64.netstat.replacingOccurrences(of: "192.168.64         link#7             UCS                   en0      !\n", with: "")
        let hostCache = """
           route to: 192.168.64.1
        destination: 192.168.64.1
          interface: en0
              flags: <UP,HOST,DONE,LLINFO,WASCLONED,IFREF,ROUTER>
        """
        XCTAssertNotNil(refusal("192.168.64.1", route: hostCache, netstat: onlyCache))
    }

    // MARK: synthetic mutations of the observed outputs

    func testRefusesInterfacesThatAreOursOrNotPhysical() {
        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, owned: ["en0"]), "helper-owned")

        let noPorts = "\nVLAN Configurations\n===================\n"
        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, hardware: noPorts), "'not ours' is not physical")

        let otherVPN = ObservedARM64.neighbor.replacingOccurrences(of: "interface: en0", with: "interface: utun0")
        XCTAssertNotNil(refusal("192.168.64.2", route: otherVPN), "another VPN's interface")

        let pointToPoint = ObservedARM64.ifconfig.replacingOccurrences(of: "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>", with: "en0: flags=8051<UP,POINTOPOINT,RUNNING,MULTICAST>")
        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, ifconfig: pointToPoint))

        let down = ObservedARM64.ifconfig.replacingOccurrences(of: "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST>", with: "en0: flags=8822<BROADCAST,SMART,SIMPLEX,MULTICAST>")
        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, ifconfig: down))

        let inactive = ObservedARM64.ifconfig.replacingOccurrences(of: "status: active", with: "status: inactive")
        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, ifconfig: inactive))
    }

    func testLoopbackIsAFlagNotAName() {
        let fakeLoopback = ObservedARM64.ifconfig.replacingOccurrences(of: "lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST>", with: "lo0: flags=8041<UP,RUNNING,MULTICAST>")
        XCTAssertNotNil(refusal("127.0.0.2", route: ObservedARM64.loopbackNeighbor, ifconfig: fakeLoopback))
    }

    func testRefusesRejectBlackholeGatewayAndScopedParentLookups() {
        for flags in ["REJECT", "BLACKHOLE", "GATEWAY", "IFSCOPE"] {
            let mutated = ObservedARM64.neighbor.replacingOccurrences(of: "<UP,DONE,CLONING,STATIC>", with: "<UP,DONE,CLONING,STATIC,\(flags)>")
            XCTAssertNotNil(refusal("192.168.64.2", route: mutated), flags)
        }
    }

    func testRefusesScopedOnlyOrUnclonedParentRows() {
        let parent = "192.168.64         link#7             UCS                   en0      !"
        for replacement in [
            "192.168.64         link#7             UCSI                  en0      !",
            "192.168.64         link#7             US                    en0      !",
            "192.168.64         192.168.64.1       UGCS                  en0      !",
            "192.168.64         link#7             UCS                   en1      !",
            "192.168.64/25      link#7             UCS                   en0      !",
        ] {
            let netstat = ObservedARM64.netstat.replacingOccurrences(of: parent, with: replacement)
            XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, netstat: netstat), replacement)
        }
    }

    func testRefusesPrefixNotLongerThanTheDefaultExpansion() {
        let wide = ObservedARM64.ifconfig.replacingOccurrences(of: "netmask 0xffffff00", with: "netmask 0x80000000")
        let row = ObservedARM64.netstat.replacingOccurrences(of: "192.168.64         link#7", with: "128.0/1            link#7")
        let lookup = ObservedARM64.neighbor
            .replacingOccurrences(of: "destination: 192.168.64.0", with: "destination: 128.0.0.0")
            .replacingOccurrences(of: "mask: 255.255.255.0", with: "mask: 128.0.0.0")
        XCTAssertNotNil(refusal("192.168.64.2", route: lookup, netstat: row, ifconfig: wide))
    }

    func testRefusesMalformedOrDisagreeingEvidence() {
        XCTAssertNotNil(refusal("192.168.64.2", route: "garbage"))
        XCTAssertNotNil(refusal("192.168.64.2", route: ""))
        XCTAssertNotNil(refusal("not-an-ip", route: ObservedARM64.neighbor))
        XCTAssertNotNil(refusal("fd00::1", route: ObservedARM64.neighbor), "IPv6 is not provable here")

        let badMask = ObservedARM64.ifconfig.replacingOccurrences(of: "netmask 0xffffff00", with: "netmask 0xff00ff00")
        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, ifconfig: badMask))

        let otherMask = ObservedARM64.neighbor.replacingOccurrences(of: "mask: 255.255.255.0", with: "mask: 255.255.0.0")
        XCTAssertNotNil(refusal("192.168.64.2", route: otherMask), "lookup disagrees with the interface")

        let outsideParent = ObservedARM64.neighbor
        XCTAssertNotNil(refusal("192.168.65.2", route: outsideParent), "endpoint outside the parent")

        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, netstat: "no table here"))
        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, ifconfig: ""))

        let duplicated = ObservedARM64.ifconfig + "en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500\n"
        XCTAssertNotNil(refusal("192.168.64.2", route: ObservedARM64.neighbor, ifconfig: duplicated))
    }

    func testRefusesFailedOrTimedOutCommands() {
        let timedOut = CommandResult(status: 124, output: "Timed out")
        let good = ok(ObservedARM64.netstat), lookup = ok(ObservedARM64.neighbor), config = ok(ObservedARM64.ifconfig), ports = ok(ObservedARM64.hardware)
        func refused(_ route: CommandResult, _ netstat: CommandResult, _ ifconfig: CommandResult, _ hardware: CommandResult) -> Bool {
            EndpointRouteProof.refusal(endpoint: "192.168.64.2", routeLookup: route, netstat: netstat, ifconfig: ifconfig, hardwarePorts: hardware, ownedInterfaces: []) != nil
        }
        XCTAssertFalse(refused(lookup, good, config, ports))
        XCTAssertTrue(refused(timedOut, good, config, ports))
        XCTAssertTrue(refused(lookup, timedOut, config, ports))
        XCTAssertTrue(refused(lookup, good, timedOut, ports))
        XCTAssertTrue(refused(lookup, good, config, timedOut))
    }

    // MARK: default expansions

    func testDefaultExpansionsMustBothBeOnThatInterface() {
        // Synthetic: this format is not in the B4 evidence, which has no default-capturing tunnel.
        let table = ObservedARM64.netstat + ""
        let rows = table.replacingOccurrences(of: "127                127.0.0.1", with: "0/1                utun5              USc                 utun5\n128.0/1            utun5              USc                 utun5\n127                127.0.0.1")
        XCTAssertTrue(EndpointRouteProof.defaultExpansionsInstalled(netstat: rows, on: "utun5"))
        XCTAssertFalse(EndpointRouteProof.defaultExpansionsInstalled(netstat: rows, on: "utun6"))
        XCTAssertFalse(EndpointRouteProof.defaultExpansionsInstalled(netstat: ObservedARM64.netstat, on: "utun5"))
        let half = table.replacingOccurrences(of: "127                127.0.0.1", with: "0/1                utun5              USc                 utun5\n127                127.0.0.1")
        XCTAssertFalse(EndpointRouteProof.defaultExpansionsInstalled(netstat: half, on: "utun5"))
    }

    func testInstalledRouteMustMatchNetworkPrefixAndInterfaceExactly() {
        // Synthetic rows, in the abbreviated forms of the observed table.
        let table = ObservedARM64.netstat + """
        198.18.72          utun5              USc                 utun5
        10.2/16            utun5              USc                 utun5
        198.18.73.2        utun5              UH                  utun5
        198.18.74          utun5              USIc                utun5
        198.18.75          utun5              UBSc                utun5
        198.18.76.9        link#9             UHWIi               utun5
        """
        func installed(_ address: String, _ prefix: Int, on interface: String = "utun5") -> Bool {
            EndpointRouteProof.routeInstalled(netstat: table, address: address, prefix: prefix, on: interface)
        }
        XCTAssertTrue(installed("198.18.72.0", 24))
        XCTAssertTrue(installed("198.18.72.9", 24), "AllowedIPs may carry host bits")
        XCTAssertTrue(installed("10.2.0.0", 16))
        XCTAssertTrue(installed("198.18.73.2", 32))
        XCTAssertFalse(installed("198.18.72.0", 24, on: "utun6"))
        XCTAssertFalse(installed("198.18.72.0", 25), "longer than installed")
        XCTAssertFalse(installed("198.18.72.0", 16), "shorter than installed")
        XCTAssertFalse(installed("198.18.72.5", 32), "inside the route, but not that route")
        XCTAssertFalse(installed("198.18.74.0", 24), "scoped")
        XCTAssertFalse(installed("198.18.75.0", 24), "blackhole")
        XCTAssertFalse(installed("198.18.76.9", 32), "a cached clone is not an installed route")
        XCTAssertFalse(EndpointRouteProof.routeInstalled(netstat: "no table", address: "198.18.72.0", prefix: 24, on: "utun5"))
    }

    func testWgEndpointParsing() {
        XCTAssertEqual(parseWgEndpoints("\(testKey(2))\t192.168.86.51:51820\n\(testKey(3))\t[2001:db8::1]:51820\n"), ["192.168.86.51", "2001:db8::1"])
        XCTAssertNil(parseWgEndpoints("\(testKey(2))\t(none)\n"), "unknown is not safe")
        XCTAssertNil(parseWgEndpoints(""))
        XCTAssertNil(parseWgEndpoints("garbage"))
        XCTAssertNil(parseWgEndpoints("\(testKey(2))\tvpn.example.com:51820\n"), "wg only reports resolved addresses")
    }
}

/// Real read-only commands on this Mac: no route or DNS changes. Runs in both native CI architectures.
final class EndpointRouteProofNativeTests: XCTestCase {
    /// Core cannot import the helper's ProcessRunner. Only `run` is reached, with the fixed commands of the proof.
    private final class ReadOnlyRunner: CommandRunning {
        func run(_ executable: String, _ args: [String], timeout: TimeInterval, readyMarker: String?) -> CommandResult {
            let process = Process()
            let pipe = Pipe()
            process.executableURL = URL(fileURLWithPath: executable)
            process.arguments = args
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

    private func refusal(_ endpoint: String, owned: Set<String> = []) -> String? {
        EndpointRouteProof.refusal(endpoint: endpoint, ownedInterfaces: owned, runner: ReadOnlyRunner())
    }

    func testRealLoopbackIsProven() {
        XCTAssertNil(refusal("127.0.0.2"))
        XCTAssertNil(refusal("127.0.0.1"))
    }

    func testRealLoopbackThatIsOursIsRefused() {
        XCTAssertNotNil(refusal("127.0.0.2", owned: ["lo0"]))
    }

    func testRealDocumentationAddressThroughTheDefaultRouteIsRefused() {
        XCTAssertNotNil(refusal("198.51.100.1"))
    }

    func testRealDefaultGatewayIsProvenThroughItsConnectedParent() throws {
        let lookup = ReadOnlyRunner().run("/sbin/route", ["-n", "get", "-inet", "default"], timeout: 5, readyMarker: nil)
        let gateway = lookup.output.split(separator: "\n")
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { $0.hasPrefix("gateway:") }?
            .dropFirst("gateway:".count)
            .trimmingCharacters(in: .whitespaces)
        guard let gateway, CIDR(gateway)?.isIPv6 == false else { throw XCTSkip("This Mac has no IPv4 gateway address.") }
        let onVPN = lookup.output.contains("interface: utun")
        try XCTSkipIf(onVPN, "The default route on this Mac is a VPN, so its gateway is rightly not provable.")
        XCTAssertNil(refusal(gateway))
    }
}

final class FullLANAssessmentTests: XCTestCase {
    private func named(_ name: String, _ text: String) throws -> NamedConfig {
        NamedConfig(name: name, config: try WireGuardConfig.parse(text))
    }

    /// The reported pair: a split tunnel with a numeric LAN endpoint beside a full tunnel with its own hostname.
    private let localSome = confText(address: "192.168.111.2/24", allowedIPs: "192.168.111.0/24", endpoint: "192.168.86.51:51820")
    private let airVPN = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0", endpoint: "vpn.example.com:1637")

    func testReportedPairHasNoDefiniteConflictButNeedsProofInBothOrders() throws {
        for tunnels in [[try named("local-some", localSome), try named("AirVPN", airVPN)], [try named("AirVPN", airVPN), try named("local-some", localSome)]] {
            let assessment = assessRoutes(tunnels)
            XCTAssertEqual(assessment.conflicts, [])
            XCTAssertEqual(assessment.exposures, [
                EndpointExposure(tunnel: "local-some", defaultOwner: "AirVPN", isIPv6: false, configuredEndpoints: ["192.168.86.51"]),
            ], "safe only if proved at run time")
        }
    }

    func testFullTunnelWithIPv6AlsoKeepsProofOnlyForTheFamilyThatCaptures() throws {
        let dual = confText(address: "10.128.0.2/32, fd7d::2/128", allowedIPs: "0.0.0.0/0, ::/0", endpoint: "vpn.example.com:1637")
        let assessment = assessRoutes([try named("local-some", localSome), try named("AirVPN", dual)])
        XCTAssertEqual(assessment.conflicts, [])
        XCTAssertEqual(assessment.exposures.filter { !$0.isIPv6 }.map(\.configuredEndpoints), [["192.168.86.51"]])
        XCTAssertEqual(assessment.exposures.filter { $0.isIPv6 }.map(\.configuredEndpoints), [[]], "an IPv4 endpoint cannot be captured by ::/0")
    }

    func testImportSavesAndEnablesTheReportedPair() throws {
        var state = AppState()
        let profile = state.addProfile(name: "p")
        let local = try state.importTunnel(text: localSome, name: "local-some", into: profile)
        let air = try state.importTunnel(text: airVPN, name: "AirVPN", into: profile)
        XCTAssertEqual(air.conflicts, [])
        XCTAssertTrue(state.tunnel(local.tunnelID)!.enabled)
        XCTAssertTrue(state.tunnel(air.tunnelID)!.enabled)
        try state.connect(profile, pinContext: nil, ssid: noWiFi)
        XCTAssertEqual(try state.desiredTunnels(ssid: noWiFi).count, 2)
    }

    private func kinds(_ a: String, _ b: String) throws -> [RouteConflict.Kind] {
        let found = findRouteConflicts([try named("A", a), try named("B", b)]).map(\.kind)
        XCTAssertEqual(found, findRouteConflicts([try named("B", b), try named("A", a)]).map(\.kind), "order must not matter")
        return found
    }

    func testDefiniteConflictsStayDefinite() throws {
        let full = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0")
        XCTAssertEqual(try kinds(full, confText(address: "10.2.0.2/32", allowedIPs: "0.0.0.0/0")), [.multipleDefaultRoutes])
        XCTAssertTrue(try kinds(full, confText(address: "192.168.9.2/32", allowedIPs: "0.0.0.0/1")).contains(.overlappingRoutes), "a /1 ties with the expansion")
        XCTAssertTrue(try kinds(full, confText(address: "192.168.9.2/32", allowedIPs: "128.0.0.0/1")).contains(.overlappingRoutes))
        XCTAssertTrue(try kinds(full, confText(address: "192.168.9.2/32", allowedIPs: "0.0.0.0/1, 128.0.0.0/1")).contains(.overlappingRoutes), "paired /1 is a second full capture")
    }

    func testNarrowRoutesCarriedByTheDefaultOwnerStillConflict() throws {
        let fullWithNarrow = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0, 192.168.0.0/16")
        XCTAssertTrue(try kinds(fullWithNarrow, localSome).contains(.overlappingRoutes))
    }

    func testAddressAndListenPortConflictsStay() throws {
        let inRoute = confText(address: "192.168.111.9/32", allowedIPs: "0.0.0.0/0")
        XCTAssertTrue(try kinds(inRoute, localSome).contains(.overlappingRoutes), "the owner's address inside the split route")
        let a = confText(address: "10.128.0.2/32", extraInterface: "ListenPort = 51000", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "192.168.111.2/24", extraInterface: "ListenPort = 51000", allowedIPs: "192.168.111.0/24", endpoint: "192.168.86.51:51820")
        XCTAssertEqual(try kinds(a, b), [.listenPort])
    }

    func testAnAddressOfSlash0IsNotAnInstalledDefaultRoute() throws {
        let addressOnly = confText(address: "10.1.0.2/0", allowedIPs: "10.1.0.0/24")
        XCTAssertTrue(try kinds(addressOnly, localSome).contains(.overlappingRoutes))
        XCTAssertEqual(assessRoutes([try named("A", addressOnly), try named("B", localSome)]).exposures, [])

        let full = confText(address: "10.1.0.2/0", allowedIPs: "0.0.0.0/0")
        XCTAssertTrue(try kinds(full, localSome).contains(.overlappingRoutes), "a real route beside it does not excuse that address")
    }

    func testAShortAddressBesideADefaultRouteStaysAConflict() throws {
        let full = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0")
        let shortAddress = confText(address: "192.168.111.2/1", allowedIPs: "192.168.111.0/24", endpoint: "192.168.86.51:51820")
        XCTAssertTrue(try kinds(full, shortAddress).contains(.overlappingRoutes))
    }

    func testNonDefaultEndpointCaptureStaysDefinite() throws {
        let capturing = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0, 192.168.86.0/24")
        XCTAssertTrue(try kinds(capturing, localSome).contains(.endpointCaptured))
    }

    func testTableOffOwnsNoRoutesAndKeepsAddressChecks() throws {
        let off = confText(address: "10.128.0.2/32", extraInterface: "Table = off", allowedIPs: "0.0.0.0/0")
        XCTAssertEqual(try kinds(off, localSome), [])
        XCTAssertEqual(assessRoutes([try named("A", off), try named("B", localSome)]).exposures, [])

        let sameAddress = confText(address: "192.168.111.2/24", extraInterface: "Table = off", allowedIPs: "0.0.0.0/0")
        XCTAssertEqual(try kinds(sameAddress, localSome), [.overlappingRoutes])
    }

    func testTableOffTunnelBesideADefaultStillNeedsItsEndpointProved() throws {
        let off = confText(address: "192.168.111.2/24", extraInterface: "Table = off", allowedIPs: "192.168.111.0/24", endpoint: "192.168.86.51:51820")
        let assessment = assessRoutes([try named("off", off), try named("full", airVPN)])
        XCTAssertEqual(assessment.conflicts, [])
        XCTAssertEqual(assessment.exposures.map(\.configuredEndpoints), [["192.168.86.51"]])
    }

    func testIPv6ConditionalOverlapStaysUnsupported() throws {
        let v6Full = confText(address: "fd01::2/128", allowedIPs: "::/0", endpoint: "[2001:db8::1]:51820")
        let v6Split = confText(address: "fd02::2/128", allowedIPs: "fd02::/64", endpoint: "[2001:db8::2]:51820")
        let found = try kinds(v6Full, v6Split)
        XCTAssertTrue(found.contains(.overlappingRoutes))
        XCTAssertTrue(found.contains(.endpointCaptured))
    }

    func testSplitHostnameExposedToAnotherDefaultStaysRefusedButTheOwnersOwnHostnameIsFine() throws {
        let splitWithName = confText(address: "192.168.111.2/24", allowedIPs: "192.168.111.0/24", endpoint: "lab.example.com:51820")
        XCTAssertEqual(try kinds(airVPN, splitWithName), [.endpointCaptured])
        XCTAssertEqual(try kinds(airVPN, localSome), [])
    }

    func testMissingEndpointBesideADefaultCannotWaiveTheProof() throws {
        let noEndpoint = "[Interface]\nPrivateKey = \(testKey(1))\nAddress = 192.168.111.2/24\n\n[Peer]\nPublicKey = \(testKey(2))\nAllowedIPs = 192.168.111.0/24\n"
        XCTAssertEqual(try kinds(airVPN, noEndpoint), [.endpointCaptured])
        let split = confText(address: "10.3.0.2/32", allowedIPs: "10.3.0.0/24")
        XCTAssertEqual(try kinds(split, noEndpoint), [], "with no default route there is nothing to prove")
    }

    func testNumericCrossFamilyEndpointNeedsNoProofForADefaultThatCannotCaptureIt() throws {
        let v4Full = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0")
        let v6Endpoint = confText(address: "192.168.111.2/24", allowedIPs: "192.168.111.0/24", endpoint: "[2001:db8::2]:51820")
        let assessment = assessRoutes([try named("full", v4Full), try named("split", v6Endpoint)])
        XCTAssertEqual(assessment.conflicts, [])
        XCTAssertEqual(assessment.exposures.map(\.configuredEndpoints), [[]])
    }

    func testDisjointTunnelsNeedNoProofSoExistingSmokeRoutesAreUnaffected() throws {
        let a = confText(address: "198.18.71.1/32", allowedIPs: "198.18.71.2/32", endpoint: "127.0.0.1:51000")
        let b = confText(address: "198.18.72.1/32", allowedIPs: "198.18.72.2/32", endpoint: "127.0.0.1:51001")
        XCTAssertEqual(assessRoutes([try named("a", a), try named("b", b)]), RouteAssessment(conflicts: [], exposures: []))
    }
}

final class FullLANRootTests: XCTestCase {
    private var paths: HelperPaths!
    private var commands: FakeCommands!
    private var engine: HelperEngine!

    private let localSome = confText(address: "192.168.111.2/24", allowedIPs: "192.168.111.0/24", endpoint: "192.168.86.51:51820")
    private let airVPN = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0", endpoint: "vpn.example.com:1637")
    private let local = UUID(), air = UUID()

    override func setUpWithError() throws {
        let root = try tempDirectory()
        paths = HelperPaths(
            runtimeDir: root.appendingPathComponent("run"),
            wireguardRunDir: root.appendingPathComponent("wg"),
            toolsDir: root.appendingPathComponent("tools"),
            durableDir: root.appendingPathComponent("durable")
        )
        commands = FakeCommands(paths: paths)
        commands.installSyntheticLAN()
        engine = try HelperEngine(paths: paths, runner: commands)
    }

    private func ok(_ request: HelperRequest, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(engine.handle(request).error, file: file, line: line)
    }

    private var status: HelperStatus { engine.handle(.status).status! }

    private func running(_ id: UUID) -> Bool {
        status.tunnels.contains { $0.tunnelID == id && $0.alive }
    }

    private var upCount: Int { commands.quickCalls.filter { $0[1] == "up" }.count }

    /// Synthetic: the proof's route lookup now says the LAN parent went away, leaving only the full tunnel's /1.
    private func loseLANProof() {
        commands.routeGet["192.168.86.51"] = CommandResult(status: 0, output: """
           route to: 192.168.86.51
        destination: 128.0.0.0
               mask: 128.0.0.0
          interface: utun9
              flags: <UP,DONE,STATIC>
        """)
    }

    // MARK: both orders

    func testPairStartsInBothOrdersWithProof() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        XCTAssertTrue(running(local))
        XCTAssertTrue(running(air))

        ok(.downAll)
        ok(.up(tunnelID: air, config: airVPN))
        ok(.up(tunnelID: local, config: localSome))
        XCTAssertTrue(running(local))
        XCTAssertTrue(running(air))
    }

    func testPreflightRefusesTheDefaultOwnerBeforeAnySpawn() throws {
        ok(.up(tunnelID: local, config: localSome))
        loseLANProof()
        let before = upCount
        let response = engine.handle(.up(tunnelID: air, config: airVPN))
        let error = try XCTUnwrap(response.error)
        XCTAssertEqual(upCount, before)
        XCTAssertTrue(error.contains("192.168.86.51"))
        XCTAssertTrue(error.contains("No protective route was added"))
        XCTAssertTrue(running(local), "the sibling is untouched")
    }

    func testPreflightRefusesTheSplitTunnelBeforeAnySpawn() {
        ok(.up(tunnelID: air, config: airVPN))
        loseLANProof()
        let before = upCount
        XCTAssertNotNil(engine.handle(.up(tunnelID: local, config: localSome)).error)
        XCTAssertEqual(upCount, before)
    }

    // MARK: postflight

    func testPostflightFailureRetiresOnlyTheNewDefaultOwner() {
        ok(.up(tunnelID: local, config: localSome))
        commands.onQuick = { [unowned self] action in if action == "up" { self.loseLANProof() } }
        XCTAssertNotNil(engine.handle(.up(tunnelID: air, config: airVPN)).error)
        commands.onQuick = nil
        XCTAssertFalse(status.tunnels.contains { $0.tunnelID == air })
        XCTAssertTrue(commands.slots["wn0"] != nil, "the split sibling keeps running")
        XCTAssertNil(commands.slots["wn1"], "the new tunnel's routes are gone")
    }

    func testDefaultExpansionsThatNeverAppearDoNotBecomeRunning() {
        ok(.up(tunnelID: local, config: localSome))
        commands.defaultRowsAppearAfterPauses = 100_000
        XCTAssertNotNil(engine.handle(.up(tunnelID: air, config: airVPN)).error)
        XCTAssertFalse(status.tunnels.contains { $0.tunnelID == air })
        XCTAssertNotNil(commands.slots["wn0"])
    }

    func testDelayedDefaultExpansionsAreWaitedFor() {
        ok(.up(tunnelID: local, config: localSome))
        commands.defaultRowsAppearAfterPauses = 2
        let pausesBefore = commands.pauses
        ok(.up(tunnelID: air, config: airVPN))
        XCTAssertGreaterThanOrEqual(commands.pauses - pausesBefore, 2)
        XCTAssertTrue(running(air))
    }

    func testSplitRouteThatDoesNotWinIsNotRunning() {
        ok(.up(tunnelID: air, config: airVPN))
        commands.routeGet["192.168.111.0"] = CommandResult(status: 0, output: "   route to: 192.168.111.0\n  interface: en0\n      flags: <UP,DONE>\n")
        XCTAssertNotNil(engine.handle(.up(tunnelID: local, config: localSome)).error)
        XCTAssertFalse(status.tunnels.contains { $0.tunnelID == local })
        XCTAssertTrue(running(air), "only the new tunnel is rolled back")
    }

    func testFailedPostflightCleanupKeepsTheJournal() {
        ok(.up(tunnelID: local, config: localSome))
        commands.defaultRowsAppearAfterPauses = 100_000
        commands.failDown = true
        XCTAssertNotNil(engine.handle(.up(tunnelID: air, config: airVPN)).error)
        XCTAssertTrue(status.tunnels.contains { $0.tunnelID == air }, "still owned, so it can be finished")
        XCTAssertTrue(FileManager.default.fileExists(atPath: paths.runtimeDir.appendingPathComponent("wn1.conf").path))
    }

    // MARK: running pair

    func testSameConfigUpChecksTheProofAgain() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        let calls = commands.quickCalls.count
        ok(.up(tunnelID: air, config: airVPN))
        XCTAssertEqual(commands.quickCalls.count, calls, "still proven, so nothing restarts")

        loseLANProof()
        XCTAssertNotNil(engine.handle(.up(tunnelID: air, config: airVPN)).error)
        XCTAssertFalse(status.tunnels.contains { $0.tunnelID == air })
        XCTAssertNotNil(commands.slots["wn0"])
    }

    func testRestartingEitherMemberIsCheckedEachTime() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        ok(.down(tunnelID: air))
        ok(.up(tunnelID: air, config: airVPN))
        ok(.down(tunnelID: local))
        ok(.up(tunnelID: local, config: localSome))
        XCTAssertTrue(running(local))
        XCTAssertTrue(running(air))

        ok(.down(tunnelID: local))
        loseLANProof()
        let before = upCount
        XCTAssertNotNil(engine.handle(.up(tunnelID: local, config: localSome)).error)
        XCTAssertEqual(upCount, before)
    }

    func testLostProofRetiresOnlyTheDefaultOwnerAndIsVisibleWhileDNSStaysWithTheSibling() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        let slotOfLocal = commands.slots["wn0"]!

        loseLANProof()
        let after = status
        XCTAssertFalse(after.tunnels.contains { $0.tunnelID == air })
        XCTAssertTrue(after.tunnels.contains { $0.tunnelID == local && $0.alive })
        XCTAssertTrue(after.routeFailure?.contains("192.168.86.51") == true)
        XCTAssertNil(commands.slots["wn1"])
        XCTAssertEqual(commands.slots["wn0"]!.real, slotOfLocal.real)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["9.9.9.9"], "a tunnel is still up")
    }

    func testActualEndpointIsWhatGetsProvedAfterRoaming() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        commands.routeGet["203.0.113.7"] = CommandResult(status: 0, output: """
           route to: 203.0.113.7
        destination: default
               mask: default
            gateway: 192.168.86.1
          interface: en0
              flags: <UP,GATEWAY,DONE,STATIC>
        """)
        commands.actualEndpoints["wn0"] = "\(testKey(2))\t203.0.113.7:51820\n"
        XCTAssertEqual(status.tunnels.map(\.tunnelID), [local], "the stale configured endpoint is still provable, the actual one is not")
    }

    func testRoamingToTheOtherFamilyNeedsNoProofButUnknownFailsClosed() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        commands.actualEndpoints["wn0"] = "\(testKey(2))\t[2001:db8::9]:51820\n"
        XCTAssertTrue(running(air))

        commands.actualEndpoints["wn0"] = "\(testKey(2))\t(none)\n"
        XCTAssertFalse(status.tunnels.contains { $0.tunnelID == air })
    }

    func testRecoveryEnforcesProofAndKeepsAProvenPair() throws {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        let kept = try HelperEngine(paths: paths, runner: commands)
        kept.recoverOnStart()
        XCTAssertEqual(kept.handle(.status).status?.tunnels.count, 2)

        loseLANProof()
        let recovered = try HelperEngine(paths: paths, runner: commands)
        recovered.recoverOnStart()
        XCTAssertEqual(recovered.handle(.status).status?.tunnels.map(\.tunnelID), [local])
        XCTAssertNil(commands.slots["wn1"])
    }

    func testCleanupFailureAfterLostProofStaysOwnedVisibleAndIsRetried() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        loseLANProof()
        commands.downLeavesDeviceAlive = true
        let failed = status
        XCTAssertTrue(failed.tunnels.contains { $0.tunnelID == air }, "never forgotten while its routes may remain")
        XCTAssertNotNil(failed.routeFailure)
        XCTAssertNotNil(commands.slots["wn1"])

        commands.slots["wn1"] = nil
        commands.downLeavesDeviceAlive = false
        XCTAssertFalse(status.tunnels.contains { $0.tunnelID == air }, "the next status finishes the cleanup")
    }

    func testRecoveredProofClearsTheFailure() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        loseLANProof()
        XCTAssertNotNil(status.routeFailure)

        commands.installSyntheticLAN()
        XCTAssertNil(status.routeFailure)
        ok(.up(tunnelID: air, config: airVPN))
        XCTAssertTrue(running(air))
    }

    // MARK: unreadable is not stopped

    func testStatsTimeoutNeverWaivesTheProofOfALiveSplitTunnel() {
        for failing in ["latest-handshakes", "transfer"] {
            commands.installSyntheticLAN()
            commands.wgShowTimeouts = []
            ok(.up(tunnelID: local, config: localSome))
            ok(.up(tunnelID: air, config: airVPN))

            commands.wgShowTimeouts = [failing]
            loseLANProof()
            let after = status
            XCTAssertNil(commands.slots["wn1"], "\(failing): the default route must go, even though stats could not be read")
            XCTAssertNotNil(commands.slots["wn0"], "\(failing): the split tunnel is preserved")
            XCTAssertTrue(after.tunnels.contains { $0.tunnelID == local }, failing)
            XCTAssertFalse(after.tunnels.contains { $0.tunnelID == air }, failing)
            XCTAssertTrue(after.routeFailure?.contains("192.168.86.51") == true, failing)

            commands.wgShowTimeouts = []
            commands.installSyntheticLAN()
            ok(.downAll)
        }
    }

    func testStatsTimeoutDoesNotLetTheDefaultOwnerPastPreflight() {
        ok(.up(tunnelID: local, config: localSome))
        commands.wgShowTimeouts = ["latest-handshakes"]
        loseLANProof()
        let before = upCount
        XCTAssertNotNil(engine.handle(.up(tunnelID: air, config: airVPN)).error)
        XCTAssertEqual(upCount, before, "no spawn")
        XCTAssertFalse(FileManager.default.fileExists(atPath: paths.runtimeDir.appendingPathComponent("wn1.conf").path), "no config written")
    }

    func testUnreadableEndpointsFailClosedOnALiveTunnel() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        commands.wgShowTimeouts = ["endpoints"]
        XCTAssertNotNil(status.routeFailure, "the LAN route is fine, but which endpoint is in use is not known")
        XCTAssertNil(commands.slots["wn1"])
        XCTAssertNotNil(commands.slots["wn0"])
    }

    func testOnlyAnAbsentInterfaceExemptsATunnelFromProof() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        loseLANProof()
        commands.slots["wn0"] = nil
        XCTAssertNil(status.routeFailure, "ifconfig says it is gone, so it has nothing to send")
        XCTAssertNotNil(commands.slots["wn1"])
    }

    func testAnUnknownInterfaceStateIsNotAbsence() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        commands.wgShowTimeouts = ["endpoints"]
        commands.ifconfigBroken = true
        XCTAssertNotNil(status.routeFailure)
        XCTAssertNil(commands.slots["wn1"])
    }

    func testRetiringStillRunsTheRealTeardownWhenStatsAreUnreadable() {
        ok(.up(tunnelID: air, config: airVPN))
        commands.wgShowTimeouts = ["latest-handshakes"]
        ok(.down(tunnelID: air))
        XCTAssertTrue(commands.quickCalls.contains { $0[1] == "down" })
        XCTAssertNil(commands.slots["wn0"])
    }

    // MARK: the installed route, not one lucky address

    /// The split tunnel's address is outside its AllowedIPs, so no connected route could stand in for the missing one.
    private let splitOutsideAddress = confText(address: "10.9.0.2/32", allowedIPs: "192.168.111.0/24", endpoint: "192.168.86.51:51820")

    func testAMissingNarrowRouteIsNotRunningEvenIfItsBaseAddressLooksRight() {
        for destination in ["", "192.168.111.0/32", "192.168.111/25", "192.168/16"] {
            commands.narrowRowDestination = [:]
            ok(.up(tunnelID: air, config: airVPN))
            let slotOfAir = commands.slots["wn0"]!
            commands.narrowRowDestination = ["192.168.111.0/24": destination]

            XCTAssertNotNil(engine.handle(.up(tunnelID: local, config: splitOutsideAddress)).error, destination)
            XCTAssertFalse(status.tunnels.contains { $0.tunnelID == local }, destination)
            XCTAssertNil(commands.slots["wn1"], "\(destination): only the new tunnel is retired")
            XCTAssertEqual(commands.slots["wn0"]?.real, slotOfAir.real, destination)
            XCTAssertTrue(running(air), destination)
            ok(.downAll)
        }
    }

    func testTheExactInstalledRouteIsAccepted() {
        ok(.up(tunnelID: air, config: airVPN))
        commands.narrowRowDestination = ["192.168.111.0/24": "192.168.111"]
        ok(.up(tunnelID: local, config: splitOutsideAddress))
        XCTAssertTrue(running(local))
    }

    func testTunnelsWithNoDefaultRouteNeverRunRouteCommands() {
        ok(.up(tunnelID: local, config: confText(address: "198.18.71.1/32", allowedIPs: "198.18.71.2/32", endpoint: "127.0.0.1:51000")))
        ok(.up(tunnelID: air, config: confText(address: "198.18.72.1/32", allowedIPs: "198.18.72.2/32", endpoint: "127.0.0.1:51001")))
        _ = status
        let forbidden = ["/sbin/route", "/usr/sbin/netstat"]
        XCTAssertFalse(commands.calls.contains { forbidden.contains($0.executable) })
        XCTAssertFalse(commands.calls.contains { $0.args.last == "endpoints" })
    }
}

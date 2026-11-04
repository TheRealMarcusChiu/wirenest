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

    func testInterfacePresenceComesOnlyFromACompleteListing() {
        func presence(_ name: String, _ result: CommandResult) -> InterfacePresence {
            EndpointRouteProof.interfacePresence(name, ifconfigAll: result)
        }
        let observed = ok(ObservedARM64.ifconfig)
        XCTAssertEqual(presence("en0", observed), .present)
        XCTAssertEqual(presence("utun0", observed), .present)
        XCTAssertEqual(presence("utun9", observed), .absent, "a good listing without it")

        // Synthetic mutations of the observed listing.
        XCTAssertEqual(presence("utun9", CommandResult(status: 1, output: ObservedARM64.ifconfig)), .unknown, "failed")
        XCTAssertEqual(presence("utun9", CommandResult(status: 124, output: ObservedARM64.ifconfig)), .unknown, "timed out")
        XCTAssertEqual(presence("utun9", ok("")), .unknown, "empty")
        XCTAssertEqual(presence("utun9", ok("not a listing\n")), .unknown, "malformed")
        XCTAssertEqual(presence("utun9", ok(ObservedARM64.ifconfig + "ifconfig: some warning\n")), .unknown, "stray text")
        XCTAssertEqual(presence("utun9", ok(ObservedARM64.ifconfig + "en0: flags=8863<UP> mtu 1500\n")), .unknown, "ambiguous")

        let withoutLoopback = String(ObservedARM64.ifconfig[ObservedARM64.ifconfig.range(of: "gif0:")!.lowerBound...])
        XCTAssertEqual(presence("utun9", ok(withoutLoopback)), .unknown, "cut at a line boundary: the head is what truncation loses")
        let cutMidBlock = String(ObservedARM64.ifconfig[ObservedARM64.ifconfig.range(of: "\toptions=400")!.lowerBound...])
        XCTAssertEqual(presence("utun9", ok(cutMidBlock)), .unknown, "cut inside a block")

        let padded = ObservedARM64.ifconfig + String(repeating: "\tnd6 options=201<PERFORMNUD,DAD>\n", count: HelperConstants.maxCommandOutputBytes / 32)
        XCTAssertEqual(presence("utun9", ok(padded)), .unknown, "as long as the captured limit, so possibly cut")
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

/// Everything here is synthetic: documentation addresses shaped like Darwin output, with no route ever changed for real.
final class PhysicalGatewayParsingTests: XCTestCase {
    private let table = """
    Routing tables

    Internet:
    Destination        Gateway            Flags               Netif Expire
    default            192.168.86.1       UGScg                 en0
    127                127.0.0.1          UCS                   lo0
    192.168.86         link#7             UCS                   en0      !

    """
    private let interfaces = """
    lo0: flags=8049<UP,LOOPBACK,RUNNING,MULTICAST> mtu 16384
    \tinet 127.0.0.1 netmask 0xff000000
    en0: flags=8863<UP,BROADCAST,SMART,RUNNING,SIMPLEX,MULTICAST> mtu 1500
    \tinet 192.168.86.20 netmask 0xffffff00 broadcast 192.168.86.255
    \tstatus: active

    """
    private let ports = "\nHardware Port: Wi-Fi\nDevice: en0\nEthernet Address: 00:00:00:00:00:01\n"

    private func good(_ output: String) -> CommandResult { CommandResult(status: 0, output: output) }

    private func physical(
        table tableText: String? = nil, netstat: CommandResult? = nil, interfaces interfaceText: String? = nil,
        ifconfig: CommandResult? = nil, ports portText: String? = nil, owned: Set<String> = []
    ) -> PhysicalGateway? {
        EndpointRouteProof.physicalGateway(
            netstat: netstat ?? good(tableText ?? table), ifconfig: ifconfig ?? good(interfaceText ?? interfaces),
            hardwarePorts: good(portText ?? ports), ownedInterfaces: owned
        )
    }

    func testAUniqueUnscopedDefaultOnAConnectedHardwarePortIsThePhysicalGateway() {
        XCTAssertEqual(physical(), PhysicalGateway(gateway: "192.168.86.1", interface: "en0"))
        XCTAssertEqual(physical(table: table + "default            192.168.90.1       UGScIg                en1\n"),
                       PhysicalGateway(gateway: "192.168.86.1", interface: "en0"), "a scoped default on another interface is not ambiguous")
        XCTAssertEqual(physical(table: table + "0/1 utun8 USc utun8\n128.0/1 utun8 USc utun8\n", owned: ["utun8"]),
                       PhysicalGateway(gateway: "192.168.86.1", interface: "en0"), "the kernel still lists it under our own /1 routes")
    }

    func testAnythingButThatIsNoGateway() {
        let cases: [(String, PhysicalGateway?)] = [
            ("no default", physical(table: table.replacingOccurrences(of: "default            192.168.86.1       UGScg                 en0\n", with: ""))),
            ("two unscoped defaults", physical(table: table + "default            192.168.90.1       UGScg                 en1\n")),
            ("link gateway", physical(table: table.replacingOccurrences(of: "192.168.86.1       UGScg", with: "link#7             UGScg"))),
            ("no gateway flag", physical(table: table.replacingOccurrences(of: "UGScg", with: "UScg"))),
            ("scoped only", physical(table: table.replacingOccurrences(of: "UGScg", with: "UGScIg"))),
            ("outside the connected network", physical(table: table.replacingOccurrences(of: "192.168.86.1 ", with: "192.168.99.1 "))),
            ("no connected row", physical(table: table.replacingOccurrences(of: "192.168.86         link#7             UCS                   en0      !\n", with: ""))),
            ("a foreign VPN's default", physical(table: table.replacingOccurrences(of: "UGScg                 en0", with: "UGScg                 utun3"))),
            ("our own tunnel's default", physical(table: table.replacingOccurrences(of: "UGScg                 en0", with: "UGScg                 en0"), owned: ["en0"])),
            ("a foreign /1", physical(table: table + "0/1 utun3 USc utun3\n")),
            ("not a hardware port", physical(ports: "\nHardware Port: Other\nDevice: en5\n")),
            ("not running", physical(interfaces: interfaces.replacingOccurrences(of: "RUNNING,SIMPLEX", with: "SIMPLEX"))),
            ("point to point", physical(interfaces: interfaces.replacingOccurrences(of: "BROADCAST", with: "POINTOPOINT"))),
            ("inactive", physical(interfaces: interfaces.replacingOccurrences(of: "status: active", with: "status: inactive"))),
            ("the gateway is ourselves", physical(table: table.replacingOccurrences(of: "192.168.86.1 ", with: "192.168.86.20"))),
            ("netstat failed", physical(netstat: CommandResult(status: 1, output: table))),
            ("netstat timed out", physical(netstat: CommandResult(status: 124, output: ""))),
            ("netstat cut at the capture limit", physical(netstat: good(table + String(repeating: "x", count: HelperConstants.maxCommandOutputBytes)))),
            ("netstat with its head cut off", physical(table: "192.168.86         link#7             UCS                   en0\n")),
            ("a malformed row", physical(table: table + "nonsense\n")),
            ("no header", physical(table: "Internet:\ndefault 192.168.86.1 UGScg en0\n")),
            ("ifconfig failed", physical(ifconfig: CommandResult(status: 1, output: interfaces))),
            ("ifconfig without its loopback", physical(interfaces: "en0: flags=8863<UP,RUNNING> mtu 1500\n\tinet 192.168.86.20 netmask 0xffffff00\n")),
        ]
        for (label, result) in cases { XCTAssertNil(result, label) }
    }

    func testOnlyNumericUnicastEndpointsCanBeProtected() {
        for good in ["203.0.113.50", "198.51.100.13", "10.1.2.3", "223.255.255.254"] {
            XCTAssertTrue(EndpointRouteProof.isProtectableEndpoint(good), good)
        }
        for bad in ["0.0.0.0", "0.1.2.3", "127.0.0.1", "127.77.0.2", "169.254.1.1", "224.0.0.1", "239.1.1.1", "240.0.0.1", "255.255.255.255",
                    "2001:db8::1", "::1", "vpn.example.com", "203.0.113.50/32", "203.0.113.50; id", "", "-gateway"] {
            XCTAssertFalse(EndpointRouteProof.isProtectableEndpoint(bad), bad)
        }
    }

    private func row(_ extra: String, netstat: CommandResult? = nil) -> EndpointRowState {
        EndpointRouteProof.endpointRow("203.0.113.50", gateway: "192.168.86.1", interface: "en0", netstat: netstat ?? good(table + extra))
    }

    func testEndpointRowsAreClassifiedStrictly() {
        XCTAssertEqual(row(""), .absent)
        XCTAssertEqual(row("203.0.113.50 192.168.86.1 UGHS en0\n"), .exact)
        XCTAssertEqual(row("203.0.113.50/32 192.168.86.1 UGHS en0\n"), .exact, "the same route, however it is printed")
        XCTAssertEqual(row("203.0.113.50 192.168.86.1 UGHWIig en0\n"), .cloneOnly)
        for foreign in ["203.0.113.50 192.168.86.9 UGHS en0", "203.0.113.50 192.168.86.1 UGHS en1", "203.0.113.50 link#9 UHS utun3",
                        "203.0.113.50 192.168.86.1 UGHSI en0", "203.0.113.50 192.168.86.1 UGHSB en0", "203.0.113.50 192.168.86.1 UGHSR en0",
                        "203.0.113.50 192.168.86.1 UGS en0", "203.0.113.50%en0 192.168.86.1 UGHS en0"] {
            XCTAssertEqual(row(foreign + "\n"), .foreign, foreign)
        }
        for mixed in ["203.0.113.50 192.168.86.1 UGHS en0\n203.0.113.50 192.168.86.9 UGHS en0\n",
                      "203.0.113.50 192.168.86.1 UGHS en0\n203.0.113.50 192.168.86.1 UGHSI en1\n",
                      "203.0.113.50 192.168.86.1 UGHS en0\n203.0.113.50%en1 192.168.90.1 UGHS en1\n",
                      "203.0.113.50 192.168.86.1 UGHS en0\n203.0.113.50 192.168.86.1 UGHS en0\n"] {
            XCTAssertEqual(row(mixed), .mixed, mixed)
        }
        XCTAssertEqual(row("203.0.113.50 192.168.86.1 UGHS en0\n203.0.113.50 192.168.86.1 UGHWIig en0\n"), .exact, "a clone beside it changes nothing")
        XCTAssertEqual(row("", netstat: CommandResult(status: 1, output: table)), .unknown)
        XCTAssertEqual(row("", netstat: good("no table")), .unknown)
        XCTAssertEqual(row("", netstat: good(table + "broken\n")), .unknown)
        XCTAssertEqual(row("", netstat: good(table + String(repeating: "x", count: HelperConstants.maxCommandOutputBytes))), .unknown, "a cut table cannot show absence")
    }

    func testOnlyANonClonedPrefixCoversAnEndpoint() {
        func covered(_ extra: String) -> Bool { EndpointRouteProof.hasCoveringRoute("203.0.113.50", netstat: good(table + extra)) }
        XCTAssertFalse(covered(""))
        XCTAssertFalse(covered("0/1 utun8 USc utun8\n128.0/1 utun8 USc utun8\n"), "the /1 routes are what the protective route has to beat")
        XCTAssertFalse(covered("203.0.113.50 192.168.86.1 UGHWIig en0\n"))
        XCTAssertFalse(covered("203.0.113.50 192.168.86.1 UGHS en0\n"), "the endpoint's own row is judged separately")
        XCTAssertTrue(covered("203.0.113/24 192.168.86.9 UGSc en0\n"))
        XCTAssertTrue(covered("203/8 link#9 USc utun3\n"))
        XCTAssertTrue(EndpointRouteProof.hasCoveringRoute("203.0.113.50", netstat: CommandResult(status: 1, output: "")), "unknown counts as covered")
    }

    func testAnEndpointOnAConnectedNetworkIsNotForAGatewayRoute() {
        XCTAssertTrue(EndpointRouteProof.isOnLink("192.168.86.51", ifconfig: good(interfaces)))
        XCTAssertFalse(EndpointRouteProof.isOnLink("203.0.113.50", ifconfig: good(interfaces)))
        XCTAssertTrue(EndpointRouteProof.isOnLink("203.0.113.50", ifconfig: CommandResult(status: 1, output: "")), "unknown counts as on-link")
    }

    private func proven(lookup: String, status: Int32 = 0, extra: String = "203.0.113.50 192.168.86.1 UGHS en0\n") -> Bool {
        EndpointRouteProof.gatewayRouteProven(
            endpoint: "203.0.113.50", via: PhysicalGateway(gateway: "192.168.86.1", interface: "en0"),
            netstat: good(table + extra), routeLookup: CommandResult(status: status, output: lookup)
        )
    }

    private func lookup(destination: String = "203.0.113.50", gateway: String = "192.168.86.1", interface: String = "en0",
                        flags: String = "UP,GATEWAY,HOST,DONE,STATIC", mask: String? = nil) -> String {
        "   route to: 203.0.113.50\ndestination: \(destination)\n" + (mask.map { "       mask: \($0)\n" } ?? "")
            + "    gateway: \(gateway)\n  interface: \(interface)\n      flags: <\(flags)>\n"
    }

    /// Which check failed, without changing what fails: every reason here is also a refusal by `gatewayRouteProven`.
    func testEachGatewayProofFailureHasItsOwnReason() {
        let pinned = "203.0.113.50 192.168.86.1 UGHS en0\n"
        let clone = "203.0.113.50 192.168.86.1 UGHWIig en0\n"
        let cached = "UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE"
        func failure(_ lookupText: String, status: Int32 = 0, netstat: CommandResult? = nil, extra: String? = nil) -> GatewayRouteProofFailure? {
            EndpointRouteProof.gatewayRouteFailure(
                endpoint: "203.0.113.50", via: PhysicalGateway(gateway: "192.168.86.1", interface: "en0"),
                netstat: netstat ?? good(table + (extra ?? pinned)), routeLookup: CommandResult(status: status, output: lookupText)
            )
        }
        XCTAssertNil(failure(lookup()))
        XCTAssertNil(failure(lookup(mask: "255.255.255.255")))

        let cases: [(String, GatewayRouteProofFailure, GatewayRouteProofFailure?)] = [
            ("unreadable table", .tableUnreadable, failure(lookup(), netstat: CommandResult(status: 124, output: ""))),
            ("cut table", .tableUnreadable, failure(lookup(), netstat: good(table + pinned + String(repeating: "x", count: HelperConstants.maxCommandOutputBytes)))),
            ("malformed table", .tableUnreadable, failure(lookup(), netstat: good(table + pinned + "broken\n"))),
            ("no row", .noPinnedRow, failure(lookup(), extra: "")),
            ("a clone is no pinned row", .noPinnedRow, failure(lookup(flags: cached), extra: clone)),
            ("another row", .differentRow, failure(lookup(), extra: "203.0.113.50 192.168.86.9 UGHS en0\n")),
            ("our row beside another", .ambiguousRow, failure(lookup(), extra: pinned + "203.0.113.50 192.168.90.1 UGHSI en1\n")),
            ("the same row twice", .ambiguousRow, failure(lookup(), extra: pinned + pinned)),
            ("failed lookup", .lookupFailed, failure(lookup(), status: 1)),
            ("timed out lookup", .lookupFailed, failure("", status: 124)),
            ("malformed lookup", .lookupMalformed, failure("garbage")),
            ("destination", .lookupDestination, failure(lookup(destination: "default"))),
            ("gateway", .lookupGateway, failure(lookup(gateway: "192.168.86.9"))),
            ("interface", .lookupInterface, failure(lookup(interface: "utun8"))),
            ("the row the kernel chose is cached", .lookupCached, failure(lookup(flags: cached), extra: pinned + clone)),
            ("cloned alone", .lookupCached, failure(lookup(flags: "UP,GATEWAY,HOST,DONE,STATIC,WASCLONED"))),
            ("scoped alone", .lookupCached, failure(lookup(flags: "UP,GATEWAY,HOST,DONE,STATIC,IFSCOPE"))),
            ("a cached row on the wrong gateway", .lookupGateway, failure(lookup(gateway: "192.168.86.9", flags: cached), extra: pinned + clone)),
            ("reject", .lookupRejected, failure(lookup(flags: "UP,GATEWAY,HOST,DONE,STATIC,REJECT"))),
            ("blackhole", .lookupRejected, failure(lookup(flags: "UP,GATEWAY,HOST,DONE,STATIC,BLACKHOLE"))),
            ("not static", .lookupFlags, failure(lookup(flags: "UP,GATEWAY,HOST,DONE"))),
            ("not a host", .lookupFlags, failure(lookup(flags: "UP,GATEWAY,DONE,STATIC"))),
            ("no gateway", .lookupFlags, failure(lookup(flags: "UP,HOST,DONE,STATIC"))),
            ("mask", .lookupMask, failure(lookup(mask: "255.255.255.0"))),
        ]
        for (label, expected, actual) in cases { XCTAssertEqual(actual, expected, label) }

        // A reason only ever explains a refusal: the same inputs are refused by the Bool, and accepted when there is none.
        XCTAssertTrue(proven(lookup: lookup()))
        XCTAssertFalse(proven(lookup: lookup(flags: cached), extra: pinned + clone), "cached is named, not accepted")
        XCTAssertFalse(proven(lookup: lookup(flags: cached), extra: clone))
        XCTAssertFalse(proven(lookup: lookup(gateway: "192.168.86.9", flags: cached), extra: pinned + clone))
        XCTAssertFalse(proven(lookup: lookup(interface: "utun8", flags: cached), extra: pinned + clone))
    }

    func testGatewayProofReasonsAreFixedTextOnly() {
        let hostile = "SECRETKEY aa:bb:cc:dd:ee:ff vpn-user 203.0.113.77"
        let reason = EndpointRouteProof.gatewayRouteFailure(
            endpoint: "203.0.113.50", via: PhysicalGateway(gateway: "192.168.86.1", interface: "en0"),
            netstat: good(table + "203.0.113.50 192.168.86.1 UGHS en0\n"), routeLookup: CommandResult(status: 1, output: hostile)
        )?.description
        XCTAssertEqual(reason, GatewayRouteProofFailure.lookupFailed.description)
        for value in ["SECRETKEY", "aa:bb", "vpn-user", "203.0.113", "192.168.86"] {
            XCTAssertFalse(reason?.contains(value) == true, value)
        }
        XCTAssertEqual(EndpointRouteProof.throughGatewayRefusal, "its route goes through a gateway", "the connected-route refusal's own text is unchanged")
    }

    func testAGatewayRouteIsProvenOnlyByTheRowAndAnOrdinaryLookupTogether() {
        XCTAssertTrue(proven(lookup: lookup()))
        XCTAssertTrue(proven(lookup: lookup(mask: "255.255.255.255")))
        XCTAssertFalse(proven(lookup: lookup(), extra: ""), "no row")
        XCTAssertFalse(proven(lookup: lookup(), extra: "203.0.113.50 192.168.86.9 UGHS en0\n"), "another row")
        XCTAssertFalse(proven(lookup: lookup(), extra: "203.0.113.50 192.168.86.1 UGHS en0\n203.0.113.50 192.168.90.1 UGHSI en1\n"), "a good row and a good lookup, beside another row")
        XCTAssertFalse(proven(lookup: lookup(), status: 1))
        XCTAssertFalse(proven(lookup: "garbage"))
        XCTAssertFalse(proven(lookup: lookup(destination: "default")))
        XCTAssertFalse(proven(lookup: lookup(gateway: "192.168.86.9")), "the lookup must name the gateway too")
        XCTAssertFalse(proven(lookup: lookup(interface: "utun8")))
        XCTAssertFalse(proven(lookup: lookup(mask: "255.255.255.0")))
        XCTAssertFalse(proven(lookup: lookup(flags: "UP,GATEWAY,HOST,DONE")), "not static")
        XCTAssertFalse(proven(lookup: lookup(flags: "UP,GATEWAY,HOST,DONE,STATIC,WASCLONED")))
        XCTAssertFalse(proven(lookup: lookup(flags: "UP,GATEWAY,HOST,DONE,STATIC,IFSCOPE")))
        XCTAssertFalse(proven(lookup: lookup(flags: "UP,GATEWAY,HOST,DONE,STATIC,REJECT")))
    }
}

/// The real pair shape, with documentation addresses standing in for its public endpoints. Nothing here routes anything.
final class GatewayEndpointRootTests: XCTestCase {
    private var paths: HelperPaths!
    private var commands: FakeCommands!
    private var engine: HelperEngine!

    private let endpoint = "203.0.113.50"
    private let fullEndpoint = "198.51.100.13"
    private lazy var split = confText(address: "10.20.0.2/32", allowedIPs: "192.168.111.0/24, 192.168.112.0/24", endpoint: "\(endpoint):12345")
    private lazy var full = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0, ::/0", endpoint: "\(fullEndpoint):1637", extraPeer: "PersistentKeepalive = 15")
    private let splitID = UUID(), fullID = UUID()

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
        for address in [endpoint, fullEndpoint, "203.0.113.7"] {
            commands.routeGet[address] = CommandResult(status: 0, output: """
               route to: \(address)
            destination: default
                   mask: default
                gateway: 192.168.86.1
              interface: en0
                  flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>
            """)
        }
        engine = try HelperEngine(paths: paths, runner: commands)
    }

    private func ok(_ request: HelperRequest, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(engine.handle(request).error, file: file, line: line)
    }

    private var status: HelperStatus { engine.handle(.status).status! }
    private var routeProblem: String? { status.routeFailure }
    private func running(_ id: UUID) -> Bool { status.tunnels.contains { $0.tunnelID == id && $0.alive } }
    private var upCount: Int { commands.quickCalls.filter { $0[1] == "up" }.count }
    private var journalURL: URL { paths.runtimeDir.appendingPathComponent("session.json") }
    private var journal: String { (try? String(contentsOf: journalURL, encoding: .utf8)) ?? "" }
    private var deletes: [[String]] { commands.routeChanges.filter { $0[2] == "delete" } }
    private var adds: [[String]] { commands.routeChanges.filter { $0[2] == "add" } }
    private func restarted() throws -> HelperEngine {
        let restarted = try HelperEngine(paths: paths, runner: commands)
        restarted.recoverOnStart()
        return restarted
    }

    private func startPair() {
        ok(.up(tunnelID: splitID, config: split))
        ok(.up(tunnelID: fullID, config: full))
    }

    // MARK: a route the config asks for

    func testASplitTunnelsHookedHostRouteIsAddedBeforeSpawnAndRemovedAfterTheTunnelIsGone() throws {
        let hooked = "198.51.100.50", gateway = "192.168.64.1"
        commands.netstatBase = commands.netstatBase.replacingOccurrences(of: "192.168.86", with: "192.168.64")
        commands.ifconfigAll = commands.ifconfigAll.replacingOccurrences(of: "192.168.86", with: "192.168.64")
        commands.routeGet[hooked] = CommandResult(status: 0, output: "   route to: \(hooked)\ndestination: default\n       mask: default\n    gateway: \(gateway)\n  interface: en0\n      flags: <UP,GATEWAY,DONE,STATIC,PRCLONING,GLOBAL>\n")
        let config = confText(
            address: "10.20.0.2/32",
            extraInterface: "PreUp = /sbin/route -n add -host \(hooked) \(gateway)\nPostDown = /sbin/route -n delete -host \(hooked) \(gateway)",
            allowedIPs: "192.168.111.0/24", endpoint: "\(hooked):12345"
        )

        var routeAtSpawn: String?, configAtSpawn: String?
        commands.onQuick = { [unowned self] action in
            guard action == "up" else { return }
            routeAtSpawn = self.commands.hostRoutes[hooked]
            configAtSpawn = try? String(contentsOf: self.paths.runtimeDir.appendingPathComponent("wn0.conf"), encoding: .utf8)
        }
        ok(.up(tunnelID: splitID, config: config))

        XCTAssertNotNil(routeAtSpawn, "in place before the tunnel starts, with no default-route tunnel involved")
        XCTAssertEqual(adds, [["-q", "-n", "add", "-inet", hooked, "-gateway", gateway]], "fixed argv from validated values")
        let backendConfig = try XCTUnwrap(configAtSpawn)
        XCTAssertFalse(backendConfig.lowercased().contains("preup"), "wg-quick would run it through a root shell")
        XCTAssertFalse(backendConfig.lowercased().contains("postdown"))
        XCTAssertFalse(commands.flatArgv.contains("-host"), "the hook's own text never runs")
        XCTAssertTrue(running(splitID))
        XCTAssertNotNil(commands.hostRoutes[hooked], "polling leaves it alone")
        XCTAssertTrue(deletes.isEmpty)

        var tunnelGoneAtDelete: Bool?
        commands.onRouteChange = { [unowned self] verb in
            if verb == "delete" { tunnelGoneAtDelete = self.commands.slots["wn0"] == nil }
        }
        ok(.down(tunnelID: splitID))
        XCTAssertEqual(tunnelGoneAtDelete, true)
        XCTAssertEqual(deletes, [["-q", "-n", "delete", "-inet", hooked, gateway]])
        XCTAssertNil(commands.hostRoutes[hooked])
        XCTAssertFalse(journal.contains(hooked), "nothing of ours is left")
    }

    // MARK: the pair

    func testTheDualStackPairRunsInBothOrdersWithFixedArgv() {
        startPair()
        XCTAssertTrue(running(splitID))
        XCTAssertTrue(running(fullID))
        XCTAssertEqual(adds, [["-q", "-n", "add", "-inet", endpoint, "-gateway", "192.168.86.1"]])
        XCTAssertNil(status.routeFailure)
        XCTAssertFalse(commands.flatArgv.contains("inet6"), "nothing about IPv6 changes for an IPv4 endpoint")

        ok(.downAll)
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertFalse(journal.contains(endpoint))

        ok(.up(tunnelID: fullID, config: full))
        commands.routeGet[endpoint] = CommandResult(status: 0, output: "   route to: \(endpoint)\ndestination: 128.0.0.0\n       mask: 128.0.0.0\n  interface: utun9\n      flags: <UP,DONE,STATIC>\n")
        ok(.up(tunnelID: splitID, config: split))
        XCTAssertTrue(running(splitID))
        XCTAssertTrue(running(fullID))
        XCTAssertNotNil(commands.hostRoutes[endpoint])
    }

    func testTheRouteIsInPlaceBeforeTheCapturingTunnelsConfigOrSpawn() {
        ok(.up(tunnelID: splitID, config: split))
        var routeAtSpawn: String?, confAtAdd = true, journalAtAdd = ""
        commands.onQuick = { [unowned self] _ in routeAtSpawn = self.commands.hostRoutes[self.endpoint] }
        commands.onRouteChange = { [unowned self] verb in
            guard verb == "add" else { return }
            confAtAdd = FileManager.default.fileExists(atPath: self.paths.runtimeDir.appendingPathComponent("wn1.conf").path)
            journalAtAdd = self.journal
        }
        ok(.up(tunnelID: fullID, config: full))
        XCTAssertNotNil(routeAtSpawn)
        XCTAssertFalse(confAtAdd, "no config is written before the route")
        XCTAssertTrue(journalAtAdd.contains(endpoint) && journalAtAdd.contains("adding"), "ownership is durable before the change")
        XCTAssertTrue(journal.contains("installed"))
    }

    func testTheSplitTunnelAloneNeverRunsRouteCommands() {
        ok(.up(tunnelID: splitID, config: split))
        _ = status
        XCTAssertTrue(commands.routeChanges.isEmpty)
    }

    // MARK: independent stops and the last consumer

    func testStoppingTheFullTunnelRemovesOurRouteOnlyAfterItsRoutesAreGone() {
        startPair()
        var slotAtDelete: Bool?
        commands.onRouteChange = { [unowned self] _ in slotAtDelete = self.commands.slots["wn1"] != nil }
        ok(.down(tunnelID: fullID))
        XCTAssertEqual(slotAtDelete, false)
        XCTAssertEqual(deletes, [["-q", "-n", "delete", "-inet", endpoint, "192.168.86.1"]])
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertTrue(running(splitID), "the split is untouched")
    }

    func testStoppingTheSplitTunnelRemovesOurRouteAndKeepsTheFullTunnel() {
        startPair()
        ok(.down(tunnelID: splitID))
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertTrue(running(fullID))
    }

    func testTwoSplitTunnelsShareOneRouteUntilTheLastStops() {
        let other = UUID()
        let second = confText(address: "10.21.0.2/32", allowedIPs: "192.168.113.0/24", endpoint: "\(endpoint):12346")
        startPair()
        ok(.up(tunnelID: other, config: second))
        XCTAssertEqual(adds.count, 1, "no duplicate route")
        ok(.down(tunnelID: splitID))
        XCTAssertNotNil(commands.hostRoutes[endpoint], "still in use")
        XCTAssertTrue(deletes.isEmpty)
        ok(.down(tunnelID: other))
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertEqual(deletes.count, 1)
    }

    func testAFailedSpawnRollsBackOnlyItsNewRoute() {
        ok(.up(tunnelID: splitID, config: split))
        commands.failUp = true
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        commands.failUp = false
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertFalse(journal.contains(endpoint))
        XCTAssertTrue(running(splitID))
    }

    // MARK: adding

    func testAFailedAddRefusesWithoutAdoptingOrDeletingAnything() throws {
        ok(.up(tunnelID: splitID, config: split))
        for refused in [CommandResult(status: 1, output: "route: writing to routing socket: File exists"), CommandResult(status: 1, output: "route: writing to routing socket: Network is unreachable")] {
            commands.routeAddResult = refused
            let before = upCount
            let error = try XCTUnwrap(engine.handle(.up(tunnelID: fullID, config: full)).error)
            XCTAssertEqual(upCount, before, "no spawn")
            XCTAssertFalse(FileManager.default.fileExists(atPath: paths.runtimeDir.appendingPathComponent("wn1.conf").path))
            XCTAssertTrue(error.contains("No protective route was added"), error)
            XCTAssertTrue(deletes.isEmpty, "a failed add is never cleaned up by deleting")
            XCTAssertFalse(journal.contains(endpoint))
        }
    }

    func testATimedOutAddThatLeftNoRowLeavesNothingToTrack() throws {
        for exitStatus: Int32 in [124, 137] {
            ok(.up(tunnelID: splitID, config: split))
            commands.routeAddResult = CommandResult(status: exitStatus, output: "Timed out")
            let error = try XCTUnwrap(engine.handle(.up(tunnelID: fullID, config: full)).error)
            XCTAssertFalse(error.contains("No protective route was added"), error)
            XCTAssertTrue(deletes.isEmpty)
            XCTAssertFalse(journal.contains(endpoint), "the table shows there is nothing, which is affirmative")
            XCTAssertEqual(upCount, 1)
            commands.routeAddResult = nil
            ok(.downAll)
            commands.calls.removeAll()
        }
    }

    /// Absence, then intent, then an identical row does not show the row is ours: another root writer could have put it there.
    func testAnIdenticalRowAfterAnUnconfirmedAddIsNeverPromotedOrDeleted() throws {
        for exitStatus: Int32 in [124, 137] {
            ok(.up(tunnelID: splitID, config: split))
            let identical = "\(endpoint)     192.168.86.1     UGHS     en0\n"
            commands.routeAddResult = CommandResult(status: exitStatus, output: "Timed out")
            commands.onRouteChange = { [unowned self] verb in
                if verb == "add" { self.commands.hostRoutes[self.endpoint] = identical }
            }
            XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
            commands.onRouteChange = nil
            commands.routeAddResult = nil

            func assertUnresolved(_ context: String) {
                XCTAssertTrue(deletes.isEmpty, context)
                XCTAssertEqual(commands.hostRoutes[endpoint], identical, context)
                XCTAssertTrue(journal.contains("adding") && !journal.contains("installed"), context)
                XCTAssertEqual(upCount, 1, "\(context): the capturing tunnel never ran")
            }
            assertUnresolved("rollback")

            XCTAssertNotNil(routeProblem, "visible on every poll")
            assertUnresolved("polled")

            XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error, "a retry is refused too")
            assertUnresolved("retried")

            ok(.down(tunnelID: splitID))
            XCTAssertNotNil(engine.handle(.downAll).error, "uninstall must not call this complete")
            assertUnresolved("uninstall")

            engine = try restarted()
            XCTAssertNotNil(routeProblem)
            assertUnresolved("restarted")

            // By hand, or by whoever owned it. Absence is the only thing that settles it.
            commands.hostRoutes[endpoint] = nil
            XCTAssertNil(routeProblem, "resolved")
            XCTAssertFalse(journal.contains(endpoint))
            ok(.downAll)
            commands.calls.removeAll()
        }
    }

    func testAnUnconfirmedAddKeepsARunningPairsDefaultStopped() throws {
        startPair()
        // The same state, reached by a crash with the row still present and the full tunnel up.
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: journalURL)) as? [String: Any])
        var routes = try XCTUnwrap(object["endpointRoutes"] as? [String: [String: String]])
        routes[endpoint]?["phase"] = "adding"
        object["endpointRoutes"] = routes
        try JSONSerialization.data(withJSONObject: object).write(to: journalURL)

        engine = try restarted()
        XCTAssertNil(commands.slots["wn1"], "contained, even though the row looks exactly right")
        XCTAssertNotNil(commands.slots["wn0"])
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertNotNil(commands.hostRoutes[endpoint])
        XCTAssertNotNil(routeProblem)
    }

    func testAConfirmedAddWhoseReadBackIsUnknownIsOursOnceItCanBeRead() {
        ok(.up(tunnelID: splitID, config: split))
        commands.onRouteChange = { [unowned self] verb in
            if verb == "add" { self.commands.netstatResult = CommandResult(status: 124, output: "") }
        }
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        commands.onRouteChange = nil
        XCTAssertEqual(upCount, 1, "unread is not proven")
        XCTAssertTrue(journal.contains("installed"), "exit 0 is the receipt, recorded before any read-back")
        XCTAssertTrue(deletes.isEmpty)

        commands.netstatResult = nil
        XCTAssertNil(routeProblem)
        XCTAssertEqual(deletes.count, 1, "confirmed as ours, with nothing needing it now")
        XCTAssertNil(commands.hostRoutes[endpoint])
    }

    func testAReceiptThatCannotBeRecordedIsNotQuietlyUpgradedLater() throws {
        try XCTSkipIf(geteuid() == 0, "root ignores directory permissions")
        ok(.up(tunnelID: splitID, config: split))
        let directory = paths.runtimeDir.path
        func allowWrites(_ allowed: Bool) {
            try? FileManager.default.setAttributes([.posixPermissions: allowed ? 0o700 : 0o500], ofItemAtPath: directory)
        }
        defer { allowWrites(true) }
        commands.onRouteChange = { verb in
            if verb == "add" { allowWrites(false) }
        }
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        commands.onRouteChange = nil
        allowWrites(true)

        for context in ["polled", "polled again"] {
            XCTAssertNotNil(routeProblem, context)
            XCTAssertTrue(journal.contains("adding") && !journal.contains("installed"), context)
            XCTAssertTrue(deletes.isEmpty, context)
        }
        engine = try restarted()
        XCTAssertNotNil(routeProblem)
        XCTAssertTrue(journal.contains("adding") && !journal.contains("installed"))
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertNotNil(commands.hostRoutes[endpoint], "even our own row, which nothing durable can show is ours")
        XCTAssertEqual(upCount, 1)
    }

    func testATimedOutAddStaysTrackedWhileTheTableCannotBeRead() throws {
        ok(.up(tunnelID: splitID, config: split))
        commands.routeAddResult = CommandResult(status: 124, output: "Timed out")
        commands.onRouteChange = { [unowned self] _ in self.commands.netstatResult = CommandResult(status: 1, output: "") }
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertTrue(journal.contains(endpoint), "not erased")
        XCTAssertTrue(deletes.isEmpty)
    }

    func testAnAddThatInstallsTheWrongRowIsNeitherKeptNorDeleted() throws {
        ok(.up(tunnelID: splitID, config: split))
        commands.routeAddInstalls = "\(endpoint)     192.168.86.9     UGHS     en0\n"
        let error = try XCTUnwrap(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertFalse(error.contains("No protective route was added"), "an add did run")
        XCTAssertTrue(deletes.isEmpty, "the row is not one we can prove is ours")
        XCTAssertFalse(journal.contains(endpoint))
        XCTAssertEqual(upCount, 1, "only the split started")
    }

    func testAnUnreadableTableChangesNothing() {
        ok(.up(tunnelID: splitID, config: split))
        let unusable = [
            CommandResult(status: 1, output: ""), CommandResult(status: 124, output: ""), CommandResult(status: 0, output: "no table"),
            CommandResult(status: 0, output: commands.netstatBase + "broken\n"),
            CommandResult(status: 0, output: commands.netstatBase + String(repeating: "x", count: HelperConstants.maxCommandOutputBytes)),
        ]
        for table in unusable {
            commands.netstatResult = table
            XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error, table.output)
            XCTAssertTrue(commands.routeChanges.isEmpty, table.output)
            XCTAssertEqual(upCount, 1, table.output)
        }
    }

    func testAnUnusableGatewayChangesNothing() {
        ok(.up(tunnelID: splitID, config: split))
        let lan = commands.netstatBase
        for table in [lan.replacingOccurrences(of: "UGScg                 en0", with: "UGScg                 utun3"),
                      lan + "default            192.168.90.1       UGScg                 en1\n",
                      lan.replacingOccurrences(of: "192.168.86.1 ", with: "link#7       "),
                      lan.replacingOccurrences(of: "192.168.86.1 ", with: "192.168.99.1 ")] {
            commands.netstatBase = table
            XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error, table)
            XCTAssertTrue(commands.routeChanges.isEmpty, table)
            XCTAssertEqual(upCount, 1, table)
        }
    }

    // MARK: rows that are not ours

    func testAnExactPredatedRowIsBorrowedAndNeverDeleted() {
        commands.hostRoutes[endpoint] = "\(endpoint)     192.168.86.1     UGHS     en0\n"
        startPair()
        XCTAssertTrue(running(fullID))
        XCTAssertTrue(adds.isEmpty)
        XCTAssertFalse(journal.contains(endpoint), "borrowed, not owned")
        ok(.downAll)
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertNotNil(commands.hostRoutes[endpoint], "still there, as it was found")
    }

    func testADifferentOrCoveringRowRefusesWithoutOverwriting() {
        ok(.up(tunnelID: splitID, config: split))
        let lan = commands.netstatBase
        commands.hostRoutes[endpoint] = "\(endpoint)     192.168.86.9     UGHS     en0\n"
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertTrue(commands.routeChanges.isEmpty)
        XCTAssertEqual(commands.hostRoutes[endpoint], "\(endpoint)     192.168.86.9     UGHS     en0\n")

        commands.hostRoutes[endpoint] = nil
        commands.netstatBase = lan + "203.0.113/24       192.168.86.9       UGSc                  en0\n"
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertTrue(commands.routeChanges.isEmpty)
    }

    func testAClonedRowIsOnlyEverGivenASafeAdd() throws {
        let clone = "\(endpoint)     192.168.86.1     UGHWIig     en0\n"
        ok(.up(tunnelID: splitID, config: split))
        commands.hostRoutes[endpoint] = clone
        commands.cloneBlocksRouteAdd = true
        let error = try XCTUnwrap(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertTrue(error.contains(endpoint))
        XCTAssertTrue(deletes.isEmpty, "a clone is never deleted to force the add")
        XCTAssertEqual(commands.hostRoutes[endpoint], clone)

        commands.cloneBlocksRouteAdd = false
        ok(.up(tunnelID: fullID, config: full))
        XCTAssertTrue(running(fullID))
        XCTAssertTrue(journal.contains("installed"))
    }

    // MARK: while it runs

    func testAnExternallyDeletedRouteIsAddedBackUnderTheSameChecks() {
        startPair()
        commands.hostRoutes[endpoint] = nil
        XCTAssertTrue(running(fullID))
        XCTAssertNotNil(commands.hostRoutes[endpoint])
        XCTAssertEqual(adds.count, 2)
    }

    func testAForeignReplacementIsReleasedWithoutDeletingAndStopsOnlyTheDefault() {
        startPair()
        let foreign = "\(endpoint)     192.168.86.9     UGHS     en0\n"
        commands.hostRoutes[endpoint] = foreign
        let after = status
        XCTAssertFalse(after.tunnels.contains { $0.tunnelID == fullID })
        XCTAssertTrue(after.tunnels.contains { $0.tunnelID == splitID && $0.alive })
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertEqual(commands.hostRoutes[endpoint], foreign)
        XCTAssertFalse(journal.contains("\"\(endpoint)\""))
    }

    func testAGatewayChangeStopsTheDefaultBeforeTheOldRouteIsTouched() {
        startPair()
        var fullStoppedBeforeDelete: Bool?
        commands.onRouteChange = { [unowned self] verb in
            if verb == "delete" { fullStoppedBeforeDelete = self.commands.slots["wn1"] == nil }
        }
        commands.netstatBase = commands.netstatBase.replacingOccurrences(of: "192.168.86.1 ", with: "192.168.86.2 ")
        let after = status
        XCTAssertFalse(after.tunnels.contains { $0.tunnelID == fullID }, "contained")
        XCTAssertTrue(after.tunnels.contains { $0.tunnelID == splitID && $0.alive })
        XCTAssertEqual(fullStoppedBeforeDelete, true)
        XCTAssertEqual(deletes, [["-q", "-n", "delete", "-inet", endpoint, "192.168.86.1"]], "the old gateway's exact row")
        XCTAssertNil(commands.hostRoutes[endpoint])

        ok(.up(tunnelID: fullID, config: full))
        XCTAssertEqual(adds.last, ["-q", "-n", "add", "-inet", endpoint, "-gateway", "192.168.86.2"], "a retry validates the new one from scratch")
    }

    func testAnUnknownGatewayKeepsTheRouteAndStopsTheDefault() {
        startPair()
        commands.netstatBase = commands.netstatBase.replacingOccurrences(of: "default            192.168.86.1       UGScg                 en0\n", with: "")
        let after = status
        XCTAssertFalse(after.tunnels.contains { $0.tunnelID == fullID })
        XCTAssertTrue(after.tunnels.contains { $0.tunnelID == splitID && $0.alive })
    }

    func testAnUnreadableTableKeepsTheJournalAndStopsTheDefault() {
        startPair()
        commands.netstatResult = CommandResult(status: 124, output: "")
        XCTAssertNotNil(status.routeFailure)
        XCTAssertNil(commands.slots["wn1"])
        XCTAssertNotNil(commands.slots["wn0"])
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertTrue(journal.contains(endpoint), "cleanup debt stays recorded")

        commands.netstatResult = nil
        XCTAssertNil(status.routeFailure)
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertFalse(journal.contains(endpoint))
    }

    func testSameConfigUpChecksTheRouteAgain() {
        startPair()
        commands.hostRoutes[endpoint] = "\(endpoint)     192.168.86.9     UGHS     en0\n"
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertNil(commands.slots["wn1"])
    }

    // MARK: endpoints

    func testRoamingMovesTheRouteToTheRealEndpoint() {
        startPair()
        commands.actualEndpoints["wn0"] = "\(testKey(2))\t203.0.113.7:12345\n"
        XCTAssertTrue(running(fullID))
        XCTAssertNotNil(commands.hostRoutes["203.0.113.7"])
        XCTAssertNil(commands.hostRoutes[endpoint])
    }

    /// Unknown must not read as "nobody needs it": the route stays until the capture it protects from has really gone.
    func testAnEndpointThatCannotBeReadStopsTheDefaultBeforeItsRouteIsTouched() {
        let unreadable: [(String, () -> Void)] = [
            ("(none)", { self.commands.actualEndpoints["wn0"] = "\(testKey(2))\t(none)\n" }),
            ("garbage", { self.commands.actualEndpoints["wn0"] = "garbage\n" }),
            ("timeout", { self.commands.wgShowTimeouts = ["endpoints"] }),
        ]
        for (label, makeUnreadable) in unreadable {
            startPair()
            var fullGoneAtDelete: Bool?
            commands.onRouteChange = { [unowned self] verb in
                if verb == "delete" { fullGoneAtDelete = self.commands.slots["wn1"] == nil }
            }
            makeUnreadable()
            let after = status
            XCTAssertFalse(after.tunnels.contains { $0.tunnelID == fullID }, label)
            XCTAssertTrue(after.tunnels.contains { $0.tunnelID == splitID }, label)
            XCTAssertNotNil(commands.slots["wn0"], label)
            XCTAssertEqual(fullGoneAtDelete, true, label)

            commands.onRouteChange = nil
            commands.actualEndpoints["wn0"] = nil
            commands.wgShowTimeouts = []
            ok(.downAll)
        }
    }

    func testAnExposedIPv6EndpointStillFailsClosedAndNoV6RouteRuns() {
        startPair()
        commands.actualEndpoints["wn0"] = "\(testKey(2))\t[2001:db8::9]:12345\n"
        XCTAssertFalse(status.tunnels.contains { $0.tunnelID == fullID })
        XCTAssertFalse(commands.routeChanges.contains { $0.contains("2001:db8::9") })
    }

    func testAnOnLinkOrInvalidEndpointNeverGetsARoute() {
        let onLink = confText(address: "10.20.0.2/32", allowedIPs: "192.168.111.0/24", endpoint: "192.168.86.77:12345")
        commands.routeGet["192.168.86.77"] = CommandResult(status: 1, output: "not in table")
        ok(.up(tunnelID: splitID, config: onLink))
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertTrue(commands.routeChanges.isEmpty)
        ok(.downAll)

        let loopback = confText(address: "10.20.0.2/32", allowedIPs: "192.168.111.0/24", endpoint: "127.77.0.9:12345")
        ok(.up(tunnelID: splitID, config: loopback))
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertTrue(commands.routeChanges.isEmpty)
    }

    // MARK: the default owner's own endpoint is wg-quick's

    private lazy var sharedFull = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0", endpoint: "\(endpoint):1637")

    // MARK: saying which check failed

    private let cachedFlags = "UP,GATEWAY,HOST,DONE,WASCLONED,IFSCOPE"
    private let rollbackTail = "WireNest removes its own protective routes when they are no longer needed; unresolved cleanup stays tracked."

    func testAStartRefusedByACachedLookupSaysSoAndIsStillRefused() throws {
        ok(.up(tunnelID: splitID, config: split))
        commands.hostLookupFlags = cachedFlags
        let error = try XCTUnwrap(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertTrue(error.contains(GatewayRouteProofFailure.lookupCached.description), error)
        XCTAssertFalse(error.contains(EndpointRouteProof.throughGatewayRefusal), error)
        XCTAssertTrue(error.contains(rollbackTail), error)
        XCTAssertFalse(error.contains("stay tracked until"), error)
        XCTAssertEqual(upCount, 1, "named, not accepted: the capturing tunnel never starts")

        // Everything else about the attempt is what it was.
        XCTAssertEqual(adds.count, 1)
        XCTAssertEqual(deletes, [["-q", "-n", "delete", "-inet", endpoint, "192.168.86.1"]], "the route we added is rolled back")
        XCTAssertFalse(journal.contains(endpoint))
        XCTAssertTrue(running(splitID))
    }

    func testARunningPairReportsTheReasonThroughRouteFailure() {
        startPair()
        commands.hostLookupFlags = cachedFlags
        let after = status
        XCTAssertTrue(after.routeFailure?.contains(GatewayRouteProofFailure.lookupCached.description) == true, after.routeFailure ?? "")
        XCTAssertFalse(after.routeFailure?.contains(EndpointRouteProof.throughGatewayRefusal) == true)
        XCTAssertFalse(after.tunnels.contains { $0.tunnelID == fullID }, "contained exactly as before")
        XCTAssertTrue(after.tunnels.contains { $0.tunnelID == splitID && $0.alive })
    }

    func testATrackedRowWithNoProvableGatewaySaysSo() {
        startPair()
        commands.netstatBase = commands.netstatBase.replacingOccurrences(of: "default            192.168.86.1       UGScg                 en0\n", with: "")
        let after = status
        XCTAssertTrue(after.routeFailure?.contains("physical default gateway could not be proven") == true, after.routeFailure ?? "")
        XCTAssertFalse(after.routeFailure?.contains(EndpointRouteProof.throughGatewayRefusal) == true)
        XCTAssertFalse(after.tunnels.contains { $0.tunnelID == fullID })
    }

    func testAMovedGatewaySaysTheRowIsNotTheCurrentOne() {
        startPair()
        commands.netstatBase = commands.netstatBase.replacingOccurrences(of: "192.168.86.1 ", with: "192.168.86.2 ")
        let after = status
        XCTAssertTrue(after.routeFailure?.contains(GatewayRouteProofFailure.differentRow.description) == true, after.routeFailure ?? "")
        XCTAssertFalse(after.tunnels.contains { $0.tunnelID == fullID })
    }

    func testAMixedRowSaysItIsAmbiguousThroughTheExistingProblem() {
        startPair()
        commands.hostRoutes[endpoint] = "\(endpoint)     192.168.86.1     UGHS     en0\n\(endpoint)     192.168.90.1     UGHSI     en1\n"
        XCTAssertTrue(status.routeFailure?.contains("another route to it exists beside the protective one") == true, "creation and ownership problems keep priority")
    }

    func testAnOutstandingAddStillKeepsItsSpecificProblemFirst() throws {
        ok(.up(tunnelID: splitID, config: split))
        commands.routeAddResult = CommandResult(status: 124, output: "Timed out")
        let error = try XCTUnwrap(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertTrue(error.contains("adding the route timed out"), error)
        XCTAssertFalse(error.contains(rollbackTail), "that tail is for a route with no specific problem")
    }

    func testAnUnconfirmedAddWithNoProblemOfItsOwnStillHasASpecificReason() throws {
        // Shared with the default owner, so no reconcile looks at it and only the proof can say why.
        commands.wgQuickManagesOwnEndpoint = true
        let sharedOwner = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0", endpoint: "\(endpoint):1637")
        ok(.up(tunnelID: fullID, config: sharedOwner))
        var object = try XCTUnwrap(JSONSerialization.jsonObject(with: Data(contentsOf: journalURL)) as? [String: Any])
        object["endpointRoutes"] = [endpoint: ["gateway": "192.168.86.1", "interface": "en0", "phase": "adding"]]
        try JSONSerialization.data(withJSONObject: object).write(to: journalURL)
        engine = try restarted()

        let error = try XCTUnwrap(engine.handle(.up(tunnelID: splitID, config: split)).error)
        XCTAssertTrue(error.contains("an earlier route add is still unconfirmed"), error)
        XCTAssertFalse(error.contains(EndpointRouteProof.throughGatewayRefusal), error)
        XCTAssertTrue(deletes.isEmpty)
    }

    func testAConnectedRouteRefusalKeepsItsOwnSpecificReason() throws {
        // A LAN endpoint behind a hostname owner, so nothing is reconciled and the refusal that fired is the specific one.
        let lanSplit = confText(address: "10.20.0.2/32", allowedIPs: "192.168.111.0/24", endpoint: "192.168.86.51:51820")
        let namedFull = confText(address: "10.128.0.2/32", allowedIPs: "0.0.0.0/0", endpoint: "vpn.example.com:1637")
        ok(.up(tunnelID: fullID, config: namedFull))
        commands.routeGet["192.168.86.51"] = CommandResult(status: 0, output: "   route to: 192.168.86.51\ndestination: 128.0.0.0\n       mask: 128.0.0.0\n  interface: utun7\n      flags: <UP,DONE,STATIC>\n")
        let error = try XCTUnwrap(engine.handle(.up(tunnelID: splitID, config: lanSplit)).error)
        XCTAssertTrue(error.contains("its route goes into a WireNest tunnel"), error)
    }

    func testASharedEndpointIsBorrowedFromWgQuickInBothOrders() {
        commands.wgQuickManagesOwnEndpoint = true
        ok(.up(tunnelID: splitID, config: split))
        ok(.up(tunnelID: fullID, config: sharedFull))
        XCTAssertTrue(running(fullID))
        XCTAssertTrue(commands.routeChanges.isEmpty, "the helper neither adds nor owns it")

        ok(.down(tunnelID: fullID))
        XCTAssertNil(commands.hostRoutes[endpoint], "wg-quick took its own route away")
        XCTAssertTrue(running(splitID))
        ok(.downAll)

        ok(.up(tunnelID: fullID, config: sharedFull))
        ok(.up(tunnelID: splitID, config: split))
        XCTAssertTrue(running(splitID))
        ok(.down(tunnelID: splitID))
        XCTAssertNotNil(commands.hostRoutes[endpoint], "stopping the split must not take the full tunnel's endpoint route")
        XCTAssertTrue(running(fullID))
        XCTAssertTrue(commands.routeChanges.isEmpty)
    }

    func testOurRouteIsKeptWhileTheDefaultOwnerHasRoamedOntoIt() {
        startPair()
        commands.actualEndpoints["wn1"] = "\(testKey(2))\t\(endpoint):1637\n"
        ok(.down(tunnelID: splitID))
        XCTAssertTrue(deletes.isEmpty, "the full tunnel would be left captured by itself")
        XCTAssertNotNil(commands.hostRoutes[endpoint])
        XCTAssertTrue(journal.contains(endpoint), "not forgotten either")

        ok(.down(tunnelID: fullID))
        XCTAssertEqual(deletes.count, 1)
        XCTAssertNil(commands.hostRoutes[endpoint])
    }

    // MARK: removal

    func testAFailedDeleteStaysTrackedVisibleAndRetried() throws {
        startPair()
        commands.routeDeleteResult = CommandResult(status: 1, output: "route: writing to routing socket: Operation not permitted")
        XCTAssertNotNil(engine.handle(.downAll).error, "uninstall must not pass over this")
        XCTAssertNotNil(status.routeFailure)
        XCTAssertTrue(journal.contains(endpoint))

        commands.routeDeleteResult = nil
        ok(.downAll)
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertFalse(journal.contains(endpoint))
    }

    func testADeleteThatExitsZeroButLeavesTheRowIsNotSuccess() {
        startPair()
        commands.routeDeleteLeavesRow = true
        XCTAssertNotNil(engine.handle(.downAll).error)
        XCTAssertTrue(journal.contains(endpoint))
    }

    func testAChangedRowIsNeverDeleted() {
        startPair()
        let foreign = "\(endpoint)     192.168.86.9     UGHS     en0\n"
        commands.hostRoutes[endpoint] = foreign
        ok(.down(tunnelID: fullID))
        XCTAssertEqual(commands.hostRoutes[endpoint], foreign)
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertFalse(journal.contains("\"\(endpoint)\""), "affirmatively someone else's, so ownership ends")
    }

    func testAnUnknownTableDuringTeardownRetainsCleanupDebt() {
        startPair()
        commands.netstatResult = CommandResult(status: 1, output: "")
        XCTAssertNotNil(engine.handle(.downAll).error)
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertTrue(journal.contains(endpoint))
        XCTAssertNotNil(commands.hostRoutes[endpoint])

        commands.netstatResult = nil
        ok(.downAll)
        XCTAssertNil(commands.hostRoutes[endpoint])
    }

    func testARetiringDefaultOwnerWithItsInterfaceLeftKeepsTheRoute() {
        startPair()
        commands.downLeavesInterfaceOnly = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: fullID)).error)
        XCTAssertTrue(deletes.isEmpty, "its routes may still be installed")
        XCTAssertNotNil(commands.hostRoutes[endpoint])
    }

    func testAnUnknownInterfaceKeepsTheRoute() {
        startPair()
        commands.downLeavesInterfaceOnly = true
        commands.ifconfigEnumeration = CommandResult(status: 1, output: "")
        XCTAssertNotNil(engine.handle(.down(tunnelID: fullID)).error)
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertTrue(journal.contains(endpoint))
    }

    // MARK: crashes

    private func journalAtFirst(_ verb: String, while action: () -> Void) throws -> Data {
        var captured: Data?
        commands.onRouteChange = { [unowned self] seen in
            if seen == verb, captured == nil { captured = try? Data(contentsOf: self.journalURL) }
        }
        action()
        commands.onRouteChange = nil
        return try XCTUnwrap(captured)
    }

    func testCrashWhileAddingBeforeTheRowExistsLeavesNothingBehind() throws {
        ok(.up(tunnelID: splitID, config: split))
        let atAdd = try journalAtFirst("add") { ok(.up(tunnelID: fullID, config: full)) }
        ok(.down(tunnelID: fullID))
        try atAdd.write(to: journalURL)
        XCTAssertTrue(String(decoding: atAdd, as: UTF8.self).contains("adding"))

        let recovered = try restarted()
        XCTAssertNil(recovered.handle(.status).status?.routeFailure)
        XCTAssertFalse(journal.contains(endpoint))
        XCTAssertEqual(deletes.count, 1, "only the earlier real stop")
    }

    func testCrashWhileAddingWithAMatchingRowKeepsItAsVisibleDebt() throws {
        ok(.up(tunnelID: splitID, config: split))
        let atAdd = try journalAtFirst("add") { ok(.up(tunnelID: fullID, config: full)) }
        commands.slots["wn1"] = nil
        try atAdd.write(to: journalURL)
        XCTAssertNotNil(commands.hostRoutes[endpoint])

        engine = try restarted()
        XCTAssertNotNil(commands.hostRoutes[endpoint], "it might be someone else's")
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertTrue(journal.contains("adding") && !journal.contains("installed"))
        XCTAssertNotNil(routeProblem)
        XCTAssertNotNil(commands.slots["wn0"], "the split is untouched")
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertNil(commands.slots["wn1"], "and the capturing tunnel cannot start on it")

        XCTAssertNotNil(engine.handle(.downAll).error, "uninstall must not call this complete")
        XCTAssertTrue(journal.contains("adding"))
        XCTAssertNotNil(commands.hostRoutes[endpoint])

        commands.hostRoutes[endpoint] = nil
        ok(.downAll)
        XCTAssertFalse(journal.contains(endpoint))
    }

    // MARK: our row beside another

    private lazy var ownRow = "\(endpoint)     192.168.86.1     UGHS     en0\n"
    private lazy var scopedForeignRow = "\(endpoint)     192.168.90.1     UGHSI     en1\n"

    func testAMixedRowWhileRunningStopsTheDefaultAndKeepsOwnershipUntilItIsClear() {
        startPair()
        commands.hostRoutes[endpoint] = ownRow + scopedForeignRow
        XCTAssertNotNil(routeProblem)
        XCTAssertNil(commands.slots["wn1"], "our row and the lookup both look right, but the table is ambiguous")
        XCTAssertNotNil(commands.slots["wn0"])
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertEqual(commands.hostRoutes[endpoint], ownRow + scopedForeignRow)
        XCTAssertTrue(journal.contains("\"\(endpoint)\""), "our row is still there, so ownership did not end")

        XCTAssertNotNil(routeProblem, "visible while it lasts")
        XCTAssertTrue(deletes.isEmpty)

        commands.hostRoutes[endpoint] = ownRow
        XCTAssertNil(routeProblem)
        XCTAssertEqual(deletes, [["-q", "-n", "delete", "-inet", endpoint, "192.168.86.1"]], "unambiguous again, and confirmed ours")
        XCTAssertFalse(journal.contains(endpoint))
    }

    func testAMixedRowBlocksTeardownAndRecoveryUntilItIsClear() throws {
        startPair()
        commands.hostRoutes[endpoint] = ownRow + scopedForeignRow
        XCTAssertNotNil(engine.handle(.downAll).error, "uninstall must not call this complete")
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertTrue(journal.contains(endpoint))

        engine = try restarted()
        XCTAssertNotNil(routeProblem)
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertTrue(journal.contains(endpoint))

        commands.hostRoutes[endpoint] = ownRow
        ok(.downAll)
        XCTAssertEqual(deletes.count, 1)
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertFalse(journal.contains(endpoint))
    }

    func testOnceOurRowIsGoneAForeignRowEndsOwnershipAndStays() {
        startPair()
        commands.hostRoutes[endpoint] = ownRow + scopedForeignRow
        XCTAssertNotNil(routeProblem)

        commands.hostRoutes[endpoint] = scopedForeignRow
        XCTAssertNil(routeProblem)
        XCTAssertEqual(commands.hostRoutes[endpoint], scopedForeignRow)
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertFalse(journal.contains("\"\(endpoint)\""))
    }

    func testAMixedRowAfterAConfirmedAddIsKeptWithoutDeleting() {
        ok(.up(tunnelID: splitID, config: split))
        commands.routeAddInstalls = ownRow + scopedForeignRow
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertEqual(upCount, 1)
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertTrue(journal.contains("installed"))
    }

    func testAMixedRowThatWasNeverOursIsRefusedAndNotAdopted() {
        ok(.up(tunnelID: splitID, config: split))
        commands.hostRoutes[endpoint] = ownRow + scopedForeignRow
        XCTAssertNotNil(engine.handle(.up(tunnelID: fullID, config: full)).error)
        XCTAssertEqual(upCount, 1)
        XCTAssertTrue(commands.routeChanges.isEmpty)
        XCTAssertFalse(journal.contains(endpoint))
    }

    func testATwoRowDuplicateIsMixedInTheLifecycleToo() {
        startPair()
        commands.hostRoutes[endpoint] = ownRow + ownRow
        XCTAssertNotNil(routeProblem)
        XCTAssertNil(commands.slots["wn1"])
        XCTAssertTrue(deletes.isEmpty)
        XCTAssertTrue(journal.contains(endpoint))
    }

    func testCrashWhileRemovingFinishesAndAnUnknownTableWaits() throws {
        startPair()
        let atDelete = try journalAtFirst("delete") { ok(.down(tunnelID: fullID)) }
        XCTAssertTrue(String(decoding: atDelete, as: UTF8.self).contains("removing"))
        commands.hostRoutes[endpoint] = "\(endpoint)     192.168.86.1     UGHS     en0\n"
        try atDelete.write(to: journalURL)

        commands.netstatResult = CommandResult(status: 1, output: "")
        _ = try restarted()
        XCTAssertTrue(journal.contains(endpoint), "unknown is not gone")
        XCTAssertNotNil(commands.hostRoutes[endpoint])

        commands.netstatResult = nil
        _ = try restarted()
        XCTAssertNil(commands.hostRoutes[endpoint])
        XCTAssertFalse(journal.contains(endpoint))
    }

    func testRecoveryAdoptsThePairWithItsRoute() throws {
        startPair()
        let recovered = try restarted()
        XCTAssertEqual(recovered.handle(.status).status?.tunnels.count, 2)
        XCTAssertNotNil(commands.hostRoutes[endpoint])
        XCTAssertEqual(deletes.count, 0)
        XCTAssertEqual(adds.count, 1, "no duplicate route")
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

    // MARK: unknown is not absent

    /// The device and its monitor are really there, its endpoints cannot be read, and `ifconfig IF` exits 1 as it does for any error.
    private func makeSplitUnreadable() {
        commands.wgShowTimeouts = ["endpoints"]
        commands.ifconfigNamedFailsGenerically = true
    }

    func testGenericIfconfigFailureDoesNotLetTheDefaultOwnerPastPreflight() {
        ok(.up(tunnelID: local, config: localSome))
        let slot = commands.slots["wn0"]!
        makeSplitUnreadable()
        let before = upCount

        XCTAssertNotNil(engine.handle(.up(tunnelID: air, config: airVPN)).error)
        XCTAssertEqual(upCount, before, "no spawn")
        XCTAssertFalse(FileManager.default.fileExists(atPath: paths.runtimeDir.appendingPathComponent("wn1.conf").path), "no config written")
        XCTAssertEqual(commands.slots["wn0"]?.real, slot.real)
        XCTAssertEqual(commands.slots["wn0"]?.monitorAlive, true, "the sibling is untouched")
        XCTAssertTrue(commands.terminatedGroups.isEmpty)
    }

    func testGenericIfconfigFailureAtRuntimeStopsTheDefaultOwnerAndKeepsTheSplit() {
        for proofLost in [false, true] {
            commands.wgShowTimeouts = []
            commands.ifconfigNamedFailsGenerically = false
            commands.installSyntheticLAN()
            ok(.up(tunnelID: local, config: localSome))
            ok(.up(tunnelID: air, config: airVPN))

            makeSplitUnreadable()
            if proofLost { loseLANProof() }
            let after = status
            XCTAssertNil(commands.slots["wn1"], "proofLost \(proofLost): the capturing routes must go")
            XCTAssertEqual(commands.slots["wn0"]?.monitorAlive, true, "proofLost \(proofLost)")
            XCTAssertTrue(after.tunnels.contains { $0.tunnelID == local }, "proofLost \(proofLost)")
            XCTAssertFalse(after.tunnels.contains { $0.tunnelID == air }, "proofLost \(proofLost)")
            XCTAssertTrue(after.routeFailure?.contains("unknown") == true, "proofLost \(proofLost): the uncertainty is reported")

            commands.wgShowTimeouts = []
            commands.ifconfigNamedFailsGenerically = false
            ok(.downAll)
        }
    }

    private func nameFile(_ name: String) -> String {
        paths.wireguardRunDir.appendingPathComponent("\(name).name").path
    }

    private func confFile(_ name: String) -> String {
        paths.runtimeDir.appendingPathComponent("\(name).conf").path
    }

    func testPresentInterfaceWithNoMonitorAndUnreadableStatsKeepsEveryOwnershipRecord() throws {
        ok(.up(tunnelID: local, config: localSome))
        let real = try XCTUnwrap(commands.slots["wn0"]?.real)
        commands.slots["wn0"]?.monitorAlive = false
        commands.wgShowTimeouts = ["latest-handshakes", "transfer"]
        commands.ifconfigNamedFailsGenerically = true
        commands.failDown = true
        let socket = paths.wireguardRunDir.appendingPathComponent("\(real).sock").path

        XCTAssertNotNil(engine.handle(.down(tunnelID: local)).error, "no false cleanup success")
        XCTAssertTrue(commands.quickCalls.contains { $0[1] == "down" }, "uncertainty must still attempt the real teardown")
        XCTAssertTrue(FileManager.default.fileExists(atPath: confFile("wn0")), "config")
        XCTAssertTrue(FileManager.default.fileExists(atPath: nameFile("wn0")), "name")
        XCTAssertTrue(FileManager.default.fileExists(atPath: socket), "no socket is ever unlinked by the helper")
        XCTAssertTrue(status.tunnels.contains { $0.tunnelID == local }, "journal")

        let restarted = try HelperEngine(paths: paths, runner: commands)
        restarted.recoverOnStart()
        XCTAssertEqual(restarted.handle(.status).status?.tunnels.map(\.tunnelID), [local], "the journal survives a restart")
    }

    func testGenericIfconfigFailureAfterADownThatLeavesTheInterfaceIsNotCleanup() {
        ok(.up(tunnelID: local, config: localSome))
        commands.downLeavesInterfaceOnly = true
        commands.ifconfigNamedFailsGenerically = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: local)).error)
        XCTAssertTrue(FileManager.default.fileExists(atPath: confFile("wn0")))

        let upsBefore = upCount
        XCTAssertNotNil(engine.handle(.up(tunnelID: air, config: airVPN)).error, "new tunnels stay blocked")
        XCTAssertEqual(upCount, upsBefore)
    }

    func testAGoodListingWithoutTheInterfaceIsRealAbsenceEvenWhileIfconfigIFErrors() {
        ok(.up(tunnelID: local, config: localSome))
        commands.downLeavesInterfaceOnly = true
        commands.ifconfigNamedFailsGenerically = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: local)).error)

        commands.slots.removeAll()
        ok(.down(tunnelID: local))
        XCTAssertTrue(status.tunnels.isEmpty)
        XCTAssertFalse(FileManager.default.fileExists(atPath: confFile("wn0")))
    }

    func testAGoodListingWithoutTheSplitTunnelExemptsIt() {
        ok(.up(tunnelID: local, config: localSome))
        ok(.up(tunnelID: air, config: airVPN))
        makeSplitUnreadable()
        commands.slots["wn0"] = nil
        XCTAssertNil(status.routeFailure)
        XCTAssertNotNil(commands.slots["wn1"])
    }

    func testAnUnusableListingIsNeverAbsence() {
        let unusable: [(String, CommandResult)] = [
            ("failed", CommandResult(status: 1, output: "ifconfig: socket: Operation not permitted")),
            ("empty", CommandResult(status: 0, output: "")),
            ("malformed", CommandResult(status: 0, output: "not a listing\n")),
            ("no loopback, so possibly cut", CommandResult(status: 0, output: "en0: flags=8863<UP,RUNNING> mtu 1500\n")),
            ("timed out", CommandResult(status: 124, output: "")),
        ]
        for (reason, listing) in unusable {
            commands.ifconfigEnumeration = nil
            commands.downLeavesInterfaceOnly = false
            ok(.up(tunnelID: local, config: localSome))
            commands.downLeavesInterfaceOnly = true
            XCTAssertNotNil(engine.handle(.down(tunnelID: local)).error, reason)

            // The fake's device is gone now, but nothing here can know that.
            commands.slots.removeAll()
            commands.ifconfigEnumeration = listing
            XCTAssertNotNil(engine.handle(.down(tunnelID: local)).error, reason)
            XCTAssertTrue(FileManager.default.fileExists(atPath: confFile("wn0")), reason)

            commands.ifconfigEnumeration = nil
            ok(.down(tunnelID: local))
        }
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

import Foundation

/// Proves from the running system that an endpoint stays outside a default-route tunnel, because an existing
/// connected physical or loopback route to it is more specific than the tunnel's `/1` routes. Read-only: it never
/// adds a route. Anything unknown, malformed or ambiguous is a refusal.
public enum EndpointRouteProof {
    /// Why the endpoint is not proven, or nil if it is.
    public static func refusal(endpoint: String, ownedInterfaces: Set<String>, runner: CommandRunning) -> String? {
        refusal(
            endpoint: endpoint,
            routeLookup: runner.run("/sbin/route", ["-n", "get", "-inet", endpoint], timeout: 5, readyMarker: nil),
            netstat: readRoutingTable(runner),
            ifconfig: runner.run("/sbin/ifconfig", ["-a"], timeout: 5, readyMarker: nil),
            hardwarePorts: runner.run("/usr/sbin/networksetup", ["-listallhardwareports"], timeout: 15, readyMarker: nil),
            ownedInterfaces: ownedInterfaces
        )
    }

    public static func readRoutingTable(_ runner: CommandRunning) -> CommandResult {
        runner.run("/usr/sbin/netstat", ["-rn", "-f", "inet"], timeout: 5, readyMarker: nil)
    }

    /// The interface an ordinary, unscoped lookup of this address uses, if the answer is well formed.
    public static func lookupInterface(_ address: String, runner: CommandRunning) -> String? {
        let result = runner.run("/sbin/route", ["-n", "get", "-inet", address], timeout: 5, readyMarker: nil)
        guard result.status == 0, let lookup = RouteLookup(result.output),
              lookup.flags.isDisjoint(with: ["REJECT", "BLACKHOLE"]) else { return nil }
        return lookup.interface
    }

    static func refusal(
        endpoint: String, routeLookup: CommandResult, netstat: CommandResult, ifconfig: CommandResult,
        hardwarePorts: CommandResult, ownedInterfaces: Set<String>
    ) -> String? {
        guard let address = ipv4Value(endpoint) else { return "only IPv4 endpoints can be proved" }
        guard routeLookup.status == 0, netstat.status == 0, ifconfig.status == 0, hardwarePorts.status == 0 else {
            return "the system's routes could not be read"
        }
        guard let lookup = RouteLookup(routeLookup.output), let interfaces = parseInterfaces(ifconfig.output),
              let rows = parseRoutingTable(netstat.output) else {
            return "the system's routes could not be understood"
        }

        guard lookup.flags.isDisjoint(with: ["REJECT", "BLACKHOLE"]) else { return "its route is a reject or blackhole route" }
        guard !lookup.flags.contains("GATEWAY") else { return "its route goes through a gateway" }
        guard !ownedInterfaces.contains(lookup.interface) else { return "its route goes into a WireNest tunnel" }
        guard let interface = interfaces[lookup.interface] else { return "its route uses an unknown interface" }

        guard interface.flags.isSuperset(of: ["UP", "RUNNING"]) else { return "\(lookup.interface) is not running" }
        if !interface.flags.contains("LOOPBACK") {
            guard parseHardwareDevices(hardwarePorts.output).contains(lookup.interface),
                  !interface.flags.contains("POINTOPOINT"), interface.status == nil || interface.status == "active" else {
                return "\(lookup.interface) is not a proven physical network"
            }
        }

        // The interface's own mask decides which network it is connected to. A /32 is never a parent, and /1 only ties with the tunnel.
        let networks = interface.networks.filter { (2...31).contains($0.prefix) && $0.contains(address) }
        guard let network = networks.max(by: { $0.prefix < $1.prefix }) else {
            return "\(lookup.interface) has no connected network containing it"
        }
        let parent = rows.first { row in
            row.network == network && row.interface == lookup.interface
                && row.flags.contains("U") && row.flags.contains("C") && row.flags.isDisjoint(with: Set("GHIWBRL"))
                && (row.gateway.hasPrefix("link#") || ipv4Value(row.gateway).map { interface.addresses.contains($0) } == true)
        }
        guard parent != nil else { return "the routing table has no unscoped connected route for \(lookup.interface)" }

        if let mask = lookup.mask {
            // The connected parent itself. CLONING here is the parent, not a WASCLONED cached child.
            guard let lookupPrefix = prefixLength(ofMask: mask), lookup.destination.flatMap(ipv4Value) == network.address,
                  lookupPrefix == network.prefix, lookup.flags.contains("CLONING"),
                  lookup.flags.isDisjoint(with: ["HOST", "WASCLONED", "IFSCOPE"]) else {
                return "its route is not the connected route of \(lookup.interface)"
            }
        } else {
            // A host entry proves nothing alone. It counts only as a child of the parent proven above.
            guard lookup.destination.flatMap(ipv4Value) == address, lookup.flags.contains("HOST"),
                  !lookup.flags.isDisjoint(with: ["WASCLONED", "LOCAL"]) else {
                return "its route is a host route with no proven origin"
            }
        }
        return nil
    }

    /// wg-quick's `/0` as installed: both `/1` rows on this interface, in the kernel's table.
    public static func defaultExpansionsInstalled(netstat: String, on interface: String) -> Bool {
        guard let rows = parseRoutingTable(netstat) else { return false }
        return [IPv4Network(address: 0, prefix: 1), IPv4Network(address: 0x8000_0000, prefix: 1)].allSatisfy { half in
            rows.contains { $0.network == half && $0.interface == interface && $0.flags.contains("U") && $0.flags.isDisjoint(with: Set("IBR")) }
        }
    }
}

public enum InterfacePresence: Equatable {
    case present, absent, unknown
}

/// The only kind of gateway a protective endpoint route may use, derived from the kernel's own default route.
public struct PhysicalGateway: Codable, Equatable {
    public let gateway: String
    public let interface: String

    public init(gateway: String, interface: String) {
        self.gateway = gateway
        self.interface = interface
    }
}

/// What the kernel's table holds for one endpoint, judged against one gateway. `unknown` is never `absent`.
/// `foreign` means no matching row at all. `mixed` means a matching row is there with another, or twice, so neither may be touched.
public enum EndpointRowState: Equatable {
    case unknown, absent, exact, cloneOnly, foreign, mixed
}

extension EndpointRouteProof {
    /// A capture the proof can reason about: a failed or possibly cut one shows nothing, least of all that something is missing.
    private static func isComplete(_ result: CommandResult) -> Bool {
        result.status == 0 && result.output.utf8.count < HelperConstants.maxCommandOutputBytes
    }

    /// The unique unscoped IPv4 default, on a running hardware port, through a gateway on its connected network.
    /// A foreign `/1` means something else already decides where traffic goes, so that is no answer either.
    public static func physicalGateway(netstat: CommandResult, ifconfig: CommandResult, hardwarePorts: CommandResult, ownedInterfaces: Set<String>) -> PhysicalGateway? {
        guard isComplete(netstat), isComplete(ifconfig), isComplete(hardwarePorts),
              let rows = completeRoutingTable(netstat.output), let interfaces = parseInterfaces(ifconfig.output),
              interfaces["lo0"]?.flags.contains("LOOPBACK") == true else { return nil }
        guard !rows.contains(where: { $0.network.prefix == 1 && !ownedInterfaces.contains($0.interface) }) else { return nil }

        let defaults = rows.filter { $0.network.prefix == 0 && !$0.isScoped && !$0.flags.contains("I") }
        guard defaults.count == 1, let row = defaults.first, row.flags.isSuperset(of: Set("UG")), row.flags.isDisjoint(with: Set("BRW")),
              let gateway = ipv4Value(row.gateway), !ownedInterfaces.contains(row.interface),
              let interface = interfaces[row.interface], interface.flags.isSuperset(of: ["UP", "RUNNING"]),
              interface.flags.isDisjoint(with: ["LOOPBACK", "POINTOPOINT"]), interface.status == nil || interface.status == "active",
              parseHardwareDevices(hardwarePorts.output).contains(row.interface), !interface.addresses.contains(gateway) else { return nil }

        let networks = interface.networks.filter { (2...31).contains($0.prefix) && $0.contains(gateway) }
        guard let network = networks.max(by: { $0.prefix < $1.prefix }) else { return nil }
        let connected = rows.contains { candidate in
            candidate.network == network && candidate.interface == row.interface && !candidate.isScoped
                && candidate.flags.contains("U") && candidate.flags.contains("C") && candidate.flags.isDisjoint(with: Set("GHIWBRL"))
                && (candidate.gateway.hasPrefix("link#") || ipv4Value(candidate.gateway).map { interface.addresses.contains($0) } == true)
        }
        return connected ? PhysicalGateway(gateway: row.gateway, interface: row.interface) : nil
    }

    /// Numeric IPv4 unicast only, so nothing else can ever reach `route` as an endpoint.
    public static func isProtectableEndpoint(_ endpoint: String) -> Bool {
        guard let value = ipv4Value(endpoint) else { return false }
        let first = value >> 24
        return first != 0 && first != 127 && first < 224 && value >> 16 != 0xA9FE
    }

    /// True for an endpoint on any connected network, or when that cannot be told. Those belong to the connected-route proof.
    public static func isOnLink(_ endpoint: String, ifconfig: CommandResult) -> Bool {
        guard isComplete(ifconfig), let value = ipv4Value(endpoint), let interfaces = parseInterfaces(ifconfig.output) else { return true }
        return interfaces.values.contains { interface in
            interface.addresses.contains(value) || interface.networks.contains { (2...31).contains($0.prefix) && $0.contains(value) }
        }
    }

    /// Whether a non-cloned route narrower than `/1` but wider than a host covers it, which a pinned host route would silently override. Unknown is yes.
    public static func hasCoveringRoute(_ endpoint: String, netstat: CommandResult) -> Bool {
        guard isComplete(netstat), let value = ipv4Value(endpoint), let rows = completeRoutingTable(netstat.output) else { return true }
        return rows.contains { (2...31).contains($0.network.prefix) && $0.network.contains(value) && !$0.flags.contains("W") }
    }

    public static func endpointRow(_ endpoint: String, gateway: String, interface: String, netstat: CommandResult) -> EndpointRowState {
        guard isComplete(netstat), let value = ipv4Value(endpoint), let rows = completeRoutingTable(netstat.output) else { return .unknown }
        let matching = rows.filter { $0.network == IPv4Network(address: value, prefix: 32) }
        guard !matching.isEmpty else { return .absent }
        let isExact: (RoutingRow) -> Bool = { row in
            !row.isScoped && row.gateway == gateway && row.interface == interface
                && row.flags.isSuperset(of: Set("UGHS")) && row.flags.isDisjoint(with: Set("IBRW"))
        }
        let exactCount = matching.filter(isExact).count
        let others = matching.filter { !isExact($0) && !$0.flags.contains("W") }
        if !others.isEmpty { return exactCount == 0 ? .foreign : .mixed }
        if exactCount > 1 { return .mixed }
        return exactCount == 1 ? .exact : .cloneOnly
    }

    /// The exact pinned row in the kernel's table, and an ordinary lookup that actually selects it.
    public static func gatewayRouteProven(endpoint: String, via physical: PhysicalGateway, netstat: CommandResult, routeLookup: CommandResult) -> Bool {
        guard endpointRow(endpoint, gateway: physical.gateway, interface: physical.interface, netstat: netstat) == .exact,
              routeLookup.status == 0, let lookup = RouteLookup(routeLookup.output), let value = ipv4Value(endpoint) else { return false }
        return lookup.destination.flatMap(ipv4Value) == value && lookup.gateway == physical.gateway && lookup.interface == physical.interface
            && lookup.flags.isSuperset(of: ["HOST", "GATEWAY", "STATIC"])
            && lookup.flags.isDisjoint(with: ["REJECT", "BLACKHOLE", "WASCLONED", "IFSCOPE"])
            && lookup.mask.map { prefixLength(ofMask: $0) == 32 } ?? true
    }
}

extension EndpointRouteProof {
    /// Only a complete `ifconfig -a` listing can show that something is missing. `ifconfig IF` exits 1 for permission, socket
    /// and read errors too. Capture keeps the end of long output, and lo0 comes first, so its absence or a full capture means a cut.
    public static func interfacePresence(_ name: String, ifconfigAll result: CommandResult) -> InterfacePresence {
        guard result.status == 0, result.output.utf8.count < HelperConstants.maxCommandOutputBytes,
              let interfaces = parseInterfaces(result.output), interfaces["lo0"]?.flags.contains("LOOPBACK") == true else {
            return .unknown
        }
        return interfaces[name] == nil ? .absent : .present
    }

    /// This exact network and prefix as an unscoped, installed route on this interface. A cached clone does not count.
    public static func routeInstalled(netstat: String, address: String, prefix: Int, on interface: String) -> Bool {
        guard let rows = parseRoutingTable(netstat), let value = ipv4Value(address), (0...32).contains(prefix) else { return false }
        let wanted = IPv4Network(address: value, prefix: prefix)
        return rows.contains {
            $0.network == wanted && $0.interface == interface && $0.flags.contains("U") && $0.flags.isDisjoint(with: Set("IBRW"))
        }
    }

    /// Whether anything installed other than the `/1` expansions or a default covers this address. A clone made by
    /// traffic through those routes is not a route of its own. An unreadable table counts as yes.
    public static func hasNarrowerRoute(netstat: String, to address: String) -> Bool {
        guard let rows = parseRoutingTable(netstat), let value = ipv4Value(address) else { return true }
        return rows.contains { $0.network.prefix >= 2 && $0.network.contains(value) && !$0.flags.contains("W") }
    }
}

/// Addresses from `wg show … endpoints`, or nil if any is unknown or the output is not understood. A peer with no
/// endpoint yet says "(none)", and that peer could still appear anywhere.
public func parseWgEndpoints(_ output: String) -> [String]? {
    let lines = output.split(separator: "\n")
    guard !lines.isEmpty else { return nil }
    var hosts: [String] = []
    for line in lines {
        let fields = line.split(separator: "\t")
        guard fields.count == 2, let endpoint = WireGuardEndpoint(String(fields[1])), isIPAddress(endpoint.host) else { return nil }
        hosts.append(endpoint.host)
    }
    return hosts
}

private func ipv4Value(_ text: String) -> UInt32? {
    guard let cidr = CIDR(text), !cidr.isIPv6, !text.contains("/") else { return nil }
    return cidr.bytes.reduce(UInt32(0)) { $0 << 8 | UInt32($1) }
}

private func maskValue(prefix: Int) -> UInt32 {
    prefix == 0 ? 0 : ~UInt32(0) << UInt32(32 - prefix)
}

private func prefixLength(ofMask mask: String) -> Int? {
    guard let value = ipv4Value(mask) else { return nil }
    return prefixLength(ofMaskValue: value)
}

private func prefixLength(ofMaskValue value: UInt32) -> Int? {
    let prefix = value.nonzeroBitCount
    return maskValue(prefix: prefix) == value ? prefix : nil
}

private struct IPv4Network: Equatable {
    let address: UInt32
    let prefix: Int

    func contains(_ other: UInt32) -> Bool {
        other & maskValue(prefix: prefix) == address & maskValue(prefix: prefix)
    }

    /// netstat drops trailing zero octets and omits the prefix when it is the address's classful one: `127`, `192.168.64`, `10.0/20`.
    init?(netstatDestination text: String) {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false)
        guard parts.count <= 2 else { return nil }
        let octets = parts[0].split(separator: ".", omittingEmptySubsequences: false).map { UInt8($0) }
        guard (1...4).contains(octets.count), !octets.contains(where: { $0 == nil }) else { return nil }
        let value = octets.compactMap { $0 }.reduce(UInt32(0)) { $0 << 8 | UInt32($1) } << UInt32(8 * (4 - octets.count))
        let first = octets[0]!
        let prefix: Int?
        if parts.count == 2 {
            prefix = Int(parts[1])
        } else if octets.count == 4 {
            prefix = 32
        } else {
            prefix = first < 128 ? 8 : first < 192 ? 16 : first < 224 ? 24 : nil
        }
        guard let prefix, (0...32).contains(prefix), value & ~maskValue(prefix: prefix) == 0 else { return nil }
        self.address = value
        self.prefix = prefix
    }

    init(address: UInt32, prefix: Int) {
        self.address = address & maskValue(prefix: prefix)
        self.prefix = prefix
    }
}

/// `route -n get`, which prints `key: value` lines and then a table of metrics.
private struct RouteLookup {
    let destination: String?
    let mask: String?
    let gateway: String?
    let interface: String
    let flags: Set<String>

    init?(_ text: String) {
        var fields: [String: String] = [:]
        for line in text.split(separator: "\n") {
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces)
            guard ["destination", "mask", "interface", "flags", "gateway", "route to"].contains(key) else { continue }
            guard fields[key] == nil else { return nil }
            fields[key] = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
        }
        guard let interface = fields["interface"], isInterfaceName(interface),
              let flagText = fields["flags"], flagText.hasPrefix("<"), flagText.hasSuffix(">") else { return nil }
        self.destination = fields["destination"]
        self.mask = fields["mask"]
        self.gateway = fields["gateway"]
        self.interface = interface
        self.flags = Set(flagText.dropFirst().dropLast().split(separator: ",").map(String.init))
        guard !flags.isEmpty else { return nil }
    }
}

private func isInterfaceName(_ name: String) -> Bool {
    !name.isEmpty && name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
}

private struct InterfaceInfo {
    var flags: Set<String>
    var addresses: [UInt32] = []
    var networks: [IPv4Network] = []
    var status: String?
}

/// `ifconfig -a`. A name that appears twice makes the whole output ambiguous.
private func parseInterfaces(_ output: String) -> [String: InterfaceInfo]? {
    var interfaces: [String: InterfaceInfo] = [:]
    var current: String?
    for line in output.split(separator: "\n") {
        if let first = line.first, !first.isWhitespace {
            guard let colon = line.firstIndex(of: ":"),
                  let open = line.firstIndex(of: "<"), let close = line.firstIndex(of: ">"), open < close else { return nil }
            let name = String(line[..<colon])
            guard isInterfaceName(name), interfaces[name] == nil else { return nil }
            interfaces[name] = InterfaceInfo(flags: Set(line[line.index(after: open)..<close].split(separator: ",").map(String.init)))
            current = name
            continue
        }
        guard let owner = current else { return nil }
        let tokens = line.split(whereSeparator: \.isWhitespace).map(String.init)
        if tokens.first == "status:", tokens.count >= 2 {
            interfaces[owner]?.status = tokens[1]
        } else if tokens.first == "inet" {
            guard tokens.count >= 4, tokens[2] == "netmask" else { continue }
            // A contiguous mask or nothing: a malformed one must not become a network.
            guard let address = ipv4Value(tokens[1]), tokens[3].hasPrefix("0x"),
                  let mask = UInt32(tokens[3].dropFirst(2), radix: 16), let prefix = prefixLength(ofMaskValue: mask) else { return nil }
            interfaces[owner]?.addresses.append(address)
            interfaces[owner]?.networks.append(IPv4Network(address: address, prefix: prefix))
        }
    }
    return interfaces.isEmpty ? nil : interfaces
}

private struct RoutingRow {
    let network: IPv4Network
    let gateway: String
    let flags: Set<Character>
    let interface: String
    var isScoped = false
}

/// `netstat -rn -f inet` for decisions that change routes, where a row not understood could be the one that matters: any such row, a
/// missing header or an empty table makes the whole table unknown. Includes `default`, which the proof-only parser below has no use for.
private func completeRoutingTable(_ output: String) -> [RoutingRow]? {
    var rows: [RoutingRow] = []
    var inInternet = false, sawHeader = false
    for line in output.split(separator: "\n") {
        if line.hasPrefix("Internet:") {
            guard !inInternet else { return nil }
            inInternet = true
            continue
        }
        guard inInternet else { continue }
        let tokens = line.split(whereSeparator: \.isWhitespace).map(String.init)
        if tokens.isEmpty { continue }
        if tokens[0] == "Destination" {
            guard !sawHeader, tokens.starts(with: ["Destination", "Gateway", "Flags", "Netif"]) else { return nil }
            sawHeader = true
            continue
        }
        guard sawHeader, tokens.count >= 4, isInterfaceName(tokens[3]) else { return nil }

        var destination = tokens[0]
        var isScoped = false
        if let percent = destination.firstIndex(of: "%") {
            isScoped = true
            let end = destination[percent...].firstIndex(of: "/") ?? destination.endIndex
            destination.removeSubrange(percent..<end)
        }
        let parsed: IPv4Network? = destination == "default" ? IPv4Network(address: 0, prefix: 0) : IPv4Network(netstatDestination: destination)
        guard let network = parsed else { return nil }
        rows.append(RoutingRow(network: network, gateway: tokens[1], flags: Set(tokens[2]), interface: tokens[3], isScoped: isScoped))
    }
    return sawHeader && !rows.isEmpty ? rows : nil
}

/// `netstat -rn -f inet`. Rows it cannot read are skipped, as they can only fail to provide proof.
private func parseRoutingTable(_ output: String) -> [RoutingRow]? {
    guard output.contains("Internet:") else { return nil }
    var rows: [RoutingRow] = []
    var inInternet = false
    for line in output.split(separator: "\n") {
        if line.hasPrefix("Internet:") {
            inInternet = true
            continue
        }
        guard inInternet else { continue }
        let tokens = line.split(whereSeparator: \.isWhitespace).map(String.init)
        guard tokens.count >= 4, tokens[0] != "Destination", let network = IPv4Network(netstatDestination: tokens[0]) else { continue }
        rows.append(RoutingRow(network: network, gateway: tokens[1], flags: Set(tokens[2]), interface: tokens[3]))
    }
    return rows
}

private func parseHardwareDevices(_ output: String) -> Set<String> {
    Set(output.split(separator: "\n").compactMap { line -> String? in
        guard line.hasPrefix("Device: ") else { return nil }
        return String(line.dropFirst("Device: ".count))
    })
}

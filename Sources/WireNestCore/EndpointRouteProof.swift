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

    static func readRoutingTable(_ runner: CommandRunning) -> CommandResult {
        runner.run("/usr/sbin/netstat", ["-rn", "-f", "inet"], timeout: 5, readyMarker: nil)
    }

    /// The interface an ordinary, unscoped lookup of this address uses, if the answer is well formed.
    static func lookupInterface(_ address: String, runner: CommandRunning) -> String? {
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

extension EndpointRouteProof {
    /// This exact network and prefix as an unscoped, installed route on this interface. A cached clone does not count.
    public static func routeInstalled(netstat: String, address: String, prefix: Int, on interface: String) -> Bool {
        guard let rows = parseRoutingTable(netstat), let value = ipv4Value(address), (0...32).contains(prefix) else { return false }
        let wanted = IPv4Network(address: value, prefix: prefix)
        return rows.contains {
            $0.network == wanted && $0.interface == interface && $0.flags.contains("U") && $0.flags.isDisjoint(with: Set("IBRW"))
        }
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

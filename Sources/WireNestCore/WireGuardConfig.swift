import CryptoKit
import Foundation

public struct ConfigError: LocalizedError, Equatable {
    public enum Kind: Equatable {
        case structure, unsafeDirective, unknownDirective, duplicateDirective
        case invalidKey, invalidAddress, invalidEndpoint, invalidValue
    }

    public let kind: Kind
    public let line: Int?
    public let message: String

    init(_ kind: Kind, line: Int? = nil, _ message: String) {
        self.kind = kind
        self.line = line
        self.message = message
    }

    public var errorDescription: String? {
        line.map { "Line \($0): \(message)" } ?? message
    }
}

public struct WireGuardEndpoint: Equatable {
    public let host: String
    public let port: Int

    /// The form WireGuard expects, with IPv6 hosts bracketed.
    public var text: String { host.contains(":") ? "[\(host)]:\(port)" : "\(host):\(port)" }

    init?(_ text: String) {
        let hostPart: String, portPart: Substring
        if text.hasPrefix("[") {
            guard let close = text.firstIndex(of: "]"),
                  text.index(after: close) < text.endIndex, text[text.index(after: close)] == ":" else { return nil }
            hostPart = String(text[text.index(after: text.startIndex)..<close])
            guard hostPart.contains(":"), isIPAddress(hostPart) else { return nil }
            portPart = text[text.index(close, offsetBy: 2)...]
        } else {
            guard let colon = text.lastIndex(of: ":") else { return nil }
            hostPart = String(text[..<colon])
            guard !hostPart.contains(":"), isValidHostname(hostPart) else { return nil }
            portPart = text[text.index(after: colon)...]
        }
        guard !portPart.isEmpty, portPart.count <= 5, portPart.allSatisfy({ $0.isASCII && $0.isNumber }),
              let port = Int(portPart), (1...65535).contains(port) else { return nil }
        self.host = hostPart
        self.port = port
    }
}

private func isValidHostname(_ host: String) -> Bool {
    guard (1...253).contains(host.utf8.count) else { return false }
    let labels = host.split(separator: ".", omittingEmptySubsequences: false)
    let allowed = Set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-")
    let wellFormed = labels.allSatisfy { label in
        !label.isEmpty && label.count <= 63 && label.first != "-" && label.last != "-" && label.allSatisfy { allowed.contains($0) }
    }
    guard wellFormed, let last = labels.last else { return false }
    // A numeric final label can only be an IPv4 literal, so `999.1.1.1` must not pass as a hostname.
    return last.allSatisfy({ $0.isNumber }) ? isIPAddress(host) : true
}

public struct WireGuardPeer: Equatable {
    public var publicKey: String
    public var presharedKey: String?
    public var allowedIPs: [CIDR] = []
    public var endpoint: WireGuardEndpoint?
    public var persistentKeepalive: Int?
}

/// A fully validated configuration. Every output is generated from these typed
/// fields, never from the input text, so nothing unvalidated can reach `wg-quick`.
public struct WireGuardConfig: Equatable {
    public enum Table: Equatable { case auto, off }

    public static let maxBytes = 64 * 1024

    public var privateKey: String
    public var addresses: [CIDR]
    public var dnsEntries: [String]
    public var listenPort: Int?
    public var mtu: Int?
    public var table: Table
    public var peers: [WireGuardPeer]

    private static let hookDirectives: Set<String> = ["preup", "postup", "predown", "postdown", "saveconfig"]

    public static func parse(_ text: String) throws -> WireGuardConfig {
        guard text.utf8.count <= maxBytes else {
            throw ConfigError(.structure, "Configuration is larger than \(maxBytes / 1024) KB.")
        }

        var section = ""
        var sawInterface = false
        var privateKey: String?
        var addresses: [CIDR] = []
        var dnsEntries: [String] = []
        var listenPort: Int?
        var mtu: Int?
        var table: Table?
        var peers: [WireGuardPeer] = []
        var peerSeen: Set<String> = []

        func requireFirst(_ isUnset: Bool, _ key: String, _ line: Int) throws {
            if !isUnset { throw ConfigError(.duplicateDirective, line: line, "\(key) appears more than once.") }
        }

        for (index, rawLine) in text.split(omittingEmptySubsequences: false, whereSeparator: \.isNewline).enumerated() {
            let number = index + 1
            let line = rawLine.split(separator: "#", maxSplits: 1, omittingEmptySubsequences: false).first
                .map { $0.trimmingCharacters(in: .whitespaces) } ?? ""
            if line.isEmpty { continue }

            if line.hasPrefix("[") {
                switch line.lowercased() {
                case "[interface]":
                    guard !sawInterface else { throw ConfigError(.structure, line: number, "Only one [Interface] section is allowed.") }
                    sawInterface = true
                    section = "interface"
                case "[peer]":
                    guard sawInterface else { throw ConfigError(.structure, line: number, "[Interface] must come before [Peer].") }
                    section = "peer"
                    peers.append(WireGuardPeer(publicKey: ""))
                    peerSeen = []
                default:
                    throw ConfigError(.structure, line: number, "Unknown section.")
                }
                continue
            }

            guard let equals = line.firstIndex(of: "="), !section.isEmpty else {
                throw ConfigError(.structure, line: number, "Expected “Key = Value” inside a section.")
            }
            let keyName = line[..<equals].trimmingCharacters(in: .whitespaces)
            let key = keyName.lowercased()
            let value = line[line.index(after: equals)...].trimmingCharacters(in: .whitespaces)
            // Names are echoed in errors, so only print them if they are plain identifiers; values never are.
            let shownName = keyName.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber) }) ? keyName : "This directive"

            if hookDirectives.contains(key) {
                throw ConfigError(.unsafeDirective, line: number, "\(shownName) is refused: WireNest never runs hooks or rewrites saved configurations.")
            }

            if section == "interface" {
                switch key {
                case "privatekey":
                    try requireFirst(privateKey == nil, "PrivateKey", number)
                    privateKey = try validatedKey(value, name: "PrivateKey", line: number)
                case "address":
                    addresses += try cidrList(value, name: "Address", line: number)
                case "dns":
                    dnsEntries += try dnsList(value, line: number)
                case "listenport":
                    try requireFirst(listenPort == nil, "ListenPort", number)
                    listenPort = try intValue(value, in: 1...65535, name: "ListenPort", line: number)
                case "mtu":
                    try requireFirst(mtu == nil, "MTU", number)
                    mtu = try intValue(value, in: 576...65535, name: "MTU", line: number)
                case "table":
                    try requireFirst(table == nil, "Table", number)
                    switch value.lowercased() {
                    case "auto": table = .auto
                    case "off": table = .off
                    default: throw ConfigError(.invalidValue, line: number, "Table must be auto or off on macOS.")
                    }
                default:
                    throw ConfigError(.unknownDirective, line: number, "\(shownName) is not supported in [Interface].")
                }
            } else {
                let current = peers.count - 1
                switch key {
                case "publickey":
                    try requireFirst(peerSeen.insert(key).inserted, "PublicKey", number)
                    peers[current].publicKey = try validatedKey(value, name: "PublicKey", line: number)
                case "presharedkey":
                    try requireFirst(peerSeen.insert(key).inserted, "PresharedKey", number)
                    peers[current].presharedKey = try validatedKey(value, name: "PresharedKey", line: number)
                case "allowedips":
                    peers[current].allowedIPs += try cidrList(value, name: "AllowedIPs", line: number)
                case "endpoint":
                    try requireFirst(peerSeen.insert(key).inserted, "Endpoint", number)
                    guard let endpoint = WireGuardEndpoint(value) else {
                        throw ConfigError(.invalidEndpoint, line: number, "Endpoint must be host:port or [IPv6]:port with a port from 1 to 65535.")
                    }
                    peers[current].endpoint = endpoint
                case "persistentkeepalive":
                    try requireFirst(peerSeen.insert(key).inserted, "PersistentKeepalive", number)
                    if value.lowercased() != "off" {
                        let seconds = try intValue(value, in: 0...65535, name: "PersistentKeepalive", line: number)
                        peers[current].persistentKeepalive = seconds == 0 ? nil : seconds
                    }
                default:
                    throw ConfigError(.unknownDirective, line: number, "\(shownName) is not supported in [Peer].")
                }
            }
        }

        guard sawInterface, let privateKey else { throw ConfigError(.structure, "[Interface] with a PrivateKey is required.") }
        guard !addresses.isEmpty else { throw ConfigError(.structure, "[Interface] needs at least one Address.") }
        guard !peers.isEmpty else { throw ConfigError(.structure, "At least one [Peer] is required.") }

        var publicKeys: Set<String> = []
        var routes: Set<CIDR> = []
        for peer in peers {
            guard !peer.publicKey.isEmpty else { throw ConfigError(.structure, "Every [Peer] needs a PublicKey.") }
            guard publicKeys.insert(peer.publicKey).inserted else {
                throw ConfigError(.invalidValue, "Two peers share the same PublicKey.")
            }
            for route in peer.allowedIPs {
                guard routes.insert(route).inserted else {
                    throw ConfigError(.invalidValue, "AllowedIPs \(route) appears more than once; WireGuard would silently keep only one.")
                }
            }
        }

        return WireGuardConfig(
            privateKey: privateKey, addresses: addresses, dnsEntries: dnsEntries,
            listenPort: listenPort, mtu: mtu, table: table ?? .auto, peers: peers
        )
    }

    /// What goes to `wg-quick`: DNS is omitted because connection-level DNS is managed centrally.
    public var runtimeText: String { render(includingDNS: false) }

    /// What WireNest stores and shows in the editor. Keeps imported DNS entries for reference.
    public var storedText: String { render(includingDNS: true) }

    /// Identifies the running configuration without revealing it, so edits restart only the edited tunnel.
    public var fingerprint: String {
        SHA256.hash(data: Data(runtimeText.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    private func render(includingDNS: Bool) -> String {
        var lines = ["[Interface]", "PrivateKey = \(privateKey)", "Address = \(addresses.map(\.description).joined(separator: ", "))"]
        if includingDNS, !dnsEntries.isEmpty { lines.append("DNS = \(dnsEntries.joined(separator: ", "))") }
        if let listenPort { lines.append("ListenPort = \(listenPort)") }
        if let mtu { lines.append("MTU = \(mtu)") }
        if table == .off { lines.append("Table = off") }
        for peer in peers {
            lines += ["", "[Peer]", "PublicKey = \(peer.publicKey)"]
            if let key = peer.presharedKey { lines.append("PresharedKey = \(key)") }
            if !peer.allowedIPs.isEmpty { lines.append("AllowedIPs = \(peer.allowedIPs.map(\.description).joined(separator: ", "))") }
            if let endpoint = peer.endpoint { lines.append("Endpoint = \(endpoint.text)") }
            if let keepalive = peer.persistentKeepalive { lines.append("PersistentKeepalive = \(keepalive)") }
        }
        return lines.joined(separator: "\n") + "\n"
    }
}

private func validatedKey(_ value: String, name: String, line: Int) throws -> String {
    guard value.utf8.count == 44, let data = Data(base64Encoded: value), data.count == 32 else {
        throw ConfigError(.invalidKey, line: line, "\(name) must be a 32-byte base64 WireGuard key.")
    }
    return value
}

private func cidrList(_ value: String, name: String, line: Int) throws -> [CIDR] {
    try value.split(separator: ",", omittingEmptySubsequences: false).map { item in
        let trimmed = item.trimmingCharacters(in: .whitespaces)
        guard let cidr = CIDR(trimmed) else {
            throw ConfigError(.invalidAddress, line: line, "\(name) contains an invalid IP address or CIDR.")
        }
        return cidr
    }
}

private func dnsList(_ value: String, line: Int) throws -> [String] {
    try value.split(separator: ",", omittingEmptySubsequences: false).map { item in
        let trimmed = item.trimmingCharacters(in: .whitespaces)
        guard isIPAddress(trimmed) || isValidHostname(trimmed) else {
            throw ConfigError(.invalidValue, line: line, "DNS entries must be IP addresses or search domains.")
        }
        return trimmed
    }
}

private func intValue(_ value: String, in range: ClosedRange<Int>, name: String, line: Int) throws -> Int {
    guard !value.isEmpty, value.count <= 6, value.allSatisfy({ $0.isASCII && $0.isNumber }),
          let number = Int(value), range.contains(number) else {
        throw ConfigError(.invalidValue, line: line, "\(name) must be a number from \(range.lowerBound) to \(range.upperBound).")
    }
    return number
}

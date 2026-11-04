import Foundation

/// The frozen contract between the app, the installer and the launchd daemon.
public enum HelperConstants {
    public static let protocolVersion = 1
    public static let appIdentifier = "com.marcuschiu.WireNest"
    public static let launchdLabel = "com.marcuschiu.WireNest.helper"
    public static let machServiceName = "com.marcuschiu.WireNest.helper"
    public static let installDir = "/Library/PrivilegedHelperTools/com.marcuschiu.WireNest"
    public static let installedHelper = installDir + "/WireNestHelper"
    public static let installedTools = installDir + "/Tools"
    public static let clientPinPath = installDir + "/client.json"
    public static let launchdPlistPath = "/Library/LaunchDaemons/com.marcuschiu.WireNest.helper.plist"
    public static let toolNames = ["bash", "wg", "wg-quick", "wireguard-go"]
    public static let maxRequestBytes = 256 * 1024
    public static let maxTunnels = 16
    public static let slotNames = (0..<maxTunnels).map { "wn\($0)" }
}

/// One bounded entry point: requests are data, decoded and validated by the helper. There is no way to name a command.
@objc public protocol WireNestHelperXPC {
    func perform(_ request: Data, withReply reply: @escaping (Data) -> Void)
}

public enum HelperRequest: Codable, Equatable {
    case status
    case up(tunnelID: UUID, config: String)
    case down(tunnelID: UUID)
    case downAll
    /// An empty primary restores the original system DNS.
    case setDNS(primary: String, secondary: String)

    public static func decodeBounded(_ data: Data) throws -> HelperRequest {
        guard data.count <= HelperConstants.maxRequestBytes else { throw SecureFileError("Request is too large.") }
        return try JSONDecoder().decode(HelperRequest.self, from: data)
    }
}

public struct PeerStats: Codable, Equatable {
    public let publicKey: String
    public let latestHandshake: Date?
    public let rxBytes: UInt64
    public let txBytes: UInt64

    public init(publicKey: String, latestHandshake: Date?, rxBytes: UInt64, txBytes: UInt64) {
        self.publicKey = publicKey
        self.latestHandshake = latestHandshake
        self.rxBytes = rxBytes
        self.txBytes = txBytes
    }
}

public struct HelperTunnelStatus: Codable, Equatable {
    public let tunnelID: UUID
    public let interface: String
    public let fingerprint: String
    public let alive: Bool
    public let peers: [PeerStats]

    public init(tunnelID: UUID, interface: String, fingerprint: String, alive: Bool, peers: [PeerStats]) {
        self.tunnelID = tunnelID
        self.interface = interface
        self.fingerprint = fingerprint
        self.alive = alive
        self.peers = peers
    }
}

public struct HelperStatus: Codable, Equatable {
    public let protocolVersion: Int
    public let tunnels: [HelperTunnelStatus]
    public let dnsManaged: Bool
    /// Network services whose original DNS servers still wait to be restored.
    public let dnsPendingServices: [String]
}

public struct HelperResponse: Codable, Equatable {
    public let error: String?
    public let status: HelperStatus?

    public init(error: String? = nil, status: HelperStatus? = nil) {
        self.error = error
        self.status = status
    }
}

public func parseWgShow(handshakes: String, transfer: String) -> [PeerStats] {
    var counters: [String: (rx: UInt64, tx: UInt64)] = [:]
    for line in transfer.split(separator: "\n") {
        let fields = line.split(separator: "\t")
        if fields.count == 3, let rx = UInt64(fields[1]), let tx = UInt64(fields[2]) {
            counters[String(fields[0])] = (rx, tx)
        }
    }
    return handshakes.split(separator: "\n").compactMap { line in
        let fields = line.split(separator: "\t")
        guard fields.count == 2, let epoch = TimeInterval(fields[1]) else { return nil }
        let key = String(fields[0])
        return PeerStats(
            publicKey: key,
            latestHandshake: epoch > 0 ? Date(timeIntervalSince1970: epoch) : nil,
            rxBytes: counters[key]?.rx ?? 0,
            txBytes: counters[key]?.tx ?? 0
        )
    }
}

/// Removes anything shaped like a WireGuard key from tool output before it leaves the helper.
public func redactSecrets(_ text: String) -> String {
    text.replacingOccurrences(of: "[A-Za-z0-9+/]{43}=", with: "<redacted>", options: .regularExpression)
}

import Foundation

/// Input to the opt-in `WireNestApp --helper-smoke` diagnostic. Validated strictly so this mode can only ever
/// drive throwaway tunnels on reserved test addresses, and never touch real routing or DNS.
public struct HelperSmokeManifest {
    public struct Tunnel {
        public let id: UUID
        public let configText: String
        public let config: WireGuardConfig
        public let probeHost: String
        public let probePort: Int
        public let expectedToken: String
    }

    private struct Raw: Decodable {
        struct Tunnel: Decodable {
            let id: UUID
            let configPath: String
            let probeHost: String
            let probePort: Int
            let expectedToken: String
        }
        let tunnels: [Tunnel]
        let restartCount: Int
    }

    public let tunnels: [Tunnel]
    public let restartCount: Int

    private static let reservedRange = CIDR("198.18.0.0/15")!

    public static func load(path: String) throws -> HelperSmokeManifest {
        let raw = try JSONDecoder().decode(Raw.self, from: readPrivateFile(path, requirePrivate: false))
        guard raw.tunnels.count == 2, Set(raw.tunnels.map(\.id)).count == 2 else { throw problem("Exactly two distinct tunnels are required.") }
        guard (1...5).contains(raw.restartCount) else { throw problem("restartCount must be from 1 to 5.") }

        let tunnels = try raw.tunnels.map { tunnel -> Tunnel in
            let text = String(decoding: try readPrivateFile(tunnel.configPath, requirePrivate: true), as: UTF8.self)
            let config = try WireGuardConfig.parse(text)
            guard config.dnsEntries.isEmpty else { throw problem("Test configurations must not set DNS.") }
            let routes = config.peers.flatMap(\.allowedIPs)
            guard (routes + config.addresses).allSatisfy(isReserved) else {
                throw problem("Test addresses and routes must stay inside \(reservedRange).")
            }
            guard config.peers.allSatisfy({ $0.endpoint?.host == "127.0.0.1" }) else {
                throw problem("Test peers must use a 127.0.0.1 endpoint.")
            }
            guard let probe = CIDR(tunnel.probeHost), isReserved(probe), routes.contains(where: { $0.overlaps(probe) }) else {
                throw problem("A probe host must be inside its own tunnel's routes.")
            }
            guard (1...65535).contains(tunnel.probePort), !tunnel.expectedToken.isEmpty else {
                throw problem("A probe needs a valid port and an expected token.")
            }
            return Tunnel(
                id: tunnel.id, configText: config.runtimeText, config: config,
                probeHost: tunnel.probeHost, probePort: tunnel.probePort, expectedToken: tunnel.expectedToken
            )
        }
        let conflicts = findRouteConflicts(tunnels.map { NamedConfig(name: $0.id.uuidString, config: $0.config) })
        guard conflicts.isEmpty else { throw RouteConflictError(conflicts: conflicts) }
        return HelperSmokeManifest(tunnels: tunnels, restartCount: raw.restartCount)
    }

    private static func isReserved(_ cidr: CIDR) -> Bool {
        cidr.prefix >= reservedRange.prefix && reservedRange.overlaps(cidr)
    }

    private static func problem(_ message: String) -> SecureFileError {
        SecureFileError("Invalid smoke manifest: \(message)")
    }

    /// Absolute, a regular file, owned by this user. Configs hold private keys, so they must also be unreadable to others.
    private static func readPrivateFile(_ path: String, requirePrivate: Bool) throws -> Data {
        var info = stat()
        guard path.hasPrefix("/"), lstat(path, &info) == 0, info.st_mode & S_IFMT == S_IFREG, info.st_uid == geteuid(),
              !requirePrivate || info.st_mode & 0o077 == 0 else {
            throw problem("A file is not an absolute path to a regular file this user owns\(requirePrivate ? " with mode 0600" : "").")
        }
        let handle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))
        defer { try? handle.close() }
        return try handle.read(upToCount: WireGuardConfig.maxBytes) ?? Data()
    }
}

/// True only for a complete HTTP 200 whose whole body is the token, so a stale or other peer's answer cannot pass.
public func smokeResponseMatches(_ response: String, token: String) -> Bool {
    guard let split = response.range(of: "\r\n\r\n") else { return false }
    let status = response[..<split.lowerBound].components(separatedBy: "\r\n").first ?? ""
    return status.split(separator: " ").dropFirst().first == "200" && response[split.upperBound...] == token
}

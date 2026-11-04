import Foundation

/// Hosted CI only, and on a request made explicitly. This mode captures the whole machine's default route.
public func fullRouteSmokeOptedIn(_ environment: [String: String]) -> Bool {
    environment["WIRENEST_FULL_ROUTE_SMOKE"] == "1" && environment["GITHUB_ACTIONS"] == "true"
        && environment["RUNNER_ENVIRONMENT"] == "github-hosted"
}

/// Input to the opt-in `WireNestApp --helper-full-route-smoke` diagnostic. Separate from `HelperSmokeManifest`, which
/// must keep refusing default routes. Exact values rather than ranges: the harness owns these aliases and test addresses.
public struct HelperFullRouteManifest {
    public enum StartupOrder: String, Decodable {
        case splitFirst = "split-first", fullFirst = "full-first"
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
        let startupOrder: StartupOrder
    }

    public let full: HelperSmokeManifest.Tunnel
    public let split: HelperSmokeManifest.Tunnel
    public let order: StartupOrder

    public static func load(path: String) throws -> HelperFullRouteManifest {
        let data = try HelperSmokeManifest.readPrivateFile(path, requirePrivate: false)
        guard let object = try JSONSerialization.jsonObject(with: data) as? [String: Any],
              Set(object.keys) == ["tunnels", "restartCount", "startupOrder"],
              let entries = object["tunnels"] as? [[String: Any]],
              entries.allSatisfy({ Set($0.keys) == ["id", "configPath", "probeHost", "probePort", "expectedToken"] }) else {
            throw HelperSmokeManifest.problem("Unexpected fields.")
        }
        let raw = try JSONDecoder().decode(Raw.self, from: data)
        guard raw.tunnels.count == 2, raw.tunnels[0].id != raw.tunnels[1].id else {
            throw HelperSmokeManifest.problem("Exactly two distinct tunnels are required.")
        }
        guard raw.restartCount == 1 else { throw HelperSmokeManifest.problem("restartCount must be 1.") }

        let full = try validated(raw.tunnels[0], address: "198.18.71.1/32", route: "0.0.0.0/0", endpoint: "127.77.0.2", probe: "198.18.71.2")
        let split = try validated(raw.tunnels[1], address: "198.18.72.1/32", route: "198.18.72.0/24", endpoint: "127.77.0.3", probe: "198.18.72.2")
        let conflicts = findRouteConflicts([NamedConfig(name: "full", config: full.config), NamedConfig(name: "split", config: split.config)])
        guard conflicts.isEmpty else { throw RouteConflictError(conflicts: conflicts) }
        return HelperFullRouteManifest(full: full, split: split, order: raw.startupOrder)
    }

    private static func validated(_ tunnel: Raw.Tunnel, address: String, route: String, endpoint: String, probe: String) throws -> HelperSmokeManifest.Tunnel {
        let text = String(decoding: try HelperSmokeManifest.readPrivateFile(tunnel.configPath, requirePrivate: true), as: UTF8.self)
        let config = try WireGuardConfig.parse(text)
        guard config.addresses.map(\.description) == [address], config.dnsEntries.isEmpty, config.table == .auto,
              config.peers.count == 1, config.peers[0].allowedIPs.map(\.description) == [route],
              config.peers[0].endpoint?.host == endpoint else {
            throw HelperSmokeManifest.problem("A test configuration is not exactly Address \(address), AllowedIPs \(route), Endpoint \(endpoint).")
        }
        guard tunnel.probeHost == probe, (1...65535).contains(tunnel.probePort), !tunnel.expectedToken.isEmpty else {
            throw HelperSmokeManifest.problem("A probe must be \(probe), with a valid port and an expected token.")
        }
        return HelperSmokeManifest.Tunnel(
            id: tunnel.id, configText: config.runtimeText, config: config,
            probeHost: tunnel.probeHost, probePort: tunnel.probePort, expectedToken: tunnel.expectedToken
        )
    }
}

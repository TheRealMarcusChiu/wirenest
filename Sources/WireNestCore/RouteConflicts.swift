import Foundation

public struct NamedConfig {
    public let name: String
    public let config: WireGuardConfig

    public init(name: String, config: WireGuardConfig) {
        self.name = name
        self.config = config
    }
}

public struct RouteConflict: Equatable {
    public enum Kind: Equatable { case overlappingRoutes, multipleDefaultRoutes, endpointCaptured, listenPort }
    public let kind: Kind
    public let message: String
}

public struct RouteConflictError: LocalizedError, Equatable {
    public let conflicts: [RouteConflict]

    public init(conflicts: [RouteConflict]) { self.conflicts = conflicts }

    public var errorDescription: String? { conflicts.map(\.message).joined(separator: "\n") }
}

/// Reports at most one conflict per tunnel pair per kind, in input order.
///
/// A `/0` route is exempt from overlap checks against other tunnels: wg-quick installs
/// it as two `/1` routes, so another tunnel's narrower route deterministically wins by
/// longest-prefix match. Two owners of the same family's default are never allowed.
public func findRouteConflicts(_ tunnels: [NamedConfig]) -> [RouteConflict] {
    var conflicts: [RouteConflict] = []
    for (i, a) in tunnels.enumerated() {
        for b in tunnels[(i + 1)...] {
            conflicts += conflictsBetween(a, b)
        }
    }
    return conflicts
}

private func installedRoutes(_ config: WireGuardConfig) -> [CIDR] {
    config.table == .off ? [] : config.peers.flatMap(\.allowedIPs)
}

private func conflictsBetween(_ a: NamedConfig, _ b: NamedConfig) -> [RouteConflict] {
    var result: [RouteConflict] = []
    let routesA = installedRoutes(a.config), routesB = installedRoutes(b.config)

    for isIPv6 in [false, true] {
        let hasDefault: ([CIDR]) -> Bool = { $0.contains { $0.isDefaultRoute && $0.isIPv6 == isIPv6 } }
        if hasDefault(routesA) && hasDefault(routesB) {
            result.append(RouteConflict(
                kind: .multipleDefaultRoutes,
                message: "“\(a.name)” and “\(b.name)” both claim the \(isIPv6 ? "IPv6" : "IPv4") default route. Only one tunnel can own it: disable one or narrow its AllowedIPs."
            ))
            break
        }
    }

    let specificA = routesA.filter { !$0.isDefaultRoute } + a.config.addresses
    let specificB = routesB.filter { !$0.isDefaultRoute } + b.config.addresses
    overlap: for routeA in specificA {
        for routeB in specificB where routeA.overlaps(routeB) {
            result.append(RouteConflict(
                kind: .overlappingRoutes,
                message: "“\(a.name)” (\(routeA)) and “\(b.name)” (\(routeB)) overlap. Disable one tunnel or change its Address or AllowedIPs."
            ))
            break overlap
        }
    }

    capture: for (owner, otherName, other) in [(a, b.name, specificB), (b, a.name, specificA)] {
        for peer in owner.config.peers {
            guard let host = peer.endpoint?.host, let endpoint = CIDR(host) else { continue }
            if let route = other.first(where: { $0.overlaps(endpoint) }) {
                result.append(RouteConflict(
                    kind: .endpointCaptured,
                    message: "The endpoint of “\(owner.name)” (\(host)) would be routed into “\(otherName)” by \(route). Disable one tunnel or change its AllowedIPs."
                ))
                break capture
            }
        }
    }

    if let port = a.config.listenPort, port == b.config.listenPort {
        result.append(RouteConflict(
            kind: .listenPort,
            message: "“\(a.name)” and “\(b.name)” both use ListenPort \(port). Remove or change one of them."
        ))
    }
    return result
}

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

/// One tunnel's encrypted traffic could be captured by another tunnel's default route unless each
/// endpoint has a more specific route. Only the running system can answer that.
public struct EndpointExposure: Equatable {
    public let tunnel: String
    public let defaultOwner: String
    public let isIPv6: Bool
    /// Endpoints from the config in the default route's family. A running tunnel's actual endpoints take over.
    public let configuredEndpoints: [String]
}

public struct RouteAssessment: Equatable {
    /// Can never be safe, whatever the system's routes are.
    public let conflicts: [RouteConflict]
    /// Allowed only if proved at run time.
    public let exposures: [EndpointExposure]
}

/// Compares what each tunnel really installs, pair by pair in input order, with at most one conflict per pair per kind.
///
/// wg-quick installs an IPv4 `/0` as two `/1` routes, so a narrower route of another tunnel wins by longest-prefix
/// match. That is the only overlap excused here, and only on the condition recorded in `exposures`. A `/1` ties
/// with the expansion, and IPv6 has no such exception.
public func assessRoutes(_ tunnels: [NamedConfig]) -> RouteAssessment {
    var conflicts: [RouteConflict] = []
    var exposures: [EndpointExposure] = []
    for (i, a) in tunnels.enumerated() {
        for b in tunnels[(i + 1)...] {
            let found = conflictsBetween(a, b)
            conflicts += found
            if found.contains(where: { $0.kind == .multipleDefaultRoutes }) { continue }
            exposures += exposuresOf(a, to: b) + exposuresOf(b, to: a)
        }
    }
    return RouteAssessment(conflicts: conflicts, exposures: exposures)
}

public func findRouteConflicts(_ tunnels: [NamedConfig]) -> [RouteConflict] {
    assessRoutes(tunnels).conflicts
}

private func installedRoutes(_ config: WireGuardConfig) -> [CIDR] {
    config.table == .off ? [] : config.peers.flatMap(\.allowedIPs)
}

private func exposuresOf(_ tunnel: NamedConfig, to owner: NamedConfig) -> [EndpointExposure] {
    let defaults = installedRoutes(owner.config).filter(\.isDefaultRoute)
    return [false, true].filter { family in defaults.contains { $0.isIPv6 == family } }.map { family in
        EndpointExposure(
            tunnel: tunnel.name, defaultOwner: owner.name, isIPv6: family,
            configuredEndpoints: tunnel.config.peers.compactMap { peer in
                guard let host = peer.endpoint?.host, CIDR(host)?.isIPv6 == family else { return nil }
                return host
            }
        )
    }
}

/// Only an installed IPv4 default route, beside anything narrower than its `/1` expansion.
private func excusedByLongestPrefix(_ route: CIDR, isInstalledRoute: Bool, against other: CIDR) -> Bool {
    isInstalledRoute && route.isDefaultRoute && !route.isIPv6 && other.prefix >= 2
}

private func conflictsBetween(_ a: NamedConfig, _ b: NamedConfig) -> [RouteConflict] {
    var result: [RouteConflict] = []
    let routesA = installedRoutes(a.config), routesB = installedRoutes(b.config)

    for isIPv6 in [false, true] {
        let hasDefault: ([CIDR]) -> Bool = { $0.contains { $0.isDefaultRoute && $0.isIPv6 == isIPv6 } }
        if hasDefault(routesA) && hasDefault(routesB) {
            // This one fix is needed first, and every other overlap of a /0 would only repeat it.
            return [RouteConflict(
                kind: .multipleDefaultRoutes,
                message: "“\(a.name)” and “\(b.name)” both claim the \(isIPv6 ? "IPv6" : "IPv4") default route. Only one tunnel can own it: disable one or narrow its AllowedIPs."
            )]
        }
    }

    let coveredA: [(CIDR, Bool)] = routesA.map { ($0, true) } + a.config.addresses.map { ($0, false) }
    let coveredB: [(CIDR, Bool)] = routesB.map { ($0, true) } + b.config.addresses.map { ($0, false) }
    overlap: for (routeA, isRouteA) in coveredA {
        for (routeB, isRouteB) in coveredB where routeA.overlaps(routeB) {
            if excusedByLongestPrefix(routeA, isInstalledRoute: isRouteA, against: routeB)
                || excusedByLongestPrefix(routeB, isInstalledRoute: isRouteB, against: routeA) { continue }
            result.append(RouteConflict(
                kind: .overlappingRoutes,
                message: "“\(a.name)” (\(routeA)) and “\(b.name)” (\(routeB)) overlap. Disable one tunnel or change its Address or AllowedIPs."
            ))
            break overlap
        }
    }

    capture: for (owner, otherName, otherRoutes, otherAddresses) in [(a, b.name, routesB, b.config.addresses), (b, a.name, routesA, a.config.addresses)] {
        let other = otherRoutes + otherAddresses
        for peer in owner.config.peers {
            guard let host = peer.endpoint?.host else {
                // The peer's address arrives at run time, so nothing can be checked in advance.
                if let route = other.first(where: \.isDefaultRoute) {
                    result.append(RouteConflict(
                        kind: .endpointCaptured,
                        message: "A peer of “\(owner.name)” has no Endpoint, so it cannot be kept out of “\(otherName)” and its \(route). Set a numeric Endpoint, or disable one tunnel."
                    ))
                    break capture
                }
                continue
            }
            guard let endpoint = CIDR(host) else {
                // A name can resolve to either family at any time, so only a numeric endpoint can prove it escapes a default route.
                if let route = other.first(where: \.isDefaultRoute) {
                    result.append(RouteConflict(
                        kind: .endpointCaptured,
                        message: "The endpoint of “\(owner.name)” (\(host)) is a hostname that could be routed into “\(otherName)” by \(route). Use a numeric endpoint, or disable one tunnel."
                    ))
                    break capture
                }
                continue
            }
            // An IPv4 default route is the one capture that can be disproved at run time, through an `EndpointExposure`.
            let capturing = otherRoutes.first { $0.overlaps(endpoint) && !($0.isDefaultRoute && !$0.isIPv6) }
                ?? otherAddresses.first { $0.overlaps(endpoint) }
            if let route = capturing {
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

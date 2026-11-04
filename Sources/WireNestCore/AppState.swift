import Foundation

public struct SavedTunnel: Codable, Identifiable, Equatable {
    public var id: UUID
    public var name: String
    public var enabled: Bool
    /// The canonical configuration, held by value: the imported file is never referenced again.
    public var configText: String

    public init(id: UUID = UUID(), name: String, enabled: Bool, configText: String) {
        self.id = id
        self.name = name
        self.enabled = enabled
        self.configText = configText
    }
}

public struct ConnectionProfile: Codable, Identifiable, Equatable {
    public var id: UUID
    public var name: String
    public var tunnels: [SavedTunnel]
    public var primaryDNS: String
    public var secondaryDNS: String

    public init(id: UUID = UUID(), name: String, tunnels: [SavedTunnel] = [], primaryDNS: String = "", secondaryDNS: String = "") {
        self.id = id
        self.name = name
        self.tunnels = tunnels
        self.primaryDNS = primaryDNS
        self.secondaryDNS = secondaryDNS
    }

    /// Empty means “leave system DNS alone”.
    public var dnsServers: [String] { [primaryDNS, secondaryDNS].filter { !$0.isEmpty } }
}

public enum RuleCondition: Codable, Equatable {
    case ssidEquals(String)
    case ssidNotEquals(String)
    case publicIPInRange(String)
}

public struct NetworkRule: Codable, Identifiable, Equatable {
    public var id: UUID
    public var enabled: Bool
    public var condition: RuleCondition
    public var profileID: UUID

    public init(id: UUID = UUID(), enabled: Bool = true, condition: RuleCondition, profileID: UUID) {
        self.id = id
        self.enabled = enabled
        self.condition = condition
        self.profileID = profileID
    }
}

public struct DesiredTunnel: Equatable {
    public let id: UUID
    public let name: String
    public let configText: String
    public let fingerprint: String

    public init(id: UUID, name: String, configText: String, fingerprint: String) {
        self.id = id
        self.name = name
        self.configText = configText
        self.fingerprint = fingerprint
    }
}

public struct ImportOutcome: Equatable {
    public let tunnelID: UUID
    public let conflicts: [RouteConflict]
}

public struct StateError: LocalizedError, Equatable {
    public let errorDescription: String?

    init(_ message: String) { errorDescription = message }
}

public struct AppState: Codable, Equatable {
    public static let defaultPublicIPCheckURL = "https://api.ipify.org/"

    public var profiles: [ConnectionProfile] = []
    public var activeProfileID: UUID?
    /// The user's persisted intent, restored at login. False after any disconnect.
    public var connectionOn = false
    /// Set only by an explicit disconnect; blocks every automatic connect until the user connects again.
    public var manualOff = false
    /// Network context in which the user picked a connection by hand; rules wait until it changes.
    public var pinnedContext: String?
    /// Evaluated in order: the first matching rule wins.
    public var rules: [NetworkRule] = []
    public var publicIPAutomationEnabled = false
    public var publicIPCheckURL = AppState.defaultPublicIPCheckURL

    public init() {}

    public func profile(_ id: UUID) -> ConnectionProfile? {
        profiles.first { $0.id == id }
    }

    public func tunnel(_ id: UUID) -> SavedTunnel? {
        for profile in profiles {
            if let tunnel = profile.tunnels.first(where: { $0.id == id }) { return tunnel }
        }
        return nil
    }

    private func location(of tunnelID: UUID) -> (profile: Int, tunnel: Int)? {
        for (p, profile) in profiles.enumerated() {
            if let t = profile.tunnels.firstIndex(where: { $0.id == tunnelID }) { return (p, t) }
        }
        return nil
    }

    // MARK: Profiles

    @discardableResult
    public mutating func addProfile(name: String) -> UUID {
        let profile = ConnectionProfile(name: name)
        profiles.append(profile)
        return profile.id
    }

    @discardableResult
    public mutating func duplicateProfile(_ id: UUID) -> UUID? {
        guard var copy = profile(id) else { return nil }
        copy.id = UUID()
        copy.name += " Copy"
        copy.tunnels = copy.tunnels.map { SavedTunnel(name: $0.name, enabled: $0.enabled, configText: $0.configText) }
        profiles.append(copy)
        return copy.id
    }

    public mutating func removeProfile(_ id: UUID) {
        profiles.removeAll { $0.id == id }
        rules.removeAll { $0.profileID == id }
        if activeProfileID == id {
            activeProfileID = nil
            connectionOn = false
        }
    }

    public mutating func renameProfile(_ id: UUID, to name: String) {
        if let index = profiles.firstIndex(where: { $0.id == id }) { profiles[index].name = name }
    }

    public mutating func setDNS(_ id: UUID, primary: String, secondary: String) throws {
        guard let index = profiles.firstIndex(where: { $0.id == id }) else { throw StateError("Connection no longer exists.") }
        let primary = primary.trimmingCharacters(in: .whitespacesAndNewlines)
        let secondary = secondary.trimmingCharacters(in: .whitespacesAndNewlines)
        try validateDNS(primary: primary, secondary: secondary)
        profiles[index].primaryDNS = primary
        profiles[index].secondaryDNS = secondary
    }

    // MARK: Tunnels

    public mutating func importTunnel(fileAt url: URL, into profileID: UUID) throws -> ImportOutcome {
        let handle = try FileHandle(forReadingFrom: url)
        defer { try? handle.close() }
        let data = try handle.read(upToCount: WireGuardConfig.maxBytes + 1) ?? Data()
        guard data.count <= WireGuardConfig.maxBytes else {
            throw ConfigError(.structure, "Configuration is larger than \(WireGuardConfig.maxBytes / 1024) KB.")
        }
        guard let text = String(data: data, encoding: .utf8) else {
            throw ConfigError(.structure, "Configuration is not UTF-8 text.")
        }
        return try importTunnel(text: text, name: url.deletingPathExtension().lastPathComponent, into: profileID)
    }

    /// A tunnel that conflicts with an enabled sibling is still saved, but disabled, so the import is not lost.
    public mutating func importTunnel(text: String, name: String, into profileID: UUID) throws -> ImportOutcome {
        guard let index = profiles.firstIndex(where: { $0.id == profileID }) else { throw StateError("Connection no longer exists.") }
        let config = try WireGuardConfig.parse(text)
        let conflicts = try conflictsWithEnabled(config, name: name, in: profiles[index], excluding: nil)
        let tunnel = SavedTunnel(name: name, enabled: conflicts.isEmpty, configText: config.storedText)
        profiles[index].tunnels.append(tunnel)
        return ImportOutcome(tunnelID: tunnel.id, conflicts: conflicts)
    }

    /// The copy starts disabled because it necessarily overlaps its source.
    public mutating func duplicateTunnel(_ id: UUID) -> UUID? {
        guard let at = location(of: id) else { return nil }
        let source = profiles[at.profile].tunnels[at.tunnel]
        let copy = SavedTunnel(name: source.name + " Copy", enabled: false, configText: source.configText)
        profiles[at.profile].tunnels.insert(copy, at: at.tunnel + 1)
        return copy.id
    }

    public mutating func updateTunnel(_ id: UUID, name: String, configText: String) throws {
        guard let at = location(of: id) else { throw StateError("Tunnel no longer exists.") }
        let config = try WireGuardConfig.parse(configText)
        if profiles[at.profile].tunnels[at.tunnel].enabled {
            let conflicts = try conflictsWithEnabled(config, name: name, in: profiles[at.profile], excluding: id)
            if !conflicts.isEmpty { throw RouteConflictError(conflicts: conflicts) }
        }
        profiles[at.profile].tunnels[at.tunnel].name = name
        profiles[at.profile].tunnels[at.tunnel].configText = config.storedText
    }

    public mutating func removeTunnel(_ id: UUID) {
        guard let at = location(of: id) else { return }
        profiles[at.profile].tunnels.remove(at: at.tunnel)
    }

    public mutating func setTunnelEnabled(_ id: UUID, _ enabled: Bool) throws {
        guard let at = location(of: id) else { throw StateError("Tunnel no longer exists.") }
        if enabled {
            let tunnel = profiles[at.profile].tunnels[at.tunnel]
            let config = try WireGuardConfig.parse(tunnel.configText)
            let conflicts = try conflictsWithEnabled(config, name: tunnel.name, in: profiles[at.profile], excluding: id)
            if !conflicts.isEmpty { throw RouteConflictError(conflicts: conflicts) }
        }
        profiles[at.profile].tunnels[at.tunnel].enabled = enabled
    }

    private func conflictsWithEnabled(_ config: WireGuardConfig, name: String, in profile: ConnectionProfile, excluding: UUID?) throws -> [RouteConflict] {
        let others = try profile.tunnels.filter { $0.enabled && $0.id != excluding }.map {
            NamedConfig(name: $0.name, config: try WireGuardConfig.parse($0.configText))
        }
        let candidate = NamedConfig(name: name, config: config)
        return others.flatMap { findRouteConflicts([$0, candidate]) }
    }

    // MARK: Connect / disconnect

    public mutating func connect(_ profileID: UUID, pinContext: String?) throws {
        guard let target = profile(profileID) else { throw StateError("Connection no longer exists.") }
        _ = try Self.resolveEnabledTunnels(target, requireAny: true)
        activeProfileID = profileID
        connectionOn = true
        manualOff = false
        pinnedContext = pinContext
    }

    public mutating func disconnect() {
        connectionOn = false
        manualOff = true
        pinnedContext = nil
    }

    /// What should be running right now. Throws rather than returning a partial set if the saved data conflicts.
    public func desiredTunnels() throws -> [DesiredTunnel] {
        guard connectionOn, let id = activeProfileID, let active = profile(id) else { return [] }
        return try Self.resolveEnabledTunnels(active, requireAny: false)
    }

    private static func resolveEnabledTunnels(_ profile: ConnectionProfile, requireAny: Bool) throws -> [DesiredTunnel] {
        let enabled = profile.tunnels.filter(\.enabled)
        if requireAny, enabled.isEmpty {
            throw StateError("“\(profile.name)” has no enabled tunnels. Import or enable one first.")
        }
        let parsed = try enabled.map { tunnel -> NamedConfig in
            do {
                return NamedConfig(name: tunnel.name, config: try WireGuardConfig.parse(tunnel.configText))
            } catch {
                throw StateError("“\(tunnel.name)”: \(error.localizedDescription)")
            }
        }
        let conflicts = findRouteConflicts(parsed)
        if !conflicts.isEmpty { throw RouteConflictError(conflicts: conflicts) }
        return zip(enabled, parsed).map {
            DesiredTunnel(id: $0.id, name: $0.name, configText: $1.config.runtimeText, fingerprint: $1.config.fingerprint)
        }
    }
}

/// Used by both the app and, again, by the root helper.
public func validateDNS(primary: String, secondary: String) throws {
    if !primary.isEmpty, !isIPAddress(primary) { throw StateError("Primary DNS must be an IP address.") }
    if !secondary.isEmpty, !isIPAddress(secondary) { throw StateError("Secondary DNS must be an IP address.") }
    if primary.isEmpty, !secondary.isEmpty { throw StateError("Set a primary DNS server before a secondary one.") }
}

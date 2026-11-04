import Foundation

public enum SSIDObservation: Equatable {
    case known(String)
    case unavailable(String)

    public var name: String? {
        if case .known(let name) = self { return name }
        return nil
    }
}

public struct NetworkSnapshot: Equatable {
    public var ssid: SSIDObservation
    public var publicIP: String?

    public init(ssid: SSIDObservation, publicIP: String? = nil) {
        self.ssid = ssid
        self.publicIP = publicIP
    }

    /// Identifies the network for manual pins. Nil means “no information”, which never sets a pin.
    public func contextKey(includingPublicIP: Bool) -> String? {
        let ip = includingPublicIP ? publicIP : nil
        if ssid.name == nil, ip == nil { return nil }
        return "ssid:\(ssid.name ?? "?")|ip:\(ip ?? "?")"
    }

    /// Only a known value that differs from a known pinned value counts: a failed probe or a
    /// missing SSID is not a network change.
    func contradicts(pin: String, includingPublicIP: Bool) -> Bool {
        guard let split = pin.range(of: "|ip:", options: .backwards) else { return true }
        let pinnedSSID = pin[..<split.lowerBound].dropFirst("ssid:".count)
        let pinnedIP = pin[split.upperBound...]
        if let name = ssid.name, pinnedSSID != "?", name != pinnedSSID { return true }
        if includingPublicIP, let publicIP, pinnedIP != "?", publicIP != pinnedIP { return true }
        return false
    }
}

extension RuleCondition {
    /// Unknown values never match: an unavailable SSID must not satisfy “not this SSID”.
    func matches(_ snapshot: NetworkSnapshot, publicIPAllowed: Bool, publicIPChanged: Bool) -> Bool {
        switch self {
        case .publicIPChanges:
            return publicIPChanged
        case .ssidEquals(let name):
            return snapshot.ssid.name == name
        case .ssidNotEquals(let name):
            guard let current = snapshot.ssid.name else { return false }
            return current != name
        case .publicIPInRange(let range):
            guard publicIPAllowed, let ip = snapshot.publicIP, let network = CIDR(range), let address = CIDR(ip) else { return false }
            return network.overlaps(address)
        }
    }
}

public struct RuleEngine {
    /// A candidate must stay the same this long before it acts, which absorbs network flaps.
    public let debounce: TimeInterval = 5
    /// Minimum time between automatic switches.
    public let minDwell: TimeInterval = 30

    private var pending: (profile: UUID, since: Date)?
    private var lastSwitch: Date?
    /// Last known stable public IP this run. Deliberately kept through failed probes.
    private var publicIPBaseline: String?
    /// A real change waiting out debounce and dwell. Rules that win over it, or any guard, drop it.
    private var publicIPChangePending = false

    public init() {}

    /// Returns the profile that should be connected now, or nil to keep the current state.
    /// A rule never disconnects: with no match the current connection stays as it is.
    public mutating func evaluate(state: inout AppState, snapshot: NetworkSnapshot, now: Date) -> UUID? {
        let publicIPAllowed = state.publicIPAutomationEnabled
        let changedNow = observePublicIP(snapshot.publicIP, enabled: publicIPAllowed)

        guard !state.manualOff else {
            pending = nil
            publicIPChangePending = false
            return nil
        }
        if let pin = state.pinnedContext {
            guard changedNow || snapshot.contradicts(pin: pin, includingPublicIP: publicIPAllowed) else {
                pending = nil
                publicIPChangePending = false
                return nil
            }
            state.pinnedContext = nil
        }

        let changed = publicIPChangePending
        let winner = state.rules.first { rule in
            guard rule.enabled, let target = state.profile(rule.profileID), target.ineligibilityReason(snapshot.ssid) == nil else { return false }
            return rule.condition.matches(snapshot, publicIPAllowed: publicIPAllowed, publicIPChanged: changed)
        }
        let firesOnChange = winner?.condition == .publicIPChanges
        if !firesOnChange { publicIPChangePending = false }

        guard let candidate = winner?.profileID, !(candidate == state.activeProfileID && state.connectionOn) else {
            pending = nil
            publicIPChangePending = false
            return nil
        }

        guard let pending, pending.profile == candidate else {
            self.pending = (candidate, now)
            return nil
        }
        guard now.timeIntervalSince(pending.since) >= debounce else { return nil }
        if let lastSwitch, now.timeIntervalSince(lastSwitch) < minDwell { return nil }
        self.pending = nil
        lastSwitch = now
        if firesOnChange {
            publicIPChangePending = false
            // A one-shot event has nothing to hold it afterwards, so lower rules would otherwise flip straight back.
            state.pinnedContext = snapshot.contextKey(includingPublicIP: true)
        }
        return candidate
    }

    /// True only for a known address replacing a different known one: the first address is just a baseline.
    private mutating func observePublicIP(_ ip: String?, enabled: Bool) -> Bool {
        guard enabled else {
            publicIPBaseline = nil
            publicIPChangePending = false
            return false
        }
        guard let ip, ip != publicIPBaseline else { return false }
        defer { publicIPBaseline = ip }
        guard publicIPBaseline != nil else { return false }
        publicIPChangePending = true
        return true
    }
}

/// Accepts a public IP change only after two consecutive identical probes, so one odd answer cannot move rules.
public struct PublicIPStabilizer {
    private var candidate: String??
    private var stable: String?

    public init() {}

    public mutating func observe(_ ip: String?) -> String? {
        if candidate == .some(ip) { stable = ip }
        candidate = .some(ip)
        return stable
    }
}

/// A validated public-IP check URL. Only plain HTTPS with no embedded credentials.
public struct PublicIPEndpoint: Equatable {
    public let host: String
    public let path: String

    public init?(urlString: String) {
        guard urlString.allSatisfy({ $0.isASCII && !$0.isWhitespace && !$0.isNewline }),
              let parts = URLComponents(string: urlString), parts.scheme == "https",
              parts.user == nil, parts.password == nil, parts.port == nil,
              let host = parts.host, !host.isEmpty else { return nil }
        self.host = host
        var path = parts.percentEncodedPath.isEmpty ? "/" : parts.percentEncodedPath
        if let query = parts.percentEncodedQuery { path += "?" + query }
        self.path = path
    }

    /// Deliberately minimal: nothing about the user or their tunnels is sent.
    public var requestData: Data {
        Data("GET \(path) HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: WireNest\r\nAccept: text/plain\r\nConnection: close\r\n\r\n".utf8)
    }
}

public func publicIP(fromHTTPResponse response: String) -> String? {
    guard let split = response.range(of: "\r\n\r\n") else { return nil }
    let status = response[..<split.lowerBound].components(separatedBy: "\r\n").first ?? ""
    guard status.split(separator: " ").dropFirst().first == "200" else { return nil }
    return response[split.upperBound...]
        .components(separatedBy: .whitespacesAndNewlines)
        .first(where: isIPAddress)
}

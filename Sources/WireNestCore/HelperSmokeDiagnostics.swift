import Foundation

/// How far one probe connection got. Typed, so no response bytes or system-worded error text can reach a log.
public enum SmokeProbeStage: Int, Comparable {
    case setup, preparing, waiting, ready, sent, receivedData, endOfStream

    public static func < (lhs: SmokeProbeStage, rhs: SmokeProbeStage) -> Bool { lhs.rawValue < rhs.rawValue }
}

public struct SmokeProbeError: Hashable {
    public enum Category: String { case posix, dns, tls, other }
    public let category: Category
    public let code: Int32

    public init(category: Category, code: Int32) {
        self.category = category
        self.code = code
    }
}

public struct SmokeProbeProgress: Equatable {
    public private(set) var stage = SmokeProbeStage.setup
    public private(set) var lastError: SmokeProbeError?
    public var timedOut = false

    public init() {}

    public mutating func reach(_ next: SmokeProbeStage) {
        stage = max(stage, next)
    }

    public mutating func note(_ error: SmokeProbeError) {
        lastError = error
    }
}

/// What one probe establishes, with the response itself dropped here so that nothing later can log it.
public struct SmokeProbeAttempt: Hashable {
    public let stage: SmokeProbeStage
    public let lastError: SmokeProbeError?
    public let timedOut: Bool
    public let receivedBytes: Int
    public let headerComplete: Bool
    public let status200: Bool
    public let bodyMatches: Bool

    public init(progress: SmokeProbeProgress, response: String, receivedBytes: Int, token: String) {
        stage = progress.stage
        lastError = progress.lastError
        timedOut = progress.timedOut
        self.receivedBytes = receivedBytes
        let check = SmokeResponseCheck(response: response, token: token)
        headerComplete = check.headerComplete
        status200 = check.status200
        bodyMatches = check.bodyMatches
    }

    public var matches: Bool { headerComplete && status200 && bodyMatches }
}

private func safeLabel(_ text: String) -> String {
    text.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "/" || $0 == "-") } && (1...40).contains(text.count) ? text : "invalid"
}

/// One line per probe however many attempts it took, with repeats counted and distinct outcomes capped.
public func formatProbeDiagnostic(tunnel: String, phase: String, attempts: [SmokeProbeAttempt]) -> String {
    let limit = 4
    var order: [SmokeProbeAttempt] = []
    var counts: [SmokeProbeAttempt: Int] = [:]
    for attempt in attempts {
        if counts[attempt] == nil { order.append(attempt) }
        counts[attempt, default: 0] += 1
    }
    let outcomes = order.prefix(limit).map { outcome -> String in
        let error = outcome.lastError.map { "\($0.category.rawValue):\($0.code)" } ?? "none"
        return "\(counts[outcome] ?? 0)x[stage=\(outcome.stage) error=\(error) timedOut=\(outcome.timedOut) bytes=\(outcome.receivedBytes) header=\(outcome.headerComplete) status200=\(outcome.status200) body=\(outcome.bodyMatches)]"
    }
    let hidden = order.dropFirst(limit).reduce(0) { $0 + (counts[$1] ?? 0) }
    let matched = attempts.last?.matches ?? false
    return "probe tunnel=\(safeLabel(tunnel)) phase=\(safeLabel(phase)) matched=\(matched) attempts=\(attempts.count) "
        + outcomes.joined(separator: " ") + (hidden > 0 ? " otherOutcomes=\(hidden)" : "")
}

/// Only an interface name, health and counters: never keys, the fingerprint or an endpoint.
public func formatTunnelStatusDiagnostic(tunnel: String, status: HelperTunnelStatus?, now: Date) -> String {
    guard let status else { return "status tunnel=\(safeLabel(tunnel)) tracked=false" }
    let peer = status.peers.first
    let handshake = peer?.latestHandshake.map { "present age=\(Int(now.timeIntervalSince($0)))s" } ?? "absent"
    let interface = isSmokeInterfaceName(status.interface) ? status.interface : "invalid"
    return "status tunnel=\(safeLabel(tunnel)) tracked=true interface=\(interface) alive=\(status.alive) handshake=\(handshake) rx=\(peer?.rxBytes ?? 0) tx=\(peer?.txBytes ?? 0)"
}

/// The probe is printed only if it is a reserved fixture address, as anything else could be real network information.
public func formatRouteDiagnostic(tunnel: String, probeHost: String, lookup: String?, expected: String?) -> String {
    let reserved = CIDR("198.18.0.0/15")!
    let probe = CIDR(probeHost).map { reserved.overlaps($0) && !probeHost.contains("/") } == true ? probeHost : "invalid"
    let shown = lookup.flatMap { isSmokeInterfaceName($0) ? $0 : nil } ?? "unknown"
    return "route tunnel=\(safeLabel(tunnel)) probe=\(probe) lookup=\(shown) matchesTunnel=\(lookup != nil && lookup == expected)"
}

private func isSmokeInterfaceName(_ name: String) -> Bool {
    (1...15).contains(name.count) && name.allSatisfy { $0.isASCII && ($0.isLetter || $0.isNumber) }
}

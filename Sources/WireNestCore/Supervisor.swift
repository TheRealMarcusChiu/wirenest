import Foundation

public struct Backoff: Equatable {
    public let base: TimeInterval
    public let cap: TimeInterval
    public let jitter: Double
    private var attempts = 0

    public init(base: TimeInterval = 2, cap: TimeInterval = 300, jitter: Double = 0.2) {
        self.base = base
        self.cap = cap
        self.jitter = jitter
    }

    public mutating func nextDelay(random: () -> Double = { Double.random(in: 0...1) }) -> TimeInterval {
        let raw = min(cap, base * pow(2, Double(min(attempts, 20))))
        attempts += 1
        return min(cap, raw * (1 - jitter + 2 * jitter * random()))
    }

    public mutating func reset() {
        attempts = 0
    }
}

public enum TunnelHealth: String, Codable, Equatable {
    case disconnected, connecting, connected, degraded
}

public struct HealthVerdict: Equatable {
    public let state: TunnelHealth
    public let detail: String
    public let shouldRestart: Bool
}

/// Judges a tunnel from real counters. An old handshake alone is never a failure, because
/// WireGuard only handshakes when there is traffic. A failure is outbound bytes with no reply.
public struct HealthTracker: Equatable {
    /// WireGuard's REJECT_AFTER_TIME: a session older than this cannot carry data.
    static let handshakeFresh: TimeInterval = 180
    static let grace: TimeInterval = 30
    static let stallDegraded: TimeInterval = 45
    static let stallRestart: TimeInterval = 180
    static let txQuietClearsStall: TimeInterval = 120

    private var graceUntil: Date
    private var stallSince: Date?
    private var lastRx: UInt64?
    private var lastTx: UInt64?
    private var lastTxGrowth: Date?
    private(set) var healthySince: Date?

    public init(now: Date) {
        graceUntil = now.addingTimeInterval(Self.grace)
    }

    /// Sleep, wake or a path change: counters mean little for a moment, so wait instead of restarting.
    public mutating func noteNetworkEvent(now: Date) {
        stallSince = nil
        graceUntil = now.addingTimeInterval(Self.grace)
    }

    public mutating func update(_ status: HelperTunnelStatus, now: Date) -> HealthVerdict {
        guard status.alive else {
            healthySince = nil
            return HealthVerdict(state: .disconnected, detail: "Interface is gone", shouldRestart: true)
        }

        let rx = status.peers.reduce(UInt64(0)) { $0 &+ $1.rxBytes }
        let tx = status.peers.reduce(UInt64(0)) { $0 &+ $1.txBytes }
        let rxGrew = lastRx.map { rx > $0 } ?? false
        let txGrew = lastTx.map { tx > $0 } ?? false
        lastRx = rx
        lastTx = tx
        if txGrew { lastTxGrowth = now }

        let handshake = status.peers.compactMap(\.latestHandshake).max()
        if let handshake, now.timeIntervalSince(handshake) < Self.handshakeFresh {
            stallSince = nil
            healthySince = healthySince ?? now
            return HealthVerdict(state: .connected, detail: "Handshake \(Int(now.timeIntervalSince(handshake)))s ago", shouldRestart: false)
        }
        healthySince = nil

        let inGrace = now < graceUntil
        if rxGrew || inGrace {
            stallSince = nil
        } else if txGrew {
            stallSince = stallSince ?? now
        } else if let lastTxGrowth, now.timeIntervalSince(lastTxGrowth) > Self.txQuietClearsStall {
            stallSince = nil
        }

        if let stallSince {
            let stalled = now.timeIntervalSince(stallSince)
            if stalled >= Self.stallRestart {
                return HealthVerdict(state: .degraded, detail: "No reply for \(Int(stalled))s, reconnecting", shouldRestart: true)
            }
            if stalled >= Self.stallDegraded {
                return HealthVerdict(state: .degraded, detail: "Sending but no reply for \(Int(stalled))s", shouldRestart: false)
            }
        }
        guard let handshake else {
            return HealthVerdict(state: .connecting, detail: "Waiting for first handshake", shouldRestart: false)
        }
        return HealthVerdict(state: .connected, detail: "Idle, last handshake \(Int(now.timeIntervalSince(handshake)))s ago", shouldRestart: false)
    }
}

public struct TunnelView: Equatable {
    public var state: TunnelHealth = .disconnected
    public var detail: String?
    public var lastError: String?
    public var nextRetry: Date?
    public var interface: String?
}

public struct SupervisorPlan: Equatable {
    public var stop: [UUID] = []
    public var start: [UUID] = []
}

/// Decides, per tunnel, what to stop or start. Only a tunnel that is actually
/// unhealthy or changed is touched, and every automatic attempt is paced by its own backoff.
public struct TunnelSupervisor {
    static let stableBeforeBackoffReset: TimeInterval = 120

    private struct Entry {
        var backoff = Backoff()
        var nextAttempt = Date.distantPast
        var tracker: HealthTracker?
        var fingerprint: String?
        var lastError: String?
    }

    private var entries: [UUID: Entry] = [:]
    public private(set) var views: [UUID: TunnelView] = [:]
    public var random: () -> Double = { Double.random(in: 0...1) }

    public init() {}

    public mutating func plan(desired: [DesiredTunnel], status: [HelperTunnelStatus], now: Date) -> SupervisorPlan {
        var plan = SupervisorPlan()
        let desiredIDs = Set(desired.map(\.id))
        plan.stop = status.map(\.tunnelID).filter { !desiredIDs.contains($0) }
        entries = entries.filter { desiredIDs.contains($0.key) }
        views = views.filter { desiredIDs.contains($0.key) }

        for tunnel in desired {
            var entry = entries[tunnel.id] ?? Entry()
            var view = TunnelView()
            let running = status.first { $0.tunnelID == tunnel.id }
            var needsStart = running == nil

            if entry.fingerprint != tunnel.fingerprint {
                // A new configuration is a new attempt, not a repeat of the old failure.
                entry = Entry()
                entry.fingerprint = tunnel.fingerprint
            }

            if let running {
                view.interface = running.interface
                if running.fingerprint != tunnel.fingerprint {
                    plan.stop.append(tunnel.id)
                    needsStart = true
                    entry.tracker = nil
                } else {
                    var tracker = entry.tracker ?? HealthTracker(now: now)
                    let verdict = tracker.update(running, now: now)
                    view.state = verdict.state
                    view.detail = verdict.detail
                    if let since = tracker.healthySince, now.timeIntervalSince(since) >= Self.stableBeforeBackoffReset {
                        entry.backoff.reset()
                        entry.lastError = nil
                    }
                    entry.tracker = tracker
                    if verdict.shouldRestart {
                        if now >= entry.nextAttempt {
                            plan.stop.append(tunnel.id)
                            needsStart = true
                            entry.tracker = nil
                        } else {
                            view.nextRetry = entry.nextAttempt
                        }
                    }
                }
            }

            if needsStart {
                if now >= entry.nextAttempt {
                    plan.start.append(tunnel.id)
                    entry.nextAttempt = now.addingTimeInterval(entry.backoff.nextDelay(random: random))
                    view.state = .connecting
                    view.detail = "Starting"
                } else {
                    view.state = .disconnected
                    view.detail = "Waiting to retry"
                    view.nextRetry = entry.nextAttempt
                }
            }

            view.lastError = entry.lastError
            entries[tunnel.id] = entry
            views[tunnel.id] = view
        }
        return plan
    }

    public mutating func noteStarted(_ id: UUID, now: Date) {
        entries[id]?.tracker = HealthTracker(now: now)
        entries[id]?.lastError = nil
        views[id]?.lastError = nil
    }

    public mutating func noteStartFailed(_ id: UUID, error: String, now: Date) {
        entries[id]?.lastError = error
        views[id]?.lastError = error
        views[id]?.state = .disconnected
        views[id]?.detail = "Start failed"
        views[id]?.nextRetry = entries[id]?.nextAttempt
    }

    public mutating func noteNetworkEvent(now: Date) {
        for id in entries.keys {
            entries[id]?.tracker?.noteNetworkEvent(now: now)
        }
    }

    /// The user asked to retry: the next plan may start immediately, with a fresh backoff.
    public mutating func retryAll() {
        for id in entries.keys {
            entries[id]?.backoff.reset()
            entries[id]?.nextAttempt = .distantPast
            entries[id]?.lastError = nil
        }
    }
}

public func aggregateHealth(_ states: [TunnelHealth]) -> TunnelHealth {
    if states.isEmpty || states.allSatisfy({ $0 == .disconnected }) { return .disconnected }
    if states.contains(.degraded) || states.contains(.disconnected) { return .degraded }
    return states.contains(.connecting) ? .connecting : .connected
}

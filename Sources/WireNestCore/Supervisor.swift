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

/// Judges a tunnel from real counters, peer by peer. An old handshake alone is never a failure,
/// because WireGuard only handshakes when there is traffic. A failure is outbound bytes with no reply
/// from that same peer, so one healthy peer can never hide another that has stalled.
public struct HealthTracker: Equatable {
    private struct PeerTrack: Equatable {
        var rx: UInt64
        var tx: UInt64
        var stallSince: Date?
        var lastTxGrowth: Date?
    }

    /// WireGuard's REJECT_AFTER_TIME: a session older than this cannot carry data.
    static let handshakeFresh: TimeInterval = 180
    static let grace: TimeInterval = 30
    static let stallDegraded: TimeInterval = 45
    static let stallRestart: TimeInterval = 180
    static let txQuietClearsStall: TimeInterval = 120

    private var graceUntil: Date
    private var tracks: [String: PeerTrack] = [:]
    private(set) var healthySince: Date?

    public init(now: Date) {
        graceUntil = now.addingTimeInterval(Self.grace)
    }

    /// Sleep, wake or a path change: counters mean little for a moment, so wait instead of restarting.
    public mutating func noteNetworkEvent(now: Date) {
        for key in tracks.keys { tracks[key]?.stallSince = nil }
        graceUntil = now.addingTimeInterval(Self.grace)
    }

    public mutating func update(_ status: HelperTunnelStatus, now: Date) -> HealthVerdict {
        guard status.alive else {
            healthySince = nil
            return HealthVerdict(state: .disconnected, detail: "Interface is gone", shouldRestart: true)
        }

        let inGrace = now < graceUntil
        var updated: [String: PeerTrack] = [:]
        var longestStall: TimeInterval?
        var anyFresh = false
        var anyAwaitingFirstHandshake = false
        for peer in status.peers {
            // A new peer, or a counter that went backwards, gets a baseline: its bytes say nothing yet.
            let previous = tracks[peer.publicKey].flatMap { $0.rx <= peer.rxBytes && $0.tx <= peer.txBytes ? $0 : nil }
            var track = previous ?? PeerTrack(rx: peer.rxBytes, tx: peer.txBytes)
            let rxGrew = peer.rxBytes > track.rx
            let txGrew = peer.txBytes > track.tx
            track.rx = peer.rxBytes
            track.tx = peer.txBytes
            if txGrew { track.lastTxGrowth = now }

            let fresh = peer.latestHandshake.map { now.timeIntervalSince($0) < Self.handshakeFresh } ?? false
            if fresh || rxGrew || inGrace {
                track.stallSince = nil
            } else if txGrew {
                track.stallSince = track.stallSince ?? now
            } else if let growth = track.lastTxGrowth, now.timeIntervalSince(growth) > Self.txQuietClearsStall {
                track.stallSince = nil
            }
            if let since = track.stallSince { longestStall = max(longestStall ?? 0, now.timeIntervalSince(since)) }
            anyFresh = anyFresh || fresh
            anyAwaitingFirstHandshake = anyAwaitingFirstHandshake || peer.latestHandshake == nil
            updated[peer.publicKey] = track
        }
        tracks = updated

        if anyFresh, longestStall == nil, !anyAwaitingFirstHandshake {
            healthySince = healthySince ?? now
        } else {
            healthySince = nil
        }

        if let longestStall {
            if longestStall >= Self.stallRestart {
                return HealthVerdict(state: .degraded, detail: "A peer has not replied for \(Int(longestStall))s, reconnecting", shouldRestart: true)
            }
            if longestStall >= Self.stallDegraded {
                return HealthVerdict(state: .degraded, detail: "Sending to a peer with no reply for \(Int(longestStall))s", shouldRestart: false)
            }
        }
        guard !anyAwaitingFirstHandshake, let handshake = status.peers.compactMap(\.latestHandshake).max() else {
            return HealthVerdict(state: .connecting, detail: "Waiting for a first handshake", shouldRestart: false)
        }
        let age = Int(now.timeIntervalSince(handshake))
        return HealthVerdict(state: .connected, detail: anyFresh ? "Handshake \(age)s ago" : "Idle, last handshake \(age)s ago", shouldRestart: false)
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

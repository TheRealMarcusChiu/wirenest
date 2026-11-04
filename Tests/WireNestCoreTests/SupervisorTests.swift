import XCTest
@testable import WireNestCore

final class BackoffTests: XCTestCase {
    func testGrowsExponentiallyWithinCap() {
        var backoff = Backoff(base: 2, cap: 60, jitter: 0)
        let delays = (0..<8).map { _ in backoff.nextDelay(random: { 0.5 }) }
        XCTAssertEqual(delays, [2, 4, 8, 16, 32, 60, 60, 60])
    }

    func testJitterStaysInBandAndNeverExceedsCap() {
        var low = Backoff(base: 10, cap: 100, jitter: 0.2)
        XCTAssertEqual(low.nextDelay(random: { 0 }), 8, accuracy: 0.001)
        var high = Backoff(base: 10, cap: 100, jitter: 0.2)
        XCTAssertEqual(high.nextDelay(random: { 1 }), 12, accuracy: 0.001)
        var capped = Backoff(base: 100, cap: 100, jitter: 0.2)
        XCTAssertLessThanOrEqual(capped.nextDelay(random: { 1 }), 100)
    }

    func testManyAttemptsDoNotOverflowAndResetRestarts() {
        var backoff = Backoff(base: 2, cap: 300, jitter: 0)
        for _ in 0..<500 { _ = backoff.nextDelay(random: { 0.5 }) }
        XCTAssertEqual(backoff.nextDelay(random: { 0.5 }), 300)
        backoff.reset()
        XCTAssertEqual(backoff.nextDelay(random: { 0.5 }), 2)
    }
}

final class HealthTrackerTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 2_000_000)

    private func status(alive: Bool = true, handshake: Date?, rx: UInt64 = 0, tx: UInt64 = 0) -> HelperTunnelStatus {
        HelperTunnelStatus(
            tunnelID: UUID(), interface: "utun7", fingerprint: "f", alive: alive,
            peers: [PeerStats(publicKey: "p", latestHandshake: handshake, rxBytes: rx, txBytes: tx)]
        )
    }

    func testDeadInterfaceIsDisconnectedAndRestartable() {
        var tracker = HealthTracker(now: t0)
        let verdict = tracker.update(status(alive: false, handshake: nil), now: t0.addingTimeInterval(1))
        XCTAssertEqual(verdict.state, .disconnected)
        XCTAssertTrue(verdict.shouldRestart)
    }

    func testFreshHandshakeIsConnected() {
        var tracker = HealthTracker(now: t0)
        let verdict = tracker.update(status(handshake: t0), now: t0.addingTimeInterval(5))
        XCTAssertEqual(verdict.state, .connected)
        XCTAssertFalse(verdict.shouldRestart)
    }

    func testIdleTunnelWithOldHandshakeIsNotAFailure() {
        var tracker = HealthTracker(now: t0)
        let old = t0.addingTimeInterval(-3600)
        for offset in stride(from: 40.0, through: 4000, by: 40) {
            let verdict = tracker.update(status(handshake: old, rx: 500, tx: 500), now: t0.addingTimeInterval(offset))
            XCTAssertEqual(verdict.state, .connected, "offset \(offset)")
            XCTAssertFalse(verdict.shouldRestart)
        }
    }

    func testNoHandshakeNoTrafficStaysConnectingWithoutRestart() {
        var tracker = HealthTracker(now: t0)
        let verdict = tracker.update(status(handshake: nil), now: t0.addingTimeInterval(1000))
        XCTAssertEqual(verdict.state, .connecting)
        XCTAssertFalse(verdict.shouldRestart)
    }

    func testOutboundWithoutReplyDegradesThenRestarts() {
        var tracker = HealthTracker(now: t0)
        let old = t0.addingTimeInterval(-3600)
        var tx: UInt64 = 100
        var verdicts: [Double: HealthVerdict] = [:]
        for offset in stride(from: 40.0, through: 280, by: 10) {
            tx += 200
            verdicts[offset] = tracker.update(status(handshake: old, rx: 50, tx: tx), now: t0.addingTimeInterval(offset))
        }
        XCTAssertEqual(verdicts[50]?.state, .connected, "stall is not yet long enough")
        XCTAssertEqual(verdicts[100]?.state, .degraded)
        XCTAssertEqual(verdicts[100]?.shouldRestart, false)
        XCTAssertEqual(verdicts[240]?.state, .degraded)
        XCTAssertEqual(verdicts[240]?.shouldRestart, true)
    }

    func testReceivedTrafficClearsStall() {
        var tracker = HealthTracker(now: t0)
        let old = t0.addingTimeInterval(-3600)
        _ = tracker.update(status(handshake: old, rx: 50, tx: 100), now: t0.addingTimeInterval(40))
        _ = tracker.update(status(handshake: old, rx: 50, tx: 300), now: t0.addingTimeInterval(60))
        _ = tracker.update(status(handshake: old, rx: 50, tx: 500), now: t0.addingTimeInterval(120))
        let verdict = tracker.update(status(handshake: old, rx: 90, tx: 600), now: t0.addingTimeInterval(130))
        XCTAssertEqual(verdict.state, .connected)
    }

    func testNetworkEventGivesGraceInsteadOfRestart() {
        var tracker = HealthTracker(now: t0)
        let old = t0.addingTimeInterval(-3600)
        var tx: UInt64 = 100
        for offset in stride(from: 40.0, through: 210, by: 10) {
            tx += 100
            _ = tracker.update(status(handshake: old, rx: 1, tx: tx), now: t0.addingTimeInterval(offset))
        }
        tracker.noteNetworkEvent(now: t0.addingTimeInterval(215))
        tx += 100
        let verdict = tracker.update(status(handshake: old, rx: 1, tx: tx), now: t0.addingTimeInterval(220))
        XCTAssertFalse(verdict.shouldRestart)
        XCTAssertEqual(verdict.state, .connected)
    }
}

final class TunnelSupervisorTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 3_000_000)
    private let a = UUID(), b = UUID()

    private func desired(_ id: UUID, fingerprint: String = "f") -> DesiredTunnel {
        DesiredTunnel(id: id, name: "t", configText: "", fingerprint: fingerprint)
    }

    private func running(_ id: UUID, fingerprint: String = "f", alive: Bool = true, handshake: Date? = nil) -> HelperTunnelStatus {
        HelperTunnelStatus(tunnelID: id, interface: "utun1", fingerprint: fingerprint, alive: alive,
                           peers: [PeerStats(publicKey: "p", latestHandshake: handshake, rxBytes: 0, txBytes: 0)])
    }

    private func makeSupervisor() -> TunnelSupervisor {
        var supervisor = TunnelSupervisor()
        supervisor.random = { 0.5 }
        return supervisor
    }

    func testStartsMissingAndStopsUndesiredOnly() {
        var supervisor = makeSupervisor()
        let plan = supervisor.plan(desired: [desired(a)], status: [running(b)], now: t0)
        XCTAssertEqual(plan.start, [a])
        XCTAssertEqual(plan.stop, [b])
    }

    func testHealthyTunnelIsLeftAloneWhenSiblingFails() {
        var supervisor = makeSupervisor()
        let healthy = running(a, handshake: t0)
        let plan = supervisor.plan(desired: [desired(a), desired(b)], status: [healthy, running(b, alive: false)], now: t0)
        XCTAssertEqual(plan.stop, [b])
        XCTAssertEqual(plan.start, [b])
        XCTAssertEqual(supervisor.views[a]?.state, .connected)
    }

    func testAdoptsAlreadyRunningMatchingTunnelWithoutRestart() {
        var supervisor = makeSupervisor()
        let plan = supervisor.plan(desired: [desired(a)], status: [running(a, handshake: t0)], now: t0)
        XCTAssertEqual(plan.start, [])
        XCTAssertEqual(plan.stop, [])
    }

    func testEditedConfigRestartsOnlyThatTunnel() {
        var supervisor = makeSupervisor()
        let plan = supervisor.plan(desired: [desired(a, fingerprint: "new"), desired(b)],
                                   status: [running(a, fingerprint: "old"), running(b, handshake: t0)], now: t0)
        XCTAssertEqual(plan.stop, [a])
        XCTAssertEqual(plan.start, [a])
    }

    func testRepeatedFailuresBackOffNoRestartStorm() {
        var supervisor = makeSupervisor()
        XCTAssertEqual(supervisor.plan(desired: [desired(a)], status: [], now: t0).start, [a])
        supervisor.noteStartFailed(a, error: "boom", now: t0)
        XCTAssertEqual(supervisor.views[a]?.lastError, "boom")

        XCTAssertEqual(supervisor.plan(desired: [desired(a)], status: [], now: t0.addingTimeInterval(1)).start, [])
        XCTAssertEqual(supervisor.views[a]?.state, .disconnected)
        XCTAssertNotNil(supervisor.views[a]?.nextRetry)

        // Attempts over a simulated hour stay bounded by exponential backoff up to the cap.
        var attempts = 0
        var now = t0.addingTimeInterval(1)
        while now < t0.addingTimeInterval(3600) {
            now.addTimeInterval(10)
            if !supervisor.plan(desired: [desired(a)], status: [], now: now).start.isEmpty { attempts += 1 }
        }
        XCTAssertLessThan(attempts, 20)
        XCTAssertGreaterThan(attempts, 5, "must keep retrying at the capped interval")
    }

    func testRetryNowClearsBackoff() {
        var supervisor = makeSupervisor()
        _ = supervisor.plan(desired: [desired(a)], status: [], now: t0)
        supervisor.noteStartFailed(a, error: "boom", now: t0)
        supervisor.retryAll()
        XCTAssertEqual(supervisor.plan(desired: [desired(a)], status: [], now: t0.addingTimeInterval(1)).start, [a])
        XCTAssertNil(supervisor.views[a]?.lastError)
    }

    func testNotDesiredTunnelForgetsItsState() {
        var supervisor = makeSupervisor()
        _ = supervisor.plan(desired: [desired(a)], status: [], now: t0)
        _ = supervisor.plan(desired: [], status: [], now: t0.addingTimeInterval(1))
        XCTAssertNil(supervisor.views[a])
    }

    func testAggregateState() {
        XCTAssertEqual(aggregateHealth([]), .disconnected)
        XCTAssertEqual(aggregateHealth([.connected, .connected]), .connected)
        XCTAssertEqual(aggregateHealth([.connected, .disconnected]), .degraded)
        XCTAssertEqual(aggregateHealth([.connected, .connecting]), .connecting)
        XCTAssertEqual(aggregateHealth([.disconnected]), .disconnected)
    }
}

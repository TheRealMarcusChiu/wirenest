import XCTest
@testable import WireNestCore

final class SSIDEligibilityTests: XCTestCase {
    private func restricted(_ eligibility: SSIDEligibility?) throws -> (AppState, UUID, UUID) {
        var state = AppState()
        let profile = state.addProfile(name: "Work")
        let tunnel = try state.importTunnel(text: confText(), name: "t", into: profile).tunnelID
        try state.setSSIDEligibility(profile, eligibility)
        return (state, profile, tunnel)
    }

    func testAllowsOnlyTheMatchingKnownSSID() {
        XCTAssertTrue(SSIDEligibility.onlyEquals("Home").allows(.known("Home")))
        XCTAssertFalse(SSIDEligibility.onlyEquals("Home").allows(.known("Cafe")))
        XCTAssertTrue(SSIDEligibility.onlyNotEquals("Home").allows(.known("Cafe")))
        XCTAssertFalse(SSIDEligibility.onlyNotEquals("Home").allows(.known("Home")))
    }

    func testUnknownSSIDFailsClosedInBothModes() {
        for reason in ["Location permission denied", "Wi-Fi is off", "Not joined to a Wi-Fi network"] {
            XCTAssertFalse(SSIDEligibility.onlyEquals("Home").allows(.unavailable(reason)))
            XCTAssertFalse(SSIDEligibility.onlyNotEquals("Home").allows(.unavailable(reason)))
        }
    }

    func testRejectsEmptyAndImpossibleSSIDs() throws {
        var (state, profile, _) = try restricted(nil)
        XCTAssertThrowsError(try state.setSSIDEligibility(profile, .onlyEquals("   ")))
        XCTAssertThrowsError(try state.setSSIDEligibility(profile, .onlyNotEquals(String(repeating: "x", count: 33))))
        XCTAssertNil(state.profile(profile)?.ssidEligibility)
        try state.setSSIDEligibility(profile, .onlyEquals(" Home "))
        XCTAssertEqual(state.profile(profile)?.ssidEligibility, .onlyEquals("Home"))
    }

    func testManualConnectOnWrongSSIDIsRefusedWithClearErrorAndChangesNothing() throws {
        var (state, profile, _) = try restricted(.onlyEquals("Home"))
        let before = state
        XCTAssertThrowsError(try state.connect(profile, pinContext: nil, ssid: .known("Cafe"))) { error in
            XCTAssertTrue(error.localizedDescription.contains("Home"))
            XCTAssertTrue(error.localizedDescription.contains("Cafe"))
        }
        XCTAssertThrowsError(try state.connect(profile, pinContext: nil, ssid: .unavailable("Wi-Fi is off"))) { error in
            XCTAssertTrue(error.localizedDescription.contains("Wi-Fi is off"))
        }
        XCTAssertEqual(state, before)
    }

    func testRefusedSwitchLeavesTheCurrentConnectionRunning() throws {
        var (state, profile, tunnel) = try restricted(nil)
        try state.connect(profile, pinContext: nil, ssid: noWiFi)
        let other = state.addProfile(name: "Home only")
        _ = try state.importTunnel(text: confText(address: "10.9.0.2/32", allowedIPs: "10.9.0.0/24"), name: "h", into: other)
        try state.setSSIDEligibility(other, .onlyEquals("Home"))
        XCTAssertThrowsError(try state.connect(other, pinContext: nil, ssid: .known("Cafe")))
        XCTAssertEqual(try state.desiredTunnels(ssid: .known("Cafe")).map(\.id), [tunnel])
    }

    func testLoginRestoreRunsOnlyWhereEligibleAfterReload() throws {
        var (state, profile, tunnel) = try restricted(.onlyNotEquals("Cafe"))
        try state.connect(profile, pinContext: nil, ssid: .known("Home"))
        let store = try StateStore(directory: tempDirectory().appendingPathComponent("s"))
        try store.save(state)
        let restored = try store.load()

        XCTAssertEqual(try restored.desiredTunnels(ssid: .known("Home")).map(\.id), [tunnel])
        XCTAssertEqual(try restored.desiredTunnels(ssid: .known("Cafe")), [])
        XCTAssertEqual(try restored.desiredTunnels(ssid: .unavailable("Checking")), [])
    }

    func testPauseReasonIsDistinctFromOffAndFromRunning() throws {
        var (state, profile, _) = try restricted(.onlyEquals("Home"))
        XCTAssertNil(state.pauseReason(ssid: .known("Cafe")), "never turned on, so not paused")
        try state.connect(profile, pinContext: nil, ssid: .known("Home"))
        XCTAssertNil(state.pauseReason(ssid: .known("Home")))
        XCTAssertNotNil(state.pauseReason(ssid: .known("Cafe")))
        state.disconnect()
        XCTAssertNil(state.pauseReason(ssid: .known("Cafe")), "off by hand is off, not paused")
    }

    func testAddingARestrictionToTheRunningConnectionTakesEffect() throws {
        var (state, profile, tunnel) = try restricted(nil)
        try state.connect(profile, pinContext: nil, ssid: noWiFi)
        XCTAssertEqual(try state.desiredTunnels(ssid: .known("Cafe")).map(\.id), [tunnel])
        try state.setSSIDEligibility(profile, .onlyEquals("Home"))
        XCTAssertEqual(try state.desiredTunnels(ssid: .known("Cafe")), [])
    }

    /// Runs the same steps as `AppController.reconcileOnce`, against the real engine, with only subprocesses faked.
    func testLosingEligibilityTearsDownRestoresDNSAndRegainResumesWithoutManualOff() throws {
        let root = try tempDirectory()
        let paths = HelperPaths(
            runtimeDir: root.appendingPathComponent("run"),
            wireguardRunDir: root.appendingPathComponent("wg"),
            toolsDir: root.appendingPathComponent("tools"),
            durableDir: root.appendingPathComponent("durable")
        )
        let commands = FakeCommands(paths: paths)
        let engine = try HelperEngine(paths: paths, runner: commands)
        var supervisor = TunnelSupervisor()
        let now = Date(timeIntervalSince1970: 4_000_000)

        func reconcile(_ state: AppState, _ ssid: SSIDObservation, at time: Date) throws -> SupervisorPlan {
            let desired = try state.desiredTunnels(ssid: ssid)
            let plan = supervisor.plan(desired: desired, status: engine.handle(.status).status?.tunnels ?? [], now: time)
            for id in plan.stop { XCTAssertNil(engine.handle(.down(tunnelID: id)).error) }
            for id in plan.start {
                let tunnel = try XCTUnwrap(desired.first { $0.id == id })
                XCTAssertNil(engine.handle(.up(tunnelID: id, config: tunnel.configText)).error)
                supervisor.noteStarted(id, now: time)
            }
            return plan
        }

        var (state, profile, tunnel) = try restricted(.onlyEquals("Home"))
        try state.connect(profile, pinContext: nil, ssid: .known("Home"))
        XCTAssertEqual(try reconcile(state, .known("Home"), at: now).start, [tunnel])
        XCTAssertNil(engine.handle(.setDNS(primary: "9.9.9.9", secondary: "")).error)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["9.9.9.9"])

        XCTAssertEqual(try reconcile(state, .known("Cafe"), at: now.addingTimeInterval(5)).stop, [tunnel])
        XCTAssertEqual(engine.handle(.status).status?.tunnels.count, 0)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"], "the last tunnel leaving restores DNS")
        XCTAssertTrue(state.connectionOn, "a guard pause keeps the user's intent")
        XCTAssertFalse(state.manualOff)

        XCTAssertEqual(try reconcile(state, .unavailable("Wi-Fi is off"), at: now.addingTimeInterval(10)), SupervisorPlan())
        XCTAssertEqual(try reconcile(state, .known("Home"), at: now.addingTimeInterval(15)).start, [tunnel])

        state.disconnect()
        XCTAssertEqual(try reconcile(state, .known("Home"), at: now.addingTimeInterval(20)).stop, [tunnel])
        XCTAssertEqual(try reconcile(state, .known("Home"), at: now.addingTimeInterval(25)), SupervisorPlan(), "explicit off wins over a regained SSID")
    }

    func testStateSavedBeforeThisFeatureStillLoadsWithItsPrivateConfig() throws {
        let profileID = UUID(), tunnelID = UUID()
        let config = try JSONEncoder().encode(confText())
        let configJSON = String(decoding: config, as: UTF8.self)
        let legacy = """
        {"profiles":[{"id":"\(profileID)","name":"Old","primaryDNS":"","secondaryDNS":"",
        "tunnels":[{"id":"\(tunnelID)","name":"t","enabled":true,"configText":\(configJSON)}]}],
        "connectionOn":false,"manualOff":false,"rules":[],"publicIPAutomationEnabled":false,
        "publicIPCheckURL":"https://api.ipify.org/"}
        """
        let store = try StateStore(directory: tempDirectory().appendingPathComponent("s"))
        try Data(legacy.utf8).write(to: store.stateURL)

        let loaded = try store.load()
        XCTAssertNil(loaded.profile(profileID)?.ssidEligibility)
        XCTAssertEqual(loaded.tunnel(tunnelID)?.configText, confText())
    }

    func testEligibilityAndChangeRuleRoundTripThroughSavedState() throws {
        var (state, profile, _) = try restricted(.onlyNotEquals("Cafe"))
        state.rules = [NetworkRule(condition: .publicIPChanges, profileID: profile)]
        let store = try StateStore(directory: tempDirectory().appendingPathComponent("s"))
        try store.save(state)
        XCTAssertEqual(try store.load(), state)
    }

    func testDuplicateConnectionKeepsItsRestriction() throws {
        var (state, profile, _) = try restricted(.onlyEquals("Home"))
        let copy = try XCTUnwrap(state.duplicateProfile(profile))
        XCTAssertEqual(state.profile(copy)?.ssidEligibility, .onlyEquals("Home"))
    }
}

final class ImportDNSTests: XCTestCase {
    func testFirstImportSeedsBlankConnectionDNSFromFirstTwoIPs() throws {
        var state = AppState()
        let profile = state.addProfile(name: "p")
        let outcome = try state.importTunnel(text: confText(dns: "corp.example, 1.1.1.1, 2606:4700:4700::1111, 8.8.8.8"), name: "t", into: profile)
        XCTAssertEqual(state.profile(profile)?.dnsServers, ["1.1.1.1", "2606:4700:4700::1111"])
        XCTAssertEqual(outcome.seededDNS, ["1.1.1.1", "2606:4700:4700::1111"])
        XCTAssertEqual(outcome.ignoredDNS, ["corp.example", "8.8.8.8"])
    }

    func testNeverOverwritesConfiguredDNSEvenOnFirstImport() throws {
        var state = AppState()
        let profile = state.addProfile(name: "p")
        try state.setDNS(profile, primary: "9.9.9.9", secondary: "")
        let outcome = try state.importTunnel(text: confText(dns: "1.1.1.1"), name: "t", into: profile)
        XCTAssertEqual(state.profile(profile)?.dnsServers, ["9.9.9.9"])
        XCTAssertEqual(outcome.seededDNS, [])
        XCTAssertEqual(outcome.ignoredDNS, ["1.1.1.1"])
    }

    func testLaterImportDoesNotSeedEvenWhenDNSIsStillBlank() throws {
        var state = AppState()
        let profile = state.addProfile(name: "p")
        _ = try state.importTunnel(text: confText(), name: "a", into: profile)
        let outcome = try state.importTunnel(text: confText(address: "10.2.0.2/32", dns: "1.1.1.1", allowedIPs: "10.2.0.0/24"), name: "b", into: profile)
        XCTAssertEqual(state.profile(profile)?.dnsServers, [])
        XCTAssertEqual(outcome.ignoredDNS, ["1.1.1.1"])
    }

    func testImportWithoutDNSReportsNothing() throws {
        var state = AppState()
        let profile = state.addProfile(name: "p")
        let outcome = try state.importTunnel(text: confText(), name: "t", into: profile)
        XCTAssertEqual(outcome.seededDNS, [])
        XCTAssertEqual(outcome.ignoredDNS, [])
    }
}

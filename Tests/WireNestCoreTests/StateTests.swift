import XCTest
@testable import WireNestCore

final class StateTests: XCTestCase {
    private func stateWithProfile() -> (AppState, UUID) {
        var state = AppState()
        let id = state.addProfile(name: "Work")
        return (state, id)
    }

    private func importConf(_ state: inout AppState, _ text: String, into profile: UUID, name: String = "t") throws -> UUID {
        try state.importTunnel(text: text, name: name, into: profile).tunnelID
    }

    // MARK: import by value

    func testImportIsByValueSoSourceEditsAndDeletionDoNotMatter() throws {
        var (state, profile) = stateWithProfile()
        let dir = try tempDirectory()
        let source = dir.appendingPathComponent("office.conf")
        try confText(allowedIPs: "10.10.0.0/24").write(to: source, atomically: true, encoding: .utf8)

        let outcome = try state.importTunnel(fileAt: source, into: profile)
        let stored = state.tunnel(outcome.tunnelID)!.configText
        XCTAssertEqual(state.tunnel(outcome.tunnelID)!.name, "office")

        try confText(allowedIPs: "172.16.0.0/12").write(to: source, atomically: true, encoding: .utf8)
        XCTAssertEqual(state.tunnel(outcome.tunnelID)!.configText, stored)
        try FileManager.default.removeItem(at: source)
        XCTAssertEqual(state.tunnel(outcome.tunnelID)!.configText, stored)
        XCTAssertTrue(stored.contains("10.10.0.0/24"))
    }

    func testImportRejectsUnsafeFileAndLeavesStateUntouched() throws {
        var (state, profile) = stateWithProfile()
        let before = state
        XCTAssertThrowsError(try state.importTunnel(text: confText(extraInterface: "PostUp = id"), name: "x", into: profile))
        XCTAssertEqual(state, before)
    }

    func testImportRejectsOversizedFileWithoutReadingIt() throws {
        var (state, profile) = stateWithProfile()
        let source = try tempDirectory().appendingPathComponent("big.conf")
        try Data(repeating: 35, count: WireGuardConfig.maxBytes + 1).write(to: source)
        XCTAssertThrowsError(try state.importTunnel(fileAt: source, into: profile))
    }

    func testConflictingImportIsSavedDisabledAndReportsConflict() throws {
        var (state, profile) = stateWithProfile()
        _ = try importConf(&state, confText(address: "10.1.0.2/32", allowedIPs: "10.0.0.0/8"), into: profile, name: "a")
        let outcome = try state.importTunnel(text: confText(address: "10.2.0.2/32", allowedIPs: "10.3.0.0/16"), name: "b", into: profile)
        XCTAssertFalse(state.tunnel(outcome.tunnelID)!.enabled)
        XCTAssertEqual(outcome.conflicts.map(\.kind), [.overlappingRoutes])
    }

    // MARK: duplicate and edit

    func testDuplicateHasIndependentIdentityAndCopy() throws {
        var (state, profile) = stateWithProfile()
        let original = try importConf(&state, confText(), into: profile, name: "base")
        let copy = try XCTUnwrap(state.duplicateTunnel(original))
        XCTAssertNotEqual(copy, original)
        XCTAssertFalse(state.tunnel(copy)!.enabled, "a duplicate overlaps its source, so it starts disabled")

        try state.updateTunnel(copy, name: "copy", configText: confText(address: "10.8.0.2/32", allowedIPs: "10.8.0.0/24"))
        XCTAssertTrue(state.tunnel(original)!.configText.contains("10.10.0.0/24"))
        XCTAssertTrue(state.tunnel(copy)!.configText.contains("10.8.0.0/24"))
    }

    func testDuplicateProfileCopiesTunnelsWithNewIdentifiers() throws {
        var (state, profile) = stateWithProfile()
        let tunnel = try importConf(&state, confText(), into: profile)
        let copy = try XCTUnwrap(state.duplicateProfile(profile))
        let copied = state.profile(copy)!.tunnels
        XCTAssertEqual(copied.count, 1)
        XCTAssertNotEqual(copied[0].id, tunnel)
        XCTAssertEqual(copied[0].configText, state.tunnel(tunnel)!.configText)
    }

    func testEditCanonicalisesAndRejectsInvalidWithoutChangingStored() throws {
        var (state, profile) = stateWithProfile()
        let id = try importConf(&state, confText(), into: profile)
        let stored = state.tunnel(id)!.configText
        XCTAssertThrowsError(try state.updateTunnel(id, name: "t", configText: confText(allowedIPs: "not-a-cidr")))
        XCTAssertEqual(state.tunnel(id)!.configText, stored)

        try state.updateTunnel(id, name: "t", configText: "# gone\n" + confText(allowedIPs: "10.1.0.0/24, 10.2.0.0/24"))
        XCTAssertFalse(state.tunnel(id)!.configText.contains("gone"))
        XCTAssertTrue(state.tunnel(id)!.configText.contains("10.1.0.0/24, 10.2.0.0/24"))
    }

    func testEditThatConflictsWithEnabledSiblingIsRejected() throws {
        var (state, profile) = stateWithProfile()
        _ = try importConf(&state, confText(address: "10.1.0.2/32", allowedIPs: "10.1.0.0/24"), into: profile)
        let b = try importConf(&state, confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24"), into: profile)
        XCTAssertThrowsError(try state.updateTunnel(b, name: "b", configText: confText(address: "10.2.0.2/32", allowedIPs: "10.1.0.0/16")))
    }

    // MARK: toggles

    func testEnablingConflictingTunnelThrowsAndStaysDisabled() throws {
        var (state, profile) = stateWithProfile()
        let a = try importConf(&state, confText(address: "10.1.0.2/32", allowedIPs: "10.0.0.0/8"), into: profile)
        let b = try importConf(&state, confText(address: "10.2.0.2/32", allowedIPs: "10.3.0.0/16"), into: profile)
        XCTAssertThrowsError(try state.setTunnelEnabled(b, true))
        XCTAssertFalse(state.tunnel(b)!.enabled)
        try state.setTunnelEnabled(a, false)
        try state.setTunnelEnabled(b, true)
        XCTAssertTrue(state.tunnel(b)!.enabled)
    }

    func testTogglesAreIndependentAndDesiredOnlyListsEnabledTunnelsOfActiveProfile() throws {
        var (state, profile) = stateWithProfile()
        let a = try importConf(&state, confText(address: "10.1.0.2/32", allowedIPs: "10.1.0.0/24"), into: profile)
        let b = try importConf(&state, confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24"), into: profile)
        let other = state.addProfile(name: "Home")
        _ = try importConf(&state, confText(address: "10.3.0.2/32", allowedIPs: "10.3.0.0/24"), into: other)

        XCTAssertEqual(try state.desiredTunnels(ssid: noWiFi).map(\.id), [])
        try state.connect(profile, pinContext: nil, ssid: noWiFi)
        XCTAssertEqual(try state.desiredTunnels(ssid: noWiFi).map(\.id), [a, b])
        try state.setTunnelEnabled(a, false)
        XCTAssertEqual(try state.desiredTunnels(ssid: noWiFi).map(\.id), [b])
    }

    // MARK: connect / disconnect

    func testManualDisconnectPersistsOffAcrossReload() throws {
        var (state, profile) = stateWithProfile()
        _ = try importConf(&state, confText(), into: profile)
        try state.connect(profile, pinContext: nil, ssid: noWiFi)
        state.disconnect()

        let store = try StateStore(directory: tempDirectory().appendingPathComponent("s"))
        try store.save(state)
        let reloaded = try store.load()
        XCTAssertFalse(reloaded.connectionOn)
        XCTAssertTrue(reloaded.manualOff)
        XCTAssertEqual(reloaded.activeProfileID, profile)
        XCTAssertEqual(try reloaded.desiredTunnels(ssid: noWiFi), [])
    }

    func testConnectClearsManualOffAndRestoresDesiredAfterReload() throws {
        var (state, profile) = stateWithProfile()
        let t = try importConf(&state, confText(), into: profile)
        state.disconnect()
        try state.connect(profile, pinContext: "ssid:home", ssid: noWiFi)
        XCTAssertFalse(state.manualOff)
        XCTAssertEqual(state.pinnedContext, "ssid:home")

        let store = try StateStore(directory: tempDirectory().appendingPathComponent("s"))
        try store.save(state)
        XCTAssertEqual(try store.load().desiredTunnels(ssid: noWiFi).map(\.id), [t])
    }

    func testConnectRefusesConflictingOrEmptyProfile() throws {
        var (state, profile) = stateWithProfile()
        XCTAssertThrowsError(try state.connect(profile, pinContext: nil, ssid: noWiFi))
        XCTAssertFalse(state.connectionOn)

        _ = try importConf(&state, confText(address: "10.1.0.2/32", allowedIPs: "10.1.0.0/24"), into: profile)
        let b = try importConf(&state, confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24"), into: profile)
        // A hand-edited or legacy state file can hold a conflict; connect must still refuse it.
        state.profiles[0].tunnels[1].configText = confText(address: "10.2.0.2/32", allowedIPs: "10.1.0.0/24")
        XCTAssertTrue(state.tunnel(b)!.enabled)
        XCTAssertThrowsError(try state.connect(profile, pinContext: nil, ssid: noWiFi))
        XCTAssertFalse(state.connectionOn)
    }

    func testRemovingActiveProfileTurnsOffAndDropsItsRules() throws {
        var (state, profile) = stateWithProfile()
        _ = try importConf(&state, confText(), into: profile)
        state.rules = [NetworkRule(condition: .ssidEquals("x"), profileID: profile)]
        try state.connect(profile, pinContext: nil, ssid: noWiFi)
        state.removeProfile(profile)
        XCTAssertFalse(state.connectionOn)
        XCTAssertNil(state.activeProfileID)
        XCTAssertEqual(state.rules, [])
    }

    // MARK: DNS settings

    func testDNSValidation() throws {
        var (state, profile) = stateWithProfile()
        try state.setDNS(profile, primary: "1.1.1.1", secondary: "2606:4700:4700::1111")
        XCTAssertEqual(state.profile(profile)?.dnsServers, ["1.1.1.1", "2606:4700:4700::1111"])
        XCTAssertThrowsError(try state.setDNS(profile, primary: "bad; rm", secondary: ""))
        XCTAssertThrowsError(try state.setDNS(profile, primary: "", secondary: "1.1.1.1"), "secondary requires primary")
        try state.setDNS(profile, primary: "", secondary: "")
        XCTAssertEqual(state.profile(profile)?.dnsServers, [], "empty primary preserves system DNS")
    }

    // MARK: persistence

    func testStoreUsesPrivatePermissionsAndRepairsWideOnes() throws {
        let dir = try tempDirectory().appendingPathComponent("store")
        let store = try StateStore(directory: dir)
        try store.save(AppState())
        let fm = FileManager.default
        func mode(_ path: String) throws -> Int {
            (try fm.attributesOfItem(atPath: path)[.posixPermissions] as! NSNumber).intValue
        }
        XCTAssertEqual(try mode(dir.path), 0o700)
        XCTAssertEqual(try mode(store.stateURL.path), 0o600)

        try fm.setAttributes([.posixPermissions: 0o644], ofItemAtPath: store.stateURL.path)
        _ = try store.load()
        XCTAssertEqual(try mode(store.stateURL.path), 0o600)
    }

    func testStateRoundTripIncludingRulesAndToggles() throws {
        var (state, profile) = stateWithProfile()
        let t = try importConf(&state, confText(), into: profile)
        try state.setTunnelEnabled(t, false)
        state.rules = [
            NetworkRule(condition: .ssidNotEquals("Home"), profileID: profile),
            NetworkRule(condition: .publicIPInRange("203.0.113.0/24"), profileID: profile),
        ]
        state.publicIPAutomationEnabled = true
        let store = try StateStore(directory: tempDirectory().appendingPathComponent("s"))
        try store.save(state)
        XCTAssertEqual(try store.load(), state)
    }

    func testCorruptStateThrowsAndCanBeQuarantinedWithoutLoss() throws {
        let store = try StateStore(directory: tempDirectory().appendingPathComponent("s"))
        try Data("{broken".utf8).write(to: store.stateURL)
        XCTAssertThrowsError(try store.load())
        let moved = try store.quarantineCorruptState()
        XCTAssertEqual(try Data(contentsOf: moved), Data("{broken".utf8))
        XCTAssertEqual(try store.load(), AppState())
    }
}

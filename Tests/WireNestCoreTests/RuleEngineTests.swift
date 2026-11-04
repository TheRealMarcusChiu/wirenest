import XCTest
@testable import WireNestCore

final class RuleEngineTests: XCTestCase {
    private let home = UUID(), away = UUID()
    private let t0 = Date(timeIntervalSince1970: 1_000_000)

    private func makeState(ordered: [(RuleCondition, UUID)] = []) -> AppState {
        var state = AppState()
        state.profiles = [
            ConnectionProfile(id: home, name: "Home"),
            ConnectionProfile(id: away, name: "Away"),
        ]
        state.rules = ordered.map { NetworkRule(condition: $0.0, profileID: $0.1) }
        return state
    }

    /// Evaluates twice across the debounce window, the way the periodic tick does.
    private func settled(_ engine: inout RuleEngine, _ state: inout AppState, _ snap: NetworkSnapshot, at start: Date) -> UUID? {
        _ = engine.evaluate(state: &state, snapshot: snap, now: start)
        return engine.evaluate(state: &state, snapshot: snap, now: start.addingTimeInterval(engine.debounce))
    }

    func testSSIDEqualityMatchesKnownSSIDOnly() {
        var state = makeState(ordered: [(.ssidEquals("Home"), home)])
        var engine = RuleEngine()
        XCTAssertEqual(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0), home)
    }

    func testSSIDInequalityMatchesDifferentKnownSSID() {
        var state = makeState(ordered: [(.ssidNotEquals("Home"), away)])
        var engine = RuleEngine()
        XCTAssertEqual(settled(&engine, &state, NetworkSnapshot(ssid: .known("Cafe")), at: t0), away)
    }

    func testInequalityDoesNotMatchTheNamedSSID() {
        var state = makeState(ordered: [(.ssidNotEquals("Home"), away)])
        var engine = RuleEngine()
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0))
    }

    func testUnknownSSIDFailsClosedForInequality() {
        var state = makeState(ordered: [(.ssidNotEquals("Home"), away)])
        var engine = RuleEngine()
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .unavailable("Location denied")), at: t0))
    }

    func testFirstMatchingRuleWinsDeterministically() {
        var state = makeState(ordered: [(.ssidEquals("Home"), home), (.ssidNotEquals("Other"), away)])
        var engine = RuleEngine()
        XCTAssertEqual(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0), home)

        var flipped = makeState(ordered: [(.ssidNotEquals("Other"), away), (.ssidEquals("Home"), home)])
        var engine2 = RuleEngine()
        XCTAssertEqual(settled(&engine2, &flipped, NetworkSnapshot(ssid: .known("Home")), at: t0), away)
    }

    func testDisabledRulesAndMissingProfilesAreSkipped() {
        var state = makeState(ordered: [(.ssidEquals("Home"), UUID()), (.ssidEquals("Home"), home)])
        state.rules.insert(NetworkRule(enabled: false, condition: .ssidEquals("Home"), profileID: away), at: 0)
        var engine = RuleEngine()
        XCTAssertEqual(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0), home)
    }

    func testDebounceRequiresCandidateToStayStable() {
        var state = makeState(ordered: [(.ssidEquals("Home"), home), (.ssidEquals("Cafe"), away)])
        var engine = RuleEngine()
        XCTAssertNil(engine.evaluate(state: &state, snapshot: NetworkSnapshot(ssid: .known("Home")), now: t0))
        XCTAssertNil(engine.evaluate(state: &state, snapshot: NetworkSnapshot(ssid: .known("Cafe")), now: t0.addingTimeInterval(2)))
        XCTAssertNil(engine.evaluate(state: &state, snapshot: NetworkSnapshot(ssid: .known("Cafe")), now: t0.addingTimeInterval(3)), "flap restarted the debounce")
        XCTAssertEqual(engine.evaluate(state: &state, snapshot: NetworkSnapshot(ssid: .known("Cafe")), now: t0.addingTimeInterval(2 + engine.debounce)), away)
    }

    func testHysteresisBlocksRapidSecondSwitch() {
        var state = makeState(ordered: [(.ssidEquals("Home"), home), (.ssidEquals("Cafe"), away)])
        var engine = RuleEngine()
        XCTAssertEqual(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0), home)
        state.activeProfileID = home
        state.connectionOn = true

        let cafe = NetworkSnapshot(ssid: .known("Cafe"))
        let soon = t0.addingTimeInterval(10)
        XCTAssertNil(settled(&engine, &state, cafe, at: soon), "inside minimum dwell")
        XCTAssertEqual(engine.evaluate(state: &state, snapshot: cafe, now: t0.addingTimeInterval(engine.debounce + engine.minDwell)), away)
    }

    func testAlreadyActiveCandidateProducesNoSwitch() {
        var state = makeState(ordered: [(.ssidEquals("Home"), home)])
        state.activeProfileID = home
        state.connectionOn = true
        var engine = RuleEngine()
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0))
    }

    func testActiveProfileThatIsOffCanStillBeTurnedOnByRule() {
        var state = makeState(ordered: [(.ssidEquals("Home"), home)])
        state.activeProfileID = home
        var engine = RuleEngine()
        XCTAssertEqual(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0), home)
    }

    func testManualOffBlocksAutomationAcrossContextChanges() {
        var state = makeState(ordered: [(.ssidEquals("Home"), home), (.ssidNotEquals("Home"), away)])
        state.manualOff = true
        var engine = RuleEngine()
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0))
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .known("Cafe")), at: t0.addingTimeInterval(500)))
    }

    func testManualSelectionPinsUntilContextChanges() {
        var state = makeState(ordered: [(.ssidEquals("Home"), home), (.ssidEquals("Cafe"), away)])
        state.activeProfileID = away
        state.connectionOn = true
        state.pinnedContext = NetworkSnapshot(ssid: .known("Home")).contextKey(includingPublicIP: false)
        var engine = RuleEngine()
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .known("Home")), at: t0))
        XCTAssertNotNil(state.pinnedContext)

        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .unavailable("off")), at: t0.addingTimeInterval(1000)), "unknown SSID holds the pin")
        XCTAssertNotNil(state.pinnedContext)

        state.activeProfileID = home
        XCTAssertEqual(settled(&engine, &state, NetworkSnapshot(ssid: .known("Cafe")), at: t0.addingTimeInterval(2000)), away)
        XCTAssertNil(state.pinnedContext)
    }

    func testPublicIPRuleIsOptIn() {
        var state = makeState(ordered: [(.publicIPInRange("203.0.113.0/24"), away)])
        let snapshot = NetworkSnapshot(ssid: .unavailable("none"), publicIP: "203.0.113.9")
        var engine = RuleEngine()
        XCTAssertNil(settled(&engine, &state, snapshot, at: t0))

        state.publicIPAutomationEnabled = true
        var engine2 = RuleEngine()
        XCTAssertEqual(settled(&engine2, &state, snapshot, at: t0), away)
    }

    func testPublicIPOutsideRangeOrUnknownDoesNotMatch() {
        var state = makeState(ordered: [(.publicIPInRange("203.0.113.0/24"), away)])
        state.publicIPAutomationEnabled = true
        var engine = RuleEngine()
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .known("x"), publicIP: "198.51.100.1"), at: t0))
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .known("x"), publicIP: nil), at: t0))
    }

    func testNoMatchKeepsCurrentConnection() {
        var state = makeState(ordered: [(.ssidEquals("Cafe"), away)])
        state.activeProfileID = home
        state.connectionOn = true
        var engine = RuleEngine()
        XCTAssertNil(settled(&engine, &state, NetworkSnapshot(ssid: .known("Elsewhere")), at: t0))
        XCTAssertEqual(state.activeProfileID, home)
    }

    func testPublicIPStabilizerRequiresTwoEqualProbes() {
        var stabilizer = PublicIPStabilizer()
        XCTAssertNil(stabilizer.observe("203.0.113.1"))
        XCTAssertEqual(stabilizer.observe("203.0.113.1"), "203.0.113.1")
        XCTAssertEqual(stabilizer.observe("198.51.100.1"), "203.0.113.1", "one different probe does not rebaseline")
        XCTAssertEqual(stabilizer.observe("203.0.113.1"), "203.0.113.1")
        XCTAssertEqual(stabilizer.observe("198.51.100.1"), "203.0.113.1")
        XCTAssertEqual(stabilizer.observe("198.51.100.1"), "198.51.100.1")
        XCTAssertEqual(stabilizer.observe(nil), "198.51.100.1")
        XCTAssertNil(stabilizer.observe(nil), "two failed probes fail closed to unknown")
    }

    func testHTTPBodyIPExtractionRejectsNonIPContent() {
        XCTAssertEqual(publicIP(fromHTTPResponse: "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\n203.0.113.9"), "203.0.113.9")
        XCTAssertEqual(publicIP(fromHTTPResponse: "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nb\r\n203.0.113.9\r\n0\r\n\r\n"), "203.0.113.9")
        XCTAssertNil(publicIP(fromHTTPResponse: "HTTP/1.1 500 Oops\r\n\r\n203.0.113.9"))
        XCTAssertNil(publicIP(fromHTTPResponse: "HTTP/1.1 200 OK\r\n\r\n<html>nope</html>"))
    }

    func testPublicIPCheckURLMustBePlainHTTPS() {
        XCTAssertEqual(PublicIPEndpoint(urlString: "https://api.ipify.org/")?.host, "api.ipify.org")
        XCTAssertEqual(PublicIPEndpoint(urlString: "https://ip.example.com/v1/ip")?.path, "/v1/ip")
        XCTAssertNil(PublicIPEndpoint(urlString: "http://api.ipify.org/"))
        XCTAssertNil(PublicIPEndpoint(urlString: "https://user:pw@example.com/"))
        XCTAssertNil(PublicIPEndpoint(urlString: "https://example.com/a\r\nX: y"))
    }
}

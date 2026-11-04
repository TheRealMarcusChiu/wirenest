import XCTest
@testable import WireNestCore

final class ActivityLogTests: XCTestCase {
    private let t0 = Date(timeIntervalSince1970: 1_800_000_000)
    private let utc = TimeZone(identifier: "UTC")!

    func testStartsEmpty() {
        XCTAssertTrue(ActivityLog().entries.isEmpty)
        XCTAssertEqual(ActivityLog().text(), "")
    }

    func testAStableErrorIsLoggedOnceHoweverOftenItIsReported() {
        var log = ActivityLog()
        for tick in 0..<100 {
            log.report("Cannot reach the helper.", source: "helper", context: "Helper", now: t0.addingTimeInterval(Double(tick) * 5))
        }
        XCTAssertEqual(log.entries.map(\.message), ["Cannot reach the helper."])
        XCTAssertEqual(log.entries.first?.date, t0)
    }

    func testAChangedErrorIsANewEntry() {
        var log = ActivityLog()
        log.report("First.", source: "dns", context: "DNS", now: t0)
        log.report("Second.", source: "dns", context: "DNS", now: t0)
        XCTAssertEqual(log.entries.map(\.message), ["First.", "Second."])
    }

    func testAnErrorThatClearsAndReturnsIsLoggedAgain() {
        var log = ActivityLog()
        log.report("Down.", source: "dns", context: "DNS", now: t0)
        log.report(nil, source: "dns", context: "DNS", now: t0)
        XCTAssertEqual(log.entries.count, 1, "clearing is not itself an error")
        log.report("Down.", source: "dns", context: "DNS", now: t0)
        XCTAssertEqual(log.entries.count, 2)
    }

    func testSourcesAreIndependent() {
        var log = ActivityLog()
        log.report("Same words.", source: "a", context: "A", now: t0)
        log.report("Same words.", source: "b", context: "B", now: t0)
        log.report(nil, source: "a", context: "A", now: t0)
        log.report("Same words.", source: "b", context: "B", now: t0)
        XCTAssertEqual(log.entries.map(\.context), ["A", "B"])
    }

    func testHistoryIsBoundedAndKeepsTheNewest() {
        var log = ActivityLog()
        for index in 0..<(ActivityLog.capacity + 25) {
            log.report("Failure \(index).", source: "s", context: "C", now: t0)
        }
        XCTAssertEqual(log.entries.count, ActivityLog.capacity)
        XCTAssertEqual(log.entries.last?.message, "Failure \(ActivityLog.capacity + 24).")
        XCTAssertEqual(log.entries.first?.message, "Failure 25.")
        XCTAssertEqual(Set(log.entries.map(\.id)).count, ActivityLog.capacity, "stable identity for the list")
    }

    func testVeryLongMessagesAreCut() {
        var log = ActivityLog()
        log.report(String(repeating: "x", count: 50_000), source: "s", context: "C", now: t0)
        XCTAssertLessThanOrEqual(log.entries[0].message.count, ActivityLog.maxMessageLength + 1)
    }

    func testKeysAreRedactedAtCaptureEvenWhenACutWouldSplitThem() {
        let key = testKey(9), psk = testKey(7)
        var log = ActivityLog()
        log.report("PrivateKey = \(key) PresharedKey = \(psk)", source: "s", context: "C", now: t0)
        XCTAssertFalse(log.entries[0].message.contains(key))
        XCTAssertFalse(log.entries[0].message.contains(psk))
        XCTAssertTrue(log.entries[0].message.contains("<redacted>"))

        var split = ActivityLog()
        let padding = String(repeating: "x", count: ActivityLog.maxMessageLength - 20)
        split.report(padding + key, source: "s", context: "C", now: t0)
        XCTAssertFalse(split.entries[0].message.contains(String(key.prefix(15))), "no fragment of a key survives the cut")
    }

    func testAContextCannotCarryAKeyEither() {
        var log = ActivityLog()
        log.report("Failed.", source: "s", context: "Tunnel \(testKey(4))", now: t0)
        XCTAssertFalse(log.text().contains(testKey(4)))
    }

    func testCopiedTextIsExactlyTheVisibleRedactedText() {
        var log = ActivityLog()
        log.report("Bad \(testKey(9)).", source: "s", context: "Tunnel lab", now: t0)
        log.report("Second.", source: "t", context: "DNS", now: t0.addingTimeInterval(61))
        XCTAssertEqual(log.text(timeZone: utc), """
        2027-01-15 08:00:00  Tunnel lab  Bad <redacted>.
        2027-01-15 08:01:01  DNS  Second.
        """)
        XCTAssertFalse(log.text().contains(testKey(9)))
    }

    func testAMessageCannotForgeASecondLine() {
        var log = ActivityLog()
        log.report("One\n2027-01-15 08:00:00  Fake  Two", source: "s", context: "C", now: t0)
        XCTAssertEqual(log.text(timeZone: utc).components(separatedBy: "\n").count, 1)
    }

    func testClearEmptiesHistoryWithoutRelistingAnErrorThatIsStillActive() {
        var log = ActivityLog()
        log.report("Down.", source: "s", context: "C", now: t0)
        log.clear()
        XCTAssertTrue(log.entries.isEmpty)
        log.report("Down.", source: "s", context: "C", now: t0)
        XCTAssertTrue(log.entries.isEmpty)
        log.report(nil, source: "s", context: "C", now: t0)
        log.report("Down.", source: "s", context: "C", now: t0)
        XCTAssertEqual(log.entries.count, 1)
    }

    // MARK: short status

    func testTheReportedRoutingErrorBecomesAShortStatus() {
        let message = "Cannot safely run this tunnel beside the default-route tunnel: no proven physical-LAN or loopback route to 97.98.221.111 more specific than its /1 routes (its route goes through a gateway). No protective route was added."
        XCTAssertEqual(shortFailure(message), "Route safety check failed")
    }

    func testOtherErrorsKeepTheirFirstSentenceWithinALimit() {
        XCTAssertEqual(shortFailure("Could not save. Try again later."), "Could not save")
        XCTAssertEqual(shortFailure("First line\nSecond line"), "First line")
        let long = shortFailure(String(repeating: "word ", count: 60))
        XCTAssertLessThanOrEqual(long.count, 60)
        XCTAssertTrue(long.hasSuffix("…"))
    }

    func testAShortStatusDoesNotBreakAnAddressOrLeakAKey() {
        XCTAssertEqual(shortFailure("Endpoint 10.0.0.1 failed"), "Endpoint 10.0.0.1 failed")
        XCTAssertFalse(shortFailure("Bad key \(testKey(3)) here").contains(testKey(3)))
    }
}

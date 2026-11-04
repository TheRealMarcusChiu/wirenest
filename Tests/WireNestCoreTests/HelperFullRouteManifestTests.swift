import XCTest
@testable import WireNestCore

final class HelperFullRouteManifestTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = try tempDirectory()
    }

    private let fullConf = confText(address: "198.18.71.1/32", allowedIPs: "0.0.0.0/0", endpoint: "127.77.0.2:51000")
    private let splitConf = confText(address: "198.18.72.1/32", allowedIPs: "198.18.72.0/24", endpoint: "127.77.0.3:51001")

    private func write(_ text: String, _ name: String, mode: Int = 0o600) throws -> String {
        let url = dir.appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url.path
    }

    private func entry(_ configPath: String, probeHost: String, port: Int, token: String, id: String = UUID().uuidString) -> [String: Any] {
        ["id": id, "configPath": configPath, "probeHost": probeHost, "probePort": port, "expectedToken": token]
    }

    private func manifest(
        full: String? = nil, split: String? = nil, fullProbe: String = "198.18.71.2", splitProbe: String = "198.18.72.2",
        restartCount: Int = 1, startupOrder: String = "split-first", extraTopLevel: [String: Any] = [:], sameID: Bool = false
    ) throws -> String {
        let id = UUID().uuidString
        let first = entry(try write(full ?? fullConf, "a.conf"), probeHost: fullProbe, port: 18081, token: "token-a", id: id)
        let second = entry(try write(split ?? splitConf, "b.conf"), probeHost: splitProbe, port: 18082, token: "token-b", id: sameID ? id : UUID().uuidString)
        var object: [String: Any] = ["tunnels": [first, second], "restartCount": restartCount, "startupOrder": startupOrder]
        object.merge(extraTopLevel) { _, new in new }
        let url = dir.appendingPathComponent("manifest.json")
        try JSONSerialization.data(withJSONObject: object).write(to: url)
        return url.path
    }

    private func assertRejected(_ path: @autoclosure () throws -> String, _ reason: String, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try HelperFullRouteManifest.load(path: path()), reason, file: file, line: line)
    }

    func testAcceptsTheFrozenShapeInBothOrders() throws {
        let splitFirst = try HelperFullRouteManifest.load(path: manifest())
        XCTAssertEqual(splitFirst.order, .splitFirst)
        XCTAssertEqual(splitFirst.full.probeHost, "198.18.71.2")
        XCTAssertEqual(splitFirst.split.probeHost, "198.18.72.2")
        XCTAssertEqual(try HelperFullRouteManifest.load(path: manifest(startupOrder: "full-first")).order, .fullFirst)
    }

    func testTheTwoTunnelsNeedRunTimeProofNotAConflict() throws {
        let loaded = try HelperFullRouteManifest.load(path: manifest())
        let assessment = assessRoutes([
            NamedConfig(name: "full", config: loaded.full.config), NamedConfig(name: "split", config: loaded.split.config),
        ])
        XCTAssertEqual(assessment.conflicts, [])
        XCTAssertEqual(assessment.exposures.map(\.configuredEndpoints), [["127.77.0.3"]])
    }

    func testRejectsAnyOtherCountOrderOrShape() throws {
        assertRejected(try manifest(restartCount: 0), "restart")
        assertRejected(try manifest(restartCount: 2), "no restart loops in this mode")
        assertRejected(try manifest(startupOrder: "whatever"), "order")
        assertRejected(try manifest(sameID: true), "same ID")
        assertRejected(try manifest(extraTopLevel: ["surprise": true]), "unknown field")
        let single = dir.appendingPathComponent("one.json")
        try Data("{\"tunnels\":[],\"restartCount\":1,\"startupOrder\":\"split-first\"}".utf8).write(to: single)
        XCTAssertThrowsError(try HelperFullRouteManifest.load(path: single.path))
    }

    func testRejectsAnExtraFieldInATunnelEntry() throws {
        var first = entry(try write(fullConf, "a.conf"), probeHost: "198.18.71.2", port: 18081, token: "a")
        first["route"] = "198.18.71.2/32"
        let second = entry(try write(splitConf, "b.conf"), probeHost: "198.18.72.2", port: 18082, token: "b")
        let url = dir.appendingPathComponent("extra.json")
        try JSONSerialization.data(withJSONObject: ["tunnels": [first, second], "restartCount": 1, "startupOrder": "split-first"]).write(to: url)
        XCTAssertThrowsError(try HelperFullRouteManifest.load(path: url.path))
    }

    func testRejectsTheEntriesInTheWrongRole() throws {
        assertRejected(try manifest(full: splitConf, split: fullConf, fullProbe: "198.18.72.2", splitProbe: "198.18.71.2"), "swapped")
    }

    func testFullTunnelMustBeExactly() throws {
        for (reason, text) in [
            ("no default", confText(address: "198.18.71.1/32", allowedIPs: "198.18.71.0/24", endpoint: "127.77.0.2:51000")),
            ("narrow route to its own probe", confText(address: "198.18.71.1/32", allowedIPs: "0.0.0.0/0, 198.18.71.2/32", endpoint: "127.77.0.2:51000")),
            ("IPv6", confText(address: "198.18.71.1/32", allowedIPs: "0.0.0.0/0, ::/0", endpoint: "127.77.0.2:51000")),
            ("other address", confText(address: "198.18.71.9/32", allowedIPs: "0.0.0.0/0", endpoint: "127.77.0.2:51000")),
            ("extra address", confText(address: "198.18.71.1/32, 198.18.70.1/32", allowedIPs: "0.0.0.0/0", endpoint: "127.77.0.2:51000")),
            ("ordinary loopback", confText(address: "198.18.71.1/32", allowedIPs: "0.0.0.0/0", endpoint: "127.0.0.1:51000")),
            ("the other alias", confText(address: "198.18.71.1/32", allowedIPs: "0.0.0.0/0", endpoint: "127.77.0.3:51000")),
            ("DNS", confText(address: "198.18.71.1/32", dns: "198.18.71.53", allowedIPs: "0.0.0.0/0", endpoint: "127.77.0.2:51000")),
            ("Table off", confText(address: "198.18.71.1/32", extraInterface: "Table = off", allowedIPs: "0.0.0.0/0", endpoint: "127.77.0.2:51000")),
            ("hook", confText(address: "198.18.71.1/32", extraInterface: "PostUp = id", allowedIPs: "0.0.0.0/0", endpoint: "127.77.0.2:51000")),
            ("second peer", confText(address: "198.18.71.1/32", allowedIPs: "0.0.0.0/0", endpoint: "127.77.0.2:51000") + "\n[Peer]\nPublicKey = \(testKey(5))\nAllowedIPs = 198.18.70.0/24\n"),
        ] {
            assertRejected(try manifest(full: text), reason)
        }
    }

    func testSplitTunnelMustBeExactly() throws {
        for (reason, text) in [
            ("wider route", confText(address: "198.18.72.1/32", allowedIPs: "198.18.72.0/23", endpoint: "127.77.0.3:51001")),
            ("extra route", confText(address: "198.18.72.1/32", allowedIPs: "198.18.72.0/24, 198.18.73.0/24", endpoint: "127.77.0.3:51001")),
            ("wide address", confText(address: "198.18.72.1/24", allowedIPs: "198.18.72.0/24", endpoint: "127.77.0.3:51001")),
            ("hostname endpoint", confText(address: "198.18.72.1/32", allowedIPs: "198.18.72.0/24", endpoint: "peer.example.com:51001")),
            ("public endpoint", confText(address: "198.18.72.1/32", allowedIPs: "198.18.72.0/24", endpoint: "198.51.100.1:51001")),
        ] {
            assertRejected(try manifest(split: text), reason)
        }
    }

    func testRejectsWrongProbes() throws {
        assertRejected(try manifest(fullProbe: "198.18.71.3"), "full probe")
        assertRejected(try manifest(splitProbe: "198.18.72.3"), "split probe")
    }

    func testRejectsUnprotectedOrRelativeFiles() throws {
        XCTAssertThrowsError(try HelperFullRouteManifest.load(path: "manifest.json"))
        let open = entry(try write(fullConf, "open.conf", mode: 0o644), probeHost: "198.18.71.2", port: 18081, token: "a")
        let second = entry(try write(splitConf, "b.conf"), probeHost: "198.18.72.2", port: 18082, token: "b")
        let url = dir.appendingPathComponent("open.json")
        try JSONSerialization.data(withJSONObject: ["tunnels": [open, second], "restartCount": 1, "startupOrder": "split-first"]).write(to: url)
        XCTAssertThrowsError(try HelperFullRouteManifest.load(path: url.path))
    }

    func testOriginalReservedOnlyManifestStillRefusesThisShape() throws {
        // Contains a default route and non-127.0.0.1 peers, and has an extra field the original never reads.
        XCTAssertThrowsError(try HelperSmokeManifest.load(path: manifest()))
    }

    func testOptInNeedsEveryHostedCIVariable() {
        let good = ["WIRENEST_FULL_ROUTE_SMOKE": "1", "GITHUB_ACTIONS": "true", "RUNNER_ENVIRONMENT": "github-hosted"]
        XCTAssertTrue(fullRouteSmokeOptedIn(good))
        for key in good.keys {
            var missing = good
            missing[key] = nil
            XCTAssertFalse(fullRouteSmokeOptedIn(missing), key)
            var wrong = good
            wrong[key] = "no"
            XCTAssertFalse(fullRouteSmokeOptedIn(wrong), key)
        }
        XCTAssertFalse(fullRouteSmokeOptedIn(["WIRENEST_HELPER_SMOKE": "1"]))
        var selfHosted = good
        selfHosted["RUNNER_ENVIRONMENT"] = "self-hosted"
        XCTAssertFalse(fullRouteSmokeOptedIn(selfHosted))
    }

    func testNarrowerRouteToAProbeIsFoundButCachedClonesAndExpansionsAreNot() {
        // Synthetic rows. No default-route tunnel has been observed on a real Mac yet.
        let base = "Routing tables\n\nInternet:\nDestination Gateway Flags Netif Expire\n"
        let expansions = "0/1 utun5 USc utun5\n128.0/1 utun5 USc utun5\ndefault 192.168.64.1 UGScg en0\n"
        XCTAssertFalse(EndpointRouteProof.hasNarrowerRoute(netstat: base + expansions, to: "198.18.71.2"))
        XCTAssertFalse(EndpointRouteProof.hasNarrowerRoute(netstat: base + expansions + "198.18.71.2 link#9 UHWIi utun5\n", to: "198.18.71.2"), "a clone made by traffic")
        XCTAssertTrue(EndpointRouteProof.hasNarrowerRoute(netstat: base + expansions + "198.18.71.2/32 utun5 USc utun5\n", to: "198.18.71.2"))
        XCTAssertTrue(EndpointRouteProof.hasNarrowerRoute(netstat: base + expansions + "198.18.71 link#7 UCS en0\n", to: "198.18.71.2"))
        XCTAssertTrue(EndpointRouteProof.hasNarrowerRoute(netstat: "unreadable", to: "198.18.71.2"), "fails closed")
    }
}

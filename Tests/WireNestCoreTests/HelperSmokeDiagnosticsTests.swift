import XCTest
@testable import WireNestCore

final class HelperSmokeDiagnosticsTests: XCTestCase {
    private let token = "secret-token-abc"

    private func attempt(_ progress: SmokeProbeProgress = SmokeProbeProgress(), response: String = "") -> SmokeProbeAttempt {
        SmokeProbeAttempt(progress: progress, response: response, receivedBytes: response.utf8.count, token: token)
    }

    private func progress(_ stage: SmokeProbeStage, timedOut: Bool = false, error: SmokeProbeError? = nil) -> SmokeProbeProgress {
        var result = SmokeProbeProgress()
        result.reach(stage)
        result.timedOut = timedOut
        if let error { result.note(error) }
        return result
    }

    func testAttemptMatchesExactlyWhenTheExistingCheckDoes() {
        for response in [
            "HTTP/1.1 200 OK\r\nContent-Length: 16\r\n\r\n\(token)",
            "HTTP/1.1 200 OK\r\n\r\nother",
            "HTTP/1.1 200 OK\r\n\r\n\(token) extra",
            "HTTP/1.1 500 Oops\r\n\r\n\(token)",
            token,
            "",
        ] {
            XCTAssertEqual(attempt(response: response).matches, smokeResponseMatches(response, token: token), response)
        }
    }

    func testDistinguishesNoHTTPFromAWrongStatusAndAWrongBody() {
        let silent = attempt(progress(.ready, timedOut: true))
        XCTAssertEqual(silent.receivedBytes, 0)
        XCTAssertFalse(silent.headerComplete)
        XCTAssertTrue(silent.timedOut)

        let wrongStatus = attempt(response: "HTTP/1.1 500 Oops\r\n\r\n\(token)")
        XCTAssertTrue(wrongStatus.headerComplete)
        XCTAssertFalse(wrongStatus.status200)
        XCTAssertTrue(wrongStatus.bodyMatches)

        let wrongBody = attempt(response: "HTTP/1.1 200 OK\r\n\r\nother")
        XCTAssertTrue(wrongBody.status200)
        XCTAssertFalse(wrongBody.bodyMatches)
    }

    func testStageKeepsTheFurthestPointReached() {
        var value = SmokeProbeProgress()
        value.reach(.ready)
        value.reach(.waiting)
        XCTAssertEqual(value.stage, .ready)
        value.reach(.endOfStream)
        XCTAssertEqual(value.stage, .endOfStream)
    }

    func testRepeatedAttemptsAreAggregatedIntoOneBoundedLine() {
        let same = attempt(progress(.preparing, timedOut: true))
        let line = formatProbeDiagnostic(tunnel: "A", phase: "restart3/re-probe", attempts: Array(repeating: same, count: 12))
        XCTAssertTrue(line.contains("tunnel=A"))
        XCTAssertTrue(line.contains("phase=restart3/re-probe"))
        XCTAssertTrue(line.contains("matched=false"))
        XCTAssertTrue(line.contains("attempts=12"))
        XCTAssertTrue(line.contains("12x"))
        XCTAssertTrue(line.contains("stage=preparing"))
        XCTAssertTrue(line.contains("timedOut=true"))
        XCTAssertEqual(line.components(separatedBy: "\n").count, 1)

        let varied = (0..<12).map { attempt(progress(.ready, error: SmokeProbeError(category: .posix, code: Int32($0)))) }
        let bounded = formatProbeDiagnostic(tunnel: "B", phase: "initial", attempts: varied)
        XCTAssertTrue(bounded.contains("otherOutcomes=8"), bounded)
        XCTAssertLessThan(bounded.utf8.count, 900)
    }

    func testAMatchingLastAttemptIsReportedAsMatched() {
        let good = attempt(progress(.endOfStream), response: "HTTP/1.1 200 OK\r\n\r\n\(token)")
        let line = formatProbeDiagnostic(tunnel: "B", phase: "initial", attempts: [attempt(progress(.waiting)), good])
        XCTAssertTrue(line.contains("matched=true"))
        XCTAssertTrue(line.contains("attempts=2"))
    }

    func testReportsErrorsOnlyAsACategoryAndCode() {
        let line = formatProbeDiagnostic(
            tunnel: "A", phase: "initial",
            attempts: [attempt(progress(.waiting, error: SmokeProbeError(category: .posix, code: 65)))]
        )
        XCTAssertTrue(line.contains("error=posix:65"), line)
        XCTAssertTrue(formatProbeDiagnostic(tunnel: "A", phase: "initial", attempts: [attempt()]).contains("error=none"))
    }

    func testProbeLinesNeverCarryResponseTokenOrKeyMaterial() {
        let key = testKey(9)
        let response = "HTTP/1.1 200 OK\r\nX-Key: \(key)\r\nServer: leaky-server\r\n\r\n\(token) body-text \(key)"
        let line = formatProbeDiagnostic(tunnel: "A", phase: "initial", attempts: [attempt(progress(.endOfStream), response: response)])
        for secret in [token, key, "leaky-server", "body-text", "X-Key"] {
            XCTAssertFalse(line.contains(secret), secret)
        }
        XCTAssertTrue(line.contains("bytes=\(response.utf8.count)"))
    }

    func testUntrustedLabelsAreNotEchoed() {
        let line = formatProbeDiagnostic(tunnel: "A\nB", phase: "bad phase \(token)", attempts: [])
        XCTAssertFalse(line.contains(token))
        XCTAssertFalse(line.contains("\n"))
        XCTAssertTrue(line.contains("attempts=0"))
    }

    func testStatusLineCarriesOnlyTheAllowedFields() {
        let handshake = Date(timeIntervalSince1970: 1000)
        let status = HelperTunnelStatus(
            tunnelID: UUID(), interface: "utun7", fingerprint: "fingerprint-value", alive: true,
            peers: [PeerStats(publicKey: testKey(2), latestHandshake: handshake, rxBytes: 11, txBytes: 22)]
        )
        let line = formatTunnelStatusDiagnostic(tunnel: "A", status: status, now: handshake.addingTimeInterval(12))
        XCTAssertEqual(line, "status tunnel=A tracked=true interface=utun7 alive=true handshake=present age=12s rx=11 tx=22")
        XCTAssertFalse(line.contains(testKey(2)))
        XCTAssertFalse(line.contains("fingerprint-value"))
        XCTAssertFalse(line.contains(status.tunnelID.uuidString))
    }

    func testStatusLineHandlesAMissingTunnelNoHandshakeAndABadInterfaceName() {
        XCTAssertEqual(formatTunnelStatusDiagnostic(tunnel: "B", status: nil, now: Date()), "status tunnel=B tracked=false")

        let waiting = HelperTunnelStatus(
            tunnelID: UUID(), interface: "not an interface \(token)", fingerprint: "", alive: false,
            peers: [PeerStats(publicKey: testKey(2), latestHandshake: nil, rxBytes: 0, txBytes: 0)]
        )
        let line = formatTunnelStatusDiagnostic(tunnel: "B", status: waiting, now: Date())
        XCTAssertEqual(line, "status tunnel=B tracked=true interface=invalid alive=false handshake=absent rx=0 tx=0")
    }

    func testRouteLineComparesTheLookupWithTheTunnelInterface() {
        XCTAssertEqual(
            formatRouteDiagnostic(tunnel: "A", probeHost: "198.18.71.2", lookup: "utun7", expected: "utun7"),
            "route tunnel=A probe=198.18.71.2 lookup=utun7 matchesTunnel=true"
        )
        XCTAssertEqual(
            formatRouteDiagnostic(tunnel: "A", probeHost: "198.18.71.2", lookup: nil, expected: "utun7"),
            "route tunnel=A probe=198.18.71.2 lookup=unknown matchesTunnel=false"
        )
        XCTAssertEqual(
            formatRouteDiagnostic(tunnel: "A", probeHost: "198.18.71.2", lookup: "en0", expected: nil),
            "route tunnel=A probe=198.18.71.2 lookup=en0 matchesTunnel=false"
        )
    }

    func testRouteLineReportsOnlyAReservedFixtureProbe() {
        let line = formatRouteDiagnostic(tunnel: "A", probeHost: "8.8.8.8", lookup: "en0", expected: nil)
        XCTAssertFalse(line.contains("8.8.8.8"))
        XCTAssertTrue(line.contains("probe=invalid"))
    }
}

import XCTest
@testable import WireNestCore

final class ConfigParserTests: XCTestCase {
    private func assertRejected(_ text: String, _ kind: ConfigError.Kind, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertThrowsError(try WireGuardConfig.parse(text), file: file, line: line) { error in
            XCTAssertEqual((error as? ConfigError)?.kind, kind, "\(error)", file: file, line: line)
        }
    }

    func testParsesMultipleAllowedIPsAcrossCommaAndRepeatedLines() throws {
        let config = try WireGuardConfig.parse(confText(
            allowedIPs: "10.10.0.0/24, 10.20.0.0/16",
            extraPeer: "AllowedIPs = fd00::/64"
        ))
        XCTAssertEqual(config.peers[0].allowedIPs.map(\.description), ["10.10.0.0/24", "10.20.0.0/16", "fd00::/64"])
    }

    func testKeysAndSectionsAreCaseInsensitiveLikeWgQuick() throws {
        let text = "[INTERFACE]\nprivatekey = \(testKey(1))\nADDRESS = 10.0.0.1/32\n[peer]\npublickey = \(testKey(2))\n"
        XCTAssertEqual(try WireGuardConfig.parse(text).addresses.map(\.description), ["10.0.0.1/32"])
    }

    func testBareAddressGetsHostPrefix() throws {
        let config = try WireGuardConfig.parse(confText(address: "10.0.0.1, fd00::1"))
        XCTAssertEqual(config.addresses.map(\.description), ["10.0.0.1/32", "fd00::1/128"])
    }

    func testRejectsEveryShellHookAndSaveConfig() {
        for directive in ["PreUp", "PostUp", "PreDown", "PostDown", "SaveConfig", "postup"] {
            assertRejected(confText(extraInterface: "\(directive) = touch /tmp/pwned"), .unsafeDirective)
        }
    }

    func testAPairedHostRouteHookIsKeptInStoredTextAndNeverReachesRuntimeText() throws {
        let preUp = "PreUp = /sbin/route -n add -host 198.51.100.50 192.168.64.1"
        let postDown = "PostDown = /sbin/route -n delete -host 198.51.100.50 192.168.64.1"
        let config = try WireGuardConfig.parse(confText(extraInterface: "\(preUp)\n\(postDown)"))

        XCTAssertTrue(config.storedText.contains(preUp), "editing a saved tunnel must not lose it")
        XCTAssertTrue(config.storedText.contains(postDown))
        XCTAssertEqual(try WireGuardConfig.parse(config.storedText), config)

        // wg-quick runs these through a root shell, so its file must never hold them.
        XCTAssertFalse(config.runtimeText.lowercased().contains("preup"))
        XCTAssertFalse(config.runtimeText.lowercased().contains("postdown"))
        XCTAssertFalse(config.runtimeText.contains("/sbin/route"))
    }

    func testRejectsUnknownDirectivesInBothSections() {
        assertRejected(confText(extraInterface: "FwMark = 51820"), .unknownDirective)
        assertRejected(confText(extraPeer: "Nonsense = 1"), .unknownDirective)
    }

    func testRejectsInvalidKeys() {
        assertRejected(confText(privateKey: "not-a-key"), .invalidKey)
        assertRejected(confText(peerKey: Data(repeating: 3, count: 31).base64EncodedString()), .invalidKey)
    }

    func testRejectsInvalidAddressesAndCIDRs() {
        assertRejected(confText(address: "10.0.0.300/32"), .invalidAddress)
        assertRejected(confText(address: "10.0.0.1/33"), .invalidAddress)
        assertRejected(confText(allowedIPs: "10.0.0.0/8; rm -rf /"), .invalidAddress)
        assertRejected(confText(allowedIPs: "fd00::/129"), .invalidAddress)
    }

    func testRejectsInvalidEndpoints() {
        for bad in ["198.51.100.1", "198.51.100.1:0", "198.51.100.1:70000", "$(id):51820", "a b:51820", "999.1.1.1:51820", "[nope]:51820"] {
            assertRejected(confText(endpoint: bad), .invalidEndpoint)
        }
    }

    func testAcceptsHostnameAndIPv6Endpoints() throws {
        XCTAssertEqual(try WireGuardConfig.parse(confText(endpoint: "vpn.example.com:51820")).peers[0].endpoint?.host, "vpn.example.com")
        XCTAssertEqual(try WireGuardConfig.parse(confText(endpoint: "[2001:db8::1]:51820")).peers[0].endpoint?.host, "2001:db8::1")
    }

    func testRejectsNumericTableButAcceptsOff() throws {
        assertRejected(confText(extraInterface: "Table = 1234"), .invalidValue)
        XCTAssertEqual(try WireGuardConfig.parse(confText(extraInterface: "Table = off")).table, .off)
    }

    func testRejectsStructuralProblems() {
        assertRejected("[Peer]\nPublicKey = \(testKey(2))\n", .structure)
        assertRejected("[Interface]\nPrivateKey = \(testKey(1))\nAddress = 10.0.0.1/32\n", .structure)
        assertRejected("garbage line\n", .structure)
        assertRejected(confText() + "[Interface]\nPrivateKey = \(testKey(1))\n", .structure)
        assertRejected(String(repeating: "#", count: WireGuardConfig.maxBytes + 1), .structure)
    }

    func testRejectsDuplicateSingleValueDirective() {
        assertRejected(confText(extraInterface: "PrivateKey = \(testKey(4))"), .duplicateDirective)
    }

    func testRejectsPeerSharingKeyOrExactRoute() {
        let peer = "\n[Peer]\nPublicKey = \(testKey(2))\nAllowedIPs = 10.99.0.0/24\n"
        assertRejected(confText() + peer, .invalidValue)
        let sameRoute = "\n[Peer]\nPublicKey = \(testKey(5))\nAllowedIPs = 10.10.0.0/24\n"
        assertRejected(confText() + sameRoute, .invalidValue)
    }

    func testErrorsNeverEchoSecretValues() {
        let secret = testKey(9)
        let text = confText(privateKey: secret + "x")
        XCTAssertThrowsError(try WireGuardConfig.parse(text)) { error in
            XCTAssertFalse(error.localizedDescription.contains(secret))
        }
        XCTAssertThrowsError(try WireGuardConfig.parse(confText(extraInterface: "PostUp = \(secret)"))) { error in
            XCTAssertFalse(error.localizedDescription.contains(secret))
        }
    }

    func testRuntimeTextStripsDNSAndComments() throws {
        let config = try WireGuardConfig.parse("# note\n" + confText(dns: "1.1.1.1, corp.example"))
        XCTAssertEqual(config.dnsEntries, ["1.1.1.1", "corp.example"])
        XCTAssertFalse(config.runtimeText.lowercased().contains("dns"))
        XCTAssertFalse(config.runtimeText.contains("note"))
        XCTAssertTrue(config.storedText.contains("DNS = 1.1.1.1, corp.example"))
    }

    func testRuntimeAndStoredTextRoundTrip() throws {
        let config = try WireGuardConfig.parse(confText(
            dns: "1.1.1.1",
            extraInterface: "MTU = 1380\nListenPort = 51000\nTable = off",
            allowedIPs: "10.1.0.0/16, fd00::/64",
            extraPeer: "PersistentKeepalive = 25\nPresharedKey = \(testKey(7))"
        ))
        XCTAssertEqual(try WireGuardConfig.parse(config.storedText), config)
        let runtime = try WireGuardConfig.parse(config.runtimeText)
        XCTAssertEqual(runtime.peers, config.peers)
        XCTAssertEqual(runtime.table, .off)
        XCTAssertEqual(runtime.mtu, 1380)
        XCTAssertEqual(runtime.dnsEntries, [])
    }

    func testFingerprintIgnoresDNSButTracksRuntimeChanges() throws {
        let base = try WireGuardConfig.parse(confText()).fingerprint
        XCTAssertEqual(base, try WireGuardConfig.parse(confText(dns: "1.1.1.1")).fingerprint)
        XCTAssertNotEqual(base, try WireGuardConfig.parse(confText(allowedIPs: "10.11.0.0/24")).fingerprint)
        XCTAssertFalse(base.contains(testKey(1)))
    }
}

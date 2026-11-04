import XCTest
@testable import WireNestCore

final class RouteConflictTests: XCTestCase {
    private func named(_ name: String, _ text: String) throws -> NamedConfig {
        NamedConfig(name: name, config: try WireGuardConfig.parse(text))
    }

    private func kinds(_ a: String, _ b: String) throws -> [RouteConflict.Kind] {
        findRouteConflicts([try named("A", a), try named("B", b)]).map(\.kind)
    }

    func testCIDROverlapAcrossPrefixesAndFamilies() {
        XCTAssertTrue(CIDR("10.0.0.0/8")!.overlaps(CIDR("10.1.2.0/24")!))
        XCTAssertTrue(CIDR("10.1.2.5/24")!.overlaps(CIDR("10.1.2.200/32")!))
        XCTAssertFalse(CIDR("10.0.0.0/24")!.overlaps(CIDR("10.0.1.0/24")!))
        XCTAssertFalse(CIDR("0.0.0.0/0")!.overlaps(CIDR("::/0")!))
        XCTAssertTrue(CIDR("fd00::/8")!.overlaps(CIDR("fd12::1/128")!))
    }

    func testDisjointTunnelsDoNotConflict() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "10.1.0.0/24")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24, fd02::/64")
        XCTAssertEqual(try kinds(a, b), [])
    }

    func testOverlappingAllowedIPsConflictWithActionableMessage() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "10.0.0.0/8")
        let b = confText(address: "192.168.9.2/32", allowedIPs: "10.2.0.0/24")
        let conflicts = findRouteConflicts([try named("Office", a), try named("Lab", b)])
        XCTAssertEqual(conflicts.map(\.kind), [.overlappingRoutes])
        XCTAssertTrue(conflicts[0].message.contains("Office"))
        XCTAssertTrue(conflicts[0].message.contains("Lab"))
        XCTAssertTrue(conflicts[0].message.contains("10.2.0.0/24"))
        XCTAssertTrue(conflicts[0].message.contains("AllowedIPs"))
    }

    func testAtMostOneDefaultRouteOwnerPerFamily() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "0.0.0.0/0")
        XCTAssertEqual(try kinds(a, b), [.multipleDefaultRoutes])
        let v6 = confText(address: "10.2.0.2/32", allowedIPs: "::/0")
        XCTAssertEqual(try kinds(a, v6), [])
    }

    func testDefaultOwnerAllowsMoreSpecificTunnelByLongestPrefixMatch() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24")
        XCTAssertEqual(try kinds(a, b), [])
    }

    func testSplitDefaultOverlapsSpecificRoute() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/1, 128.0.0.0/1")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24")
        XCTAssertTrue(try kinds(a, b).contains(.overlappingRoutes))
    }

    func testTableOffInstallsNoRoutesSoAllowedIPsDoNotConflict() throws {
        let a = confText(address: "10.1.0.2/32", extraInterface: "Table = off", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "0.0.0.0/0")
        XCTAssertEqual(try kinds(a, b), [])
    }

    func testOverlappingInterfaceAddressesConflict() throws {
        let a = confText(address: "10.5.0.2/32", allowedIPs: "10.1.0.0/24")
        let b = confText(address: "10.5.0.2/32", allowedIPs: "10.2.0.0/24")
        XCTAssertEqual(try kinds(a, b), [.overlappingRoutes])
    }

    func testEndpointCapturedByOtherTunnelConflicts() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "10.1.0.0/24", endpoint: "10.2.0.9:51820")
        let b = confText(address: "10.3.0.2/32", allowedIPs: "10.2.0.0/24", endpoint: "198.51.100.1:51820")
        XCTAssertEqual(try kinds(a, b), [.endpointCaptured])
    }

    func testSameListenPortConflicts() throws {
        let a = confText(address: "10.1.0.2/32", extraInterface: "ListenPort = 51000", allowedIPs: "10.1.0.0/24")
        let b = confText(address: "10.2.0.2/32", extraInterface: "ListenPort = 51000", allowedIPs: "10.2.0.0/24")
        XCTAssertEqual(try kinds(a, b), [.listenPort])
    }

    func testResultOrderIsDeterministic() throws {
        let tunnels = [
            try named("A", confText(address: "10.1.0.2/32", allowedIPs: "10.9.0.0/16")),
            try named("B", confText(address: "10.2.0.2/32", allowedIPs: "10.9.1.0/24")),
            try named("C", confText(address: "10.3.0.2/32", allowedIPs: "10.9.2.0/24")),
        ]
        let first = findRouteConflicts(tunnels).map(\.message)
        XCTAssertEqual(first.count, 2)
        XCTAssertEqual(first, findRouteConflicts(tunnels).map(\.message))
    }
}

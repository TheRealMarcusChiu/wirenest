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
        let v6a = confText(address: "fd01::2/128", allowedIPs: "::/0", endpoint: "[2001:db8::1]:51820")
        let v6b = confText(address: "fd02::2/128", allowedIPs: "::/0", endpoint: "[2001:db8::2]:51820")
        XCTAssertEqual(try kinds(v6a, v6b), [.multipleDefaultRoutes])
    }

    func testDefaultRoutesOfDifferentFamiliesCoexist() throws {
        let v4 = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")
        let v6 = confText(address: "fd02::2/128", allowedIPs: "::/0", endpoint: "[2001:db8::2]:51820")
        XCTAssertEqual(try kinds(v4, v6), [])
    }

    func testDefaultRouteConflictsWithAnotherTunnelsSpecificRoute() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "192.168.9.2/32", allowedIPs: "10.2.0.0/24")
        XCTAssertTrue(try kinds(a, b).contains(.overlappingRoutes))
        XCTAssertTrue(try kinds(b, a).contains(.overlappingRoutes), "order must not matter")

        let v6a = confText(address: "fd01::2/128", allowedIPs: "::/0", endpoint: "[2001:db8::1]:51820")
        let v6b = confText(address: "fd02::2/128", allowedIPs: "fd03::/64", endpoint: "[2001:db8::2]:51820")
        XCTAssertTrue(try kinds(v6a, v6b).contains(.overlappingRoutes))
    }

    func testDefaultRouteConflictsWithSameSizedSplitRoute() throws {
        // wg-quick turns 0.0.0.0/0 into two /1 routes, so longest-prefix match cannot decide against another /1.
        let a = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "192.168.9.2/32", allowedIPs: "0.0.0.0/1")
        XCTAssertTrue(try kinds(a, b).contains(.overlappingRoutes))
    }

    func testDefaultRouteConflictsWithAnotherTunnelsAddressAlone() throws {
        let v4 = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "fd02::/64", endpoint: "[2001:db8::2]:51820")
        XCTAssertEqual(try kinds(v4, b), [.overlappingRoutes])

        let v6 = confText(address: "fd01::2/128", allowedIPs: "::/0", endpoint: "[2001:db8::1]:51820")
        let c = confText(address: "fd02::2/128", allowedIPs: "10.2.0.0/24", endpoint: "198.51.100.1:51820")
        XCTAssertEqual(try kinds(v6, c), [.overlappingRoutes])
    }

    func testDefaultRouteCapturesAnotherTunnelsEndpoint() throws {
        let v4 = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")
        let v6Only = confText(address: "fd02::2/128", allowedIPs: "fd02::/64", endpoint: "198.51.100.9:51820")
        XCTAssertEqual(try kinds(v4, v6Only), [.endpointCaptured])
    }

    func testHostnameEndpointBesideADefaultRouteFailsClosedAcrossFamiliesInBothOrders() throws {
        // The name may resolve into the other tunnel's default route, whatever family that tunnel's own routes use.
        let v4Default = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")
        let v6Only = confText(address: "fd02::2/128", allowedIPs: "fd02::/64", endpoint: "vpn.example.com:51820")
        XCTAssertEqual(try kinds(v4Default, v6Only), [.endpointCaptured])
        XCTAssertEqual(try kinds(v6Only, v4Default), [.endpointCaptured])

        let v6Default = confText(address: "fd01::2/128", allowedIPs: "::/0", endpoint: "[2001:db8::1]:51820")
        let v4Only = confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24", endpoint: "vpn.example.com:51820")
        XCTAssertEqual(try kinds(v6Default, v4Only), [.endpointCaptured])
        XCTAssertEqual(try kinds(v4Only, v6Default), [.endpointCaptured])

        let conflict = findRouteConflicts([try named("Full", v4Default), try named("Lab", v6Only)])[0]
        XCTAssertTrue(conflict.message.contains("vpn.example.com"))
        XCTAssertTrue(conflict.message.contains("Full"))
    }

    func testHostnameEndpointsOfADefaultRouteOwnerAreAlsoChecked() throws {
        let v4Default = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0", endpoint: "vpn.example.com:51820")
        let v6Default = confText(address: "fd02::2/128", allowedIPs: "::/0", endpoint: "[2001:db8::2]:51820")
        XCTAssertEqual(try kinds(v4Default, v6Default), [.endpointCaptured])
    }

    func testHostnameEndpointWithoutADefaultRouteAroundStaysAllowed() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "10.1.0.0/24", endpoint: "a.example.com:51820")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24", endpoint: "b.example.com:51820")
        XCTAssertEqual(try kinds(a, b), [])
    }

    func testHostnameEndpointIsNotCapturedByATableOffDefaultRoute() throws {
        let off = confText(address: "fd01::2/128", extraInterface: "Table = off", allowedIPs: "0.0.0.0/0", endpoint: "[2001:db8::1]:51820")
        let name = confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24", endpoint: "vpn.example.com:51820")
        XCTAssertEqual(try kinds(off, name), [])
    }

    func testDisabledSiblingIsIgnoredAndConflictingImportIsSavedDisabled() throws {
        var state = AppState()
        let profile = state.addProfile(name: "p")
        let full = try state.importTunnel(text: confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0"), name: "full", into: profile).tunnelID
        let outcome = try state.importTunnel(text: confText(address: "192.168.9.2/32", allowedIPs: "10.2.0.0/24"), name: "lab", into: profile)
        XCTAssertFalse(state.tunnel(outcome.tunnelID)!.enabled)
        XCTAssertTrue(outcome.conflicts.map(\.kind).contains(.overlappingRoutes))

        XCTAssertThrowsError(try state.setTunnelEnabled(outcome.tunnelID, true))
        try state.setTunnelEnabled(full, false)
        try state.setTunnelEnabled(outcome.tunnelID, true)
        XCTAssertThrowsError(try state.setTunnelEnabled(full, true))
    }

    func testSplitDefaultOverlapsSpecificRoute() throws {
        let a = confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/1, 128.0.0.0/1")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24")
        XCTAssertTrue(try kinds(a, b).contains(.overlappingRoutes))
    }

    func testTableOffInstallsNoRoutesSoAllowedIPsDoNotConflict() throws {
        let a = confText(address: "10.1.0.2/32", extraInterface: "Table = off", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "10.2.0.0/24")
        XCTAssertEqual(try kinds(a, b), [])
    }

    func testTableOffStillHasAnAddressThatADefaultRouteCovers() throws {
        let a = confText(address: "10.1.0.2/32", extraInterface: "Table = off", allowedIPs: "0.0.0.0/0")
        let b = confText(address: "10.2.0.2/32", allowedIPs: "0.0.0.0/0")
        XCTAssertTrue(try kinds(a, b).contains(.overlappingRoutes))
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

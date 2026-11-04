import XCTest
@testable import WireNestCore

final class HelperLifecycleTests: XCTestCase {
    private var paths: HelperPaths!
    private var commands: FakeCommands!
    private var engine: HelperEngine!

    override func setUpWithError() throws {
        let root = try tempDirectory()
        paths = HelperPaths(
            runtimeDir: root.appendingPathComponent("run"),
            wireguardRunDir: root.appendingPathComponent("wg"),
            toolsDir: root.appendingPathComponent("tools"),
            durableDir: root.appendingPathComponent("durable")
        )
        commands = FakeCommands(paths: paths)
        engine = try HelperEngine(paths: paths, runner: commands)
    }

    private func conf(_ n: Int, peerKey: String = testKey(2)) -> String {
        confText(address: "10.\(n).0.2/32", peerKey: peerKey, allowedIPs: "10.\(n).0.0/24")
    }

    private func ok(_ request: HelperRequest, file: StaticString = #filePath, line: UInt = #line) {
        XCTAssertNil(engine.handle(request).error, file: file, line: line)
    }

    private var tunnels: [HelperTunnelStatus] { engine.handle(.status).status?.tunnels ?? [] }

    private func confExists(_ name: String) -> Bool {
        FileManager.default.fileExists(atPath: paths.runtimeDir.appendingPathComponent("\(name).conf").path)
    }

    private func restartedEngine() throws -> HelperEngine {
        let restarted = try HelperEngine(paths: paths, runner: commands)
        restarted.recoverOnStart()
        return restarted
    }

    // MARK: teardown barrier

    func testDownWaitsForTheRealCleanupBeforeReleasingTheSlot() {
        let id = UUID()
        ok(.up(tunnelID: id, config: conf(1)))
        commands.monitorExitPauses = 3
        ok(.down(tunnelID: id))
        XCTAssertGreaterThanOrEqual(commands.pauses, 3, "the blocking wait is what makes this a barrier")
        XCTAssertTrue(commands.slots.isEmpty)
        XCTAssertTrue(commands.terminatedGroups.isEmpty, "a normal exit needs no signal")
        XCTAssertFalse(confExists("wn0"))
    }

    func testReusedNameAndUtunStartOnlyAfterTheOldMonitorIsGone() {
        let id = UUID()
        ok(.up(tunnelID: id, config: conf(1)))
        commands.monitorExitPauses = 2
        ok(.down(tunnelID: id))

        commands.nextUtun = 7
        var leftoversAtSpawn: Int?
        commands.onQuick = { [unowned commands = commands!] _ in leftoversAtSpawn = commands.slots.count }
        ok(.up(tunnelID: UUID(), config: conf(2)))
        XCTAssertEqual(leftoversAtSpawn, 0)
        XCTAssertEqual(tunnels.first?.interface, "utun7")
        XCTAssertEqual(URL(fileURLWithPath: commands.quickCalls.last![2]).lastPathComponent, "wn0.conf")
    }

    func testDownThatSucceedsWhileTheDeviceLivesKeepsOwnershipAndBlocksNewStarts() {
        let a = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        commands.downLeavesDeviceAlive = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: a)).error)
        XCTAssertTrue(confExists("wn0"), "the config is needed to finish the teardown")
        XCTAssertEqual(tunnels.map(\.tunnelID), [a])

        let upsBefore = commands.quickCalls.filter { $0[1] == "up" }.count
        XCTAssertNotNil(engine.handle(.up(tunnelID: UUID(), config: conf(2))).error)
        XCTAssertEqual(commands.quickCalls.filter { $0[1] == "up" }.count, upsBefore, "no replacement while a teardown is unfinished")

        commands.slots.removeAll()
        commands.downLeavesDeviceAlive = false
        let b = UUID()
        ok(.up(tunnelID: b, config: conf(2)))
        XCTAssertEqual(tunnels.map(\.tunnelID), [b])
    }

    func testMonitorThatOutlivesItsDeviceIsSignalledOnlyInItsOwnGroup() {
        let a = UUID(), b = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        ok(.up(tunnelID: b, config: conf(2)))
        let groupOfA = commands.slots["wn0"]!.pgid
        let groupOfB = commands.slots["wn1"]!.pgid

        commands.monitorExitPauses = 100_000
        ok(.down(tunnelID: a))
        XCTAssertEqual(commands.terminatedGroups, [groupOfA])
        XCTAssertFalse(commands.terminatedGroups.contains(groupOfB))
    }

    func testMonitorThatRefusesToExitBlocksNewStartsAndIsRetried() {
        let a = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        commands.monitorExitPauses = 100_000
        commands.monitorIgnoresTerm = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: a)).error)
        XCTAssertNotNil(engine.handle(.up(tunnelID: UUID(), config: conf(2))).error)

        commands.slots.removeAll()
        ok(.down(tunnelID: a))
        XCTAssertTrue(tunnels.isEmpty)
        XCTAssertFalse(confExists("wn0"))
    }

    func testInterfaceThatStillExistsIsNeverCleanupEvenWhenWgCannotReachIt() {
        let a = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        commands.downLeavesInterfaceOnly = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: a)).error)
        XCTAssertTrue(confExists("wn0"))
        XCTAssertEqual(tunnels.map(\.tunnelID), [a], "still journaled")

        let upsBefore = commands.quickCalls.filter { $0[1] == "up" }.count
        XCTAssertNotNil(engine.handle(.up(tunnelID: UUID(), config: conf(2))).error)
        XCTAssertEqual(commands.quickCalls.filter { $0[1] == "up" }.count, upsBefore, "no slot reuse, however long it has been")
    }

    func testFailingIfconfigIsNotEvidenceThatTheInterfaceIsGone() {
        let a = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        commands.downLeavesInterfaceOnly = true
        commands.ifconfigBroken = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: a)).error)
        XCTAssertTrue(confExists("wn0"))
    }

    func testInterfaceGoneAndMonitorFinishedIsNormalCleanupAfterAnEarlierFailure() {
        let a = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        commands.downLeavesInterfaceOnly = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: a)).error)

        commands.slots.removeAll()
        ok(.down(tunnelID: a))
        XCTAssertTrue(tunnels.isEmpty)
        XCTAssertFalse(confExists("wn0"))
    }

    func testASocketItCannotProveItOwnsIsNeverDeleted() throws {
        let a = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        let real = try XCTUnwrap(commands.slots["wn0"]?.real)
        commands.downLeavesInterfaceOnly = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: a)).error)

        // By now the number may belong to another app: wg-quick's own socket is already gone, so this one is theirs.
        let foreign = paths.wireguardRunDir.appendingPathComponent("\(real).sock")
        try Data("other app".utf8).write(to: foreign)
        XCTAssertNotNil(engine.handle(.down(tunnelID: a)).error)
        XCTAssertTrue(FileManager.default.fileExists(atPath: foreign.path), "not removed while failing")

        commands.slots.removeAll()
        ok(.down(tunnelID: a))
        XCTAssertTrue(FileManager.default.fileExists(atPath: foreign.path), "not removed on success either")
    }

    func testRestartingOneTunnelNeverTouchesItsHealthySibling() {
        let a = UUID(), b = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        ok(.up(tunnelID: b, config: conf(2)))
        let before = commands.quickCalls.count
        let slotOfB = commands.slots["wn1"]!

        commands.monitorExitPauses = 2
        ok(.down(tunnelID: a))
        ok(.up(tunnelID: a, config: conf(1)))

        XCTAssertFalse(commands.quickCalls[before...].contains { $0[2].hasSuffix("wn1.conf") })
        XCTAssertEqual(commands.slots["wn1"]!.real, slotOfB.real)
        XCTAssertTrue(tunnels.first { $0.tunnelID == b }!.alive)
    }

    func testRootBoundaryRefusesAHostnameEndpointBesideADefaultRoute() {
        ok(.up(tunnelID: UUID(), config: confText(address: "10.1.0.2/32", allowedIPs: "0.0.0.0/0")))
        let upsBefore = commands.quickCalls.count
        let hostname = confText(address: "fd02::2/128", allowedIPs: "fd02::/64", endpoint: "vpn.example.com:51820")
        XCTAssertNotNil(engine.handle(.up(tunnelID: UUID(), config: hostname)).error)
        XCTAssertEqual(commands.quickCalls.count, upsBefore)
    }

    // MARK: start verification

    func testReadyMarkerAloneIsNotAStart() {
        commands.upMarkerOnly = true
        XCTAssertNotNil(engine.handle(.up(tunnelID: UUID(), config: conf(1))).error)
        XCTAssertTrue(tunnels.isEmpty)
        XCTAssertFalse(confExists("wn0"))
    }

    func testStartWithoutARunningMonitorIsRolledBack() {
        commands.upWithoutMonitor = true
        XCTAssertNotNil(engine.handle(.up(tunnelID: UUID(), config: conf(1))).error)
        XCTAssertTrue(tunnels.isEmpty)
        XCTAssertTrue(commands.quickCalls.contains { $0[1] == "down" }, "the device it did create is removed")
        XCTAssertTrue(commands.slots.isEmpty)
    }

    func testStartWhoseDeviceHasTheWrongPeersIsRolledBack() {
        XCTAssertNotNil(engine.handle(.up(tunnelID: UUID(), config: conf(1, peerKey: testKey(3)))).error)
        XCTAssertTrue(tunnels.isEmpty)
        XCTAssertTrue(commands.slots.isEmpty)
    }

    // MARK: durable ownership

    func testUnwritableJournalPreventsTheStart() throws {
        try XCTSkipIf(geteuid() == 0, "root ignores directory permissions")
        try FileManager.default.setAttributes([.posixPermissions: 0o500], ofItemAtPath: paths.runtimeDir.path)
        defer { try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: paths.runtimeDir.path) }
        XCTAssertNotNil(engine.handle(.up(tunnelID: UUID(), config: conf(1))).error)
        XCTAssertTrue(commands.quickCalls.isEmpty)
        XCTAssertTrue(tunnels.isEmpty)
    }

    func testIntentIsDurableBeforeTheSpawnAndConfigExists() {
        let id = UUID()
        var journalAtSpawn = ""
        commands.onQuick = { [paths = paths!] _ in
            journalAtSpawn = (try? String(contentsOf: paths.runtimeDir.appendingPathComponent("session.json"), encoding: .utf8)) ?? ""
        }
        ok(.up(tunnelID: id, config: conf(1)))
        XCTAssertTrue(journalAtSpawn.contains("starting"))
        XCTAssertTrue(journalAtSpawn.contains(id.uuidString))
    }

    func testCrashAfterSpawnIsCleanedUpOnRecovery() throws {
        let journal = paths.runtimeDir.appendingPathComponent("session.json")
        var atSpawn: Data?
        commands.onQuick = { _ in atSpawn = try? Data(contentsOf: journal) }
        ok(.up(tunnelID: UUID(), config: conf(1)))
        commands.onQuick = nil
        try XCTUnwrap(atSpawn).write(to: journal)

        let recovered = try restartedEngine()
        XCTAssertTrue(commands.quickCalls.contains { $0[1] == "down" })
        XCTAssertTrue(commands.slots.isEmpty)
        XCTAssertEqual(recovered.handle(.status).status?.tunnels.count, 0)
        XCTAssertFalse(confExists("wn0"))
    }

    func testCrashDuringTeardownFinishesOnRecovery() throws {
        let id = UUID()
        ok(.up(tunnelID: id, config: conf(1)))
        let journal = paths.runtimeDir.appendingPathComponent("session.json")
        let config = paths.runtimeDir.appendingPathComponent("wn0.conf")
        var atSpawn: Data?, configAtSpawn: Data?
        commands.onQuick = { _ in
            atSpawn = try? Data(contentsOf: journal)
            configAtSpawn = try? Data(contentsOf: config)
        }
        commands.monitorExitPauses = 2
        ok(.down(tunnelID: id))
        commands.onQuick = nil
        XCTAssertTrue(String(decoding: try XCTUnwrap(atSpawn), as: UTF8.self).contains("retiring"))
        try XCTUnwrap(atSpawn).write(to: journal)
        try XCTUnwrap(configAtSpawn).write(to: config)

        let recovered = try restartedEngine()
        XCTAssertEqual(recovered.handle(.status).status?.tunnels.count, 0)
        XCTAssertFalse(confExists("wn0"))
    }

    func testFailedRollbackKeepsTheJournalAndConfigForRetry() throws {
        commands.failDown = true
        let id = UUID()
        XCTAssertNotNil(engine.handle(.up(tunnelID: id, config: conf(1, peerKey: testKey(3)))).error)
        XCTAssertTrue(confExists("wn0"))
        XCTAssertEqual(tunnels.map(\.tunnelID), [id])

        let recovered = try restartedEngine()
        XCTAssertEqual(recovered.handle(.status).status?.tunnels.map(\.tunnelID), [id])

        commands.failDown = false
        XCTAssertNil(recovered.handle(.downAll).error)
        XCTAssertEqual(recovered.handle(.status).status?.tunnels.count, 0)
        XCTAssertTrue(commands.slots.isEmpty)
        XCTAssertFalse(confExists("wn0"))
    }

    func testRecoveryKeepsLiveTunnelsAndCleansDeadOnes() throws {
        let live = UUID(), dead = UUID()
        ok(.up(tunnelID: live, config: conf(1)))
        ok(.up(tunnelID: dead, config: conf(2)))
        commands.slots["wn1"] = nil

        let recovered = try restartedEngine()
        XCTAssertEqual(recovered.handle(.status).status?.tunnels.map(\.tunnelID), [live])
        XCTAssertFalse(confExists("wn1"))
        XCTAssertFalse(FileManager.default.fileExists(atPath: paths.wireguardRunDir.appendingPathComponent("wn1.name").path))
    }

    func testRecoveryFindsOwnArtifactsWithoutAJournalAndLeavesOthersAlone() throws {
        ok(.up(tunnelID: UUID(), config: conf(1)))
        try Data("{broken".utf8).write(to: paths.runtimeDir.appendingPathComponent("session.json"))
        let foreign = paths.runtimeDir.appendingPathComponent("other-app.conf")
        try Data("keep".utf8).write(to: foreign)

        let recovered = try restartedEngine()
        XCTAssertEqual(recovered.handle(.status).status?.tunnels.count, 0)
        XCTAssertTrue(commands.slots.isEmpty)
        XCTAssertFalse(confExists("wn0"))
        XCTAssertTrue(FileManager.default.fileExists(atPath: foreign.path))
    }

    func testDownAllRemovesEveryOwnedDevice() {
        ok(.up(tunnelID: UUID(), config: conf(1)))
        ok(.up(tunnelID: UUID(), config: conf(2)))
        commands.monitorExitPauses = 1
        ok(.downAll)
        XCTAssertTrue(commands.slots.isEmpty)
        XCTAssertTrue(tunnels.isEmpty)
    }

    // MARK: DNS restoration

    private var status: HelperStatus? { engine.handle(.status).status }

    func testFailedRestoreIsRetriedByAnOrdinaryRequestWithoutAHelperRestart() {
        let id = UUID()
        ok(.up(tunnelID: id, config: conf(1)))
        ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        commands.failSetDNS = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: id)).error)
        XCTAssertEqual(status?.dnsManaged, true)
        XCTAssertNotNil(engine.handle(.setDNS(primary: "", secondary: "")).error, "still failing is reported")

        commands.failSetDNS = false
        ok(.setDNS(primary: "", secondary: ""))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
        XCTAssertEqual(status?.dnsManaged, false)
    }

    func testServiceDisabledBeforeDisconnectKeepsItsOriginalUntilReenabled() {
        let id = UUID()
        ok(.up(tunnelID: id, config: conf(1)))
        ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        commands.disabledServices = ["Wi-Fi"]
        ok(.down(tunnelID: id))
        XCTAssertEqual(commands.dns["Ethernet"], [], "the available service is restored now")
        XCTAssertEqual(status?.dnsManaged, true)
        XCTAssertEqual(status?.dnsPendingServices, ["Wi-Fi"])
        XCTAssertFalse(commands.calls.contains { $0.args.first == "-setdnsservers" && $0.args[1] == "Wi-Fi" && $0.args[2] != "9.9.9.9" })

        commands.disabledServices = []
        ok(.setDNS(primary: "", secondary: ""))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
        XCTAssertEqual(status?.dnsManaged, false)
        XCTAssertEqual(status?.dnsPendingServices, [])
    }

    func testPendingOriginalIsNeverReplacedByTheManagedValue() {
        let a = UUID()
        ok(.up(tunnelID: a, config: conf(1)))
        ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        commands.disabledServices = ["Wi-Fi"]
        ok(.down(tunnelID: a))

        commands.disabledServices = []
        let b = UUID()
        ok(.up(tunnelID: b, config: conf(2)))
        ok(.setDNS(primary: "8.8.8.8", secondary: ""))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["8.8.8.8"])
        ok(.down(tunnelID: b))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }

    func testDeletedServiceDoesNotLeaveRestorePendingForever() {
        let id = UUID()
        ok(.up(tunnelID: id, config: conf(1)))
        ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        commands.dns["Wi-Fi"] = nil
        ok(.down(tunnelID: id))
        XCTAssertEqual(status?.dnsManaged, false)
    }

    func testCorruptJournalIsReportedAndKept() throws {
        let journal = paths.durableDir.appendingPathComponent("dns-snapshot.json")
        try Data("{broken".utf8).write(to: journal)
        XCTAssertEqual(status?.dnsManaged, true, "unreadable is not the same as nothing to restore")
        XCTAssertNotNil(engine.handle(.setDNS(primary: "", secondary: "")).error)

        ok(.up(tunnelID: UUID(), config: conf(1)))
        XCTAssertNotNil(engine.handle(.setDNS(primary: "9.9.9.9", secondary: "")).error)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"], "no new baseline over a lost journal")
        XCTAssertEqual(try Data(contentsOf: journal), Data("{broken".utf8))
    }

    func testFailedTeardownOfLastTunnelKeepsDNSManaged() {
        let id = UUID()
        ok(.up(tunnelID: id, config: conf(1)))
        ok(.setDNS(primary: "9.9.9.9", secondary: ""))
        commands.downLeavesDeviceAlive = true
        XCTAssertNotNil(engine.handle(.down(tunnelID: id)).error)
        XCTAssertEqual(commands.dns["Wi-Fi"], ["9.9.9.9"], "a live tunnel still depends on it")

        commands.slots.removeAll()
        ok(.down(tunnelID: id))
        XCTAssertEqual(commands.dns["Wi-Fi"], ["192.168.1.1"])
    }
}

final class InstallStagingTests: XCTestCase {
    private var root: URL!
    private var app: URL!
    private var stagingRoot: URL!

    private func tool(_ base: URL, _ name: String) -> URL {
        base.appendingPathComponent("Contents/Resources/Tools/\(name)")
    }

    override func setUpWithError() throws {
        root = try tempDirectory()
        app = root.appendingPathComponent("WireNest.app")
        stagingRoot = root.appendingPathComponent("staging")
        let fm = FileManager.default
        try fm.createDirectory(at: app.appendingPathComponent("Contents/Resources/Tools"), withIntermediateDirectories: true)
        try fm.createDirectory(at: app.appendingPathComponent("Contents/Library/LaunchServices"), withIntermediateDirectories: true)
        try Data("helper".utf8).write(to: app.appendingPathComponent("Contents/Library/LaunchServices/WireNestHelper"))
        for name in HelperConstants.toolNames {
            try Data("verified \(name)".utf8).write(to: tool(app, name))
        }
    }

    private func stage(verify: (URL) throws -> HelperClientPin = { _ in HelperClientPin(ownerUID: 501, appCDHash: "ab") }) throws -> URL {
        try stageVerifiedInstall(
            appBundle: app, stagingRoot: stagingRoot,
            secure: { path, mode in
                guard chmod(path, mode) == 0 else { throw SecureFileError("chmod failed") }
            },
            verify: verify
        )
    }

    func testToolSubstitutedAfterTheSnapshotCannotBeInstalled() throws {
        let payload = try stage { [app = app!] stagedApp in
            // The attacker wins the race right after the copy, before and during verification.
            try Data("evil".utf8).write(to: self.tool(app, "wg"))
            XCTAssertNotEqual(stagedApp.path, app.path, "verification must look at the snapshot")
            return HelperClientPin(ownerUID: 501, appCDHash: "ab")
        }
        XCTAssertEqual(try Data(contentsOf: payload.appendingPathComponent("Tools/wg")), Data("verified wg".utf8))
    }

    func testPinComesFromTheVerifiedSnapshot() throws {
        let payload = try stage { _ in HelperClientPin(ownerUID: 501, appCDHash: "cafe") }
        let pin = try JSONDecoder().decode(HelperClientPin.self, from: Data(contentsOf: payload.appendingPathComponent("client.json")))
        XCTAssertEqual(pin.appCDHash, "cafe")
    }

    func testVerificationSeesThePrivateSnapshotBeforeAnyPayloadExists() throws {
        _ = try stage { [stagingRoot = stagingRoot!] stagedApp in
            XCTAssertTrue(stagedApp.path.hasPrefix(stagingRoot.path))
            let mode = (try FileManager.default.attributesOfItem(atPath: stagingRoot.path)[.posixPermissions] as! NSNumber).intValue
            XCTAssertEqual(mode, 0o700)
            XCTAssertFalse(FileManager.default.fileExists(atPath: stagingRoot.appendingPathComponent("payload").path))
            return HelperClientPin(ownerUID: 501, appCDHash: "ab")
        }
    }

    func testRejectedSnapshotProducesNoPayload() {
        XCTAssertThrowsError(try stage { _ in throw SecureFileError("bad signature") })
        XCTAssertFalse(FileManager.default.fileExists(atPath: stagingRoot.appendingPathComponent("payload").path))
    }

    func testSymlinkInsideTheBundleIsRejected() throws {
        try FileManager.default.removeItem(at: tool(app, "wg"))
        try FileManager.default.createSymbolicLink(atPath: tool(app, "wg").path, withDestinationPath: "/bin/sh")
        XCTAssertThrowsError(try stage())
    }

    func testMissingToolIsRejected() throws {
        try FileManager.default.removeItem(at: tool(app, "bash"))
        XCTAssertThrowsError(try stage())
    }

    /// A real ACL through the system tool: unlike mode bits, it survives chown and chmod and keeps granting access.
    private func grantACL(_ permission: String, on url: URL) throws {
        let chmod = Process()
        chmod.executableURL = URL(fileURLWithPath: "/bin/chmod")
        chmod.arguments = ["+a", "\(NSUserName()) allow \(permission)", url.path]
        try chmod.run()
        chmod.waitUntilExit()
        XCTAssertEqual(chmod.terminationStatus, 0)
        XCTAssertTrue(try SecureFile.hasExtendedACL(url.path), "the fixture must really have an ACL")
    }

    private func itemsInside(_ directory: URL) throws -> [String] {
        try [directory.path] + FileManager.default.subpathsOfDirectory(atPath: directory.path).map { directory.appendingPathComponent($0).path }
    }

    func testRemovingAnACLReallyRemovesIt() throws {
        let file = tool(app, "wg")
        try grantACL("write", on: file)
        try SecureFile.removeExtendedACL(file.path)
        XCTAssertFalse(try SecureFile.hasExtendedACL(file.path))
    }

    func testSourceACLsReachNeitherTheVerifiedSnapshotNorTheInstalledPayload() throws {
        let sourceTool = tool(app, "wg")
        let sourceTools = sourceTool.deletingLastPathComponent()
        try grantACL("write", on: sourceTool)
        try grantACL("add_file", on: sourceTools)

        let payload = try stage { stagedApp in
            for path in try self.itemsInside(stagedApp) {
                XCTAssertFalse(try SecureFile.hasExtendedACL(path), path)
            }
            return HelperClientPin(ownerUID: 501, appCDHash: "ab")
        }

        for path in try itemsInside(payload) {
            XCTAssertFalse(try SecureFile.hasExtendedACL(path), path)
        }
        XCTAssertEqual(try Data(contentsOf: payload.appendingPathComponent("Tools/wg")), Data("verified wg".utf8))
        XCTAssertTrue(try SecureFile.hasExtendedACL(sourceTool.path), "only the copy is ours to change")
        XCTAssertTrue(try SecureFile.hasExtendedACL(sourceTools.path), "only the copy is ours to change")
    }

    func testEveryPublishedItemIsSecuredWithItsFinalMode() throws {
        var secured: [String: mode_t] = [:]
        let payload = try stageVerifiedInstall(
            appBundle: app, stagingRoot: stagingRoot,
            secure: { path, mode in
                secured[path] = mode
                guard chmod(path, mode) == 0 else { throw SecureFileError("chmod failed") }
            },
            verify: { _ in HelperClientPin(ownerUID: 501, appCDHash: "ab") }
        )
        for path in try itemsInside(payload) {
            let expected: mode_t = path.hasSuffix("client.json") ? 0o644 : 0o755
            XCTAssertEqual(secured[path], expected, path)
        }
    }

    func testFailureToSecureAnItemStopsTheInstall() {
        XCTAssertThrowsError(try stageVerifiedInstall(
            appBundle: app, stagingRoot: stagingRoot,
            secure: { path, _ in
                if path.hasSuffix("payload/Tools/wg") { throw SecureFileError("cannot secure") }
            },
            verify: { _ in HelperClientPin(ownerUID: 501, appCDHash: "ab") }
        ))
    }

    func testWritableBitsAreStrippedFromTheSnapshotAndPayloadIsExecutable() throws {
        let payload = try stage()
        let mode = (try FileManager.default.attributesOfItem(atPath: payload.appendingPathComponent("Tools/wg").path)[.posixPermissions] as! NSNumber).intValue
        XCTAssertEqual(mode, 0o755)
    }
}

final class HelperSmokeManifestTests: XCTestCase {
    private var dir: URL!

    override func setUpWithError() throws {
        dir = try tempDirectory()
    }

    private func smokeConf(_ n: Int, allowed: String? = nil, address: String? = nil, extra: String = "", dns: String? = nil, endpoint: String = "127.0.0.1:51000") -> String {
        confText(
            address: address ?? "198.18.\(70 + n).1/32", dns: dns, extraInterface: extra,
            allowedIPs: allowed ?? "198.18.\(70 + n).2/32", endpoint: endpoint
        )
    }

    private func write(_ text: String, _ name: String, mode: Int = 0o600) throws -> String {
        let url = dir.appendingPathComponent(name)
        try Data(text.utf8).write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: mode], ofItemAtPath: url.path)
        return url.path
    }

    private func manifest(a: String? = nil, b: String? = nil, pathA: String? = nil, restartCount: Int = 3, probeHostA: String = "198.18.71.2", sameID: Bool = false) throws -> String {
        let idA = UUID().uuidString
        let tunnels: [[String: Any]] = [
            ["id": idA, "configPath": try pathA ?? write(a ?? smokeConf(1), "a.conf"), "probeHost": probeHostA, "probePort": 18081, "expectedToken": "token-a"],
            ["id": sameID ? idA : UUID().uuidString, "configPath": try write(b ?? smokeConf(2), "b.conf"), "probeHost": "198.18.72.2", "probePort": 18082, "expectedToken": "token-b"],
        ]
        let data = try JSONSerialization.data(withJSONObject: ["tunnels": tunnels, "restartCount": restartCount])
        let url = dir.appendingPathComponent("manifest.json")
        try data.write(to: url)
        return url.path
    }

    private func assertRejected(_ path: @autoclosure () throws -> String, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try HelperSmokeManifest.load(path: path()), file: file, line: line)
    }

    func testAcceptsTheFrozenShape() throws {
        let loaded = try HelperSmokeManifest.load(path: manifest())
        XCTAssertEqual(loaded.restartCount, 3)
        XCTAssertEqual(loaded.tunnels.map(\.expectedToken), ["token-a", "token-b"])
        XCTAssertEqual(loaded.tunnels[0].config.peers[0].endpoint?.host, "127.0.0.1")
    }

    func testRejectsBadCounts() throws {
        try assertRejected(manifest(restartCount: 0))
        try assertRejected(manifest(restartCount: 6))
        try assertRejected(manifest(sameID: true))
        let single = dir.appendingPathComponent("one.json")
        try Data("{\"tunnels\":[],\"restartCount\":1}".utf8).write(to: single)
        XCTAssertThrowsError(try HelperSmokeManifest.load(path: single.path))
    }

    func testRejectsRelativeOrUnprotectedPaths() throws {
        XCTAssertThrowsError(try HelperSmokeManifest.load(path: "manifest.json"))
        try assertRejected(manifest(pathA: "a.conf"))
        try assertRejected(manifest(pathA: write(smokeConf(1), "open.conf", mode: 0o644)))
        let link = dir.appendingPathComponent("link.conf")
        try FileManager.default.createSymbolicLink(atPath: link.path, withDestinationPath: try write(smokeConf(1), "real.conf"))
        try assertRejected(manifest(pathA: link.path))
    }

    func testRejectsAnythingThatCouldTouchRealNetworking() throws {
        try assertRejected(manifest(a: smokeConf(1, dns: "198.18.71.53")), "DNS")
        try assertRejected(manifest(a: smokeConf(1, allowed: "0.0.0.0/0")), "default route")
        try assertRejected(manifest(a: smokeConf(1, allowed: "10.0.0.0/24")), "route outside the reserved range")
        try assertRejected(manifest(a: smokeConf(1, allowed: "198.18.0.0/14")), "wider than the reserved range")
        try assertRejected(manifest(a: smokeConf(1, address: "10.0.0.2/32")), "address outside the reserved range")
        try assertRejected(manifest(a: smokeConf(1, endpoint: "198.51.100.1:51000")), "non-loopback endpoint")
        try assertRejected(manifest(a: smokeConf(1, extra: "PostUp = id")), "hook")
    }

    private func assertRejected(_ path: @autoclosure () throws -> String, _ reason: String, file: StaticString = #filePath, line: UInt = #line) throws {
        XCTAssertThrowsError(try HelperSmokeManifest.load(path: path()), reason, file: file, line: line)
    }

    func testRejectsProbeOutsideItsTunnel() throws {
        try assertRejected(manifest(probeHostA: "198.18.72.2"))
        try assertRejected(manifest(probeHostA: "8.8.8.8"))
    }

    func testRejectsConflictingTunnels() throws {
        let overlapping = smokeConf(2, allowed: "198.18.71.2/32, 198.18.72.2/32")
        XCTAssertThrowsError(try HelperSmokeManifest.load(path: manifest(b: overlapping))) { error in
            XCTAssertTrue(error is RouteConflictError, "\(error)")
        }
    }

    func testProbeResponseMustBeExactlyTheToken() {
        XCTAssertTrue(smokeResponseMatches("HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\ntoken-a", token: "token-a"))
        XCTAssertFalse(smokeResponseMatches("HTTP/1.1 200 OK\r\n\r\ntoken-b", token: "token-a"))
        XCTAssertFalse(smokeResponseMatches("HTTP/1.1 200 OK\r\n\r\ntoken-a extra", token: "token-a"))
        XCTAssertFalse(smokeResponseMatches("HTTP/1.1 500 Oops\r\n\r\ntoken-a", token: "token-a"))
        XCTAssertFalse(smokeResponseMatches("token-a", token: "token-a"))
    }
}

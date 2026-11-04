import AppKit
import Combine
import CoreLocation
import Network
import ServiceManagement
import UniformTypeIdentifiers
import WireNestCore

enum HelperState: Equatable {
    case checking
    case ready
    case needsInstall(String)
}

/// The single owner of app state: everything the UI does goes through here to the store and the real helper.
@MainActor
final class AppController: ObservableObject {
    private static let tickInterval: UInt64 = 5_000_000_000
    private static let dnsRefreshTicks = 12

    @Published private(set) var state = AppState()
    @Published private(set) var views: [UUID: TunnelView] = [:] {
        didSet { logTunnelErrors() }
    }
    @Published private(set) var helperState = HelperState.checking {
        didSet {
            if case .needsInstall(let reason) = helperState {
                report(reason, source: "helper", context: "Helper")
            } else {
                report(nil, source: "helper", context: "Helper")
            }
        }
    }
    @Published private(set) var ssid = SSIDObservation.unavailable("Checking")
    @Published private(set) var publicIP: String?
    @Published private(set) var loginStatus = SMAppService.mainApp.status
    /// The latest refused or failed user action.
    @Published var notice: String? {
        didSet { report(notice, source: "notice", context: "WireNest") }
    }
    /// Why the active connection cannot run as saved, e.g. a conflict.
    @Published private(set) var connectionError: String? {
        didSet { report(connectionError, source: "connection", context: "Connection") }
    }
    @Published private(set) var dnsError: String? {
        didSet { report(dnsError, source: "dns", context: "DNS") }
    }
    /// Why a matching rule cannot use its connection right now.
    @Published private(set) var ruleProblem: String? {
        didSet { report(ruleProblem, source: "rule", context: "Automation") }
    }
    /// Why the helper stopped a default-route tunnel: another tunnel's endpoint lost its protecting route.
    @Published private(set) var routeFailure: String? {
        didSet { report(routeFailure, source: "route", context: "Route safety") }
    }
    @Published private(set) var isBusy = false
    /// This session's failures. Fed only by the properties above, so it shows what really happened.
    @Published private(set) var log = ActivityLog()
    @Published var preferencesPane = PreferencesPane.connections

    var showPreferences: () -> Void = {}

    private var tunnelsWithLoggedErrors: Set<UUID> = []

    private var store: StateStore?
    private let helper = HelperClient()
    private let observer = NetworkObserver()
    private var supervisor = TunnelSupervisor()
    private var ruleEngine = RuleEngine()
    private var stabilizer = PublicIPStabilizer()
    private var loop: Task<Void, Never>?
    private var isReconciling = false
    private var needsAnotherPass = false
    private var dnsDirty = true
    private var ticks = 0
    private var nextProbe = Date.distantPast
    private var lastProbe = Date.distantPast
    private var isProbing = false

    func start() {
        loadState()
        observer.onNetworkEvent = { [weak self] in self?.networkEvent() }
        observer.onLocationChange = { [weak self] in self?.objectWillChange.send() }
        observer.start()
        refreshSSID()
        loop = Task { [weak self] in
            while !Task.isCancelled {
                await self?.tick()
                try? await Task.sleep(nanoseconds: Self.tickInterval)
            }
        }
    }

    private func loadState() {
        do {
            let store = try StateStore()
            self.store = store
            do {
                state = try store.load()
            } catch {
                let moved = try store.quarantineCorruptState()
                notice = "Saved settings could not be read and were moved to \(moved.lastPathComponent). Starting empty."
            }
        } catch {
            notice = "WireNest cannot use its private storage: \(error.localizedDescription) Changes will not be saved."
        }
    }

    /// Applies a change only if it fully succeeds, then saves. A thrown error becomes the visible notice.
    @discardableResult
    private func mutate(_ change: (inout AppState) throws -> Void) -> Bool {
        var copy = state
        do {
            try change(&copy)
        } catch {
            notice = error.localizedDescription
            return false
        }
        state = copy
        notice = nil
        persist()
        return true
    }

    private func persist() {
        do {
            try store?.save(state)
        } catch {
            notice = "Could not save settings: \(error.localizedDescription)"
        }
    }

    // MARK: Logs

    private func report(_ message: String?, source: String, context: String) {
        log.report(message, source: source, context: context, now: Date())
    }

    private func logTunnelErrors() {
        let failing = Set(views.filter { $0.value.lastError != nil }.keys)
        for id in tunnelsWithLoggedErrors.union(failing) {
            let name = state.tunnel(id)?.name ?? "removed tunnel"
            report(views[id]?.lastError, source: "tunnel.\(id)", context: "Tunnel \(name)")
        }
        tunnelsWithLoggedErrors = failing
    }

    func clearLogs() {
        log.clear()
    }

    func copyLogs() {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(log.text(), forType: .string)
    }

    func showLogs() {
        preferencesPane = .logs
        showPreferences()
    }

    /// Everything currently wrong, most specific first.
    private var activeProblems: [String] {
        var problems = [connectionError, routeFailure, dnsError, ruleProblem, notice].compactMap { $0 }
        problems += views.values.compactMap(\.lastError)
        if case .needsInstall(let reason) = helperState { problems.append(reason) }
        return problems
    }

    /// A few words for the menu. The whole story is in the Logs pane.
    var problemSummary: String? {
        guard let first = activeProblems.first else { return nil }
        let others = Set(activeProblems).count - 1
        return others > 0 ? "\(shortFailure(first)) (+\(others) more)" : shortFailure(first)
    }

    // MARK: Loop

    private func tick() async {
        ticks += 1
        refreshSSID()
        probePublicIPIfDue()
        applyRules()
        await reconcile()
    }

    private func refreshSSID() {
        let current = observer.currentSSID()
        if current != ssid { ssid = current }
    }

    private func networkEvent() {
        supervisor.noteNetworkEvent(now: Date())
        dnsDirty = true
        nextProbe = max(Date().addingTimeInterval(5), lastProbe.addingTimeInterval(20))
        kick()
    }

    private func kick() {
        Task { await reconcile() }
    }

    private func snapshot() -> NetworkSnapshot {
        NetworkSnapshot(ssid: ssid, publicIP: state.publicIPAutomationEnabled ? publicIP : nil)
    }

    private func applyRules() {
        var updated = state
        let target = ruleEngine.evaluate(state: &updated, snapshot: snapshot(), now: Date())
        ruleProblem = ruleEngine.targetProblem
        if let target {
            // Keeps only a pin the engine just set; otherwise the next network change can move this connection again.
            do {
                try updated.connect(target, pinContext: updated.pinnedContext, ssid: ssid)
            } catch {
                notice = error.localizedDescription
                return
            }
            supervisor.retryAll()
            dnsDirty = true
            notice = nil
        }
        // Committed as one, so a refused switch leaves no pin or other trace in the saved state.
        if updated != state {
            state = updated
            persist()
        }
    }

    private func reconcile() async {
        guard !isReconciling else {
            needsAnotherPass = true
            return
        }
        isReconciling = true
        isBusy = true
        repeat {
            needsAnotherPass = false
            await reconcileOnce()
        } while needsAnotherPass
        isReconciling = false
        isBusy = false
    }

    private func reconcileOnce() async {
        var status: HelperStatus
        do {
            status = try await helper.send(.status)
        } catch {
            helperState = .needsInstall(error.localizedDescription)
            views = [:]
            return
        }
        guard status.protocolVersion == HelperConstants.protocolVersion else {
            helperState = .needsInstall("The installed helper is from another WireNest version.")
            views = [:]
            return
        }
        helperState = .ready
        routeFailure = status.routeFailure

        refreshSSID()
        let desired: [DesiredTunnel]
        do {
            desired = try state.desiredTunnels(ssid: ssid)
            connectionError = nil
        } catch {
            // Fail closed: a connection whose saved tunnels conflict does not run partially.
            desired = []
            connectionError = error.localizedDescription
        }

        let plan = supervisor.plan(desired: desired, status: status.tunnels, now: Date())
        for id in plan.stop {
            do {
                status = try await helper.send(.down(tunnelID: id))
            } catch {
                notice = error.localizedDescription
            }
        }
        for id in plan.start {
            // The awaits above take seconds, and in that time the SSID or the user's choice may have forbidden this tunnel.
            refreshSSID()
            guard let tunnel = (try? state.desiredTunnels(ssid: ssid))?.first(where: { $0.id == id }) else {
                needsAnotherPass = true
                continue
            }
            do {
                status = try await helper.send(.up(tunnelID: id, config: tunnel.configText))
                supervisor.noteStarted(id, now: Date())
                dnsDirty = true
            } catch {
                supervisor.noteStartFailed(id, error: error.localizedDescription, now: Date())
            }
        }
        await applyDNS(status: status, desired: desired)
        views = supervisor.views
    }

    /// Re-applied after changes and periodically: networksetup settings can change, and new services can appear.
    private func applyDNS(status: HelperStatus, desired: [DesiredTunnel]) async {
        if status.tunnels.isEmpty {
            await restoreDNSIfPending(status)
            return
        }
        guard !desired.isEmpty, pauseReason == nil,
              let id = state.activeProfileID, let profile = state.profile(id) else { return }
        guard dnsDirty || ticks % Self.dnsRefreshTicks == 0 else { return }
        guard !profile.primaryDNS.isEmpty || status.dnsManaged else {
            dnsDirty = false
            return
        }
        do {
            _ = try await helper.send(.setDNS(primary: profile.primaryDNS, secondary: profile.secondaryDNS))
            dnsDirty = false
            dnsError = nil
        } catch {
            dnsError = error.localizedDescription
        }
    }

    /// With no tunnels left, nothing else would ever ask the helper to finish restoring DNS. Retried about once a minute, or by Retry Now.
    private func restoreDNSIfPending(_ status: HelperStatus) async {
        guard status.dnsManaged else {
            dnsError = nil
            return
        }
        guard dnsDirty || ticks % Self.dnsRefreshTicks == 0 else { return }
        dnsDirty = false
        do {
            let after = try await helper.send(.setDNS(primary: "", secondary: ""))
            dnsError = after.dnsManaged
                ? "Original DNS will be restored when these network services are enabled: \(after.dnsPendingServices.joined(separator: ", "))."
                : nil
        } catch {
            dnsError = "Could not restore your original DNS, and will keep trying: \(error.localizedDescription)"
        }
    }

    // MARK: Public IP

    private func probePublicIPIfDue() {
        guard state.publicIPAutomationEnabled, !isProbing, Date() >= nextProbe else { return }
        guard let endpoint = PublicIPEndpoint(urlString: state.publicIPCheckURL) else {
            notice = "The public IP check address must be a plain https:// URL."
            nextProbe = Date().addingTimeInterval(300)
            return
        }
        isProbing = true
        lastProbe = Date()
        let interface = observer.physicalInterface
        Task {
            var observed: String?
            if let interface { observed = await PublicIPProbe.fetch(endpoint, over: interface) }
            publicIP = stabilizer.observe(observed)
            // Disagreement with the accepted value needs one quick confirmation before it counts.
            nextProbe = Date().addingTimeInterval(observed == publicIP ? 300 : 30)
            isProbing = false
        }
    }

    func setPublicIPAutomation(_ enabled: Bool) {
        mutate { $0.publicIPAutomationEnabled = enabled }
        if enabled {
            nextProbe = .distantPast
        } else {
            publicIP = nil
            stabilizer = PublicIPStabilizer()
        }
    }

    func setPublicIPCheckURL(_ url: String) {
        guard PublicIPEndpoint(urlString: url) != nil else {
            notice = "The public IP check address must be a plain https:// URL."
            return
        }
        mutate { $0.publicIPCheckURL = url }
        nextProbe = .distantPast
    }

    // MARK: Connection actions

    var overallHealth: TunnelHealth {
        guard state.connectionOn, helperState == .ready, connectionError == nil, pauseReason == nil,
              let id = state.activeProfileID, let profile = state.profile(id) else { return .disconnected }
        let enabled = profile.tunnels.filter(\.enabled)
        return aggregateHealth(enabled.map { views[$0.id]?.state ?? .connecting })
    }

    /// Set while a connection the user left on waits for an eligible Wi-Fi network.
    var pauseReason: String? { state.pauseReason(ssid: ssid) }

    var statusLabel: String { pauseReason == nil ? overallHealth.label : "Paused" }

    func connect(_ profileID: UUID) {
        refreshSSID()
        let pin = snapshot().contextKey(includingPublicIP: state.publicIPAutomationEnabled)
        if mutate({ try $0.connect(profileID, pinContext: pin, ssid: ssid) }) {
            supervisor.retryAll()
            dnsDirty = true
            kick()
        }
    }

    func disconnect() {
        mutate { $0.disconnect() }
        kick()
    }

    /// While on, choosing another connection switches to it; while off, it only selects for later.
    func select(_ profileID: UUID) {
        if state.connectionOn {
            connect(profileID)
        } else {
            mutate { $0.activeProfileID = profileID }
        }
    }

    func setTunnelEnabled(_ id: UUID, _ enabled: Bool) {
        if mutate({ try $0.setTunnelEnabled(id, enabled) }) { kick() }
    }

    func retry() {
        notice = nil
        supervisor.retryAll()
        dnsDirty = true
        kick()
    }

    /// Leaves the saved intent alone, so the connection comes back at the next launch if it was on.
    func quit() {
        loop?.cancel()
        Task {
            _ = try? await helper.send(.downAll, timeout: 30)
            NSApp.terminate(nil)
        }
    }

    // MARK: Editing

    @discardableResult
    func addProfile() -> UUID? {
        var created: UUID?
        mutate { created = $0.addProfile(name: "Connection \($0.profiles.count + 1)") }
        return created
    }

    func duplicateProfile(_ id: UUID) {
        mutate { _ = $0.duplicateProfile(id) }
    }

    func removeProfile(_ id: UUID) {
        mutate { $0.removeProfile(id) }
        kick()
    }

    func renameProfile(_ id: UUID, to name: String) {
        mutate { $0.renameProfile(id, to: name) }
    }

    func setDNS(_ id: UUID, primary: String, secondary: String) {
        if mutate({ try $0.setDNS(id, primary: primary, secondary: secondary) }) {
            dnsDirty = true
            kick()
        }
    }

    func setSSIDEligibility(_ id: UUID, _ eligibility: SSIDEligibility?) {
        if mutate({ try $0.setSSIDEligibility(id, eligibility) }) {
            if eligibility != nil, observer.locationStatus == .notDetermined { observer.requestLocationPermission() }
            kick()
        }
    }

    func importFiles(into profileID: UUID) {
        let panel = NSOpenPanel()
        panel.title = "Import WireGuard Configuration"
        panel.allowsMultipleSelection = true
        panel.canChooseDirectories = false
        panel.allowedContentTypes = [UTType(filenameExtension: "conf") ?? .data]
        NSApp.activate(ignoringOtherApps: true)
        guard panel.runModal() == .OK else { return }

        var messages: [String] = []
        var updated = state
        for url in panel.urls {
            do {
                let outcome = try updated.importTunnel(fileAt: url, into: profileID)
                if !outcome.conflicts.isEmpty {
                    let reasons = outcome.conflicts.map(\.message).joined(separator: " ")
                    messages.append("\(url.lastPathComponent) was saved but left off: \(reasons)")
                }
                if !outcome.seededDNS.isEmpty {
                    dnsDirty = true
                    messages.append("Connection DNS set to \(outcome.seededDNS.joined(separator: ", ")) from \(url.lastPathComponent). You can change it in the DNS settings.")
                }
                if !outcome.ignoredDNS.isEmpty {
                    messages.append("\(url.lastPathComponent) also lists DNS \(outcome.ignoredDNS.joined(separator: ", ")), which is not used: DNS comes only from the connection's settings.")
                }
            } catch {
                messages.append("\(url.lastPathComponent): \(error.localizedDescription)")
            }
        }
        state = updated
        persist()
        notice = messages.isEmpty ? nil : messages.joined(separator: "\n")
        kick()
    }

    func duplicateTunnel(_ id: UUID) {
        mutate { _ = $0.duplicateTunnel(id) }
    }

    func removeTunnel(_ id: UUID) {
        mutate { $0.removeTunnel(id) }
        kick()
    }

    /// Only order changes, so nothing restarts.
    func reorderTunnels(in profileID: UUID, _ order: [UUID]) {
        mutate { try $0.reorderTunnels(in: profileID, order) }
    }

    /// Throws so the editor can keep the user's text open with the reason. Only the edited tunnel restarts.
    func saveTunnel(_ id: UUID, name: String, configText: String) throws {
        var copy = state
        try copy.updateTunnel(id, name: name, configText: configText)
        state = copy
        persist()
        kick()
    }

    // MARK: Rules

    /// Takes effect at the next evaluation. It never disconnects what is already running.
    func setRulesEnabled(_ enabled: Bool) {
        mutate { $0.rulesEnabled = enabled }
    }

    func addRule(_ condition: RuleCondition, profileID: UUID) {
        mutate { $0.rules.append(NetworkRule(condition: condition, profileID: profileID)) }
        switch condition {
        case .ssidEquals, .ssidNotEquals:
            if observer.locationStatus == .notDetermined { observer.requestLocationPermission() }
        case .publicIPInRange, .publicIPChanges:
            break
        }
    }

    func removeRule(_ id: UUID) {
        mutate { $0.rules.removeAll { $0.id == id } }
    }

    func setRuleEnabled(_ id: UUID, _ enabled: Bool) {
        mutate { state in
            if let index = state.rules.firstIndex(where: { $0.id == id }) { state.rules[index].enabled = enabled }
        }
    }

    func moveRule(_ id: UUID, by offset: Int) {
        mutate { state in
            guard let index = state.rules.firstIndex(where: { $0.id == id }) else { return }
            let target = index + offset
            guard state.rules.indices.contains(target) else { return }
            state.rules.swapAt(index, target)
        }
    }

    var locationDescription: String {
        switch observer.locationStatus {
        case .notDetermined: return "Not requested"
        case .denied: return "Denied. Enable WireNest in System Settings > Privacy & Security > Location Services."
        case .restricted: return "Restricted by this Mac's policy."
        default: return "Allowed"
        }
    }

    var canRequestLocation: Bool { observer.locationStatus == .notDetermined }

    func requestLocationPermission() {
        observer.requestLocationPermission()
    }

    // MARK: Login item

    func refreshLoginStatus() {
        loginStatus = SMAppService.mainApp.status
    }

    func setLoginItem(_ enabled: Bool) {
        do {
            if enabled {
                try SMAppService.mainApp.register()
            } else {
                try SMAppService.mainApp.unregister()
            }
        } catch {
            notice = "Could not change the login item: \(error.localizedDescription)"
        }
        refreshLoginStatus()
    }

    func openLoginItemsSettings() {
        SMAppService.openSystemSettingsLoginItems()
    }

    // MARK: Helper install

    func installHelper() {
        runPrivileged(["--install", "--uid", String(getuid())])
    }

    func removeHelper() {
        runPrivileged(["--uninstall"])
    }

    /// Asks macOS for an administrator password each time. WireNest never sees or stores the password.
    private func runPrivileged(_ arguments: [String]) {
        let helperPath = Bundle.main.bundleURL.appendingPathComponent("Contents/Library/LaunchServices/WireNestHelper").path
        let source = adminInstallAppleScript(helperPath: helperPath, arguments: arguments)
        NSApp.activate(ignoringOtherApps: true)
        var error: NSDictionary?
        NSAppleScript(source: source)?.executeAndReturnError(&error)
        helper.reset()
        if let error {
            let userCancelled = error[NSAppleScript.errorNumber] as? Int == -128
            if !userCancelled {
                notice = error[NSAppleScript.errorMessage] as? String ?? "The helper command failed."
            }
        } else {
            notice = nil
            supervisor.retryAll()
            dnsDirty = true
        }
        kick()
    }
}

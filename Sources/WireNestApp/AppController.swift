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
    @Published private(set) var views: [UUID: TunnelView] = [:]
    @Published private(set) var helperState = HelperState.checking
    @Published private(set) var ssid = SSIDObservation.unavailable("Checking")
    @Published private(set) var publicIP: String?
    @Published private(set) var loginStatus = SMAppService.mainApp.status
    /// The latest refused or failed user action.
    @Published var notice: String?
    /// Why the active connection cannot run as saved, e.g. a conflict.
    @Published private(set) var connectionError: String?
    @Published private(set) var dnsError: String?
    @Published private(set) var isBusy = false

    var showPreferences: () -> Void = {}

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

    // MARK: Loop

    private func tick() async {
        ticks += 1
        let current = observer.currentSSID()
        if current != ssid { ssid = current }
        probePublicIPIfDue()
        applyRules()
        await reconcile()
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
        if updated != state {
            state = updated
            persist()
        }
        guard let target else { return }
        // A rule connects like a manual connect but leaves no pin, so the next network change can move it again.
        if mutate({ try $0.connect(target, pinContext: nil) }) {
            supervisor.retryAll()
            dnsDirty = true
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

        let desired: [DesiredTunnel]
        do {
            desired = try state.desiredTunnels()
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
            guard let tunnel = desired.first(where: { $0.id == id }) else { continue }
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
        guard !desired.isEmpty, !status.tunnels.isEmpty,
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
        guard state.connectionOn, helperState == .ready, connectionError == nil,
              let id = state.activeProfileID, let profile = state.profile(id) else { return .disconnected }
        let enabled = profile.tunnels.filter(\.enabled)
        return aggregateHealth(enabled.map { views[$0.id]?.state ?? .connecting })
    }

    func connect(_ profileID: UUID) {
        let pin = snapshot().contextKey(includingPublicIP: state.publicIPAutomationEnabled)
        if mutate({ try $0.connect(profileID, pinContext: pin) }) {
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

    /// Throws so the editor can keep the user's text open with the reason. Only the edited tunnel restarts.
    func saveTunnel(_ id: UUID, name: String, configText: String) throws {
        var copy = state
        try copy.updateTunnel(id, name: name, configText: configText)
        state = copy
        persist()
        kick()
    }

    // MARK: Rules

    func addRule(_ condition: RuleCondition, profileID: UUID) {
        mutate { $0.rules.append(NetworkRule(condition: condition, profileID: profileID)) }
        switch condition {
        case .ssidEquals, .ssidNotEquals:
            if observer.locationStatus == .notDetermined { observer.requestLocationPermission() }
        case .publicIPInRange:
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

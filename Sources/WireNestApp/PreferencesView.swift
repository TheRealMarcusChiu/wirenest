import ServiceManagement
import SwiftUI
import WireNestCore

struct PreferencesView: View {
    @ObservedObject var controller: AppController

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            StatusBanners(controller: controller)
            TabView {
                ConnectionsTab(controller: controller).tabItem { Text("Connections") }
                RulesTab(controller: controller).tabItem { Text("Rules") }
                GeneralTab(controller: controller).tabItem { Text("General") }
            }
        }
        .padding(16)
        .frame(minWidth: 720, minHeight: 500)
    }
}

// MARK: Connections

private struct ConnectionsTab: View {
    @ObservedObject var controller: AppController
    @State private var selection: UUID?

    private var selected: ConnectionProfile? {
        selection.flatMap { controller.state.profile($0) }
    }

    var body: some View {
        HStack(alignment: .top, spacing: 12) {
            VStack(alignment: .leading) {
                List(controller.state.profiles, selection: $selection) { profile in
                    Text(profile.name).tag(profile.id)
                }
                HStack {
                    Button {
                        selection = controller.addProfile()
                    } label: {
                        Image(systemName: "plus")
                    }
                    .accessibilityLabel("Add connection")
                    Button {
                        if let selection { controller.duplicateProfile(selection) }
                    } label: {
                        Image(systemName: "plus.square.on.square")
                    }
                    .accessibilityLabel("Duplicate connection")
                    .disabled(selected == nil)
                    Button {
                        if let id = selection {
                            controller.removeProfile(id)
                            selection = nil
                        }
                    } label: {
                        Image(systemName: "minus")
                    }
                    .accessibilityLabel("Delete connection")
                    .disabled(selected == nil)
                }
            }
            .frame(width: 180)

            if let profile = selected {
                // The id resets the fields' local text when another connection is selected.
                ProfileDetail(controller: controller, profile: profile).id(profile.id)
            } else {
                Text("Select or add a connection.")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .padding(8)
    }
}

private struct ProfileDetail: View {
    @ObservedObject var controller: AppController
    let profile: ConnectionProfile

    @State private var name: String
    @State private var primaryDNS: String
    @State private var secondaryDNS: String
    @State private var editing: SavedTunnel?
    @State private var eligibilityMode: EligibilityMode
    @State private var eligibilitySSID: String

    private enum EligibilityMode: String, CaseIterable, Identifiable {
        case anywhere = "On any network"
        case onlyEquals = "Only on Wi-Fi named"
        case onlyNotEquals = "Only on Wi-Fi not named"
        var id: String { rawValue }
    }

    init(controller: AppController, profile: ConnectionProfile) {
        self.controller = controller
        self.profile = profile
        _name = State(initialValue: profile.name)
        _primaryDNS = State(initialValue: profile.primaryDNS)
        _secondaryDNS = State(initialValue: profile.secondaryDNS)
        switch profile.ssidEligibility {
        case .onlyEquals(let ssid)?:
            _eligibilityMode = State(initialValue: .onlyEquals)
            _eligibilitySSID = State(initialValue: ssid)
        case .onlyNotEquals(let ssid)?:
            _eligibilityMode = State(initialValue: .onlyNotEquals)
            _eligibilitySSID = State(initialValue: ssid)
        case nil:
            _eligibilityMode = State(initialValue: .anywhere)
            _eligibilitySSID = State(initialValue: "")
        }
    }

    private func applyEligibility() {
        switch eligibilityMode {
        case .anywhere: controller.setSSIDEligibility(profile.id, nil)
        case .onlyEquals: controller.setSSIDEligibility(profile.id, .onlyEquals(eligibilitySSID))
        case .onlyNotEquals: controller.setSSIDEligibility(profile.id, .onlyNotEquals(eligibilitySSID))
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            TextField("Name", text: $name)
                .onChange(of: name) { controller.renameProfile(profile.id, to: $0) }

            GroupBox("DNS for this connection") {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        TextField("Primary (empty keeps system DNS)", text: $primaryDNS)
                        TextField("Secondary (optional)", text: $secondaryDNS)
                        Button("Apply") {
                            controller.setDNS(profile.id, primary: primaryDNS, secondary: secondaryDNS)
                        }
                    }
                    Text("Applied while connected and restored after the last tunnel stops. macOS may use either server, so the secondary is not a guaranteed failover. DNS lines in tunnel files are not applied: this connection's settings are the only DNS used. The first import fills these fields if they are empty.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(4)
            }
            // An import can fill these in while this view is open.
            .onChange(of: profile.primaryDNS) { primaryDNS = $0 }
            .onChange(of: profile.secondaryDNS) { secondaryDNS = $0 }

            GroupBox("Where this connection may run") {
                VStack(alignment: .leading, spacing: 6) {
                    HStack {
                        Picker("Run", selection: $eligibilityMode) {
                            ForEach(EligibilityMode.allCases) { Text($0.rawValue).tag($0) }
                        }
                        if eligibilityMode != .anywhere {
                            TextField("Network name", text: $eligibilitySSID)
                        }
                        Button("Apply") { applyEligibility() }
                    }
                    Text("A limited connection stops whenever its condition is not met and resumes when it is met again, unless you turned it off. If the Wi-Fi name is unavailable (no Location permission, Wi-Fi off, Ethernet only), both limits count as not met.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(4)
            }

            HStack {
                Text("Tunnels").font(.headline)
                Spacer()
                Button("Retry Failed") { controller.retry() }
                Button("Import .conf…") { controller.importFiles(into: profile.id) }
            }

            List(profile.tunnels) { tunnel in
                HStack {
                    Toggle(isOn: Binding(
                        get: { tunnel.enabled },
                        set: { controller.setTunnelEnabled(tunnel.id, $0) }
                    )) {
                        Text(tunnel.name)
                    }
                    Spacer()
                    Text(stateLine(tunnel)).font(.caption).foregroundColor(.secondary).lineLimit(2)
                    Button("Edit") { editing = tunnel }
                    Button("Duplicate") { controller.duplicateTunnel(tunnel.id) }
                    Button("Delete") { controller.removeTunnel(tunnel.id) }
                }
            }
            Text("Tunnels with overlapping routes cannot be on together. A tunnel using the default route (0.0.0.0/0 or ::/0) needs that whole IP family to itself, including other tunnels' addresses and endpoints.")
                .font(.caption)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .sheet(item: $editing) { tunnel in
            TunnelEditor(controller: controller, tunnel: tunnel)
        }
    }

    private func stateLine(_ tunnel: SavedTunnel) -> String {
        guard controller.state.connectionOn, controller.state.activeProfileID == profile.id, tunnel.enabled else { return "" }
        if controller.pauseReason != nil { return "Paused" }
        guard let view = controller.views[tunnel.id] else { return TunnelHealth.connecting.label }
        return view.lastError ?? [view.state.label, view.detail].compactMap { $0 }.joined(separator: " · ")
    }
}

private struct TunnelEditor: View {
    @ObservedObject var controller: AppController
    let tunnel: SavedTunnel

    @Environment(\.dismiss) private var dismiss
    @State private var name: String
    @State private var text: String
    @State private var error: String?

    init(controller: AppController, tunnel: SavedTunnel) {
        self.controller = controller
        self.tunnel = tunnel
        _name = State(initialValue: tunnel.name)
        _text = State(initialValue: tunnel.configText)
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField("Tunnel name", text: $name)
            TextEditor(text: $text)
                .font(.system(.body, design: .monospaced))
                .autocorrectionDisabled()
                .frame(minHeight: 300)
                .accessibilityLabel("WireGuard configuration")
            Text("This text includes the tunnel's private key. AllowedIPs takes several comma-separated CIDRs. Hooks and SaveConfig are refused.")
                .font(.caption)
                .foregroundColor(.secondary)
            if let error {
                Text(error).font(.caption).foregroundColor(.red).fixedSize(horizontal: false, vertical: true)
            }
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Save") { save() }.keyboardShortcut(.defaultAction)
            }
        }
        .padding(16)
        .frame(width: 560)
    }

    private func save() {
        do {
            try controller.saveTunnel(tunnel.id, name: name, configText: text)
            dismiss()
        } catch {
            self.error = error.localizedDescription
        }
    }
}

// MARK: Rules

private struct RulesTab: View {
    @ObservedObject var controller: AppController

    private enum Kind: String, CaseIterable, Identifiable {
        case ssidEquals = "Wi-Fi is"
        case ssidNotEquals = "Wi-Fi is not"
        case publicIP = "Public IP is in"
        case publicIPChanges = "Public IP changes"
        var id: String { rawValue }
    }

    @State private var kind = Kind.ssidEquals
    @State private var value = ""
    @State private var profileID: UUID?
    @State private var checkURL = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("The first matching rule picks the connection, after the match has held for a few seconds, and skips a connection not allowed on this network. With no match, nothing changes. Disconnecting by hand stops rules until you connect again; choosing a connection by hand holds it until the network changes.")
                .font(.caption)
                .foregroundColor(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            List(controller.state.rules) { rule in
                HStack {
                    Toggle(isOn: Binding(
                        get: { rule.enabled },
                        set: { controller.setRuleEnabled(rule.id, $0) }
                    )) {
                        Text(describe(rule))
                    }
                    Spacer()
                    Button { controller.moveRule(rule.id, by: -1) } label: { Image(systemName: "arrow.up") }
                        .accessibilityLabel("Move rule up")
                    Button { controller.moveRule(rule.id, by: 1) } label: { Image(systemName: "arrow.down") }
                        .accessibilityLabel("Move rule down")
                    Button { controller.removeRule(rule.id) } label: { Image(systemName: "trash") }
                        .accessibilityLabel("Delete rule")
                }
            }

            HStack {
                Picker("When", selection: $kind) {
                    ForEach(Kind.allCases) { Text($0.rawValue).tag($0) }
                }
                .frame(width: 190)
                if kind != .publicIPChanges {
                    TextField(valuePrompt, text: $value)
                }
                Picker("use", selection: $profileID) {
                    Text("Choose…").tag(UUID?.none)
                    ForEach(controller.state.profiles) { Text($0.name).tag(UUID?.some($0.id)) }
                }
                .frame(width: 190)
                Button("Add") { add() }.disabled(!canAdd)
            }

            GroupBox("Wi-Fi name") {
                VStack(alignment: .leading, spacing: 4) {
                    Text(ssidText)
                    Text("macOS reveals the network name only with Location permission: \(controller.locationDescription)")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if controller.canRequestLocation {
                        Button("Allow Location Access…") { controller.requestLocationPermission() }
                    }
                    Text("If the name is unavailable, no Wi-Fi rule matches, including “Wi-Fi is not”.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            GroupBox("Public IP rules") {
                VStack(alignment: .leading, spacing: 4) {
                    Toggle("Check my public IP (off by default)", isOn: Binding(
                        get: { controller.state.publicIPAutomationEnabled },
                        set: { controller.setPublicIPAutomation($0) }
                    ))
                    HStack {
                        TextField("Check address", text: $checkURL)
                            .onSubmit { controller.setPublicIPCheckURL(checkURL) }
                        Text(controller.publicIP ?? "Unknown").foregroundColor(.secondary)
                    }
                    Text("Public IP rules do nothing until this is on. When on, WireNest contacts this third-party address over your Wi-Fi or Ethernet connection, bypassing tunnels, about every 5 minutes and after network changes. It learns your public IP; no tunnel information is sent. A new address must be seen twice before rules act on it. The first address seen after launch is a starting point, not a change.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .padding(4)
            }
        }
        .padding(8)
        .onAppear { checkURL = controller.state.publicIPCheckURL }
    }

    private var valuePrompt: String {
        kind == .publicIP ? "203.0.113.0/24" : "Network name"
    }

    private var canAdd: Bool {
        guard profileID != nil else { return false }
        if kind == .publicIPChanges { return true }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return false }
        return kind != .publicIP || CIDR(trimmed) != nil
    }

    private func add() {
        guard let profileID else { return }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        switch kind {
        case .ssidEquals: controller.addRule(.ssidEquals(trimmed), profileID: profileID)
        case .ssidNotEquals: controller.addRule(.ssidNotEquals(trimmed), profileID: profileID)
        case .publicIP: controller.addRule(.publicIPInRange(trimmed), profileID: profileID)
        case .publicIPChanges: controller.addRule(.publicIPChanges, profileID: profileID)
        }
        value = ""
    }

    private func describe(_ rule: NetworkRule) -> String {
        let target = controller.state.profile(rule.profileID)?.name ?? "?"
        switch rule.condition {
        case .ssidEquals(let name): return "Wi-Fi is “\(name)” → \(target)"
        case .ssidNotEquals(let name): return "Wi-Fi is not “\(name)” → \(target)"
        case .publicIPInRange(let range): return "Public IP is in \(range) → \(target)"
        case .publicIPChanges: return "Public IP changes → \(target)"
        }
    }

    private var ssidText: String {
        switch controller.ssid {
        case .known(let name): return "Current network: \(name)"
        case .unavailable(let reason): return "Unavailable: \(reason)"
        }
    }
}

// MARK: General

private struct GeneralTab: View {
    @ObservedObject var controller: AppController

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            GroupBox("Start at login") {
                VStack(alignment: .leading, spacing: 6) {
                    Toggle("Open WireNest when I log in", isOn: Binding(
                        get: { controller.loginStatus == .enabled || controller.loginStatus == .requiresApproval },
                        set: { controller.setLoginItem($0) }
                    ))
                    if controller.loginStatus == .requiresApproval {
                        Button("Approve in System Settings…") { controller.openLoginItemsSettings() }
                    }
                    Text("WireNest reconnects after you log in if the connection was on, and stays off if you disconnected. Tunnels do not start before login.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            GroupBox("Privileged helper") {
                VStack(alignment: .leading, spacing: 6) {
                    Text(helperText)
                    Text("Tunnels and DNS changes need root. The helper runs as a system service, accepts only this exact WireNest build from the user who installed it, and offers only tunnel and DNS operations. Update it after every WireNest update.")
                        .font(.caption)
                        .foregroundColor(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    HStack {
                        Button("Install or Update…") { controller.installHelper() }
                        Button("Remove…") { controller.removeHelper() }
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }
            Spacer()
        }
        .padding(8)
        .onAppear { controller.refreshLoginStatus() }
    }

    private var helperText: String {
        switch controller.helperState {
        case .checking: return "Checking…"
        case .ready: return "Installed and running."
        case .needsInstall: return "Not available. Install or update it."
        }
    }
}

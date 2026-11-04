import AppKit
import ServiceManagement
import SwiftUI
import WireNestCore

enum PreferencesPane: String, CaseIterable, Identifiable {
    case general = "General"
    case connections = "Connections"
    case automation = "Automation"
    case logs = "Logs"

    var id: Self { self }

    var symbol: String {
        switch self {
        case .general: return "gearshape"
        case .connections: return "network"
        case .automation: return "wand.and.stars"
        case .logs: return "doc.text"
        }
    }
}

struct PreferencesView: View {
    @ObservedObject var controller: AppController

    var body: some View {
        HStack(spacing: 0) {
            List(PreferencesPane.allCases, selection: Binding<PreferencesPane?>(
                get: { controller.preferencesPane },
                set: { if let pane = $0 { controller.preferencesPane = pane } }
            )) { pane in
                Label(pane.rawValue, systemImage: pane.symbol)
                    .accessibilityIdentifier("settings.pane.\(pane.rawValue)")
            }
            .listStyle(.sidebar)
            .frame(width: 170)

            Divider()

            VStack(spacing: 0) {
                if controller.preferencesPane != .logs { problemBar }
                switch controller.preferencesPane {
                case .general: GeneralPane(controller: controller)
                case .connections: ConnectionsPane(controller: controller)
                case .automation: AutomationPane(controller: controller)
                case .logs: LogsPane(controller: controller)
                }
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
        }
        .frame(minWidth: 820, minHeight: 540)
    }

    /// One short line and the next action. The full text is in the Logs pane.
    @ViewBuilder
    private var problemBar: some View {
        if let summary = controller.problemSummary {
            HStack {
                Label(summary, systemImage: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.multicolor)
                    .lineLimit(1)
                Spacer()
                Button("View Logs") { controller.preferencesPane = .logs }
                Button("Retry") { controller.retry() }
            }
            .controlSize(.small)
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(.bar)
            .accessibilityIdentifier("settings.problem")
            Divider()
        }
    }
}

private func caption(_ text: String) -> some View {
    Text(text)
        .font(.caption)
        .foregroundColor(.secondary)
        .fixedSize(horizontal: false, vertical: true)
}

// MARK: Connections

private struct ConnectionsPane: View {
    @ObservedObject var controller: AppController
    @State private var selection: UUID?
    @State private var confirmingDelete = false

    private var selected: ConnectionProfile? {
        selection.flatMap { controller.state.profile($0) }
    }

    var body: some View {
        HStack(spacing: 0) {
            VStack(spacing: 0) {
                List(controller.state.profiles, selection: $selection) { profile in
                    Text(profile.name).lineLimit(1)
                }
                .listStyle(.inset)
                .accessibilityIdentifier("settings.connections.list")
                Divider()
                HStack(spacing: 2) {
                    Button {
                        selection = controller.addProfile()
                    } label: {
                        Image(systemName: "plus").frame(width: 22, height: 20)
                    }
                    .help("Add connection")
                    .accessibilityLabel("Add connection")
                    .accessibilityIdentifier("settings.connections.add")
                    Button {
                        confirmingDelete = true
                    } label: {
                        Image(systemName: "minus").frame(width: 22, height: 20)
                    }
                    .help("Delete connection")
                    .accessibilityLabel("Delete connection")
                    .disabled(selected == nil)
                    Button {
                        if let selection { controller.duplicateProfile(selection) }
                    } label: {
                        Image(systemName: "plus.square.on.square").frame(width: 22, height: 20)
                    }
                    .help("Duplicate connection")
                    .accessibilityLabel("Duplicate connection")
                    .disabled(selected == nil)
                    Spacer()
                }
                .buttonStyle(.borderless)
                .padding(6)
            }
            .frame(width: 180)

            Divider()

            if let profile = selected {
                // The id resets the fields' local text when another connection is selected.
                ProfileDetail(controller: controller, profile: profile).id(profile.id)
            } else {
                Text(controller.state.profiles.isEmpty ? "Add a connection to get started." : "Select a connection.")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
            }
        }
        .onAppear { selection = selection ?? controller.state.activeProfileID ?? controller.state.profiles.first?.id }
        .confirmationDialog("Delete “\(selected?.name ?? "")” and its tunnels?", isPresented: $confirmingDelete) {
            Button("Delete", role: .destructive) {
                if let id = selection {
                    controller.removeProfile(id)
                    selection = nil
                }
            }
        }
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
        // One list, because a drag-to-reorder ForEach needs a List, and a List inside a Form or ScrollView does not lay out.
        List {
            Section {
                TextField("Name", text: $name)
                    .onChange(of: name) { controller.renameProfile(profile.id, to: $0) }
                    .accessibilityIdentifier("settings.connection.name")
            }

            Section {
                ForEach(profile.tunnels) { tunnel in
                    TunnelSettingsRow(controller: controller, profile: profile, tunnel: tunnel) { editing = tunnel }
                }
                .onMove { offsets, destination in
                    var order = profile.tunnels.map(\.id)
                    order.move(fromOffsets: offsets, toOffset: destination)
                    controller.reorderTunnels(in: profile.id, order)
                }
                if profile.tunnels.isEmpty {
                    Text("No tunnels yet. Import a WireGuard .conf file.").foregroundColor(.secondary)
                }
            } header: {
                HStack {
                    Text("Tunnels")
                    Spacer()
                    Button("Import…") { controller.importFiles(into: profile.id) }
                        .controlSize(.small)
                        .accessibilityIdentifier("settings.tunnels.import")
                }
            } footer: {
                caption("Drag to reorder. Tunnels with overlapping routes cannot be on together. A tunnel using 0.0.0.0/0 can run beside narrower IPv4 tunnels only while their endpoints have a more specific Wi-Fi, Ethernet or loopback route. WireNest adds no routes of its own, and this is not a kill switch.")
            }

            Section {
                HStack {
                    TextField("Primary", text: $primaryDNS, prompt: Text("System DNS"))
                    TextField("Secondary", text: $secondaryDNS, prompt: Text("Optional"))
                    Button("Apply") {
                        controller.setDNS(profile.id, primary: primaryDNS, secondary: secondaryDNS)
                    }
                }
                .onChange(of: profile.primaryDNS) { primaryDNS = $0 }
                .onChange(of: profile.secondaryDNS) { secondaryDNS = $0 }
            } header: {
                Text("DNS")
            } footer: {
                caption("Used while connected, and restored afterwards. macOS may use either server. DNS lines in tunnel files are not applied.")
            }

            Section {
                HStack {
                    Picker("Run", selection: $eligibilityMode) {
                        ForEach(EligibilityMode.allCases) { Text($0.rawValue).tag($0) }
                    }
                    if eligibilityMode != .anywhere {
                        TextField("Network name", text: $eligibilitySSID)
                    }
                    Button("Apply") { applyEligibility() }
                }
            } header: {
                Text("Where This Connection May Run")
            } footer: {
                caption("It stops when not allowed and resumes when allowed, unless you turned it off. If the Wi-Fi name is unavailable, both limits count as not met.")
            }
        }
        .listStyle(.inset)
        .sheet(item: $editing) { tunnel in
            TunnelEditor(controller: controller, tunnel: tunnel)
        }
    }
}

private struct TunnelSettingsRow: View {
    @ObservedObject var controller: AppController
    let profile: ConnectionProfile
    let tunnel: SavedTunnel
    let edit: () -> Void

    @State private var confirmingDelete = false

    private var index: Int? { profile.tunnels.firstIndex { $0.id == tunnel.id } }

    var body: some View {
        HStack(spacing: 8) {
            Image(systemName: "line.3.horizontal")
                .foregroundColor(.secondary)
                .help("Drag to reorder")
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 0) {
                Text(tunnel.name).lineLimit(1)
                Text(stateLine)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .help(controller.views[tunnel.id]?.lastError ?? "")
            }
            Spacer()
            Toggle(tunnel.name, isOn: Binding(
                get: { tunnel.enabled },
                set: { controller.setTunnelEnabled(tunnel.id, $0) }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.small)
            Button("Edit…", action: edit)
                .accessibilityIdentifier("settings.tunnel.edit.\(tunnel.name)")
            // The keyboard and VoiceOver route to everything a drag does.
            Menu {
                Button("Move Up") { move(by: -1) }.disabled(index == 0)
                Button("Move Down") { move(by: 1) }.disabled(index == profile.tunnels.count - 1)
                Divider()
                Button("Duplicate") { controller.duplicateTunnel(tunnel.id) }
                Button("Delete…", role: .destructive) { confirmingDelete = true }
            } label: {
                Image(systemName: "ellipsis.circle")
            }
            .menuStyle(.borderlessButton)
            .fixedSize()
            .accessibilityLabel("More actions for \(tunnel.name)")
        }
        .padding(.vertical, 2)
        .accessibilityIdentifier("settings.tunnel.\(tunnel.name)")
        .confirmationDialog("Delete “\(tunnel.name)”?", isPresented: $confirmingDelete) {
            Button("Delete", role: .destructive) { controller.removeTunnel(tunnel.id) }
        } message: {
            Text("Its configuration and private key are removed from WireNest.")
        }
    }

    private func move(by offset: Int) {
        guard let index, profile.tunnels.indices.contains(index + offset) else { return }
        var order = profile.tunnels.map(\.id)
        order.swapAt(index, index + offset)
        controller.reorderTunnels(in: profile.id, order)
    }

    private var stateLine: String {
        guard tunnel.enabled else { return "Off" }
        guard controller.state.connectionOn, controller.state.activeProfileID == profile.id else { return "Not connected" }
        if controller.pauseReason != nil { return "Paused" }
        guard let view = controller.views[tunnel.id] else { return TunnelHealth.connecting.label }
        return view.lastError.map(shortFailure) ?? view.state.label
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
            caption("This text includes the tunnel's private key. AllowedIPs takes several comma-separated CIDRs. Hooks and SaveConfig are refused.")
            if let error {
                Label(error, systemImage: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.multicolor)
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
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

// MARK: Automation

private struct AutomationPane: View {
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
        Form {
            Section {
                Toggle("Use automatic connection rules", isOn: Binding(
                    get: { controller.state.rulesEnabled },
                    set: { controller.setRulesEnabled($0) }
                ))
                .accessibilityIdentifier("settings.automation.enabled")
            } footer: {
                caption("Turning this off stops rules from choosing a connection. Anything already connected stays connected, and your own choices are not changed.")
            }

            Section {
                if controller.state.rules.isEmpty {
                    Text("No rules yet.").foregroundColor(.secondary)
                }
                ForEach(controller.state.rules) { rule in
                    HStack {
                        Toggle(describe(rule), isOn: Binding(
                            get: { rule.enabled },
                            set: { controller.setRuleEnabled(rule.id, $0) }
                        ))
                        Spacer()
                        Button { controller.moveRule(rule.id, by: -1) } label: { Image(systemName: "chevron.up") }
                            .accessibilityLabel("Move rule up")
                        Button { controller.moveRule(rule.id, by: 1) } label: { Image(systemName: "chevron.down") }
                            .accessibilityLabel("Move rule down")
                        Button { controller.removeRule(rule.id) } label: { Image(systemName: "trash") }
                            .accessibilityLabel("Delete rule")
                    }
                    .buttonStyle(.borderless)
                }
                .disabled(!controller.state.rulesEnabled)
            } header: {
                Text("Rules")
            } footer: {
                caption("The first matching rule wins, and skips a connection not allowed on this network. With no match, nothing changes. Disconnecting by hand stops rules until you connect again. Choosing a connection by hand holds it until the network changes.")
            }

            Section("Add a Rule") {
                Picker("When", selection: $kind) {
                    ForEach(Kind.allCases) { Text($0.rawValue).tag($0) }
                }
                if kind != .publicIPChanges {
                    TextField(kind == .publicIP ? "Range" as String : "Network name", text: $value, prompt: Text(valuePrompt))
                }
                Picker("Use", selection: $profileID) {
                    Text("Choose…").tag(UUID?.none)
                    ForEach(controller.state.profiles) { Text($0.name).tag(UUID?.some($0.id)) }
                }
                Button("Add Rule") { add() }
                    .disabled(!canAdd)
                    .accessibilityIdentifier("settings.automation.add")
            }

            Section {
                LabeledContent("Current network", value: ssidText)
                LabeledContent("Location access", value: controller.locationDescription)
                if controller.canRequestLocation {
                    Button("Allow Location Access…") { controller.requestLocationPermission() }
                }
            } header: {
                Text("Wi-Fi Name")
            } footer: {
                caption("macOS reveals the network name only with Location access. If it is unavailable, no Wi-Fi rule matches, including “Wi-Fi is not”.")
            }

            Section {
                Toggle("Check my public IP", isOn: Binding(
                    get: { controller.state.publicIPAutomationEnabled },
                    set: { controller.setPublicIPAutomation($0) }
                ))
                TextField("Check address", text: $checkURL)
                    .onSubmit { controller.setPublicIPCheckURL(checkURL) }
                LabeledContent("Public IP", value: controller.publicIP ?? "Unknown")
            } header: {
                Text("Public IP")
            } footer: {
                caption("Public IP rules need this on. WireNest then contacts this third-party address over Wi-Fi or Ethernet, bypassing tunnels, about every 5 minutes and after network changes. It learns your public IP; no tunnel information is sent. A new address must be seen twice before rules act on it, and the first one after launch is a starting point.")
            }
        }
        .formStyle(.grouped)
        .onAppear { checkURL = controller.state.publicIPCheckURL }
    }

    private var valuePrompt: String {
        kind == .publicIP ? "203.0.113.0/24" : "Network name"
    }

    private var canAdd: Bool {
        guard profileID != nil else { return false }
        switch kind {
        case .publicIPChanges: return true
        case .publicIP: return CIDR(value.trimmingCharacters(in: .whitespacesAndNewlines)) != nil
        case .ssidEquals, .ssidNotEquals: return !value.isEmpty
        }
    }

    private func add() {
        guard let profileID else { return }
        // Network names are used exactly as typed: spaces are real SSID bytes.
        switch kind {
        case .ssidEquals: controller.addRule(.ssidEquals(value), profileID: profileID)
        case .ssidNotEquals: controller.addRule(.ssidNotEquals(value), profileID: profileID)
        case .publicIP: controller.addRule(.publicIPInRange(value.trimmingCharacters(in: .whitespacesAndNewlines)), profileID: profileID)
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
        case .known(let name): return name
        case .unavailable(let reason): return reason
        }
    }
}

// MARK: Logs

private struct LogsPane: View {
    @ObservedObject var controller: AppController

    var body: some View {
        VStack(spacing: 0) {
            HStack {
                caption("Failures from this session only. Key material is removed, but tunnel names and addresses remain.")
                Spacer()
                Button("Copy Logs") { controller.copyLogs() }
                    .accessibilityIdentifier("settings.logs.copy")
                Button("Clear") { controller.clearLogs() }
                    .accessibilityIdentifier("settings.logs.clear")
            }
            .disabled(controller.log.entries.isEmpty)
            .controlSize(.small)
            .padding(12)
            Divider()
            if controller.log.entries.isEmpty {
                Text("No problems this session.")
                    .foregroundColor(.secondary)
                    .frame(maxWidth: .infinity, maxHeight: .infinity)
                    .accessibilityIdentifier("settings.logs.empty")
            } else {
                ScrollView {
                    // The same string Copy Logs copies, so what you see is what you get.
                    Text(controller.log.text())
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .padding(12)
                        .accessibilityIdentifier("settings.logs.text")
                }
                .background(Color(nsColor: .textBackgroundColor))
            }
        }
    }
}

// MARK: General

private struct GeneralPane: View {
    @ObservedObject var controller: AppController

    var body: some View {
        Form {
            Section {
                Toggle("Open WireNest when I log in", isOn: Binding(
                    get: { controller.loginStatus == .enabled || controller.loginStatus == .requiresApproval },
                    set: { controller.setLoginItem($0) }
                ))
                .accessibilityIdentifier("settings.general.login")
                if controller.loginStatus == .requiresApproval {
                    Button("Approve in System Settings…") { controller.openLoginItemsSettings() }
                }
            } footer: {
                caption("WireNest reconnects after you log in if the connection was on, and stays off if you disconnected. Tunnels do not start before login.")
            }

            Section {
                LabeledContent("Status", value: helperText)
                HStack {
                    Button("Install or Update…") { controller.installHelper() }
                        .accessibilityIdentifier("settings.general.helper.install")
                    Button("Remove…") { controller.removeHelper() }
                }
            } header: {
                Text("Privileged Helper")
            } footer: {
                caption("Tunnels and DNS changes need root. The helper accepts only this exact WireNest build from the user who installed it, and offers only tunnel and DNS operations. Update it after every WireNest update.")
            }
        }
        .formStyle(.grouped)
        .onAppear { controller.refreshLoginStatus() }
    }

    private var helperText: String {
        switch controller.helperState {
        case .checking: return "Checking…"
        case .ready: return "Installed and running"
        case .needsInstall: return "Not available"
        }
    }
}

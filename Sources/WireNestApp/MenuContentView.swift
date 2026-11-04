import SwiftUI
import WireNestCore

extension TunnelHealth {
    var label: String {
        switch self {
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting"
        case .connected: return "Connected"
        case .degraded: return "Degraded"
        }
    }

    var color: Color {
        switch self {
        case .disconnected: return .secondary
        case .connecting: return .orange
        case .connected: return .green
        case .degraded: return .red
        }
    }

    var symbol: String {
        switch self {
        case .disconnected: return "shield.slash"
        case .connecting: return "arrow.triangle.2.circlepath"
        case .connected: return "lock.shield.fill"
        case .degraded: return "exclamationmark.shield"
        }
    }
}

struct MenuBarIcon: View {
    @ObservedObject var controller: AppController

    var body: some View {
        Image(systemName: controller.overallHealth.symbol)
            .accessibilityLabel("WireNest: \(controller.statusLabel)")
    }
}

struct HealthDot: View {
    let health: TunnelHealth

    var body: some View {
        Circle()
            .fill(health.color)
            .frame(width: 7, height: 7)
            .accessibilityHidden(true)
    }
}

/// A row of a window-style menu, highlighted on hover the way a real menu item is.
private struct MenuItemButtonStyle: ButtonStyle {
    func makeBody(configuration: Configuration) -> some View {
        MenuItemLabel(label: configuration.label)
    }

    private struct MenuItemLabel: View {
        let label: ButtonStyleConfiguration.Label
        @State private var isHovered = false

        var body: some View {
            label
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 6)
                .padding(.vertical, 3)
                .foregroundColor(isHovered ? .white : .primary)
                .background(isHovered ? Color.accentColor : Color.clear, in: RoundedRectangle(cornerRadius: 4))
                .contentShape(Rectangle())
                .onHover { isHovered = $0 }
        }
    }
}

struct MenuContentView: View {
    @ObservedObject var controller: AppController

    private var activeProfile: ConnectionProfile? {
        controller.state.activeProfileID.flatMap { controller.state.profile($0) }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            header
            problemRow

            if controller.state.profiles.isEmpty {
                Text("No connections yet.")
                    .foregroundColor(.secondary)
            } else {
                Divider()
                Picker("Connection", selection: Binding(
                    get: { controller.state.activeProfileID },
                    set: { id in if let id { controller.select(id) } }
                )) {
                    if controller.state.activeProfileID == nil { Text("Choose…").tag(UUID?.none) }
                    ForEach(controller.state.profiles) { profile in
                        Text(profile.name).tag(UUID?.some(profile.id))
                    }
                }
                .accessibilityIdentifier("menu.connection.picker")
            }

            if let profile = activeProfile, !profile.tunnels.isEmpty {
                ForEach(profile.tunnels) { tunnel in
                    TunnelMenuRow(controller: controller, tunnel: tunnel, isOn: controller.state.connectionOn && controller.pauseReason == nil)
                }
            }

            Divider()
            Text(ssidLine)
                .font(.caption)
                .foregroundColor(.secondary)
                .lineLimit(1)

            VStack(spacing: 0) {
                Button("Settings…") {
                    controller.preferencesPane = .connections
                    controller.showPreferences()
                }
                .keyboardShortcut(",")
                .accessibilityIdentifier("menu.settings")
                Button("View Logs…") { controller.showLogs() }
                    .accessibilityIdentifier("menu.logs")
                Button("Quit WireNest") { controller.quit() }
                    .keyboardShortcut("q")
                    .help("Disconnects tunnels and quits. A connection left on returns at next launch.")
                    .accessibilityIdentifier("menu.quit")
            }
            .buttonStyle(MenuItemButtonStyle())
        }
        .padding(12)
        .frame(width: 300)
    }

    private var header: some View {
        HStack(spacing: 8) {
            Image(systemName: controller.overallHealth.symbol)
                .foregroundColor(controller.overallHealth.color)
                .font(.title3)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 0) {
                Text("WireNest").font(.headline)
                Text(controller.statusLabel)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .accessibilityIdentifier("menu.status")
            }
            Spacer()
            Toggle("Connection", isOn: Binding(
                get: { controller.state.connectionOn },
                set: { on in
                    if !on {
                        controller.disconnect()
                    } else if let id = controller.state.activeProfileID {
                        controller.connect(id)
                    }
                }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .disabled(controller.state.activeProfileID == nil)
            .accessibilityIdentifier("menu.connection.toggle")
        }
    }

    /// One short line and the next action. The full text is one click away in the Logs pane.
    @ViewBuilder
    private var problemRow: some View {
        if case .needsInstall = controller.helperState {
            HStack {
                Label("Helper not installed", systemImage: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.multicolor)
                    .font(.callout)
                Spacer()
                Button("Install…") { controller.installHelper() }
                    .controlSize(.small)
                    .accessibilityIdentifier("menu.helper.install")
            }
        } else if let summary = controller.problemSummary {
            VStack(alignment: .leading, spacing: 4) {
                Label(summary, systemImage: "exclamationmark.triangle.fill")
                    .symbolRenderingMode(.multicolor)
                    .font(.callout)
                    .lineLimit(2)
                    .accessibilityIdentifier("menu.problem")
                HStack {
                    Button("View Logs") { controller.showLogs() }
                    Button("Retry") { controller.retry() }
                        .accessibilityIdentifier("menu.retry")
                }
                .controlSize(.small)
            }
        } else if let reason = controller.pauseReason {
            Label("Waiting for an allowed Wi-Fi network", systemImage: "pause.circle")
                .font(.callout)
                .foregroundColor(.secondary)
                .help(reason)
        }
    }

    private var ssidLine: String {
        switch controller.ssid {
        case .known(let name): return "Wi-Fi: \(name)"
        case .unavailable: return "Wi-Fi name unavailable"
        }
    }
}

private struct TunnelMenuRow: View {
    @ObservedObject var controller: AppController
    let tunnel: SavedTunnel
    let isOn: Bool

    private var view: TunnelView? { controller.views[tunnel.id] }

    /// Reports only what the helper has reported: nothing shows as connected before it really is.
    private var health: TunnelHealth {
        guard isOn, tunnel.enabled else { return .disconnected }
        return view?.state ?? .connecting
    }

    var body: some View {
        HStack(spacing: 8) {
            HealthDot(health: health)
            VStack(alignment: .leading, spacing: 0) {
                Text(tunnel.name).lineLimit(1)
                Text(detail)
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .lineLimit(1)
                    .help(view?.lastError ?? "")
            }
            Spacer(minLength: 8)
            Toggle(tunnel.name, isOn: Binding(
                get: { tunnel.enabled },
                set: { controller.setTunnelEnabled(tunnel.id, $0) }
            ))
            .labelsHidden()
            .toggleStyle(.switch)
            .controlSize(.mini)
        }
        .accessibilityElement(children: .contain)
        .accessibilityValue(detail)
        .accessibilityIdentifier("menu.tunnel.\(tunnel.name)")
    }

    private var detail: String {
        if !tunnel.enabled { return "Off" }
        if controller.pauseReason != nil { return "Paused" }
        if !isOn { return "Not connected" }
        if let error = view?.lastError { return shortFailure(error) }
        return health.label
    }
}

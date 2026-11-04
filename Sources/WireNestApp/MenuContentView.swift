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
            .frame(width: 8, height: 8)
            .accessibilityHidden(true)
    }
}

/// Shared by the menu and Preferences: shows why something is not working and offers the next action.
struct StatusBanners: View {
    @ObservedObject var controller: AppController

    var body: some View {
        if case .needsInstall(let reason) = controller.helperState {
            VStack(alignment: .leading, spacing: 4) {
                Text("Helper needed").font(.headline)
                Text("WireNest needs its privileged helper to control tunnels. macOS will ask for an administrator password.")
                    .font(.caption)
                Text(reason).font(.caption).foregroundColor(.secondary)
                Button("Install or Update Helper…") { controller.installHelper() }
            }
        }
        if let reason = controller.pauseReason {
            Label("Paused: \(reason) It resumes on its own when allowed.", systemImage: "pause.circle")
                .font(.caption)
                .fixedSize(horizontal: false, vertical: true)
        }
        ForEach([controller.connectionError, controller.dnsError, controller.routeFailure, controller.ruleProblem, controller.notice].compactMap { $0 }, id: \.self) { message in
            Text(message)
                .font(.caption)
                .foregroundColor(.red)
                .fixedSize(horizontal: false, vertical: true)
        }
    }
}

struct MenuContentView: View {
    @ObservedObject var controller: AppController

    private var activeProfile: ConnectionProfile? {
        controller.state.activeProfileID.flatMap { controller.state.profile($0) }
    }

    private var hasErrors: Bool {
        controller.notice != nil || controller.connectionError != nil || controller.dnsError != nil || controller.ruleProblem != nil || controller.routeFailure != nil
            || controller.views.values.contains { $0.lastError != nil }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack {
                HealthDot(health: controller.overallHealth)
                Text("WireNest").font(.headline)
                Spacer()
                Text(controller.statusLabel).foregroundColor(.secondary)
            }

            StatusBanners(controller: controller)

            if controller.state.profiles.isEmpty {
                Text("No connections yet. Open Preferences to create one and import a .conf file.")
                    .font(.caption)
                    .foregroundColor(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            } else {
                Picker("Connection", selection: Binding(
                    get: { controller.state.activeProfileID },
                    set: { id in if let id { controller.select(id) } }
                )) {
                    if controller.state.activeProfileID == nil { Text("Choose…").tag(UUID?.none) }
                    ForEach(controller.state.profiles) { profile in
                        Text(profile.name).tag(UUID?.some(profile.id))
                    }
                }

                Toggle("On", isOn: Binding(
                    get: { controller.state.connectionOn },
                    set: { on in
                        if !on {
                            controller.disconnect()
                        } else if let id = controller.state.activeProfileID {
                            controller.connect(id)
                        }
                    }
                ))
                .toggleStyle(.switch)
                .disabled(controller.state.activeProfileID == nil)
            }

            if let profile = activeProfile {
                Divider()
                ForEach(profile.tunnels) { tunnel in
                    TunnelMenuRow(controller: controller, tunnel: tunnel, isOn: controller.state.connectionOn && controller.pauseReason == nil)
                }
                if profile.tunnels.isEmpty {
                    Text("This connection has no tunnels yet.").font(.caption).foregroundColor(.secondary)
                }
            }

            if hasErrors {
                Button("Retry Now") { controller.retry() }
            }

            Divider()
            Text(ssidLine).font(.caption).foregroundColor(.secondary)

            HStack {
                Button("Preferences…") { controller.showPreferences() }
                Spacer()
                Button("Quit") { controller.quit() }
                    .help("Disconnects tunnels and quits. A connection left on returns at next launch.")
            }
        }
        .padding(12)
        .frame(width: 320)
    }

    private var ssidLine: String {
        switch controller.ssid {
        case .known(let name): return "Wi-Fi: \(name)"
        case .unavailable(let reason): return "Wi-Fi name unavailable: \(reason)"
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
        VStack(alignment: .leading, spacing: 2) {
            Toggle(isOn: Binding(
                get: { tunnel.enabled },
                set: { controller.setTunnelEnabled(tunnel.id, $0) }
            )) {
                HStack {
                    HealthDot(health: health)
                    Text(tunnel.name).lineLimit(1)
                }
            }
            Text(detail)
                .font(.caption2)
                .foregroundColor(view?.lastError == nil ? .secondary : .red)
                .fixedSize(horizontal: false, vertical: true)
        }
        .accessibilityElement(children: .contain)
        .accessibilityValue(health.label)
    }

    private var detail: String {
        if !tunnel.enabled { return "Off" }
        if controller.pauseReason != nil { return "Paused" }
        if !isOn { return "Waiting for connection" }
        var parts = [health.label]
        if let text = view?.detail { parts.append(text) }
        if let error = view?.lastError { parts.append(error) }
        return parts.joined(separator: " · ")
    }
}

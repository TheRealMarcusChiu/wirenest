import AppKit
import SwiftUI
import WireNestCore

@MainActor
final class AppDelegate: NSObject, NSApplicationDelegate {
    let controller = AppController()
    private var preferences: NSWindow?

    func applicationDidFinishLaunching(_ notification: Notification) {
        controller.showPreferences = { [weak self] in self?.showPreferences() }
        controller.start()
    }

    /// A plain window rather than a SwiftUI scene, which macOS 13 would open at launch.
    private func showPreferences() {
        if preferences == nil {
            let window = NSWindow(contentViewController: NSHostingController(rootView: PreferencesView(controller: controller)))
            window.title = "WireNest"
            window.styleMask = [.titled, .closable, .miniaturizable, .resizable]
            window.isReleasedWhenClosed = false
            window.center()
            preferences = window
        }
        NSApp.activate(ignoringOtherApps: true)
        preferences?.makeKeyAndOrderFront(nil)
    }
}

@main
struct WireNestMain: App {
    @NSApplicationDelegateAdaptor(AppDelegate.self) private var delegate

    init() {
        // Lets packaging checks run the built binary without starting the UI.
        if CommandLine.arguments.contains("--version") {
            print("WireNest protocol \(HelperConstants.protocolVersion)")
            exit(0)
        }
    }

    var body: some Scene {
        MenuBarExtra {
            MenuContentView(controller: delegate.controller)
        } label: {
            MenuBarIcon(controller: delegate.controller)
        }
        .menuBarExtraStyle(.window)
    }
}

import Foundation

/// Paths inside a built WireNest.app, derived from where the helper binary sits.
public struct AppBundleLayout {
    public let appBundle: URL
    public let toolsDir: URL
    public let helper: URL

    public init?(helperExecutable: URL) {
        let contents = helperExecutable.deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
        guard helperExecutable.path.hasSuffix("/Contents/Library/LaunchServices/WireNestHelper"),
              contents.deletingLastPathComponent().pathExtension == "app" else { return nil }
        appBundle = contents.deletingLastPathComponent()
        toolsDir = contents.appendingPathComponent("Resources/Tools")
        helper = helperExecutable
    }
}

/// Who may talk to the daemon. Written root-owned at install time, read by the daemon at startup.
public struct HelperClientPin: Codable, Equatable {
    public let ownerUID: UInt32
    public let appCDHash: String

    public init(ownerUID: UInt32, appCDHash: String) {
        self.ownerUID = ownerUID
        self.appCDHash = appCDHash
    }

    public init?(validating uid: UInt32, cdHash: Data) {
        guard uid != 0, !cdHash.isEmpty else { return nil }
        self.init(ownerUID: uid, appCDHash: cdHash.map { String(format: "%02x", $0) }.joined())
    }

    /// Pins the exact app build, which also works for ad-hoc signatures that have no certificate to check.
    public var codeRequirement: String { "cdhash H\"\(appCDHash)\"" }
}

/// `do shell script … with administrator privileges` (Apple TN2065): the supported way for an
/// app without Developer ID to request an admin password. `quoted form of` handles the shell;
/// only the AppleScript string needs escaping here.
public func adminInstallAppleScript(helperPath: String, arguments: [String]) -> String {
    let escaped = helperPath.replacingOccurrences(of: "\\", with: "\\\\").replacingOccurrences(of: "\"", with: "\\\"")
    let args = arguments.map { " '\($0)'" }.joined()
    return "do shell script (quoted form of \"\(escaped)\") & \"\(args)\" with administrator privileges"
}

public func launchdPlist() -> [String: Any] {
    [
        "Label": HelperConstants.launchdLabel,
        "ProgramArguments": [HelperConstants.installedHelper, "--daemon"],
        "MachServices": [HelperConstants.machServiceName: true],
        // At boot the daemon undoes any DNS change a crash or power loss left behind.
        "RunAtLoad": true,
        "KeepAlive": true,
        // launchd otherwise kills the job's process group on exit, taking wg-quick's route monitors with it.
        "AbandonProcessGroup": true,
    ]
}

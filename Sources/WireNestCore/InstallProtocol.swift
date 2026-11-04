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

/// Builds the install payload from a private copy of the app, so everything checked and installed is one
/// immutable snapshot: once the copy exists, changing the original bundle can no longer affect the install.
/// `secure` applies root ownership and a mode. `verify` validates the snapshot's signature and derives the client pin.
/// Copying carries the source's ACLs along, and those could grant write access to what root later runs, so
/// every copied or created item loses its ACLs. Signatures do not cover ACLs, so the pin is unaffected.
public func stageVerifiedInstall(
    appBundle: URL, stagingRoot: URL,
    secure: (String, mode_t) throws -> Void,
    verify: (URL) throws -> HelperClientPin
) throws -> URL {
    let fm = FileManager.default
    func protect(_ path: String, _ mode: mode_t) throws {
        try SecureFile.removeExtendedACL(path)
        try secure(path, mode)
    }

    try? fm.removeItem(at: stagingRoot)
    try SecureFile.ensurePrivateDirectory(stagingRoot)
    let snapshot = stagingRoot.appendingPathComponent(appBundle.lastPathComponent)
    try fm.copyItem(at: appBundle, to: snapshot)

    for path in try [snapshot.path] + fm.subpathsOfDirectory(atPath: snapshot.path).map({ snapshot.appendingPathComponent($0).path }) {
        var info = stat()
        guard lstat(path, &info) == 0, [S_IFREG, S_IFDIR].contains(info.st_mode & S_IFMT) else {
            throw SecureFileError("WireNest.app contains an item that is not a regular file or folder.")
        }
        try protect(path, info.st_mode & 0o755)
    }

    let pin = try verify(snapshot)
    guard let layout = AppBundleLayout(helperExecutable: snapshot.appendingPathComponent("Contents/Library/LaunchServices/WireNestHelper")) else {
        throw SecureFileError("WireNest.app has an unexpected layout.")
    }

    let payload = stagingRoot.appendingPathComponent("payload")
    let payloadTools = payload.appendingPathComponent("Tools")
    try fm.createDirectory(at: payloadTools, withIntermediateDirectories: true)
    func install(_ source: URL, as destination: URL) throws {
        try fm.copyItem(at: source, to: destination)
        removexattr(destination.path, "com.apple.quarantine", XATTR_NOFOLLOW)
        try protect(destination.path, 0o755)
    }
    try install(layout.helper, as: payload.appendingPathComponent("WireNestHelper"))
    for tool in HelperConstants.toolNames {
        try install(layout.toolsDir.appendingPathComponent(tool), as: payloadTools.appendingPathComponent(tool))
    }
    let pinFile = payload.appendingPathComponent("client.json")
    try SecureFile.store(JSONEncoder().encode(pin), to: pinFile, mode: 0o644)
    try protect(pinFile.path, 0o644)
    try protect(payloadTools.path, 0o755)
    try protect(payload.path, 0o755)
    return payload
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

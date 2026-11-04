import Foundation
import Security
import WireNestCore

struct InstallError: LocalizedError {
    let errorDescription: String?

    init(_ message: String) { errorDescription = message }
}

/// Runs as root, after the user authorised it through the administrator prompt. Copies the helper
/// and tools out of the user-writable app bundle into a root-owned directory, so nothing the user
/// (or software running as the user) can modify ever executes as root.
enum Installer {
    private static let launchctl = "/bin/launchctl"
    private static let systemTarget = "system/\(HelperConstants.launchdLabel)"

    static func install(helperPath: String, ownerUID: UInt32) throws {
        let executable = URL(fileURLWithPath: helperPath).resolvingSymlinksInPath()
        guard let layout = AppBundleLayout(helperExecutable: executable) else {
            throw InstallError("Run the helper from inside WireNest.app.")
        }
        let cdHash = try verifiedAppCDHash(layout.appBundle)
        guard let pin = HelperClientPin(validating: ownerUID, cdHash: cdHash) else {
            throw InstallError("The owner must be a regular user.")
        }

        let fm = FileManager.default
        let paths = HelperPaths.production
        try SecureFile.ensurePrivateDirectory(paths.runtimeDir)
        let runner = ProcessRunner(outputDir: paths.runtimeDir)

        // Stage everything first, so a failure leaves any existing install untouched.
        let installDir = URL(fileURLWithPath: HelperConstants.installDir)
        let staging = URL(fileURLWithPath: HelperConstants.installDir + ".staging-\(getpid())")
        try? fm.removeItem(at: staging)
        try fm.createDirectory(at: installDir.deletingLastPathComponent(), withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        try protect(installDir.deletingLastPathComponent().path, mode: 0o755)
        let stagedTools = staging.appendingPathComponent("Tools")
        try fm.createDirectory(at: stagedTools, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        defer { try? fm.removeItem(at: staging) }

        try copyExecutable(layout.helper, to: staging.appendingPathComponent("WireNestHelper"))
        for tool in HelperConstants.toolNames {
            try copyExecutable(layout.toolsDir.appendingPathComponent(tool), to: stagedTools.appendingPathComponent(tool))
        }
        let pinFile = staging.appendingPathComponent("client.json")
        try SecureFile.store(JSONEncoder().encode(pin), to: pinFile, mode: 0o644)
        try protect(pinFile.path, mode: 0o644)
        try protect(stagedTools.path, mode: 0o755)
        try protect(staging.path, mode: 0o755)

        // The old daemon may be gone already. AbandonProcessGroup keeps running tunnels alive for the new one to adopt.
        _ = runner.run(launchctl, ["bootout", systemTarget], timeout: 30, readyMarker: nil)

        try? fm.removeItem(at: installDir)
        try fm.moveItem(at: staging, to: installDir)

        let plist = try PropertyListSerialization.data(fromPropertyList: launchdPlist(), format: .xml, options: 0)
        let plistURL = URL(fileURLWithPath: HelperConstants.launchdPlistPath)
        try SecureFile.store(plist, to: plistURL, mode: 0o644)
        try protect(plistURL.path, mode: 0o644)

        _ = runner.run(launchctl, ["enable", systemTarget], timeout: 15, readyMarker: nil)
        let bootstrap = runner.run(launchctl, ["bootstrap", "system", plistURL.path], timeout: 30, readyMarker: nil)
        guard bootstrap.status == 0 else {
            throw InstallError("launchctl bootstrap failed: \(bootstrap.output)")
        }
    }

    static func uninstall() throws {
        let paths = HelperPaths.production
        try SecureFile.ensurePrivateDirectory(paths.runtimeDir)
        let runner = ProcessRunner(outputDir: paths.runtimeDir)
        _ = runner.run(launchctl, ["bootout", systemTarget], timeout: 30, readyMarker: nil)

        // With the daemon gone, this process tears down what it left running.
        var teardownError: Error?
        if FileManager.default.fileExists(atPath: HelperConstants.installedTools) {
            do {
                let engine = try HelperEngine(paths: paths, runner: runner)
                engine.recoverOnStart()
                try engine.downAll()
            } catch {
                teardownError = error
            }
        }
        if let teardownError { throw teardownError }

        let fm = FileManager.default
        try? fm.removeItem(atPath: HelperConstants.launchdPlistPath)
        try? fm.removeItem(atPath: HelperConstants.installDir)
        try? fm.removeItem(at: paths.durableDir)
        try? fm.removeItem(at: paths.runtimeDir)
    }

    /// Refuses a modified bundle. An ad-hoc signature is enough here: it still seals every file,
    /// and the client pin below ties the daemon to this exact build.
    private static func verifiedAppCDHash(_ appBundle: URL) throws -> Data {
        var code: SecStaticCode?
        guard SecStaticCodeCreateWithPath(appBundle as CFURL, SecCSFlags(), &code) == errSecSuccess, let code else {
            throw InstallError("WireNest.app has no readable code signature.")
        }
        let flags = SecCSFlags(rawValue: kSecCSCheckAllArchitectures | kSecCSCheckNestedCode)
        guard SecStaticCodeCheckValidity(code, flags, nil) == errSecSuccess else {
            throw InstallError("WireNest.app failed signature validation. Reinstall it from a trusted copy.")
        }
        var information: CFDictionary?
        guard SecCodeCopySigningInformation(code, SecCSFlags(rawValue: kSecCSSigningInformation), &information) == errSecSuccess,
              let info = information as? [String: Any],
              info[kSecCodeInfoIdentifier as String] as? String == HelperConstants.appIdentifier,
              let cdHash = info[kSecCodeInfoUnique as String] as? Data else {
            throw InstallError("WireNest.app is not signed with the expected identifier.")
        }
        return cdHash
    }

    private static func copyExecutable(_ source: URL, to destination: URL) throws {
        var info = stat()
        guard lstat(source.path, &info) == 0, info.st_mode & S_IFMT == S_IFREG else {
            throw InstallError("\(source.lastPathComponent) is missing or is not a regular file.")
        }
        try FileManager.default.copyItem(at: source, to: destination)
        removexattr(destination.path, "com.apple.quarantine", XATTR_NOFOLLOW)
        try protect(destination.path, mode: 0o755)
    }

    private static func protect(_ path: String, mode: mode_t) throws {
        guard lchown(path, 0, 0) == 0, chmod(path, mode) == 0 else {
            throw InstallError("Cannot secure \(path).")
        }
    }
}

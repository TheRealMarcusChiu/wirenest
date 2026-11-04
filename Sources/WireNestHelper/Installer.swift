import Foundation
import Security
import WireNestCore

struct InstallError: LocalizedError {
    let errorDescription: String?

    init(_ message: String) { errorDescription = message }
}

/// Runs as root, after the user authorised it through the administrator prompt. Installs into a root-owned
/// directory from one verified private snapshot of the bundle. An ad-hoc signature proves the snapshot is
/// self-consistent, not who built it: this admits whichever app the administrator chose to install from.
enum Installer {
    private static let launchctl = "/bin/launchctl"
    private static let systemTarget = "system/\(HelperConstants.launchdLabel)"

    static func install(helperPath: String, ownerUID: UInt32) throws {
        let executable = URL(fileURLWithPath: helperPath).resolvingSymlinksInPath()
        guard let layout = AppBundleLayout(helperExecutable: executable) else {
            throw InstallError("Run the helper from inside WireNest.app.")
        }
        guard ownerUID != 0 else { throw InstallError("The owner must be a regular user.") }

        let fm = FileManager.default
        let paths = HelperPaths.production
        try SecureFile.ensurePrivateDirectory(paths.runtimeDir)
        let runner = ProcessRunner(outputDir: paths.runtimeDir)

        let installDir = URL(fileURLWithPath: HelperConstants.installDir)
        let parent = installDir.deletingLastPathComponent()
        try fm.createDirectory(at: parent, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o755])
        // A system directory shared with other apps' helpers: checked and never changed, since an install inside it is only as safe as it is.
        var parentInfo = stat()
        guard lstat(parent.path, &parentInfo) == 0, parentInfo.st_mode & S_IFMT == S_IFDIR, parentInfo.st_uid == 0,
              parentInfo.st_mode & 0o022 == 0, try !SecureFile.hasExtendedACL(parent.path) else {
            throw InstallError("\(parent.path) can be changed by someone other than root. Fix its permissions and access list, then install again.")
        }

        // The existing install is not touched until the snapshot has passed verification.
        let staging = URL(fileURLWithPath: HelperConstants.installDir + ".staging-\(getpid())")
        defer { try? fm.removeItem(at: staging) }
        let payload = try stageVerifiedInstall(
            appBundle: layout.appBundle, stagingRoot: staging,
            secure: { path, mode in try protect(path, mode: mode) },
            verify: { snapshot in
                guard let pin = HelperClientPin(validating: ownerUID, cdHash: try verifiedAppCDHash(snapshot)) else {
                    throw InstallError("WireNest.app has no code directory hash.")
                }
                return pin
            }
        )

        let plist = try PropertyListSerialization.data(fromPropertyList: launchdPlist(), format: .xml, options: 0)
        let plistURL = URL(fileURLWithPath: HelperConstants.launchdPlistPath)

        // AbandonProcessGroup keeps running tunnels alive for the new daemon to adopt. The old daemon may be gone already.
        _ = runner.run(launchctl, ["bootout", systemTarget], timeout: 30, readyMarker: nil)

        let previous = URL(fileURLWithPath: HelperConstants.installDir + ".previous-\(getpid())")
        let hadPrevious = fm.fileExists(atPath: installDir.path)
        if hadPrevious { try fm.moveItem(at: installDir, to: previous) }
        func start() -> CommandResult {
            _ = runner.run(launchctl, ["enable", systemTarget], timeout: 15, readyMarker: nil)
            return runner.run(launchctl, ["bootstrap", "system", plistURL.path], timeout: 30, readyMarker: nil)
        }
        do {
            try fm.moveItem(at: payload, to: installDir)
            try SecureFile.store(plist, to: plistURL, mode: 0o644)
            try SecureFile.removeExtendedACL(plistURL.path)
            try protect(plistURL.path, mode: 0o644)
            let bootstrap = start()
            guard bootstrap.status == 0 else { throw InstallError("launchctl bootstrap failed: \(bootstrap.output)") }
        } catch {
            if hadPrevious {
                try? fm.removeItem(at: installDir)
                try? fm.moveItem(at: previous, to: installDir)
                _ = start()
            }
            throw error
        }
        if hadPrevious { try? fm.removeItem(at: previous) }
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
                // Removing the helper would lose these originals, with nothing left to restore them.
                let pending = engine.handle(.status).status?.dnsPendingServices ?? []
                if !pending.isEmpty {
                    throw InstallError("Original DNS servers are still waiting to be restored for: \(pending.joined(separator: ", ")). Enable those services, then remove the helper again.")
                }
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

    /// Refuses a snapshot whose files do not match its signature, for every architecture and all nested code.
    /// The returned hash pins the daemon to this exact build; an ad-hoc signature has no certificate to pin instead.
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

    private static func protect(_ path: String, mode: mode_t) throws {
        guard lchown(path, 0, 0) == 0, chmod(path, mode) == 0 else {
            throw InstallError("Cannot secure \(path).")
        }
        // Read back, including the access list, which neither call above affects.
        var info = stat()
        guard lstat(path, &info) == 0, info.st_uid == 0, info.st_gid == 0, info.st_mode & 0o7777 == mode,
              try !SecureFile.hasExtendedACL(path) else {
            throw InstallError("\(path) is not protected as required.")
        }
    }
}

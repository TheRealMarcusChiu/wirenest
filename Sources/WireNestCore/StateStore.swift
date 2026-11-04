import Foundation

/// Persists `AppState`, including private keys, in a 0600 file inside a 0700 directory.
/// shortcut: plain files rather than Keychain, because unsigned builds get unstable Keychain ACLs; revisit with Developer ID signing.
public final class StateStore {
    public let stateURL: URL
    private let directory: URL

    public static var defaultDirectory: URL {
        FileManager.default.homeDirectoryForCurrentUser
            .appendingPathComponent("Library/Application Support/WireNest", isDirectory: true)
    }

    public init(directory: URL = StateStore.defaultDirectory) throws {
        self.directory = directory
        stateURL = directory.appendingPathComponent("state.json")
        try SecureFile.ensurePrivateDirectory(directory)
    }

    public func load() throws -> AppState {
        guard FileManager.default.fileExists(atPath: stateURL.path) else { return AppState() }
        guard chmod(stateURL.path, 0o600) == 0 else { throw SecureFileError("Cannot protect \(stateURL.lastPathComponent).") }
        return try JSONDecoder().decode(AppState.self, from: Data(contentsOf: stateURL))
    }

    public func save(_ state: AppState) throws {
        let encoder = JSONEncoder()
        encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try SecureFile.store(encoder.encode(state), to: stateURL)
    }

    /// Moves unreadable state aside so the app can start without ever overwriting recoverable data.
    public func quarantineCorruptState() throws -> URL {
        let destination = directory.appendingPathComponent("state.corrupt-\(UUID().uuidString).json")
        try FileManager.default.moveItem(at: stateURL, to: destination)
        return destination
    }
}

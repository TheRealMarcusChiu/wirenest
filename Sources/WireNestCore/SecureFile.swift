import Foundation

public struct SecureFileError: LocalizedError {
    public let errorDescription: String?

    init(_ message: String) { errorDescription = message }
}

public enum SecureFile {
    /// Creates or adopts a private directory, refusing symlinks and directories owned by anyone else.
    public static func ensurePrivateDirectory(_ url: URL) throws {
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true, attributes: [.posixPermissions: 0o700])
        var info = stat()
        guard lstat(url.path, &info) == 0 else { throw SecureFileError("Cannot inspect \(url.lastPathComponent).") }
        guard info.st_mode & S_IFMT == S_IFDIR, info.st_uid == geteuid() else {
            throw SecureFileError("\(url.path) is not a directory owned by this user.")
        }
        guard chmod(url.path, 0o700) == 0 else { throw SecureFileError("Cannot protect \(url.lastPathComponent).") }
    }

    /// Writes through a private temporary file and renames, so a crash cannot leave a partial or world-readable file.
    public static func store(_ data: Data, to url: URL, mode: mode_t = 0o600) throws {
        let temporary = url.path + ".\(getpid()).\(UUID().uuidString).tmp"
        let fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode)
        guard fd >= 0 else { throw SecureFileError("Cannot create a file next to \(url.lastPathComponent).") }
        var succeeded = false
        defer {
            close(fd)
            if !succeeded { unlink(temporary) }
        }
        let wrote = data.withUnsafeBytes { (buffer: UnsafeRawBufferPointer) -> Bool in
            var offset = 0
            while offset < buffer.count {
                let count = write(fd, buffer.baseAddress! + offset, buffer.count - offset)
                if count <= 0 { return false }
                offset += count
            }
            return true
        }
        guard wrote, fchmod(fd, mode) == 0, fsync(fd) == 0, rename(temporary, url.path) == 0 else {
            throw SecureFileError("Cannot write \(url.lastPathComponent).")
        }
        succeeded = true
    }
}

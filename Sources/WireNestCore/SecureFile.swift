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
        try removeExtendedACL(url.path)
    }

    /// Whether the item itself (never a symlink's target) has any extended ACL entry. Fails rather than guessing.
    public static func hasExtendedACL(_ path: String) throws -> Bool {
        errno = 0
        guard let acl = acl_get_link_np(path, ACL_TYPE_EXTENDED) else {
            guard errno == ENOENT else { throw SecureFileError("Cannot read the access list of \(path).") }
            return false
        }
        defer { acl_free(UnsafeMutableRawPointer(acl)) }
        var entry: acl_entry_t?
        errno = 0
        // 0 asks for the first entry. An empty list reports EINVAL, as it has no first entry.
        if acl_get_entry(acl, 0, &entry) == 0 { return entry != nil }
        guard errno == EINVAL else { throw SecureFileError("Cannot read the access list of \(path).") }
        return false
    }

    /// An ACL survives chown and chmod and keeps granting what it grants, so mode bits alone prove nothing.
    public static func removeExtendedACL(_ path: String) throws {
        guard try hasExtendedACL(path) else { return }
        guard let empty = acl_init(1) else { throw SecureFileError("Cannot clear the access list of \(path).") }
        defer { acl_free(UnsafeMutableRawPointer(empty)) }
        guard acl_set_link_np(path, ACL_TYPE_EXTENDED, empty) == 0, try !hasExtendedACL(path) else {
            throw SecureFileError("Cannot clear the access list of \(path).")
        }
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

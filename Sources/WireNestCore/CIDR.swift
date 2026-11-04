import Foundation

/// An IPv4 or IPv6 address with prefix. Keeps the host bits as written because
/// `Address = 10.0.0.2/24` is meaningful; comparisons mask them.
public struct CIDR: Hashable, CustomStringConvertible {
    public let address: String
    public let prefix: Int
    public let bytes: [UInt8]

    public init?(_ text: String) {
        let parts = text.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        guard parts.count <= 2, let bytes = parseIPBytes(parts[0]) else { return nil }
        let maxPrefix = bytes.count * 8
        if parts.count == 2 {
            guard !parts[1].isEmpty, parts[1].allSatisfy({ $0.isASCII && $0.isNumber }),
                  parts[1].count <= 3, let prefix = Int(parts[1]), prefix <= maxPrefix else { return nil }
            self.prefix = prefix
        } else {
            self.prefix = maxPrefix
        }
        self.address = parts[0]
        self.bytes = bytes
    }

    public var isDefaultRoute: Bool { prefix == 0 }
    public var isIPv6: Bool { bytes.count == 16 }
    public var description: String { "\(address)/\(prefix)" }

    public func overlaps(_ other: CIDR) -> Bool {
        guard bytes.count == other.bytes.count else { return false }
        var remaining = min(prefix, other.prefix)
        for (a, b) in zip(bytes, other.bytes) where remaining > 0 {
            let mask: UInt8 = remaining >= 8 ? 0xFF : ~(UInt8(0xFF) >> UInt8(remaining))
            if a & mask != b & mask { return false }
            remaining -= 8
        }
        return true
    }
}

func parseIPBytes(_ text: String) -> [UInt8]? {
    guard text.utf8.count <= 45, !text.utf8.contains(0) else { return nil }
    var v4 = [UInt8](repeating: 0, count: 4)
    if inet_pton(AF_INET, text, &v4) == 1 { return v4 }
    var v6 = [UInt8](repeating: 0, count: 16)
    if inet_pton(AF_INET6, text, &v6) == 1 { return v6 }
    return nil
}

public func isIPAddress(_ text: String) -> Bool {
    parseIPBytes(text) != nil
}

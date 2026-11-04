import Foundation
@testable import WireNestCore

/// Deterministic 32-byte values: valid shape for the parser, never a real or published secret.
func testKey(_ seed: UInt8) -> String {
    Data(repeating: seed, count: 32).base64EncodedString()
}

func confText(
    privateKey: String = testKey(1),
    address: String = "10.10.0.2/32",
    dns: String? = nil,
    extraInterface: String = "",
    peerKey: String = testKey(2),
    allowedIPs: String = "10.10.0.0/24",
    endpoint: String = "198.51.100.1:51820",
    extraPeer: String = ""
) -> String {
    var lines = ["[Interface]", "PrivateKey = \(privateKey)", "Address = \(address)"]
    if let dns { lines.append("DNS = \(dns)") }
    if !extraInterface.isEmpty { lines.append(extraInterface) }
    lines += ["", "[Peer]", "PublicKey = \(peerKey)", "AllowedIPs = \(allowedIPs)", "Endpoint = \(endpoint)"]
    if !extraPeer.isEmpty { lines.append(extraPeer) }
    return lines.joined(separator: "\n") + "\n"
}

func tempDirectory() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("wirenest-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    return url
}

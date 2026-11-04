import Foundation
import WireNestCore

let usage = """
WireNestHelper (protocol \(HelperConstants.protocolVersion)): privileged tunnel service for WireNest.

  --help                 Show this text.
  --version              Print the protocol version.
  --install --uid <uid>  As root: install this bundle's helper and tools for that user.
  --uninstall            As root: stop tunnels, restore DNS and remove the helper.
  --daemon               Run the launchd service. Started only by launchd.
"""

func fail(_ message: String) -> Never {
    FileHandle.standardError.write(Data((message + "\n").utf8))
    exit(1)
}

func requireRoot() {
    if geteuid() != 0 { fail("This command must run as root.") }
}

let arguments = Array(CommandLine.arguments.dropFirst())

switch arguments.first {
case "--help", "-h":
    print(usage)
case "--version":
    print("WireNestHelper protocol \(HelperConstants.protocolVersion)")
case "--install":
    requireRoot()
    guard arguments.count == 3, arguments[1] == "--uid", let uid = UInt32(arguments[2]) else { fail(usage) }
    do {
        try Installer.install(helperPath: CommandLine.arguments[0], ownerUID: uid)
    } catch {
        fail("Install failed: \(error.localizedDescription)")
    }
case "--uninstall":
    requireRoot()
    do {
        try Installer.uninstall()
    } catch {
        fail("Uninstall failed: \(error.localizedDescription)")
    }
case "--daemon":
    requireRoot()
    runDaemon()
default:
    fail(usage)
}

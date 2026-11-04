import Foundation
import WireNestCore

/// The XPC surface of the root daemon. Requests are handled one at a time.
final class HelperService: NSObject, NSXPCListenerDelegate, WireNestHelperXPC {
    private let ownerUID: UInt32
    private let engine: HelperEngine
    private let queue = DispatchQueue(label: "com.marcuschiu.WireNest.helper.requests")

    init(ownerUID: UInt32, engine: HelperEngine) {
        self.ownerUID = ownerUID
        self.engine = engine
    }

    func listener(_ listener: NSXPCListener, shouldAcceptNewConnection connection: NSXPCConnection) -> Bool {
        // The listener's code requirement has already pinned the app build; this also pins the installing user.
        guard connection.effectiveUserIdentifier == ownerUID else { return false }
        connection.exportedInterface = NSXPCInterface(with: WireNestHelperXPC.self)
        connection.exportedObject = self
        connection.resume()
        return true
    }

    func perform(_ request: Data, withReply reply: @escaping (Data) -> Void) {
        queue.async { [engine] in
            let response: HelperResponse
            do {
                response = engine.handle(try HelperRequest.decodeBounded(request))
            } catch {
                response = HelperResponse(error: "The helper refused a malformed request.")
            }
            reply((try? JSONEncoder().encode(response)) ?? Data())
        }
    }
}

/// The pin is what authorises callers, so it counts only if nobody but root could have written it.
func loadClientPin() throws -> HelperClientPin {
    var info = stat()
    guard lstat(HelperConstants.clientPinPath, &info) == 0,
          info.st_mode & S_IFMT == S_IFREG, info.st_uid == 0, info.st_mode & 0o022 == 0,
          try !SecureFile.hasExtendedACL(HelperConstants.clientPinPath) else {
        throw InstallError("The client pin is missing or not protected.")
    }
    let data = try Data(contentsOf: URL(fileURLWithPath: HelperConstants.clientPinPath))
    let pin = try JSONDecoder().decode(HelperClientPin.self, from: data)
    guard pin.ownerUID != 0, !pin.appCDHash.isEmpty, pin.appCDHash.allSatisfy(\.isHexDigit) else {
        throw InstallError("The client pin is malformed.")
    }
    return pin
}

func runDaemon() -> Never {
    do {
        let pin = try loadClientPin()
        let paths = HelperPaths.production
        try SecureFile.ensurePrivateDirectory(paths.runtimeDir)
        let engine = try HelperEngine(paths: paths, runner: ProcessRunner(outputDir: paths.runtimeDir))
        engine.recoverOnStart()

        let service = HelperService(ownerUID: pin.ownerUID, engine: engine)
        let listener = NSXPCListener(machServiceName: HelperConstants.machServiceName)
        listener.setConnectionCodeSigningRequirement(pin.codeRequirement)
        listener.delegate = service
        listener.resume()
        // Both objects must outlive the run loop below, which never returns.
        withExtendedLifetime((service, listener)) {
            RunLoop.main.run()
        }
        exit(0)
    } catch {
        fail("Daemon failed to start: \(error.localizedDescription)")
    }
}

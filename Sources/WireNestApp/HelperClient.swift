import Foundation
import WireNestCore

enum HelperClientError: LocalizedError {
    case unavailable(String)
    case rejected(String)

    var errorDescription: String? {
        switch self {
        case .unavailable(let reason): return "The WireNest helper is not reachable: \(reason)"
        case .rejected(let reason): return reason
        }
    }
}

/// `.privileged` looks the service up in the system domain, where only root can register it.
@MainActor
final class HelperClient {
    private var connection: NSXPCConnection?

    /// Forgets the connection, e.g. after the daemon was replaced.
    func reset() {
        connection?.invalidate()
        connection = nil
    }

    private func currentConnection() -> NSXPCConnection {
        if let connection { return connection }
        let created = NSXPCConnection(machServiceName: HelperConstants.machServiceName, options: .privileged)
        created.remoteObjectInterface = NSXPCInterface(with: WireNestHelperXPC.self)
        created.invalidationHandler = { [weak self] in
            Task { @MainActor in self?.connection = nil }
        }
        created.resume()
        connection = created
        return created
    }

    /// Slow `wg-quick` runs are bounded inside the helper; this bound covers a helper that vanished.
    func send(_ request: HelperRequest, timeout: TimeInterval = 90) async throws -> HelperStatus {
        let payload = try JSONEncoder().encode(request)
        let connection = currentConnection()
        return try await withCheckedThrowingContinuation { continuation in
            let gate = ResumeOnce(continuation)
            let proxy = connection.remoteObjectProxyWithErrorHandler { error in
                gate.finish(.failure(HelperClientError.unavailable(error.localizedDescription)))
            }
            guard let helper = proxy as? WireNestHelperXPC else {
                gate.finish(.failure(HelperClientError.unavailable("Unexpected XPC proxy.")))
                return
            }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                gate.finish(.failure(HelperClientError.unavailable("Timed out.")))
            }
            helper.perform(payload) { data in
                do {
                    let response = try JSONDecoder().decode(HelperResponse.self, from: data)
                    if let error = response.error {
                        gate.finish(.failure(HelperClientError.rejected(error)))
                    } else if let status = response.status {
                        gate.finish(.success(status))
                    } else {
                        gate.finish(.failure(HelperClientError.unavailable("Empty reply.")))
                    }
                } catch {
                    gate.finish(.failure(HelperClientError.unavailable("Unreadable reply.")))
                }
            }
        }
    }
}

/// XPC's error handler, its reply and the timeout can each fire; a continuation may resume only once.
private final class ResumeOnce {
    private let lock = NSLock()
    private var continuation: CheckedContinuation<HelperStatus, Error>?

    init(_ continuation: CheckedContinuation<HelperStatus, Error>) {
        self.continuation = continuation
    }

    func finish(_ result: Result<HelperStatus, Error>) {
        lock.lock()
        let pending = continuation
        continuation = nil
        lock.unlock()
        pending?.resume(with: result)
    }
}

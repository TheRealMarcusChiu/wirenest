import AppKit
import CoreLocation
import CoreWLAN
import Network
import WireNestCore

/// Reads what the OS reveals about the network. Used from the main actor; callbacks arrive on the main queue.
final class NetworkObserver: NSObject, CLLocationManagerDelegate {
    private let location = CLLocationManager()
    private let monitor = NWPathMonitor()
    private var wakeToken: NSObjectProtocol?

    var onNetworkEvent: (() -> Void)?
    var onLocationChange: (() -> Void)?
    /// The first Wi-Fi or Ethernet interface, never a VPN `utun`, so probes bound to it cannot leave through a tunnel.
    private(set) var physicalInterface: NWInterface?

    func start() {
        location.delegate = self
        monitor.pathUpdateHandler = { [weak self] path in
            let physical = path.availableInterfaces.first { $0.type == .wifi || $0.type == .wiredEthernet }
            DispatchQueue.main.async {
                self?.physicalInterface = physical
                self?.onNetworkEvent?()
            }
        }
        monitor.start(queue: DispatchQueue(label: "com.marcuschiu.WireNest.path"))
        wakeToken = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didWakeNotification, object: nil, queue: .main
        ) { [weak self] _ in
            self?.onNetworkEvent?()
        }
    }

    func requestLocationPermission() {
        location.requestWhenInUseAuthorization()
    }

    var locationStatus: CLAuthorizationStatus { location.authorizationStatus }

    func locationManagerDidChangeAuthorization(_ manager: CLLocationManager) {
        DispatchQueue.main.async { self.onLocationChange?() }
    }

    /// macOS returns no SSID without Location permission. The reason is kept so the UI can say why.
    func currentSSID() -> SSIDObservation {
        guard let wifi = CWWiFiClient.shared().interface() else { return .unavailable("No Wi-Fi hardware") }
        if let name = wifi.ssid(), !name.isEmpty { return .known(name) }
        switch locationStatus {
        case .notDetermined: return .unavailable("Location permission not requested yet")
        case .denied, .restricted: return .unavailable("Location permission denied")
        default: break
        }
        return wifi.powerOn() ? .unavailable("Not joined to a Wi-Fi network") : .unavailable("Wi-Fi is off")
    }
}

/// One HTTPS GET bound to a physical interface, so the answer is the network's address and not a tunnel's.
enum PublicIPProbe {
    static func fetch(_ endpoint: PublicIPEndpoint, over interface: NWInterface) async -> String? {
        await withCheckedContinuation { continuation in
            ProbeSession(endpoint: endpoint, interface: interface) { continuation.resume(returning: $0) }.start()
        }
    }
}

private final class ProbeSession {
    private static let maxBytes = 16 * 1024

    private let endpoint: PublicIPEndpoint
    private let connection: NWConnection
    private let queue = DispatchQueue(label: "com.marcuschiu.WireNest.probe")
    private var received = Data()
    private var completion: ((String?) -> Void)?

    init(endpoint: PublicIPEndpoint, interface: NWInterface, completion: @escaping (String?) -> Void) {
        self.endpoint = endpoint
        self.completion = completion
        let parameters = NWParameters.tls
        parameters.requiredInterface = interface
        connection = NWConnection(host: NWEndpoint.Host(endpoint.host), port: .https, using: parameters)
    }

    func start() {
        connection.stateUpdateHandler = { [self] state in
            switch state {
            case .ready:
                connection.send(content: endpoint.requestData, completion: .contentProcessed { [self] error in
                    if error != nil { finish() } else { receive() }
                })
            case .failed, .cancelled:
                finish()
            default:
                break
            }
        }
        connection.start(queue: queue)
        queue.asyncAfter(deadline: .now() + 15) { [self] in finish() }
    }

    private func receive() {
        connection.receive(minimumIncompleteLength: 1, maximumLength: Self.maxBytes) { [self] data, _, isComplete, error in
            if let data { received.append(data) }
            if isComplete || error != nil || received.count >= Self.maxBytes {
                finish()
            } else {
                receive()
            }
        }
    }

    private func finish() {
        guard let completion else { return }
        self.completion = nil
        connection.cancel()
        completion(publicIP(fromHTTPResponse: String(decoding: received, as: UTF8.self)))
    }
}

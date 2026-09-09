@preconcurrency import Foundation

public struct OutputServerAdvertisementConfiguration: Equatable, Sendable {
    public let name: String
    public let port: UInt16
    public let serverID: String

    public init(name: String, port: UInt16, serverID: String) {
        self.name = name
        self.port = port
        self.serverID = serverID
    }
}

public enum OutputServerAdvertisementState: Equatable, Sendable {
    case stopped
    case publishing
    case published
    case failed(errorCode: Int)
}

/// DNS-SD publication for the authenticated Apple control listener. This
/// adapter only advertises an already-bound listener; ownership of TLS, sockets,
/// and admission policy remains with the output-server service.
@MainActor
public final class OutputServerAdvertisement: NSObject, @preconcurrency NetServiceDelegate {
    public static let serviceType = "_ghostmedia._tcp."
    public static let domain = "local."

    public private(set) var state: OutputServerAdvertisementState = .stopped
    private var service: NetService?

    public override init() {}

    public func start(configuration: OutputServerAdvertisementConfiguration) {
        stop()
        let service = NetService(
            domain: Self.domain,
            type: Self.serviceType,
            name: configuration.name,
            port: Int32(configuration.port)
        )
        service.delegate = self
        service.setTXTRecord(Self.txtRecord(for: configuration))
        self.service = service
        state = .publishing
        service.publish(options: .noAutoRename)
    }

    public func stop() {
        service?.stop()
        service = nil
        state = .stopped
    }

    public static func txtRecord(for configuration: OutputServerAdvertisementConfiguration) -> Data {
        NetService.data(fromTXTRecord: [
            "role": Data(ProtocolRole.appleOutputServer.rawValue.utf8),
            "server_id": Data(configuration.serverID.utf8),
            "version": Data("1".utf8),
        ])
    }

    public func netServiceDidPublish(_ sender: NetService) {
        guard sender === service else { return }
        state = .published
    }

    public func netService(_ sender: NetService, didNotPublish errorDict: [String: NSNumber]) {
        guard sender === service else { return }
        state = .failed(errorCode: errorDict[NetService.errorCode]?.intValue ?? -1)
    }
}

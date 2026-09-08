public enum AppleHostPlatform: String, Sendable {
    case macOS
    case iOS
}

public enum ProtocolRole: String, Sendable {
    case appleOutputServer = "apple-output-server"
}

public struct HostConfiguration: Equatable, Sendable {
    public let displayName: String
    public let platform: AppleHostPlatform
    public let protocolRole: ProtocolRole

    public init(
        displayName: String,
        platform: AppleHostPlatform,
        protocolRole: ProtocolRole = .appleOutputServer
    ) {
        self.displayName = displayName
        self.platform = platform
        self.protocolRole = protocolRole
    }
}

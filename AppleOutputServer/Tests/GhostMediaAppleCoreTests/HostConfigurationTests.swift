import GhostMediaAppleCore
import Testing

@Test
func everyAppleHostUsesTheOutputServerProtocolRoleByDefault() {
    let macOS = HostConfiguration(displayName: "Mac", platform: .macOS)
    let iOS = HostConfiguration(displayName: "iPhone", platform: .iOS)

    #expect(macOS.protocolRole == .appleOutputServer)
    #expect(iOS.protocolRole == .appleOutputServer)
}

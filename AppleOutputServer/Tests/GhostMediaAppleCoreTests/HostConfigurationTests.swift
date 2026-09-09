import GhostMediaAppleCore
import Foundation
import Testing

@Test
func everyAppleHostUsesTheOutputServerProtocolRoleByDefault() {
    let macOS = HostConfiguration(displayName: "Mac", platform: .macOS)
    let iOS = HostConfiguration(displayName: "iPhone", platform: .iOS)

    #expect(macOS.protocolRole == .appleOutputServer)
    #expect(iOS.protocolRole == .appleOutputServer)
}

@Test
@MainActor
func outputServerAdvertisementUsesTheV1DNSServiceAndTXTFields() {
    let configuration = OutputServerAdvertisementConfiguration(
        name: "GhostMedia Test",
        port: 51_837,
        serverID: "01234567-89ab-cdef-0123-456789abcdef"
    )
    let record = NetService.dictionary(fromTXTRecord: OutputServerAdvertisement.txtRecord(for: configuration))

    #expect(OutputServerAdvertisement.serviceType == "_ghostmedia._tcp.")
    #expect(String(decoding: record["role"] ?? Data(), as: UTF8.self) == "apple-output-server")
    #expect(String(decoding: record["server_id"] ?? Data(), as: UTF8.self) == configuration.serverID)
    #expect(String(decoding: record["version"] ?? Data(), as: UTF8.self) == "1")
}

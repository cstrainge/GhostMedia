import GhostMediaAppleCore
import GhostMediaProtocolBridge
import SwiftUI

public struct OutputServerRootView: View {
    private let configuration: HostConfiguration
    private let coreVersion: ProtocolCoreVersion?

    public init(configuration: HostConfiguration) {
        self.configuration = configuration
        self.coreVersion = try? ProtocolCore.version()
    }

    public var body: some View {
        VStack(alignment: .leading, spacing: 20) {
            Image(systemName: "hifispeaker.2.fill")
                .font(.system(size: 42))
                .foregroundStyle(.tint)

            VStack(alignment: .leading, spacing: 6) {
                Text(configuration.displayName)
                    .font(.largeTitle.bold())
                Text("Apple output server foundation")
                    .font(.title3)
                    .foregroundStyle(.secondary)
            }

            LabeledContent("Host", value: configuration.platform.rawValue)
            LabeledContent("Protocol role", value: configuration.protocolRole.rawValue)

            if let coreVersion {
                LabeledContent(
                    "Shared core",
                    value: "ABI \(coreVersion.abi) · Protocol \(coreVersion.protocolMajor) · \(coreVersion.specificationRevision)"
                )
            } else {
                LabeledContent("Shared core", value: "Unavailable")
            }

            Divider()

            Label("Ready for output-server adapters", systemImage: "checkmark.circle")
                .foregroundStyle(.secondary)
        }
        .padding(32)
        .frame(minWidth: 560, minHeight: 340, alignment: .topLeading)
    }
}

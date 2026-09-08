import GhostMediaAppleCore
import GhostMediaAppleUI
import SwiftUI

@main
struct GhostMediaMacApp: App {
    private let configuration = HostConfiguration(
        displayName: "GhostMedia",
        platform: .macOS
    )

    var body: some Scene {
        WindowGroup {
            OutputServerRootView(configuration: configuration)
        }
        .defaultSize(width: 680, height: 440)
    }
}

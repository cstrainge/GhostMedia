import Foundation

public enum OutputServerState: Equatable, Sendable {
    case stopped
    case starting
    case advertising
    case listening
    case authenticating(clientLabel: String)
    case ready(clientLabel: String)
    case streaming(clientLabel: String)
    case failed(message: String)
}

public struct OutputServerSnapshot: Equatable, Sendable {
    public let state: OutputServerState
    public let capturedAt: ContinuousClock.Instant

    public init(
        state: OutputServerState,
        capturedAt: ContinuousClock.Instant = .now
    ) {
        self.state = state
        self.capturedAt = capturedAt
    }
}

/// The application-facing boundary for an Apple output-server implementation.
///
/// A concrete service composes the shared C ABI protocol core with Apple platform
/// adapters. UI code communicates through this boundary and never owns protocol
/// or real-time audio state directly.
public protocol OutputServerService: Sendable {
    func start() async throws
    func stop() async
    func snapshots() -> AsyncStream<OutputServerSnapshot>
}

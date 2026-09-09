import Darwin
import Foundation
import GhostMediaAppleSecurity
import GhostMediaProtocolBridge

private let testServerID = "01234567-89ab-cdef-0123-456789abcdef"
private let testSessionID = "00112233445566778899aabbccddeeff"
private let testBootID = "11111111-2222-3333-4444-555555555555"
private let testAppleUDPPort: UInt32 = 51_838
private let socketTimeoutSeconds = 10

private enum HarnessError: Error, CustomStringConvertible {
    case usage(String)
    case systemCall(operation: String, code: Int32)
    case connectionClosed
    case unexpectedMessage(String)

    var description: String {
        switch self {
        case .usage(let message):
            return message
        case .systemCall(let operation, let code):
            return "\(operation) failed: \(String(cString: strerror(code)))"
        case .connectionClosed:
            return "Windows probe closed the connection before the handshake completed"
        case .unexpectedMessage(let message):
            return message
        }
    }
}

private struct HarnessOptions {
    var listenPort: UInt16?
    var allowPlaintext = false
    var runPhase2Vectors = false
    var showHelp = false

    static func parse(_ arguments: [String]) throws -> HarnessOptions {
        var options = HarnessOptions()
        var index = 0
        while index < arguments.count {
            switch arguments[index] {
            case "--help", "-h":
                options.showHelp = true
            case "--allow-plaintext":
                options.allowPlaintext = true
            case "--phase2-vectors":
                options.runPhase2Vectors = true
            case "--listen":
                index += 1
                guard index < arguments.count,
                      let port = UInt16(arguments[index]),
                      port != 0 else {
                    throw HarnessError.usage("--listen requires a port in 1...65535")
                }
                options.listenPort = port
            default:
                throw HarnessError.usage("unknown argument: \(arguments[index])")
            }
            index += 1
        }

        if options.listenPort != nil && !options.allowPlaintext {
            throw HarnessError.usage(
                "--listen requires --allow-plaintext for this pre-TLS interoperability test"
            )
        }
        if options.listenPort != nil && options.runPhase2Vectors {
            throw HarnessError.usage("--listen and --phase2-vectors cannot be combined")
        }
        return options
    }
}

private final class SocketHandle {
    private(set) var descriptor: Int32

    init(_ descriptor: Int32) {
        self.descriptor = descriptor
    }

    deinit {
        if descriptor >= 0 {
            Darwin.close(descriptor)
        }
    }
}

@main
enum GhostMediaAppleHarness {
    static func main() {
        do {
            let options = try HarnessOptions.parse(Array(CommandLine.arguments.dropFirst()))
            if options.showHelp {
                printUsage()
            } else if let port = options.listenPort {
                try runListener(port: port)
            } else if options.runPhase2Vectors {
                try runPhase2Vectors()
            } else {
                try runDeterministicSmoke()
            }
        } catch {
            FileHandle.standardError.write(Data("error: \(error)\n".utf8))
            exit(EXIT_FAILURE)
        }
    }

    private static func printUsage() {
        print(
            """
            GhostMediaAppleHarness
              no arguments
                  Run the deterministic local Phase 1 smoke.
              --listen <port> --allow-plaintext
                  Accept one Windows control probe and exit after stream.open.
              --phase2-vectors
                  Run deterministic identity, exporter, and AES-GCM vector checks.

            The listener is pre-TLS and only for the first interoperability test.
            Stable test server ID: \(testServerID)
            """
        )
    }

    private static func runListener(port: UInt16) throws {
        _ = try ProtocolCore.version()
        let listener = try makeListener(port: port)

        print("warning: accepting pre-TLS control traffic for Phase 1 interoperability only")
        print("listening on 0.0.0.0:\(port)")
        print("server_id: \(testServerID)")
        fflush(stdout)

        let acceptedDescriptor = Darwin.accept(listener.descriptor, nil, nil)
        guard acceptedDescriptor >= 0 else {
            throw HarnessError.systemCall(operation: "accept", code: errno)
        }
        let connection = SocketHandle(acceptedDescriptor)
        try configureTimeouts(connection.descriptor)
        print("Windows probe connected")

        var decoder = ControlFrameDecoder()
        let hello = try receiveMessage(connection.descriptor, decoder: &decoder)
        try require(
            hello.kind == .requestSessionHello &&
                hello.id == 1 &&
                hello.role == "win-client" &&
                hello.udpPort != nil,
            "expected id:1 session.hello from win-client"
        )
        print("received session.hello")
        try sendResponse(
            """
            {"v":1,"id":1,"type":"result","result":{"version":1,"role":"apple-output-server","server_id":"\(testServerID)","session_id":"\(testSessionID)","boot_id":"\(testBootID)","udp_port":\(testAppleUDPPort),"capabilities":{"audio_send":false,"audio_receive":true,"microphone":false,"camera":false,"audio_profiles":[{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240}]},"limits":{"max_audio_subscribers":1,"playout_target_ms_min":15,"playout_target_ms_max":120}}}
            """,
            to: connection.descriptor
        )

        let bind = try receiveMessage(connection.descriptor, decoder: &decoder)
        try require(
            bind.kind == .requestTransportBind &&
                bind.id == 2 &&
                bind.sessionID == testSessionID &&
                bind.udpPort != nil,
            "expected id:2 transport.bind for the advertised session"
        )
        print("received transport.bind")
        try sendResponse(
            #"{"v":1,"id":2,"type":"result","result":{"udp_port":51838,"path_state":"bound"}}"#,
            to: connection.descriptor
        )

        let open = try receiveMessage(connection.descriptor, decoder: &decoder)
        try require(
            open.kind == .requestStreamOpen &&
                open.id == 3 &&
                open.playoutTargetMilliseconds != nil &&
                open.profile?.codec == .pcmS16LE,
            "expected id:3 PCM stream.open for win_to_apple"
        )
        print("received stream.open")
        try sendResponse(
            """
            {"v":1,"id":3,"type":"result","result":{"stream_id":1,"key_epoch":1,"profile":{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240},"packet_interval_us":5000,"path_state":"probing"}}
            """,
            to: connection.descriptor
        )

        print("control interop reached stream.open")
    }

    private static func makeListener(port: UInt16) throws -> SocketHandle {
        let descriptor = Darwin.socket(AF_INET, SOCK_STREAM, 0)
        guard descriptor >= 0 else {
            throw HarnessError.systemCall(operation: "socket", code: errno)
        }
        let listener = SocketHandle(descriptor)

        var reuseAddress: Int32 = 1
        guard setsockopt(
            descriptor,
            SOL_SOCKET,
            SO_REUSEADDR,
            &reuseAddress,
            socklen_t(MemoryLayout.size(ofValue: reuseAddress))
        ) == 0 else {
            throw HarnessError.systemCall(operation: "setsockopt(SO_REUSEADDR)", code: errno)
        }

        var address = sockaddr_in()
        address.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        address.sin_family = sa_family_t(AF_INET)
        address.sin_port = port.bigEndian
        address.sin_addr = in_addr(s_addr: INADDR_ANY)

        let bindResult = withUnsafePointer(to: &address) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.bind(
                    descriptor,
                    $0,
                    socklen_t(MemoryLayout<sockaddr_in>.size)
                )
            }
        }
        guard bindResult == 0 else {
            throw HarnessError.systemCall(operation: "bind", code: errno)
        }
        guard Darwin.listen(descriptor, 1) == 0 else {
            throw HarnessError.systemCall(operation: "listen", code: errno)
        }
        return listener
    }

    private static func configureTimeouts(_ descriptor: Int32) throws {
        var timeout = timeval(tv_sec: socketTimeoutSeconds, tv_usec: 0)
        for option in [SO_RCVTIMEO, SO_SNDTIMEO] {
            guard setsockopt(
                descriptor,
                SOL_SOCKET,
                option,
                &timeout,
                socklen_t(MemoryLayout.size(ofValue: timeout))
            ) == 0 else {
                throw HarnessError.systemCall(operation: "setsockopt(timeout)", code: errno)
            }
        }
    }

    private static func receiveMessage(
        _ descriptor: Int32,
        decoder: inout ControlFrameDecoder
    ) throws -> ControlMessage {
        while true {
            if let payload = try decoder.nextPayload() {
                return try ProtocolCore.parseControlMessage(payload)
            }

            var bytes = [UInt8](repeating: 0, count: 4096)
            let received = Darwin.recv(descriptor, &bytes, bytes.count, 0)
            if received < 0 {
                throw HarnessError.systemCall(operation: "recv", code: errno)
            }
            if received == 0 {
                throw HarnessError.connectionClosed
            }
            decoder.append(Data(bytes.prefix(received)))
        }
    }

    private static func sendResponse(_ json: String, to descriptor: Int32) throws {
        _ = try ProtocolCore.parseControlMessage(json)
        let frame = try ProtocolCore.encodeControlFrame(json)
        try frame.withUnsafeBytes { buffer in
            guard let baseAddress = buffer.baseAddress else {
                return
            }
            var sent = 0
            while sent < buffer.count {
                let result = Darwin.send(
                    descriptor,
                    baseAddress.advanced(by: sent),
                    buffer.count - sent,
                    0
                )
                if result < 0 {
                    throw HarnessError.systemCall(operation: "send", code: errno)
                }
                if result == 0 {
                    throw HarnessError.connectionClosed
                }
                sent += result
            }
        }
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        guard condition else {
            throw HarnessError.unexpectedMessage(message)
        }
    }

    private static func runDeterministicSmoke() throws {
        let version = try ProtocolCore.version()
        let hello = try ProtocolCore.parseControlMessage(
            """
            {"v":1,"id":1,"type":"session.hello","role":"win-client","client_name":"Phase 1 harness","versions":[1],"udp_port":49152}
            """
        )
        let streamOpen = try ProtocolCore.parseControlMessage(
            """
            {"v":1,"id":3,"type":"stream.open","kind":"audio","direction":"win_to_apple","profile":{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240},"playout_target_ms":30}
            """
        )
        let streamStart = try ProtocolCore.parseControlMessage(
            """
            {"v":1,"id":4,"type":"stream.start","stream_id":1,"first_media_timestamp":"240"}
            """
        )
        let handshakeResults = try [
            """
            {"v":1,"id":1,"type":"result","result":{"version":1,"role":"apple-output-server","server_id":"\(testServerID)","session_id":"\(testSessionID)","boot_id":"\(testBootID)","udp_port":51838,"capabilities":{"audio_send":false,"audio_receive":true,"microphone":false,"camera":false,"audio_profiles":[{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240}]},"limits":{"max_audio_subscribers":1,"playout_target_ms_min":15,"playout_target_ms_max":120}}}
            """,
            """
            {"v":1,"id":2,"type":"transport.bind","session_id":"\(testSessionID)","udp_port":49152}
            """,
            """
            {"v":1,"id":2,"type":"result","result":{"udp_port":51838,"path_state":"bound"}}
            """,
            """
            {"v":1,"id":3,"type":"result","result":{"stream_id":1,"key_epoch":1,"profile":{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240},"packet_interval_us":5000,"path_state":"probing"}}
            """,
            """
            {"v":1,"id":4,"type":"result","result":{"state":"started"}}
            """,
        ].map(ProtocolCore.parseControlMessage)
        let framedPing = try ProtocolCore.encodeControlFrame(
            #"{"v":1,"id":5,"type":"ping","token":"phase1"}"#
        )

        let sessionID = Array(UInt8(0)..<UInt8(16))
        let challenge = MediaHeader(
            kind: .pathChallenge,
            sessionID: sessionID,
            streamID: 1,
            direction: .windowsToApple,
            keyEpoch: 1,
            sequence: 1,
            mediaTimestamp: 0,
            payloadLength: 12
        )
        let response = MediaHeader(
            kind: .pathResponse,
            sessionID: sessionID,
            streamID: 1,
            direction: .appleToWindows,
            keyEpoch: 1,
            sequence: 2,
            mediaTimestamp: 0,
            payloadLength: 12
        )
        let encodedChallenge = try ProtocolCore.encodeMediaHeader(challenge)
        let encodedResponse = try ProtocolCore.encodeMediaHeader(response)

        var replayWindow = try ReplayWindow()
        let firstReplayDecision = try replayWindow.accept(sequence: 2_000)
        let duplicateReplayDecision = try replayWindow.accept(sequence: 2_000)

        print("GhostMedia Apple Phase 1 harness")
        print("core: ABI \(version.abi), protocol \(version.protocolMajor), spec \(version.specificationRevision)")
        print("hello: \(hello.kind), role \(hello.role ?? "missing"), UDP \(hello.udpPort ?? 0)")
        print("stream.open: \(streamOpen.kind), profile \(String(describing: streamOpen.profile))")
        print("stream.start: first timestamp \(streamStart.firstMediaTimestamp ?? "missing")")
        print("handshake continuation: \(handshakeResults.map(\.kind))")
        print("framing: \(try ProtocolCore.inspectControlFrame(framedPing))")
        print("path directions: challenge=\(encodedChallenge[28]) response=\(encodedResponse[28])")
        print("replay: first=\(firstReplayDecision) duplicate=\(duplicateReplayDecision)")
    }

    private static func runPhase2Vectors() throws {
        let windowsDigest = data(
            hex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        )
        let appleDigest = data(
            hex: "f0efeeedecebeae9e8e7e6e5e4e3e2e1e0dfdedddcdbdad9d8d7d6d5d4d3d2d1"
        )
        let sessionID = data(hex: testSessionID)
        let context = try ProtocolCore.exporterContext(
            ExporterContextInput(
                sessionID: sessionID,
                streamID: 1,
                direction: .windowsToApple,
                keyEpoch: 1,
                senderSPKIDigest: windowsDigest,
                receiverSPKIDigest: appleDigest
            )
        )
        try require(
            context == data(
                hex: "eae82ef20c131d0f5b03bb069b25d92b1d594ed041c02a8f474367c682087a02"
            ),
            "Windows-to-Apple exporter context did not match the Phase 2 vector"
        )

        let zeroKey = Data(repeating: 0, count: 32)
        let zeroNonce = Data(repeating: 0, count: 12)
        let sealed = try AppleAESGCM.seal(
            Data(),
            key: zeroKey,
            nonce: zeroNonce,
            authenticating: Data()
        )
        try require(
            sealed.ciphertext.isEmpty &&
                sealed.tag == data(hex: "530f8afbc74536b9a963b4f1c4cb738b"),
            "AES-256-GCM known-answer vector did not match"
        )

        let peerID = try ProtocolCore.peerID(forSPKIDigest: appleDigest)
        try require(
            peerID == "6dx653pm5pvot2hh43s6jy7c4hqn7xw53tn5vwoy27lnlvgt2liq",
            "Apple peer ID did not match the Phase 2 vector"
        )
        print("GhostMedia Apple Phase 2 vector harness")
        print("exporter label: \(ProtocolCore.tlsExporterLabel)")
        print("peer ID, exporter context, and AES-256-GCM vectors: passed")
    }

    private static func data(hex: String) -> Data {
        precondition(hex.count.isMultiple(of: 2))
        var output = Data()
        output.reserveCapacity(hex.count / 2)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            output.append(UInt8(hex[index..<next], radix: 16)!)
            index = next
        }
        return output
    }
}

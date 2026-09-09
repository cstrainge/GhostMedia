import Darwin
import Foundation
import GhostMediaAppleSecurity
import GhostMediaProtocolBridge
import GhostMediaRuntime

private let testServerID = "01234567-89ab-cdef-0123-456789abcdef"
private let testSessionID = "00112233445566778899aabbccddeeff"
private let testBootID = "11111111-2222-3333-4444-555555555555"
private let testAppleUDPPort: UInt32 = 51_838
private let socketTimeoutSeconds = 10
private let phase3PacketCount = 8
private let phase3WindowsPrivateKey = Data([
    0x01, 0x72, 0x65, 0x9f, 0x44, 0x3a, 0x8c, 0xd1,
    0x20, 0x6e, 0x55, 0x11, 0x93, 0x27, 0xba, 0x6f,
    0x32, 0xe8, 0x09, 0x4c, 0xa1, 0x7d, 0xf0, 0x58,
    0x6b, 0xc3, 0x16, 0x84, 0x2d, 0x97, 0x3e, 0xfa,
])
private let phase3ApplePrivateKey = Data([
    0xa2, 0x8b, 0x45, 0x19, 0xde, 0x70, 0x36, 0xc4,
    0x5f, 0x0d, 0x91, 0x2a, 0x68, 0xb7, 0xe3, 0x54,
    0x9c, 0x21, 0xf6, 0x80, 0x3b, 0xad, 0x47, 0xd2,
    0x75, 0x0e, 0x6a, 0x98, 0xc5, 0x14, 0xbf, 0x62,
])

private enum HarnessError: Error, CustomStringConvertible {
    case usage(String)
    case runtime(operation: String, status: String, detail: String)
    case connectionClosed
    case unexpectedMessage(String)

    var description: String {
        switch self {
        case .usage(let message):
            return message
        case .runtime(let operation, let status, let detail):
            return "\(operation) failed: \(status): \(detail)"
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
    var phase3Test = false
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
            case "--phase3-test":
                options.phase3Test = true
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

        if options.listenPort != nil && !options.allowPlaintext && !options.phase3Test {
            throw HarnessError.usage(
                "--listen requires --allow-plaintext or --phase3-test"
            )
        }
        if options.allowPlaintext && options.phase3Test {
            throw HarnessError.usage("choose only one of --allow-plaintext or --phase3-test")
        }
        if options.listenPort != nil && options.runPhase2Vectors {
            throw HarnessError.usage("--listen and --phase2-vectors cannot be combined")
        }
        return options
    }
}

private final class SocketHandle {
    let pointer: OpaquePointer

    init(_ pointer: OpaquePointer) {
        self.pointer = pointer
    }

    deinit {
        gm_runtime_tcp_socket_destroy(pointer)
    }
}

private final class UDPSocketHandle {
    let pointer: OpaquePointer

    init(_ pointer: OpaquePointer) {
        self.pointer = pointer
    }

    deinit {
        gm_runtime_udp_socket_destroy(pointer)
    }
}

private enum ControlTransport {
    case plaintext(OpaquePointer)
    case tls(AppleRuntimeTLSSession)
}

@main
enum GhostMediaAppleHarness {
    static func main() {
        do {
            let options = try HarnessOptions.parse(Array(CommandLine.arguments.dropFirst()))
            if options.showHelp {
                printUsage()
            } else if let port = options.listenPort {
                try runListener(port: port, phase3Test: options.phase3Test)
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
              --listen <port> --phase3-test
                  Accept pinned mutual TLS, validate UDP, and discard synthetic PCM.
              --phase2-vectors
                  Run deterministic identity, exporter, and AES-GCM vector checks.

            The plaintext listener is only for the first interoperability test.
            Stable test server ID: \(testServerID)
            """
        )
    }

    private static func runListener(port: UInt16, phase3Test: Bool) throws {
        _ = try ProtocolCore.version()
        let listener = try makeListener(port: port)

        print(phase3Test
            ? "Phase 3 test mode: accepting pinned mutual TLS and protected UDP"
            : "warning: accepting pre-TLS control traffic for Phase 1 interoperability only")
        print("listening on 0.0.0.0:\(port)")
        print("server_id: \(testServerID)")
        fflush(stdout)

        var acceptedPointer: OpaquePointer?
        try requireRuntimeOK(
            gm_runtime_tcp_accept(
                listener.pointer,
                UInt32(socketTimeoutSeconds * 1_000),
                &acceptedPointer
            ),
            operation: "accept"
        )
        guard let acceptedPointer else {
            throw HarnessError.unexpectedMessage("accept returned no connection")
        }
        let connection = SocketHandle(acceptedPointer)
        print("Windows probe connected")

        let transport: ControlTransport
        if phase3Test {
            let serverIdentity = try AppleOutputIdentity.phase3TestIdentity(
                privateKeyRaw: phase3ApplePrivateKey,
                serverID: UUID(uuidString: testServerID)!
            )
            let clientIdentity = try AppleOutputIdentity.phase3TestIdentity(
                privateKeyRaw: phase3WindowsPrivateKey
            )
            let tls = try AppleRuntimeTLSSession.accept(
                connection: connection.pointer,
                identity: serverIdentity,
                expectedClientSPKIDigest: clientIdentity.spkiDigest
            )
            try tls.handshake()
            transport = .tls(tls)
            try runSecureListener(
                transport: transport,
                udpSocket: try makeUDPListener(port: UInt16(testAppleUDPPort)),
                serverIdentity: serverIdentity,
                clientIdentity: clientIdentity,
                expectedWindowsHost: try tcpPeerHost(connection.pointer)
            )
            return
        }
        transport = .plaintext(connection.pointer)

        var decoder = ControlFrameDecoder()
        let hello = try receiveMessage(transport, decoder: &decoder)
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
            to: transport
        )

        let bind = try receiveMessage(transport, decoder: &decoder)
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
            to: transport
        )

        let open = try receiveMessage(transport, decoder: &decoder)
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
            to: transport
        )

        print("control interop reached stream.open")
    }

    private static func makeListener(port: UInt16) throws -> SocketHandle {
        var pointer: OpaquePointer?
        try requireRuntimeOK(
            gm_runtime_tcp_listen_ipv4(
                port,
                UInt32(socketTimeoutSeconds * 1_000),
                &pointer
            ),
            operation: "listen"
        )
        guard let pointer else {
            throw HarnessError.unexpectedMessage("listen returned no socket")
        }
        return SocketHandle(pointer)
    }

    private static func makeUDPListener(port: UInt16) throws -> UDPSocketHandle {
        var pointer: OpaquePointer?
        try requireRuntimeOK(
            gm_runtime_udp_bind_ipv4(
                port,
                UInt32(socketTimeoutSeconds * 1_000),
                &pointer
            ),
            operation: "udp bind"
        )
        guard let pointer else {
            throw HarnessError.unexpectedMessage("UDP bind returned no socket")
        }
        return UDPSocketHandle(pointer)
    }

    private static func tcpPeerHost(_ connection: OpaquePointer) throws -> String {
        var host = [CChar](repeating: 0, count: 64)
        var port: UInt16 = 0
        let status = host.withUnsafeMutableBufferPointer { bytes in
            gm_runtime_tcp_peer_ipv4(connection, bytes.baseAddress, bytes.count, &port)
        }
        try requireRuntimeOK(status, operation: "TCP peer address")
        guard port != 0 else {
            throw HarnessError.unexpectedMessage("TCP peer did not expose a port")
        }
        return String(cString: host)
    }

    private static func derivePhase3Keys(
        tls: AppleRuntimeTLSSession,
        sessionID: Data,
        streamID: UInt32,
        direction: MediaDirection,
        keyEpoch: UInt32,
        senderDigest: Data,
        receiverDigest: Data
    ) throws -> DirectionalKeys {
        let context = try ProtocolCore.exporterContext(
            ExporterContextInput(
                sessionID: sessionID,
                streamID: streamID,
                direction: direction,
                keyEpoch: keyEpoch,
                senderSPKIDigest: senderDigest,
                receiverSPKIDigest: receiverDigest
            )
        )
        return try ProtocolCore.splitExporterOutput(try tls.exporter(context: context))
    }

    private static func receiveUDP(_ socket: UDPSocketHandle) throws -> (Data, String, UInt16) {
        var buffer = [UInt8](repeating: 0, count: Int(GM_MEDIA_MAX_DATAGRAM_BYTES))
        var received = 0
        var source = [CChar](repeating: 0, count: 64)
        var port: UInt16 = 0
        let status = buffer.withUnsafeMutableBytes { bytes in
            source.withUnsafeMutableBufferPointer { sourceBytes in
                gm_runtime_udp_receive_from(
                    socket.pointer,
                    gm_mut_bytes(
                        data: bytes.bindMemory(to: UInt8.self).baseAddress,
                        size: bytes.count
                    ),
                    &received,
                    sourceBytes.baseAddress,
                    sourceBytes.count,
                    &port
                )
            }
        }
        try requireRuntimeOK(status, operation: "UDP receive")
        return (Data(buffer.prefix(received)), String(cString: source), port)
    }

    private static func sendUDP(
        _ socket: UDPSocketHandle,
        host: String,
        port: UInt16,
        datagram: Data
    ) throws {
        let status = host.withCString { hostPointer in
            datagram.withUnsafeBytes { bytes in
                gm_runtime_udp_send_to(
                    socket.pointer,
                    hostPointer,
                    port,
                    gm_bytes(
                        data: bytes.bindMemory(to: UInt8.self).baseAddress,
                        size: bytes.count
                    )
                )
            }
        }
        try requireRuntimeOK(status, operation: "UDP send")
    }

    private static func sealMedia(
        header: MediaHeader,
        plaintext: Data,
        key: Data
    ) throws -> Data {
        let aad = try ProtocolCore.buildMediaAAD(header)
        let nonce = try ProtocolCore.buildMediaNonce(
            keyEpoch: header.keyEpoch,
            sequence: header.sequence
        )
        let sealed = try AppleAESGCM.seal(plaintext, key: key, nonce: nonce, authenticating: aad)
        return aad + sealed.ciphertext + sealed.tag
    }

    private static func openMedia(_ datagram: Data, key: Data) throws -> (MediaHeader, Data) {
        let header = try ProtocolCore.decodeMediaHeader(from: datagram)
        let payloadStart = Int(GM_MEDIA_HEADER_BYTES)
        let payloadEnd = payloadStart + Int(header.payloadLength)
        guard datagram.count == payloadEnd + Int(GM_MEDIA_TAG_BYTES) else {
            throw HarnessError.unexpectedMessage("protected UDP datagram length changed after header decode")
        }
        let nonce = try ProtocolCore.buildMediaNonce(keyEpoch: header.keyEpoch, sequence: header.sequence)
        let plaintext = try AppleAESGCM.open(
            AESGCMSealedPayload(
                ciphertext: datagram.subdata(in: payloadStart..<payloadEnd),
                tag: datagram.subdata(in: payloadEnd..<datagram.count)
            ),
            key: key,
            nonce: nonce,
            authenticating: datagram.prefix(payloadStart)
        )
        return (header, plaintext)
    }

    private static func runSecureListener(
        transport: ControlTransport,
        udpSocket: UDPSocketHandle,
        serverIdentity: AppleOutputIdentity,
        clientIdentity: AppleOutputIdentity,
        expectedWindowsHost: String
    ) throws {
        guard case .tls(let tls) = transport else {
            throw HarnessError.unexpectedMessage("Phase 3 requires TLS transport")
        }
        var decoder = ControlFrameDecoder()
        var control = try ControlSession(configuration: ControlSessionConfiguration(
            serverID: testServerID,
            bootID: testBootID,
            sessionID: testSessionID,
            appleUDPPort: testAppleUDPPort
        ))
        var controlNow: UInt64 = 1
        let hello = try receiveMessage(transport, decoder: &decoder) { payload in
            let action = try control.ingest(payload, nowNanoseconds: controlNow)
            controlNow += 1
            try require(action.kind == .sessionHelloResult, "shared control state rejected session.hello")
        }
        try require(
            hello.kind == .requestSessionHello && hello.id == 1 && hello.role == "win-client" && hello.udpPort != nil,
            "expected encrypted id:1 session.hello from win-client"
        )
        try sendResponse(
            """
            {"v":1,"id":1,"type":"result","result":{"version":1,"role":"apple-output-server","server_id":"\(testServerID)","session_id":"\(testSessionID)","boot_id":"\(testBootID)","udp_port":\(testAppleUDPPort),"capabilities":{"audio_send":false,"audio_receive":true,"microphone":false,"camera":false,"audio_profiles":[{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240}]},"limits":{"max_audio_subscribers":1,"playout_target_ms_min":15,"playout_target_ms_max":120}}}
            """,
            to: transport
        )
        let bind = try receiveMessage(transport, decoder: &decoder) { payload in
            let action = try control.ingest(payload, nowNanoseconds: controlNow)
            controlNow += 1
            try require(action.kind == .transportBindResult, "shared control state rejected transport.bind")
        }
        try require(
            bind.kind == .requestTransportBind && bind.id == 2 && bind.sessionID == testSessionID && bind.udpPort == hello.udpPort,
            "expected encrypted id:2 transport.bind for the prebound Windows UDP port"
        )
        try sendResponse(#"{"v":1,"id":2,"type":"result","result":{"udp_port":51838,"path_state":"bound"}}"#, to: transport)

        let open = try receiveMessage(transport, decoder: &decoder) { payload in
            let action = try control.ingest(payload, nowNanoseconds: controlNow)
            controlNow += 1
            try require(action.kind == .streamOpenResult, "shared control state rejected stream.open")
        }
        try require(
            open.kind == .requestStreamOpen && open.id == 3 && open.profile?.codec == .pcmS16LE,
            "expected encrypted id:3 PCM stream.open"
        )
        try sendResponse(
            """
            {"v":1,"id":3,"type":"result","result":{"stream_id":1,"key_epoch":1,"profile":{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240},"packet_interval_us":5000,"path_state":"probing"}}
            """,
            to: transport
        )

        let sessionID = data(hex: testSessionID)
        let forward = try derivePhase3Keys(
            tls: tls, sessionID: sessionID, streamID: 1, direction: .windowsToApple, keyEpoch: 1,
            senderDigest: clientIdentity.spkiDigest, receiverDigest: serverIdentity.spkiDigest
        )
        let reverse = try derivePhase3Keys(
            tls: tls, sessionID: sessionID, streamID: 1, direction: .appleToWindows, keyEpoch: 1,
            senderDigest: serverIdentity.spkiDigest, receiverDigest: clientIdentity.spkiDigest
        )
        let (challengeDatagram, sourceHost, sourcePort) = try receiveUDP(udpSocket)
        guard sourceHost == expectedWindowsHost && sourcePort == UInt16(hello.udpPort ?? 0) else {
            throw HarnessError.unexpectedMessage("PATH_CHALLENGE tuple did not match the authenticated control peer")
        }
        let (challengeHeader, challenge) = try openMedia(challengeDatagram, key: forward.pathKey)
        try require(
            challengeHeader.kind == .pathChallenge && challengeHeader.direction == .windowsToApple &&
                challengeHeader.sessionID == Array(sessionID) && challengeHeader.streamID == 1 &&
                challengeHeader.keyEpoch == 1 && challenge.count == 12,
            "invalid authenticated PATH_CHALLENGE"
        )
        let responseHeader = MediaHeader(
            kind: .pathResponse, sessionID: Array(sessionID), streamID: 1,
            direction: .appleToWindows, keyEpoch: 1, sequence: 1,
            mediaTimestamp: 0, payloadLength: UInt32(challenge.count)
        )
        try sendUDP(
            udpSocket, host: sourceHost, port: sourcePort,
            datagram: try sealMedia(header: responseHeader, plaintext: challenge, key: reverse.pathKey)
        )
        try require(
            try control.markPathValidated(streamID: 1, keyEpoch: 1).kind == .pathValidated,
            "shared control state rejected validated UDP path"
        )
        print("protected UDP path validated for \(sourceHost):\(sourcePort)")

        let start = try receiveMessage(transport, decoder: &decoder) { payload in
            let action = try control.ingest(payload, nowNanoseconds: controlNow)
            controlNow += 1
            try require(action.kind == .streamStartResult, "shared control state rejected stream.start")
        }
        try require(
            start.kind == .requestStreamStart && start.id == 4 && start.streamID == 1 && start.firstMediaTimestamp != nil,
            "expected encrypted stream.start after validated path"
        )
        try sendResponse(#"{"v":1,"id":4,"type":"result","result":{"state":"started"}}"#, to: transport)

        var replay = try ReplayWindow()
        var acceptedPackets = 0
        var expectedTimestamp = UInt64(start.firstMediaTimestamp!)!
        while acceptedPackets < phase3PacketCount {
            let (datagram, host, port) = try receiveUDP(udpSocket)
            guard host == sourceHost && port == sourcePort else {
                throw HarnessError.unexpectedMessage("audio arrived from an unbound UDP tuple")
            }
            let (header, pcm) = try openMedia(datagram, key: forward.mediaKey)
            guard header.kind == .audio && header.direction == .windowsToApple &&
                header.sessionID == Array(sessionID) && header.streamID == 1 && header.keyEpoch == 1 &&
                header.mediaTimestamp == expectedTimestamp && pcm.count == Int(GM_AUDIO_PCM_S16LE_PAYLOAD_BYTES) else {
                throw HarnessError.unexpectedMessage("invalid encrypted synthetic PCM packet")
            }
            guard try replay.accept(sequence: header.sequence) == .accepted else {
                throw HarnessError.unexpectedMessage("duplicate or stale synthetic PCM packet")
            }
            acceptedPackets += 1
            expectedTimestamp += 240
        }
        let metrics = try control.metrics()
        try require(
            metrics.validRequests == 4 && metrics.streamsStarted == 1,
            "shared control metrics did not record the Phase 3 lifecycle"
        )
        print("Phase 3 secure media complete: discarded \(acceptedPackets) authenticated PCM packets")
        print("control metrics: requests=\(metrics.validRequests) starts=\(metrics.streamsStarted)")
    }

    private static func receiveMessage(
        _ transport: ControlTransport,
        decoder: inout ControlFrameDecoder,
        beforeParsing: ((Data) throws -> Void)? = nil
    ) throws -> ControlMessage {
        while true {
            if let payload = try decoder.nextPayload() {
                try beforeParsing?(payload)
                return try ProtocolCore.parseControlMessage(payload)
            }

            var bytes = [UInt8](repeating: 0, count: 4096)
            var received = 0
            switch transport {
            case .plaintext(let connection):
                let status = bytes.withUnsafeMutableBytes { buffer in
                    gm_runtime_tcp_receive(
                        connection,
                        gm_mut_bytes(
                            data: buffer.bindMemory(to: UInt8.self).baseAddress,
                            size: buffer.count
                        ),
                        &received
                    )
                }
                try requireRuntimeOK(status, operation: "receive")
            case .tls(let tls):
                received = try tls.receive(into: &bytes)
            }
            decoder.append(Data(bytes.prefix(received)))
        }
    }

    private static func sendResponse(_ json: String, to transport: ControlTransport) throws {
        _ = try ProtocolCore.parseControlMessage(json)
        let frame = try ProtocolCore.encodeControlFrame(json)
        switch transport {
        case .plaintext(let connection):
            let status = frame.withUnsafeBytes { buffer in
                gm_runtime_tcp_send_all(
                    connection,
                    gm_bytes(
                        data: buffer.bindMemory(to: UInt8.self).baseAddress,
                        size: buffer.count
                    )
                )
            }
            try requireRuntimeOK(status, operation: "send")
        case .tls(let tls):
            try tls.sendAll(frame)
        }
    }

    private static func require(_ condition: Bool, _ message: String) throws {
        guard condition else {
            throw HarnessError.unexpectedMessage(message)
        }
    }

    private static func requireRuntimeOK(
        _ status: gm_status,
        operation: String
    ) throws {
        guard status == GM_OK else {
            throw HarnessError.runtime(
                operation: operation,
                status: String(cString: gm_status_string(status)),
                detail: String(cString: gm_runtime_last_error())
            )
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
        let tlsClient = try AppleOutputIdentity.ephemeral()
        let tlsServer = try AppleOutputIdentity.ephemeral()
        let liveContext = try ProtocolCore.exporterContext(
            ExporterContextInput(
                sessionID: sessionID,
                streamID: 1,
                direction: .windowsToApple,
                keyEpoch: 1,
                senderSPKIDigest: tlsClient.spkiDigest,
                receiverSPKIDigest: tlsServer.spkiDigest
            )
        )
        let liveExporter = try AppleRuntimeTLS.exporterPair(
            client: tlsClient,
            server: tlsServer,
            clientExpectedServerSPKIDigest: tlsServer.spkiDigest,
            serverExpectedClientSPKIDigest: tlsClient.spkiDigest,
            context: liveContext
        )
        try require(
            liveExporter.client == liveExporter.server,
            "mutual TLS peers produced different exporter output"
        )
        print("GhostMedia Apple Phase 2 vector harness")
        print("exporter label: \(ProtocolCore.tlsExporterLabel)")
        print("peer ID, exporter context, AES-256-GCM, and mutual TLS 1.3: passed")
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

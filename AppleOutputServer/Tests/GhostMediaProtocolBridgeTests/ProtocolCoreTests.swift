import Foundation
@testable import GhostMediaProtocolBridge
import Testing

@Test
func sharedCoreVersionIsAvailableThroughTheSwiftBridge() throws {
    let version = try ProtocolCore.version()

    #expect(version.abi == 1)
    #expect(version.protocolMajor == 1)
    #expect(version.specificationRevision == "1.0-draft.1")
}

@Test
func incompatibleCoreVersionsFailBeforeIntegrationStarts() {
    #expect(
        throws: ProtocolCoreError.incompatibleCore(
            expectedABI: 1,
            actualABI: 2,
            expectedProtocolMajor: 1,
            actualProtocolMajor: 1
        )
    ) {
        try ProtocolCore.validatedVersion(
            abi: 2,
            protocolMajor: 1,
            specificationRevision: "future"
        )
    }

    #expect(
        throws: ProtocolCoreError.incompatibleCore(
            expectedABI: 1,
            actualABI: 1,
            expectedProtocolMajor: 1,
            actualProtocolMajor: 2
        )
    ) {
        try ProtocolCore.validatedVersion(
            abi: 1,
            protocolMajor: 2,
            specificationRevision: "future"
        )
    }
}

@Test
func sharedCoreOwnsControlSchemaAcceptance() throws {
    let hello = try ProtocolCore.parseControlMessage(
        """
        {"v":1,"id":1,"type":"session.hello","role":"win-client","client_name":"Swift harness","versions":[2,1],"udp_port":49152}
        """
    )
    #expect(hello.kind == .requestSessionHello)
    #expect(hello.role == "win-client")
    #expect(hello.versions == [2, 1])
    #expect(hello.udpPort == 49_152)
    #expect(hello.isMutating)

    #expect(throws: ProtocolCoreError.self) {
        try ProtocolCore.parseControlMessage(
            """
            {"v":1,"id":1,"type":"session.hello","role":"mac-client","client_name":"stale","versions":[1],"udp_port":49152}
            """
        )
    }

    let streamOpen = try ProtocolCore.parseControlMessage(
        """
        {"v":1,"id":3,"type":"stream.open","kind":"audio","direction":"win_to_apple","profile":{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240},"playout_target_ms":30}
        """
    )
    #expect(streamOpen.kind == .requestStreamOpen)
    #expect(streamOpen.playoutTargetMilliseconds == 30)
    #expect(
        streamOpen.profile == AudioProfile(
            codec: .pcmS16LE,
            sampleRateHz: 48_000,
            channels: 2,
            framesPerPacket: 240,
            channelLayout: .stereo,
            packetIntervalMicroseconds: 5_000,
            payloadBytes: 960
        )
    )

    #expect(throws: ProtocolCoreError.self) {
        try ProtocolCore.parseControlMessage(
            """
            {"v":1,"id":3,"type":"stream.open","kind":"audio","direction":"win_to_mac","profile":{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240},"playout_target_ms":30}
            """
        )
    }
}

@Test
func phaseOneHandshakeFieldsCrossTheCABI() throws {
    let transportBind = try ProtocolCore.parseControlMessage(
        #"{"v":1,"id":2,"type":"transport.bind","session_id":"00112233445566778899aabbccddeeff","udp_port":49152}"#
    )
    #expect(transportBind.kind == .requestTransportBind)
    #expect(transportBind.sessionID == "00112233445566778899aabbccddeeff")
    #expect(transportBind.udpPort == 49_152)

    let transportBound = try ProtocolCore.parseControlMessage(
        #"{"v":1,"id":2,"type":"result","result":{"udp_port":51838,"path_state":"bound"}}"#
    )
    #expect(transportBound.kind == .responseResult)
    #expect(transportBound.udpPort == 51_838)
    #expect(transportBound.pathState == "bound")

    let streamOpened = try ProtocolCore.parseControlMessage(
        """
        {"v":1,"id":3,"type":"result","result":{"stream_id":1,"key_epoch":1,"profile":{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240},"packet_interval_us":5000,"path_state":"probing"}}
        """
    )
    #expect(streamOpened.kind == .responseResult)
    #expect(streamOpened.streamID == 1)
    #expect(streamOpened.keyEpoch == 1)
    #expect(streamOpened.pathState == "probing")
    #expect(streamOpened.profile?.codec == .pcmS16LE)

    let streamStart = try ProtocolCore.parseControlMessage(
        #"{"v":1,"id":4,"type":"stream.start","stream_id":1,"first_media_timestamp":"240"}"#
    )
    #expect(streamStart.kind == .requestStreamStart)
    #expect(streamStart.streamID == 1)
    #expect(streamStart.firstMediaTimestamp == "240")

    #expect(throws: ProtocolCoreError.self) {
        try ProtocolCore.parseControlMessage(
            #"{"v":1,"id":4,"type":"stream.start","stream_id":1}"#
        )
    }

    let streamStarted = try ProtocolCore.parseControlMessage(
        #"{"v":1,"id":4,"type":"result","result":{"state":"started"}}"#
    )
    #expect(streamStarted.kind == .responseResult)
    #expect(streamStarted.state == "started")

    let helloResult = try ProtocolCore.parseControlMessage(
        """
        {"v":1,"id":6,"type":"result","result":{"version":1,"role":"apple-output-server","server_id":"01234567-89ab-cdef-0123-456789abcdef","session_id":"00112233445566778899aabbccddeeff","boot_id":"11111111-2222-3333-4444-555555555555","udp_port":49152,"capabilities":{"audio_send":false,"audio_receive":true,"microphone":false,"camera":false,"audio_profiles":[{"codec":"pcm_s16le","sample_rate_hz":48000,"channels":2,"channel_layout":"stereo","frames_per_packet":240}]},"limits":{"max_audio_subscribers":1,"playout_target_ms_min":15,"playout_target_ms_max":120}}}
        """
    )
    #expect(helloResult.kind == .responseResult)
    #expect(helloResult.role == "apple-output-server")
    #expect(helloResult.serverID == "01234567-89ab-cdef-0123-456789abcdef")
    #expect(helloResult.sessionID == "00112233445566778899aabbccddeeff")
    #expect(helloResult.bootID == "11111111-2222-3333-4444-555555555555")

    let outputEvent = try ProtocolCore.parseControlMessage(
        #"{"v":1,"type":"event.output.state","state":"available","reason":"ROUTE_READY"}"#
    )
    #expect(outputEvent.kind == .eventOutputState)
    #expect(outputEvent.state == "available")
    #expect(outputEvent.reason == "ROUTE_READY")

    let expiringEvent = try ProtocolCore.parseControlMessage(
        #"{"v":1,"type":"event.session.expiring","reason":"SERVER_RESTART","deadline_monotonic_ns":"123456789"}"#
    )
    #expect(expiringEvent.kind == .eventSessionExpiring)
    #expect(expiringEvent.reason == "SERVER_RESTART")
    #expect(expiringEvent.monotonicNanoseconds == "123456789")

    #expect(throws: ProtocolCoreError.self) {
        try ProtocolCore.parseControlMessage(
            #"{"v":1,"type":"event.path.validated","stream_id":1,"key_epoch":1}"#
        )
    }
}

@Test
func controlFramingIsByteIdenticalThroughSwift() throws {
    let json = #"{"v":1,"id":1,"type":"ping","token":"a"}"#
    let frame = try ProtocolCore.encodeControlFrame(json)

    #expect(Array(frame.prefix(4)) == [0, 0, 0, UInt8(json.utf8.count)])
    #expect(
        try ProtocolCore.inspectControlFrame(frame.prefix(3)) ==
            .needsMoreData(expectedFrameSize: nil)
    )
    #expect(
        try ProtocolCore.inspectControlFrame(frame.dropLast()) ==
            .needsMoreData(expectedFrameSize: frame.count)
    )
    #expect(
        try ProtocolCore.inspectControlFrame(frame) ==
            .complete(payloadLength: json.utf8.count, frameSize: frame.count)
    )
}

@Test
func controlFrameDecoderHandlesFragmentationAndCoalescing() throws {
    let firstJSON = #"{"v":1,"id":1,"type":"ping","token":"one"}"#
    let secondJSON = #"{"v":1,"id":2,"type":"ping","token":"two"}"#
    let firstFrame = try ProtocolCore.encodeControlFrame(firstJSON)
    let secondFrame = try ProtocolCore.encodeControlFrame(secondJSON)
    var decoder = ControlFrameDecoder()

    decoder.append(firstFrame.prefix(3))
    #expect(try decoder.nextPayload() == nil)

    var remainderAndSecondFrame = Data(firstFrame.dropFirst(3))
    remainderAndSecondFrame.append(secondFrame)
    decoder.append(remainderAndSecondFrame)

    #expect(try decoder.nextPayload() == Data(firstJSON.utf8))
    #expect(try decoder.nextPayload() == Data(secondJSON.utf8))
    #expect(try decoder.nextPayload() == nil)
    #expect(decoder.bufferedByteCount == 0)
}

@Test
func mediaLayoutNonceAndReplayCrossTheCABI() throws {
    let sessionID = Array(UInt8(0)..<UInt8(16))
    let challenge = MediaHeader(
        kind: .pathChallenge,
        sessionID: sessionID,
        streamID: 7,
        direction: .windowsToApple,
        keyEpoch: 1,
        sequence: 0x0102030405060708,
        mediaTimestamp: 0,
        payloadLength: 12
    )
    let response = MediaHeader(
        kind: .pathResponse,
        sessionID: sessionID,
        streamID: 7,
        direction: .appleToWindows,
        keyEpoch: 1,
        sequence: 2,
        mediaTimestamp: 0,
        payloadLength: 12
    )

    let challengeBytes = try ProtocolCore.encodeMediaHeader(challenge)
    let responseBytes = try ProtocolCore.encodeMediaHeader(response)
    #expect(challengeBytes[28] == 1)
    #expect(responseBytes[28] == 2)

    var datagram = challengeBytes
    datagram.append(Data(repeating: 0, count: 12 + 16))
    #expect(try ProtocolCore.decodeMediaHeader(from: datagram) == challenge)

    let nonce = try ProtocolCore.buildMediaNonce(
        keyEpoch: 2,
        sequence: 0x0102030405060708
    )
    #expect(Array(nonce) == [0, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8])

    var replayWindow = try ReplayWindow()
    #expect(try replayWindow.accept(sequence: 2_000) == .accepted)
    #expect(try replayWindow.accept(sequence: 2_000) == .duplicate)
    #expect(try replayWindow.accept(sequence: 977) == .accepted)
    #expect(try replayWindow.accept(sequence: 976) == .tooOld)
}

@Test
func audioProfilesAreValidatedByTheSharedCore() throws {
    let pcm = AudioProfile(
        codec: .pcmS16LE,
        sampleRateHz: 48_000,
        channels: 2,
        framesPerPacket: 240,
        channelLayout: .stereo,
        packetIntervalMicroseconds: 5_000,
        payloadBytes: 960
    )
    try ProtocolCore.validateAudioProfile(pcm)

    let stalePacketDuration = AudioProfile(
        codec: .pcmS16LE,
        sampleRateHz: 48_000,
        channels: 2,
        framesPerPacket: 480,
        channelLayout: .stereo,
        packetIntervalMicroseconds: 10_000,
        payloadBytes: 1_920
    )
    #expect(throws: ProtocolCoreError.self) {
        try ProtocolCore.validateAudioProfile(stalePacketDuration)
    }
}

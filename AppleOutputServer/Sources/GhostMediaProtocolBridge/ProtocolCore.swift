import Foundation
import GhostMediaCore

public struct ProtocolCoreVersion: Equatable, Sendable {
    public let abi: UInt32
    public let protocolMajor: UInt32
    public let specificationRevision: String

    public init(abi: UInt32, protocolMajor: UInt32, specificationRevision: String) {
        self.abi = abi
        self.protocolMajor = protocolMajor
        self.specificationRevision = specificationRevision
    }
}

public enum ProtocolCoreError: Error, Equatable, Sendable {
    case callFailed(operation: String, status: String)
    case missingSpecificationRevision
    case incompatibleCore(
        expectedABI: UInt32,
        actualABI: UInt32,
        expectedProtocolMajor: UInt32,
        actualProtocolMajor: UInt32
    )
    case invalidSessionIDLength(expected: Int, actual: Int)
}

public enum ControlMessageKind: Equatable, Sendable {
    case requestSessionHello
    case requestTransportBind
    case requestStreamOpen
    case requestStreamStart
    case requestStreamStop
    case requestStreamClose
    case requestStreamRekey
    case requestStatusGet
    case requestPing
    case requestSessionClose
    case responseResult
    case responseError
    case eventStreamStarted
    case eventStreamStopped
    case eventOutputState
    case eventSessionExpiring
    case unknown(UInt32)
}

public enum AudioCodec: Equatable, Sendable {
    case pcmS16LE
    case opus
    case unknown(UInt32)
}

public enum ChannelLayout: Equatable, Sendable {
    case stereo
    case unknown(UInt32)
}

public struct AudioProfile: Equatable, Sendable {
    public let codec: AudioCodec
    public let sampleRateHz: UInt32
    public let channels: UInt16
    public let framesPerPacket: UInt16
    public let channelLayout: ChannelLayout
    public let packetIntervalMicroseconds: UInt32
    public let payloadBytes: UInt32

    public init(
        codec: AudioCodec,
        sampleRateHz: UInt32,
        channels: UInt16,
        framesPerPacket: UInt16,
        channelLayout: ChannelLayout,
        packetIntervalMicroseconds: UInt32,
        payloadBytes: UInt32
    ) {
        self.codec = codec
        self.sampleRateHz = sampleRateHz
        self.channels = channels
        self.framesPerPacket = framesPerPacket
        self.channelLayout = channelLayout
        self.packetIntervalMicroseconds = packetIntervalMicroseconds
        self.payloadBytes = payloadBytes
    }
}

public struct ControlMessage: Equatable, Sendable {
    public let kind: ControlMessageKind
    public let id: UInt32?
    public let isMutating: Bool
    public let udpPort: UInt32?
    public let streamID: UInt32?
    public let keyEpoch: UInt32?
    public let playoutTargetMilliseconds: UInt32?
    public let versions: [UInt8]
    public let profile: AudioProfile?
    public let type: String
    public let role: String?
    public let clientName: String?
    public let serverID: String?
    public let bootID: String?
    public let sessionID: String?
    public let token: String?
    public let reason: String?
    public let state: String?
    public let pathState: String?
    public let outputState: String?
    public let sessionStreamState: String?
    public let transportState: String?
    public let firstMediaTimestamp: String?
    public let monotonicNanoseconds: String?
}

public enum ControlFrameInspection: Equatable, Sendable {
    case needsMoreData(expectedFrameSize: Int?)
    case complete(payloadLength: Int, frameSize: Int)
}

public struct ControlFrameDecoder: Sendable {
    private var bufferedBytes = Data()

    public init() {}

    public var bufferedByteCount: Int {
        bufferedBytes.count
    }

    public mutating func append(_ bytes: Data) {
        bufferedBytes.append(bytes)
    }

    public mutating func nextPayload() throws -> Data? {
        switch try ProtocolCore.inspectControlFrame(bufferedBytes) {
        case .needsMoreData:
            return nil
        case .complete(let payloadLength, let frameSize):
            let headerLength = frameSize - payloadLength
            let payload = bufferedBytes.subdata(in: headerLength..<frameSize)
            bufferedBytes.removeSubrange(0..<frameSize)
            return payload
        }
    }
}

public enum MediaKind: Equatable, Sendable {
    case audio
    case pathChallenge
    case pathResponse
    case feedback
}

public enum MediaDirection: Equatable, Sendable {
    case windowsToApple
    case appleToWindows
}

public struct MediaHeader: Equatable, Sendable {
    public let kind: MediaKind
    public let sessionID: [UInt8]
    public let streamID: UInt32
    public let direction: MediaDirection
    public let keyEpoch: UInt32
    public let sequence: UInt64
    public let mediaTimestamp: UInt64
    public let payloadLength: UInt32

    public init(
        kind: MediaKind,
        sessionID: [UInt8],
        streamID: UInt32,
        direction: MediaDirection,
        keyEpoch: UInt32,
        sequence: UInt64,
        mediaTimestamp: UInt64,
        payloadLength: UInt32
    ) {
        self.kind = kind
        self.sessionID = sessionID
        self.streamID = streamID
        self.direction = direction
        self.keyEpoch = keyEpoch
        self.sequence = sequence
        self.mediaTimestamp = mediaTimestamp
        self.payloadLength = payloadLength
    }
}

public enum ReplayDecision: Equatable, Sendable {
    case accepted
    case duplicate
    case tooOld
}

public struct ReplayWindow {
    private var rawValue: gm_replay_window

    public init() throws {
        var rawValue = gm_replay_window()
        rawValue.struct_size = MemoryLayout<gm_replay_window>.size
        try ProtocolCore.requireOK(
            gm_replay_window_init(&rawValue),
            operation: "gm_replay_window_init"
        )
        self.rawValue = rawValue
    }

    public mutating func accept(sequence: UInt64) throws -> ReplayDecision {
        var result: UInt32 = 0
        try ProtocolCore.requireOK(
            gm_replay_window_accept(&rawValue, sequence, &result),
            operation: "gm_replay_window_accept"
        )

        switch result {
        case UInt32(GM_REPLAY_ACCEPTED.rawValue):
            return .accepted
        case UInt32(GM_REPLAY_DUPLICATE.rawValue):
            return .duplicate
        case UInt32(GM_REPLAY_TOO_OLD.rawValue):
            return .tooOld
        default:
            throw ProtocolCoreError.callFailed(
                operation: "gm_replay_window_accept",
                status: "GM_UNKNOWN_REPLAY_RESULT"
            )
        }
    }
}

public enum ProtocolCore {
    public static func version() throws -> ProtocolCoreVersion {
        var rawVersion = gm_core_version()
        rawVersion.struct_size = MemoryLayout<gm_core_version>.size

        try requireOK(gm_get_version(&rawVersion), operation: "gm_get_version")
        guard let revision = rawVersion.spec_revision else {
            throw ProtocolCoreError.missingSpecificationRevision
        }

        return try validatedVersion(
            abi: rawVersion.abi_version,
            protocolMajor: rawVersion.protocol_major,
            specificationRevision: String(cString: revision)
        )
    }

    static func validatedVersion(
        abi: UInt32,
        protocolMajor: UInt32,
        specificationRevision: String
    ) throws -> ProtocolCoreVersion {
        let expectedABI = UInt32(GM_ABI_VERSION)
        let expectedProtocolMajor = UInt32(GM_PROTOCOL_MAJOR)
        guard abi == expectedABI, protocolMajor == expectedProtocolMajor else {
            throw ProtocolCoreError.incompatibleCore(
                expectedABI: expectedABI,
                actualABI: abi,
                expectedProtocolMajor: expectedProtocolMajor,
                actualProtocolMajor: protocolMajor
            )
        }

        return ProtocolCoreVersion(
            abi: abi,
            protocolMajor: protocolMajor,
            specificationRevision: specificationRevision
        )
    }

    public static func parseControlMessage(_ json: String) throws -> ControlMessage {
        try parseControlMessage(Data(json.utf8))
    }

    public static func parseControlMessage(_ json: Data) throws -> ControlMessage {
        var rawMessage = gm_control_message_info()
        rawMessage.struct_size = MemoryLayout<gm_control_message_info>.size

        let status = json.withUnsafeBytes { buffer in
            gm_control_parse_message(
                gm_bytes(
                    data: buffer.bindMemory(to: UInt8.self).baseAddress,
                    size: buffer.count
                ),
                &rawMessage
            )
        }
        try requireOK(status, operation: "gm_control_parse_message")

        let versions = withUnsafeBytes(of: rawMessage.versions) { buffer in
            Array(buffer.prefix(Int(rawMessage.versions_count)))
        }
        let profile = rawMessage.profile.codec == UInt32(GM_AUDIO_CODEC_UNKNOWN.rawValue)
            ? nil
            : audioProfile(from: rawMessage.profile)

        return ControlMessage(
            kind: controlMessageKind(from: rawMessage.kind),
            id: optionalNonzero(rawMessage.id),
            isMutating: rawMessage.mutating != 0,
            udpPort: optionalNonzero(rawMessage.udp_port),
            streamID: optionalNonzero(rawMessage.stream_id),
            keyEpoch: optionalNonzero(rawMessage.key_epoch),
            playoutTargetMilliseconds: optionalNonzero(rawMessage.playout_target_ms),
            versions: versions,
            profile: profile,
            type: string(from: rawMessage.type),
            role: optionalString(from: rawMessage.role),
            clientName: optionalString(from: rawMessage.client_name),
            serverID: optionalString(from: rawMessage.server_id),
            bootID: optionalString(from: rawMessage.boot_id),
            sessionID: optionalString(from: rawMessage.session_id),
            token: optionalString(from: rawMessage.token),
            reason: rawMessage.has_reason == 0 ? nil : optionalString(from: rawMessage.reason),
            state: optionalString(from: rawMessage.state),
            pathState: optionalString(from: rawMessage.path_state),
            outputState: optionalString(from: rawMessage.output_state),
            sessionStreamState: optionalString(from: rawMessage.session_stream_state),
            transportState: optionalString(from: rawMessage.transport_state),
            firstMediaTimestamp: optionalString(from: rawMessage.first_media_timestamp),
            monotonicNanoseconds: optionalString(from: rawMessage.monotonic_ns)
        )
    }

    public static func encodeControlFrame(_ json: String) throws -> Data {
        try encodeControlFrame(Data(json.utf8))
    }

    public static func encodeControlFrame(_ json: Data) throws -> Data {
        var requiredSize = 0
        let sizingStatus = json.withUnsafeBytes { input in
            gm_control_encode_frame(
                gm_bytes(
                    data: input.bindMemory(to: UInt8.self).baseAddress,
                    size: input.count
                ),
                gm_mut_bytes(data: nil, size: 0),
                &requiredSize
            )
        }
        guard sizingStatus == GM_BUFFER_TOO_SMALL else {
            try requireOK(sizingStatus, operation: "gm_control_encode_frame")
            return Data()
        }

        var output = Data(count: requiredSize)
        var written = 0
        let status = json.withUnsafeBytes { input in
            output.withUnsafeMutableBytes { destination in
                gm_control_encode_frame(
                    gm_bytes(
                        data: input.bindMemory(to: UInt8.self).baseAddress,
                        size: input.count
                    ),
                    gm_mut_bytes(
                        data: destination.bindMemory(to: UInt8.self).baseAddress,
                        size: destination.count
                    ),
                    &written
                )
            }
        }
        try requireOK(status, operation: "gm_control_encode_frame")
        output.removeSubrange(written..<output.count)
        return output
    }

    public static func inspectControlFrame(_ input: Data) throws -> ControlFrameInspection {
        var info = gm_control_frame_info()
        info.struct_size = MemoryLayout<gm_control_frame_info>.size

        let status = input.withUnsafeBytes { buffer in
            gm_control_peek_frame(
                gm_bytes(
                    data: buffer.bindMemory(to: UInt8.self).baseAddress,
                    size: buffer.count
                ),
                &info
            )
        }

        if status == GM_NEED_MORE_DATA {
            return .needsMoreData(
                expectedFrameSize: info.frame_size == 0 ? nil : Int(info.frame_size)
            )
        }
        try requireOK(status, operation: "gm_control_peek_frame")
        return .complete(
            payloadLength: Int(info.payload_length),
            frameSize: Int(info.frame_size)
        )
    }

    public static func validateAudioProfile(_ profile: AudioProfile) throws {
        var rawProfile = rawAudioProfile(from: profile)
        try requireOK(
            gm_audio_profile_validate(&rawProfile),
            operation: "gm_audio_profile_validate"
        )
    }

    public static func encodeMediaHeader(_ header: MediaHeader) throws -> Data {
        var rawHeader = try rawMediaHeader(from: header)
        var output = Data(count: Int(GM_MEDIA_HEADER_BYTES))
        var written = 0

        let status = output.withUnsafeMutableBytes { destination in
            gm_media_encode_header(
                &rawHeader,
                gm_mut_bytes(
                    data: destination.bindMemory(to: UInt8.self).baseAddress,
                    size: destination.count
                ),
                &written
            )
        }
        try requireOK(status, operation: "gm_media_encode_header")
        output.removeSubrange(written..<output.count)
        return output
    }

    public static func decodeMediaHeader(from datagram: Data) throws -> MediaHeader {
        var rawHeader = gm_media_header()
        rawHeader.struct_size = MemoryLayout<gm_media_header>.size

        let status = datagram.withUnsafeBytes { buffer in
            gm_media_decode_header(
                gm_bytes(
                    data: buffer.bindMemory(to: UInt8.self).baseAddress,
                    size: buffer.count
                ),
                &rawHeader
            )
        }
        try requireOK(status, operation: "gm_media_decode_header")

        let sessionID = withUnsafeBytes(of: rawHeader.session_id) { Array($0) }
        return MediaHeader(
            kind: try mediaKind(from: rawHeader.kind),
            sessionID: sessionID,
            streamID: rawHeader.stream_id,
            direction: try mediaDirection(from: rawHeader.direction),
            keyEpoch: rawHeader.key_epoch,
            sequence: rawHeader.sequence,
            mediaTimestamp: rawHeader.media_timestamp,
            payloadLength: rawHeader.payload_length
        )
    }

    public static func buildMediaNonce(keyEpoch: UInt32, sequence: UInt64) throws -> Data {
        var output = Data(count: Int(GM_MEDIA_NONCE_BYTES))
        let status = output.withUnsafeMutableBytes { destination in
            gm_media_build_nonce(
                keyEpoch,
                sequence,
                gm_mut_bytes(
                    data: destination.bindMemory(to: UInt8.self).baseAddress,
                    size: destination.count
                )
            )
        }
        try requireOK(status, operation: "gm_media_build_nonce")
        return output
    }

    static func requireOK(_ status: gm_status, operation: String) throws {
        guard status == GM_OK else {
            throw ProtocolCoreError.callFailed(
                operation: operation,
                status: String(cString: gm_status_string(status))
            )
        }
    }

    static func rawMediaHeader(from header: MediaHeader) throws -> gm_media_header {
        guard header.sessionID.count == Int(GM_SESSION_ID_BYTES) else {
            throw ProtocolCoreError.invalidSessionIDLength(
                expected: Int(GM_SESSION_ID_BYTES),
                actual: header.sessionID.count
            )
        }

        var rawHeader = gm_media_header()
        rawHeader.struct_size = MemoryLayout<gm_media_header>.size
        rawHeader.abi_version = UInt32(GM_ABI_VERSION)
        rawHeader.kind = rawMediaKind(from: header.kind)
        withUnsafeMutableBytes(of: &rawHeader.session_id) { destination in
            header.sessionID.withUnsafeBytes { source in
                destination.copyBytes(from: source)
            }
        }
        rawHeader.stream_id = header.streamID
        rawHeader.direction = rawMediaDirection(from: header.direction)
        rawHeader.key_epoch = header.keyEpoch
        rawHeader.sequence = header.sequence
        rawHeader.media_timestamp = header.mediaTimestamp
        rawHeader.payload_length = header.payloadLength
        return rawHeader
    }

    private static func rawAudioProfile(from profile: AudioProfile) -> gm_audio_profile {
        var rawProfile = gm_audio_profile()
        rawProfile.struct_size = MemoryLayout<gm_audio_profile>.size
        rawProfile.abi_version = UInt32(GM_ABI_VERSION)
        switch profile.codec {
        case .pcmS16LE:
            rawProfile.codec = UInt32(GM_AUDIO_CODEC_PCM_S16LE.rawValue)
        case .opus:
            rawProfile.codec = UInt32(GM_AUDIO_CODEC_OPUS.rawValue)
        case .unknown(let value):
            rawProfile.codec = value
        }
        rawProfile.sample_rate_hz = profile.sampleRateHz
        rawProfile.channels = profile.channels
        rawProfile.frames_per_packet = profile.framesPerPacket
        switch profile.channelLayout {
        case .stereo:
            rawProfile.channel_layout = UInt32(GM_CHANNEL_LAYOUT_STEREO.rawValue)
        case .unknown(let value):
            rawProfile.channel_layout = value
        }
        rawProfile.packet_interval_us = profile.packetIntervalMicroseconds
        rawProfile.payload_bytes = profile.payloadBytes
        return rawProfile
    }

    private static func audioProfile(from rawProfile: gm_audio_profile) -> AudioProfile {
        let codec: AudioCodec
        switch rawProfile.codec {
        case UInt32(GM_AUDIO_CODEC_PCM_S16LE.rawValue):
            codec = .pcmS16LE
        case UInt32(GM_AUDIO_CODEC_OPUS.rawValue):
            codec = .opus
        default:
            codec = .unknown(rawProfile.codec)
        }

        let channelLayout: ChannelLayout
        switch rawProfile.channel_layout {
        case UInt32(GM_CHANNEL_LAYOUT_STEREO.rawValue):
            channelLayout = .stereo
        default:
            channelLayout = .unknown(rawProfile.channel_layout)
        }

        return AudioProfile(
            codec: codec,
            sampleRateHz: rawProfile.sample_rate_hz,
            channels: rawProfile.channels,
            framesPerPacket: rawProfile.frames_per_packet,
            channelLayout: channelLayout,
            packetIntervalMicroseconds: rawProfile.packet_interval_us,
            payloadBytes: rawProfile.payload_bytes
        )
    }

    private static func controlMessageKind(from rawKind: UInt32) -> ControlMessageKind {
        switch rawKind {
        case UInt32(GM_CONTROL_REQUEST_SESSION_HELLO.rawValue):
            return .requestSessionHello
        case UInt32(GM_CONTROL_REQUEST_TRANSPORT_BIND.rawValue):
            return .requestTransportBind
        case UInt32(GM_CONTROL_REQUEST_STREAM_OPEN.rawValue):
            return .requestStreamOpen
        case UInt32(GM_CONTROL_REQUEST_STREAM_START.rawValue):
            return .requestStreamStart
        case UInt32(GM_CONTROL_REQUEST_STREAM_STOP.rawValue):
            return .requestStreamStop
        case UInt32(GM_CONTROL_REQUEST_STREAM_CLOSE.rawValue):
            return .requestStreamClose
        case UInt32(GM_CONTROL_REQUEST_STREAM_REKEY.rawValue):
            return .requestStreamRekey
        case UInt32(GM_CONTROL_REQUEST_STATUS_GET.rawValue):
            return .requestStatusGet
        case UInt32(GM_CONTROL_REQUEST_PING.rawValue):
            return .requestPing
        case UInt32(GM_CONTROL_REQUEST_SESSION_CLOSE.rawValue):
            return .requestSessionClose
        case UInt32(GM_CONTROL_RESPONSE_RESULT.rawValue):
            return .responseResult
        case UInt32(GM_CONTROL_RESPONSE_ERROR.rawValue):
            return .responseError
        case UInt32(GM_CONTROL_EVENT_STREAM_STARTED.rawValue):
            return .eventStreamStarted
        case UInt32(GM_CONTROL_EVENT_STREAM_STOPPED.rawValue):
            return .eventStreamStopped
        case UInt32(GM_CONTROL_EVENT_OUTPUT_STATE.rawValue):
            return .eventOutputState
        case UInt32(GM_CONTROL_EVENT_SESSION_EXPIRING.rawValue):
            return .eventSessionExpiring
        default:
            return .unknown(rawKind)
        }
    }

    private static func mediaKind(from rawKind: UInt32) throws -> MediaKind {
        switch rawKind {
        case UInt32(GM_MEDIA_KIND_AUDIO.rawValue):
            return .audio
        case UInt32(GM_MEDIA_KIND_PATH_CHALLENGE.rawValue):
            return .pathChallenge
        case UInt32(GM_MEDIA_KIND_PATH_RESPONSE.rawValue):
            return .pathResponse
        case UInt32(GM_MEDIA_KIND_FEEDBACK.rawValue):
            return .feedback
        default:
            throw ProtocolCoreError.callFailed(
                operation: "gm_media_decode_header",
                status: "GM_UNKNOWN_MEDIA_KIND"
            )
        }
    }

    private static func mediaDirection(from rawDirection: UInt32) throws -> MediaDirection {
        switch rawDirection {
        case UInt32(GM_MEDIA_DIRECTION_WIN_TO_APPLE.rawValue):
            return .windowsToApple
        case UInt32(GM_MEDIA_DIRECTION_APPLE_TO_WIN.rawValue):
            return .appleToWindows
        default:
            throw ProtocolCoreError.callFailed(
                operation: "gm_media_decode_header",
                status: "GM_UNKNOWN_MEDIA_DIRECTION"
            )
        }
    }

    private static func rawMediaKind(from kind: MediaKind) -> UInt32 {
        switch kind {
        case .audio:
            return UInt32(GM_MEDIA_KIND_AUDIO.rawValue)
        case .pathChallenge:
            return UInt32(GM_MEDIA_KIND_PATH_CHALLENGE.rawValue)
        case .pathResponse:
            return UInt32(GM_MEDIA_KIND_PATH_RESPONSE.rawValue)
        case .feedback:
            return UInt32(GM_MEDIA_KIND_FEEDBACK.rawValue)
        }
    }

    static func rawMediaDirection(from direction: MediaDirection) -> UInt32 {
        switch direction {
        case .windowsToApple:
            return UInt32(GM_MEDIA_DIRECTION_WIN_TO_APPLE.rawValue)
        case .appleToWindows:
            return UInt32(GM_MEDIA_DIRECTION_APPLE_TO_WIN.rawValue)
        }
    }

    private static func optionalNonzero(_ value: UInt32) -> UInt32? {
        value == 0 ? nil : value
    }

    private static func optionalString<T>(from value: T) -> String? {
        let result = string(from: value)
        return result.isEmpty ? nil : result
    }

    private static func string<T>(from value: T) -> String {
        var value = value
        return withUnsafeBytes(of: &value) { buffer in
            String(decoding: buffer.prefix { $0 != 0 }, as: UTF8.self)
        }
    }
}

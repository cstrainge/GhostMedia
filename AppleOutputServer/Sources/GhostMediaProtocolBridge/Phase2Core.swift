import Foundation
import GhostMediaCore

public struct TrustPermissions: OptionSet, Equatable, Sendable {
    public let rawValue: UInt32

    public init(rawValue: UInt32) {
        self.rawValue = rawValue
    }

    public static let connect = TrustPermissions(
        rawValue: UInt32(GM_TRUST_PERMISSION_CONNECT.rawValue)
    )
    public static let viewStatus = TrustPermissions(
        rawValue: UInt32(GM_TRUST_PERMISSION_VIEW_STATUS.rawValue)
    )
    public static let receiveSystemAudio = TrustPermissions(
        rawValue: UInt32(GM_TRUST_PERMISSION_RECEIVE_SYSTEM_AUDIO.rawValue)
    )
    public static let provideMicrophone = TrustPermissions(
        rawValue: UInt32(GM_TRUST_PERMISSION_PROVIDE_MICROPHONE.rawValue)
    )
    public static let provideCamera = TrustPermissions(
        rawValue: UInt32(GM_TRUST_PERMISSION_PROVIDE_CAMERA.rawValue)
    )
}

public struct TrustRecord: Equatable, Sendable {
    public let peerSPKIDigest: Data
    public let permissions: TrustPermissions
    public let isRevoked: Bool

    public init(
        peerSPKIDigest: Data,
        permissions: TrustPermissions,
        isRevoked: Bool = false
    ) {
        self.peerSPKIDigest = peerSPKIDigest
        self.permissions = permissions
        self.isRevoked = isRevoked
    }
}

public struct TLSPeerPolicyObservation: Equatable, Sendable {
    public var tlsVersion: UInt32 = 0
    public var peerCertificateCount: UInt32 = 0
    public var leafDERSize: UInt32
    public var negotiatedALPN = ""
    public var leafIsSelfSigned = false
    public var publicKeyIsEd25519 = false
    public var signatureIsEd25519 = false
    public var basicConstraintsCA = false
    public var keyUsageDigitalSignature = false
    public var extendedKeyUsageClientAuth = false
    public var extendedKeyUsageServerAuth = false
    public var hasUnknownCriticalExtension = false
    public var isWithinValidity = false
    public var localClockIsTrusted = false
    public var usedSystemTrust = false
    public var usedPublicCAPath = false
    public var usedPSKOrTicket = false
    public var usedEarlyData = false
    public var usedCompression = false
    public var usedRenegotiation = false
    public var trustRecordAllowsConnect = false
    public var trustRecordIsRevoked = false

    public init(leafDERSize: UInt32) {
        self.leafDERSize = leafDERSize
    }
}

public struct ExporterContextInput: Equatable, Sendable {
    public let sessionID: Data
    public let streamID: UInt32
    public let direction: MediaDirection
    public let keyEpoch: UInt32
    public let senderSPKIDigest: Data
    public let receiverSPKIDigest: Data

    public init(
        sessionID: Data,
        streamID: UInt32,
        direction: MediaDirection,
        keyEpoch: UInt32,
        senderSPKIDigest: Data,
        receiverSPKIDigest: Data
    ) {
        self.sessionID = sessionID
        self.streamID = streamID
        self.direction = direction
        self.keyEpoch = keyEpoch
        self.senderSPKIDigest = senderSPKIDigest
        self.receiverSPKIDigest = receiverSPKIDigest
    }
}

public struct DirectionalKeys: Equatable, Sendable {
    public let mediaKey: Data
    public let pathKey: Data
}

public enum EpochAcceptance: Equatable, Sendable {
    case rejected
    case current
    case previousGrace
}

public struct EpochWindow {
    private var rawValue: gm_epoch_window

    public init(initialEpoch: UInt32) throws {
        var rawValue = gm_epoch_window()
        rawValue.struct_size = MemoryLayout<gm_epoch_window>.size
        try ProtocolCore.requireOK(
            gm_epoch_window_init(&rawValue, initialEpoch),
            operation: "gm_epoch_window_init"
        )
        self.rawValue = rawValue
    }

    public mutating func beginRekey(to newEpoch: UInt32, nowNanoseconds: UInt64) throws {
        try ProtocolCore.requireOK(
            gm_epoch_window_begin_rekey(&rawValue, newEpoch, nowNanoseconds),
            operation: "gm_epoch_window_begin_rekey"
        )
    }

    public mutating func acceptance(
        for keyEpoch: UInt32,
        nowNanoseconds: UInt64
    ) throws -> EpochAcceptance {
        var result: UInt32 = 0
        try ProtocolCore.requireOK(
            gm_epoch_window_accept(&rawValue, keyEpoch, nowNanoseconds, &result),
            operation: "gm_epoch_window_accept"
        )
        switch result {
        case UInt32(GM_EPOCH_REJECTED.rawValue):
            return .rejected
        case UInt32(GM_EPOCH_CURRENT.rawValue):
            return .current
        case UInt32(GM_EPOCH_PREVIOUS_GRACE.rawValue):
            return .previousGrace
        default:
            throw ProtocolCoreError.callFailed(
                operation: "gm_epoch_window_accept",
                status: "GM_UNKNOWN_EPOCH_ACCEPTANCE"
            )
        }
    }
}

public extension ProtocolCore {
    static var tlsExporterLabel: String {
        String(cString: gm_tls_exporter_label())
    }

    static var tlsExporterContextLength: Int {
        Int(GM_TLS_EXPORTER_CONTEXT_BYTES)
    }

    static var tlsExporterOutputLength: Int {
        Int(GM_TLS_EXPORTER_OUTPUT_BYTES)
    }

    static func peerID(forSPKIDigest digest: Data) throws -> String {
        var output = Data(count: Int(GM_PEER_ID_BASE32_BYTES) + 1)
        var written = 0
        let status = digest.withUnsafeBytes { digestBytes in
            output.withUnsafeMutableBytes { outputBytes in
                gm_identity_encode_peer_id(
                    gm_bytes(
                        data: digestBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: digestBytes.count
                    ),
                    gm_mut_bytes(
                        data: outputBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: outputBytes.count
                    ),
                    &written
                )
            }
        }
        try requireOK(status, operation: "gm_identity_encode_peer_id")
        return String(decoding: output.prefix(written - 1), as: UTF8.self)
    }

    static func trustRecord(
        _ record: TrustRecord,
        authorizes permission: TrustPermissions
    ) throws -> Bool {
        var rawRecord = gm_trust_record()
        rawRecord.struct_size = MemoryLayout<gm_trust_record>.size
        rawRecord.abi_version = UInt32(GM_ABI_VERSION)
        try copy(
            record.peerSPKIDigest,
            expectedCount: Int(GM_SPKI_DIGEST_BYTES),
            into: &rawRecord.peer_spki_digest
        )
        rawRecord.permissions = record.permissions.rawValue
        rawRecord.revoked = record.isRevoked ? 1 : 0

        var authorized: UInt8 = 0
        try requireOK(
            gm_trust_record_authorizes(&rawRecord, permission.rawValue, &authorized),
            operation: "gm_trust_record_authorizes"
        )
        return authorized != 0
    }

    static func validateTLSPeerPolicy(_ observation: TLSPeerPolicyObservation) throws {
        var rawObservation = gm_tls_peer_policy_observation()
        rawObservation.struct_size = MemoryLayout<gm_tls_peer_policy_observation>.size
        rawObservation.abi_version = UInt32(GM_ABI_VERSION)
        rawObservation.tls_version = observation.tlsVersion
        rawObservation.peer_certificate_count = observation.peerCertificateCount
        rawObservation.leaf_der_size = observation.leafDERSize
        try copyCString(observation.negotiatedALPN, into: &rawObservation.alpn)
        rawObservation.leaf_self_signed = byte(observation.leafIsSelfSigned)
        rawObservation.public_key_ed25519 = byte(observation.publicKeyIsEd25519)
        rawObservation.signature_ed25519 = byte(observation.signatureIsEd25519)
        rawObservation.basic_constraints_ca = byte(observation.basicConstraintsCA)
        rawObservation.key_usage_digital_signature = byte(observation.keyUsageDigitalSignature)
        rawObservation.eku_client_auth = byte(observation.extendedKeyUsageClientAuth)
        rawObservation.eku_server_auth = byte(observation.extendedKeyUsageServerAuth)
        rawObservation.unknown_critical_extension = byte(observation.hasUnknownCriticalExtension)
        rawObservation.within_validity = byte(observation.isWithinValidity)
        rawObservation.local_clock_trusted = byte(observation.localClockIsTrusted)
        rawObservation.system_trust_used = byte(observation.usedSystemTrust)
        rawObservation.public_ca_path_used = byte(observation.usedPublicCAPath)
        rawObservation.psk_or_ticket_used = byte(observation.usedPSKOrTicket)
        rawObservation.early_data_used = byte(observation.usedEarlyData)
        rawObservation.compression_used = byte(observation.usedCompression)
        rawObservation.renegotiation_used = byte(observation.usedRenegotiation)
        rawObservation.trust_record_connect = byte(observation.trustRecordAllowsConnect)
        rawObservation.trust_record_revoked = byte(observation.trustRecordIsRevoked)
        try requireOK(
            gm_tls_peer_policy_validate(&rawObservation),
            operation: "gm_tls_peer_policy_validate"
        )
    }

    static func exporterContext(_ input: ExporterContextInput) throws -> Data {
        var rawInput = gm_crypto_exporter_context_input()
        rawInput.struct_size = MemoryLayout<gm_crypto_exporter_context_input>.size
        rawInput.abi_version = UInt32(GM_ABI_VERSION)
        rawInput.stream_id = input.streamID
        rawInput.direction = rawMediaDirection(from: input.direction)
        rawInput.key_epoch = input.keyEpoch
        try copy(
            input.sessionID,
            expectedCount: Int(GM_SESSION_ID_BYTES),
            into: &rawInput.session_id
        )
        try copy(
            input.senderSPKIDigest,
            expectedCount: Int(GM_SPKI_DIGEST_BYTES),
            into: &rawInput.sender_spki_digest
        )
        try copy(
            input.receiverSPKIDigest,
            expectedCount: Int(GM_SPKI_DIGEST_BYTES),
            into: &rawInput.receiver_spki_digest
        )

        var output = Data(count: Int(GM_TLS_EXPORTER_CONTEXT_BYTES))
        var written = 0
        let status = output.withUnsafeMutableBytes { outputBytes in
            gm_crypto_build_exporter_context(
                &rawInput,
                gm_mut_bytes(
                    data: outputBytes.bindMemory(to: UInt8.self).baseAddress,
                    size: outputBytes.count
                ),
                &written
            )
        }
        try requireOK(status, operation: "gm_crypto_build_exporter_context")
        output.removeSubrange(written..<output.count)
        return output
    }

    static func splitExporterOutput(_ output: Data) throws -> DirectionalKeys {
        var rawKeys = gm_directional_keys()
        rawKeys.struct_size = MemoryLayout<gm_directional_keys>.size
        let status = output.withUnsafeBytes { outputBytes in
            gm_crypto_split_exporter_output(
                gm_bytes(
                    data: outputBytes.bindMemory(to: UInt8.self).baseAddress,
                    size: outputBytes.count
                ),
                &rawKeys
            )
        }
        try requireOK(status, operation: "gm_crypto_split_exporter_output")
        return DirectionalKeys(
            mediaKey: withUnsafeBytes(of: rawKeys.media_key) { Data($0) },
            pathKey: withUnsafeBytes(of: rawKeys.path_key) { Data($0) }
        )
    }

    static func buildMediaAAD(_ header: MediaHeader) throws -> Data {
        var rawHeader = try rawMediaHeader(from: header)
        var output = Data(count: Int(GM_MEDIA_HEADER_BYTES))
        var written = 0
        let status = output.withUnsafeMutableBytes { outputBytes in
            gm_media_build_aad(
                &rawHeader,
                gm_mut_bytes(
                    data: outputBytes.bindMemory(to: UInt8.self).baseAddress,
                    size: outputBytes.count
                ),
                &written
            )
        }
        try requireOK(status, operation: "gm_media_build_aad")
        output.removeSubrange(written..<output.count)
        return output
    }

    static func validateAEADInputs(
        key: Data,
        nonce: Data,
        aad: Data,
        payload: Data,
        tag: Data
    ) throws {
        let status = key.withUnsafeBytes { keyBytes in
            nonce.withUnsafeBytes { nonceBytes in
                aad.withUnsafeBytes { aadBytes in
                    payload.withUnsafeBytes { payloadBytes in
                        tag.withUnsafeBytes { tagBytes in
                            gm_crypto_validate_aead_inputs(
                                bytes(keyBytes),
                                bytes(nonceBytes),
                                bytes(aadBytes),
                                bytes(payloadBytes),
                                bytes(tagBytes)
                            )
                        }
                    }
                }
            }
        }
        try requireOK(status, operation: "gm_crypto_validate_aead_inputs")
    }

    private static func bytes(_ buffer: UnsafeRawBufferPointer) -> gm_bytes {
        gm_bytes(
            data: buffer.bindMemory(to: UInt8.self).baseAddress,
            size: buffer.count
        )
    }

    private static func byte(_ value: Bool) -> UInt8 {
        value ? 1 : 0
    }

    private static func copy<T>(
        _ data: Data,
        expectedCount: Int,
        into destination: inout T
    ) throws {
        guard data.count == expectedCount else {
            throw ProtocolCoreError.callFailed(
                operation: "copy_fixed_bytes",
                status: "expected \(expectedCount) bytes, got \(data.count)"
            )
        }
        _ = withUnsafeMutableBytes(of: &destination) { destinationBytes in
            data.copyBytes(to: destinationBytes)
        }
    }

    private static func copyCString<T>(_ string: String, into destination: inout T) throws {
        let bytes = Array(string.utf8)
        let capacity = MemoryLayout<T>.size
        guard bytes.count < capacity else {
            throw ProtocolCoreError.callFailed(
                operation: "copy_c_string",
                status: "string exceeds fixed field"
            )
        }
        withUnsafeMutableBytes(of: &destination) { destinationBytes in
            destinationBytes.initializeMemory(as: UInt8.self, repeating: 0)
            destinationBytes.copyBytes(from: bytes)
        }
    }
}

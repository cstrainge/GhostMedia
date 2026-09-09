import Foundation
import GhostMediaAppleSecurity
import GhostMediaProtocolBridge
import Security
import Testing

private final class MemorySecureStore: SecureValueStore, @unchecked Sendable {
    private let lock = NSLock()
    private var values = [String: Data]()

    func data(for key: String) throws -> Data? {
        lock.withLock { values[key] }
    }

    func set(_ data: Data, for key: String) throws {
        lock.withLock { values[key] = data }
    }

    func value(for key: String) -> Data? {
        lock.withLock { values[key] }
    }
}

private struct StoredIdentityFixture: Codable {
    let privateKeyPKCS8: Data
    let certificateDER: Data
}

private struct Phase2Vectors: Decodable {
    struct Identity: Decodable {
        let windowsSPKISHA256Hex: String
        let windowsPeerIDBase32: String
        let appleSPKISHA256Hex: String
        let applePeerIDBase32: String

        enum CodingKeys: String, CodingKey {
            case windowsSPKISHA256Hex = "windows_spki_sha256_hex"
            case windowsPeerIDBase32 = "windows_peer_id_base32"
            case appleSPKISHA256Hex = "apple_spki_sha256_hex"
            case applePeerIDBase32 = "apple_peer_id_base32"
        }
    }

    struct TLSExporter: Decodable {
        struct Direction: Decodable {
            let name: String
            let direction: UInt32
            let senderSPKISHA256Hex: String
            let receiverSPKISHA256Hex: String
            let contextSHA256Hex: String

            enum CodingKeys: String, CodingKey {
                case name, direction
                case senderSPKISHA256Hex = "sender_spki_sha256_hex"
                case receiverSPKISHA256Hex = "receiver_spki_sha256_hex"
                case contextSHA256Hex = "context_sha256_hex"
            }
        }

        let label: String
        let sessionIDHex: String
        let streamID: UInt32
        let keyEpoch: UInt32
        let exporterOutputHex: String
        let mediaKeyHex: String
        let pathKeyHex: String
        let directions: [Direction]

        enum CodingKeys: String, CodingKey {
            case label, directions
            case sessionIDHex = "session_id_hex"
            case streamID = "stream_id"
            case keyEpoch = "key_epoch"
            case exporterOutputHex = "exporter_output_hex"
            case mediaKeyHex = "media_key_hex"
            case pathKeyHex = "path_key_hex"
        }
    }

    struct MediaAAD: Decodable {
        let sessionIDHex: String
        let streamID: UInt32
        let direction: UInt32
        let keyEpoch: UInt32
        let sequence: String
        let mediaTimestamp: String
        let payloadLength: UInt32
        let aadHex: String
        let nonceHex: String

        enum CodingKeys: String, CodingKey {
            case sequence
            case sessionIDHex = "session_id_hex"
            case streamID = "stream_id"
            case direction
            case keyEpoch = "key_epoch"
            case mediaTimestamp = "media_timestamp"
            case payloadLength = "payload_length"
            case aadHex = "aad_hex"
            case nonceHex = "nonce_hex"
        }
    }

    struct AESGCM: Decodable {
        struct PathChallenge: Decodable {
            let aadHex: String
            let plaintextHex: String
            let ciphertextHex: String
            let tagHex: String

            enum CodingKeys: String, CodingKey {
                case aadHex = "aad_hex"
                case plaintextHex = "plaintext_hex"
                case ciphertextHex = "ciphertext_hex"
                case tagHex = "tag_hex"
            }
        }

        let keyHex: String
        let nonceHex: String
        let emptyPlaintextHex: String
        let emptyAADHex: String
        let emptyCiphertextHex: String
        let emptyTagHex: String
        let mediaPathChallenge: PathChallenge

        enum CodingKeys: String, CodingKey {
            case keyHex = "key_hex"
            case nonceHex = "nonce_hex"
            case emptyPlaintextHex = "empty_plaintext_hex"
            case emptyAADHex = "empty_aad_hex"
            case emptyCiphertextHex = "empty_ciphertext_hex"
            case emptyTagHex = "empty_tag_hex"
            case mediaPathChallenge = "media_path_challenge"
        }
    }

    let identity: Identity
    let tlsExporter: TLSExporter
    let mediaAAD: MediaAAD
    let aesGCM: AESGCM

    enum CodingKeys: String, CodingKey {
        case identity
        case tlsExporter = "tls_exporter"
        case mediaAAD = "media_aad"
        case aesGCM = "aes_gcm_provider_smoke"
    }
}

private let vectors: Phase2Vectors = {
    let repositoryRoot = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
    let url = repositoryRoot.appendingPathComponent(
        "protocol/vectors/phase2_crypto_vectors.json"
    )
    return try! JSONDecoder().decode(
        Phase2Vectors.self,
        from: Data(contentsOf: url)
    )
}()

private func data(hex: String) -> Data {
    precondition(hex.count.isMultiple(of: 2))
    var result = Data()
    result.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
        let next = hex.index(index, offsetBy: 2)
        result.append(UInt8(hex[index..<next], radix: 16)!)
        index = next
    }
    return result
}

private func mediaDirection(_ value: UInt32) -> MediaDirection {
    value == 1 ? .windowsToApple : .appleToWindows
}

private func throwsError(_ body: () throws -> Void) -> Bool {
    do {
        try body()
        return false
    } catch {
        return true
    }
}

private func validPolicyObservation() -> TLSPeerPolicyObservation {
    var observation = TLSPeerPolicyObservation(leafDERSize: 256)
    observation.tlsVersion = 0x0304
    observation.peerCertificateCount = 1
    observation.negotiatedALPN = "ghostmedia/1"
    observation.leafIsSelfSigned = true
    observation.publicKeyIsEd25519 = true
    observation.signatureIsEd25519 = true
    observation.keyUsageDigitalSignature = true
    observation.extendedKeyUsageClientAuth = true
    observation.extendedKeyUsageServerAuth = true
    observation.isWithinValidity = true
    observation.localClockIsTrusted = true
    observation.trustRecordAllowsConnect = true
    return observation
}

@Test
func phase2IdentityAndExporterVectorsMatchSharedCore() throws {
    #expect(
        try ProtocolCore.peerID(
            forSPKIDigest: data(hex: vectors.identity.windowsSPKISHA256Hex)
        ) == vectors.identity.windowsPeerIDBase32
    )
    #expect(
        try ProtocolCore.peerID(
            forSPKIDigest: data(hex: vectors.identity.appleSPKISHA256Hex)
        ) == vectors.identity.applePeerIDBase32
    )
    #expect(ProtocolCore.tlsExporterLabel == vectors.tlsExporter.label)

    for direction in vectors.tlsExporter.directions {
        let context = try ProtocolCore.exporterContext(
            ExporterContextInput(
                sessionID: data(hex: vectors.tlsExporter.sessionIDHex),
                streamID: vectors.tlsExporter.streamID,
                direction: mediaDirection(direction.direction),
                keyEpoch: vectors.tlsExporter.keyEpoch,
                senderSPKIDigest: data(hex: direction.senderSPKISHA256Hex),
                receiverSPKIDigest: data(hex: direction.receiverSPKISHA256Hex)
            )
        )
        #expect(
            context == data(hex: direction.contextSHA256Hex),
            Comment(rawValue: direction.name)
        )
    }

    let keys = try ProtocolCore.splitExporterOutput(
        data(hex: vectors.tlsExporter.exporterOutputHex)
    )
    #expect(keys.mediaKey == data(hex: vectors.tlsExporter.mediaKeyHex))
    #expect(keys.pathKey == data(hex: vectors.tlsExporter.pathKeyHex))
}

@Test
func phase2MediaAADNonceAndAESGCMVectorsMatch() throws {
    let media = vectors.mediaAAD
    let header = MediaHeader(
        kind: .audio,
        sessionID: Array(data(hex: media.sessionIDHex)),
        streamID: media.streamID,
        direction: mediaDirection(media.direction),
        keyEpoch: media.keyEpoch,
        sequence: UInt64(media.sequence)!,
        mediaTimestamp: UInt64(media.mediaTimestamp)!,
        payloadLength: media.payloadLength
    )
    let aad = try ProtocolCore.buildMediaAAD(header)
    #expect(aad == data(hex: media.aadHex))
    #expect(
        try ProtocolCore.buildMediaNonce(
            keyEpoch: media.keyEpoch,
            sequence: UInt64(media.sequence)!
        ) == data(hex: media.nonceHex)
    )

    let crypto = vectors.aesGCM
    let key = data(hex: crypto.keyHex)
    let nonce = data(hex: crypto.nonceHex)
    let empty = try AppleAESGCM.seal(
        data(hex: crypto.emptyPlaintextHex),
        key: key,
        nonce: nonce,
        authenticating: data(hex: crypto.emptyAADHex)
    )
    #expect(empty.ciphertext == data(hex: crypto.emptyCiphertextHex))
    #expect(empty.tag == data(hex: crypto.emptyTagHex))

    let challenge = crypto.mediaPathChallenge
    let challengeNonce = try ProtocolCore.buildMediaNonce(keyEpoch: 1, sequence: 1)
    let sealed = try AppleAESGCM.seal(
        data(hex: challenge.plaintextHex),
        key: key,
        nonce: challengeNonce,
        authenticating: data(hex: challenge.aadHex)
    )
    #expect(sealed.ciphertext == data(hex: challenge.ciphertextHex))
    #expect(sealed.tag == data(hex: challenge.tagHex))
    #expect(
        try AppleAESGCM.open(
            sealed,
            key: key,
            nonce: challengeNonce,
            authenticating: data(hex: challenge.aadHex)
        ) == data(hex: challenge.plaintextHex)
    )

    var alteredAAD = data(hex: challenge.aadHex)
    alteredAAD[alteredAAD.startIndex] ^= 1
    var alteredCiphertext = sealed.ciphertext
    alteredCiphertext[alteredCiphertext.startIndex] ^= 1
    var alteredTag = sealed.tag
    alteredTag[alteredTag.startIndex] ^= 1
    #expect(throwsError {
        _ = try AppleAESGCM.open(
            sealed,
            key: key,
            nonce: challengeNonce,
            authenticating: alteredAAD
        )
    })
    #expect(throwsError {
        _ = try AppleAESGCM.open(
            AESGCMSealedPayload(ciphertext: alteredCiphertext, tag: sealed.tag),
            key: key,
            nonce: challengeNonce,
            authenticating: data(hex: challenge.aadHex)
        )
    })
    #expect(throwsError {
        _ = try AppleAESGCM.open(
            AESGCMSealedPayload(ciphertext: sealed.ciphertext, tag: alteredTag),
            key: key,
            nonce: challengeNonce,
            authenticating: data(hex: challenge.aadHex)
        )
    })
}

@Test
func phase2TrustPolicyAndEpochBoundariesFailClosed() throws {
    let digest = data(hex: vectors.identity.windowsSPKISHA256Hex)
    let record = TrustRecord(
        peerSPKIDigest: digest,
        permissions: [.connect, .viewStatus]
    )
    #expect(try ProtocolCore.trustRecord(record, authorizes: .connect))
    #expect(try !ProtocolCore.trustRecord(record, authorizes: .receiveSystemAudio))
    #expect(
        try !ProtocolCore.trustRecord(
            TrustRecord(
                peerSPKIDigest: digest,
                permissions: [.connect],
                isRevoked: true
            ),
            authorizes: .connect
        )
    )

    let validPolicy = validPolicyObservation()
    try ProtocolCore.validateTLSPeerPolicy(validPolicy)
    #expect(throwsError {
        try ProtocolCore.validateTLSPeerPolicy(
            TLSPeerPolicyObservation(leafDERSize: 256)
        )
    })
    var wrongALPN = validPolicy
    wrongALPN.negotiatedALPN = "http/1.1"
    #expect(throwsError { try ProtocolCore.validateTLSPeerPolicy(wrongALPN) })
    var untrusted = validPolicy
    untrusted.trustRecordAllowsConnect = false
    #expect(throwsError { try ProtocolCore.validateTLSPeerPolicy(untrusted) })
    var revoked = validPolicy
    revoked.trustRecordIsRevoked = true
    #expect(throwsError { try ProtocolCore.validateTLSPeerPolicy(revoked) })

    var replay = try ReplayWindow()
    #expect(try replay.accept(sequence: 2_000) == .accepted)
    #expect(try replay.accept(sequence: 2_000) == .duplicate)
    #expect(try replay.accept(sequence: 977) == .accepted)
    #expect(try replay.accept(sequence: 976) == .tooOld)

    var epoch = try EpochWindow(initialEpoch: 1)
    #expect(try epoch.acceptance(for: 1, nowNanoseconds: 1_000) == .current)
    try epoch.beginRekey(to: 2, nowNanoseconds: 1_000_000_000)
    #expect(try epoch.acceptance(for: 2, nowNanoseconds: 1_000_000_001) == .current)
    #expect(
        try epoch.acceptance(for: 1, nowNanoseconds: 6_000_000_000) ==
            .previousGrace
    )
    #expect(
        try epoch.acceptance(for: 1, nowNanoseconds: 6_000_000_001) ==
            .rejected
    )
    #expect(throwsError {
        try epoch.beginRekey(to: 4, nowNanoseconds: 7_000_000_000)
    })
}

@Test
func identityAndTrustRecordsPersistAndRejectCorruption() throws {
    let store = MemorySecureStore()
    let manager = AppleIdentityManager(store: store)
    let first = try manager.loadOrCreate()
    let second = try manager.loadOrCreate()
    #expect(first.serverID == second.serverID)
    #expect(first.peerID == second.peerID)
    #expect(first.spkiDER == second.spkiDER)
    #expect(first.certificateDER == second.certificateDER)

    let storedData = try #require(
        store.value(for: "identity-ed25519-pkcs8-and-certificate")
    )
    let stored = try PropertyListDecoder().decode(
        StoredIdentityFixture.self,
        from: storedData
    )
    #expect(stored.privateKeyPKCS8.count >= 32)
    let legacyPrivateKey = Data(stored.privateKeyPKCS8.suffix(32))
    let legacyStore = MemorySecureStore()
    try legacyStore.set(
        Data(first.serverID.uuidString.lowercased().utf8),
        for: "server-id"
    )
    try legacyStore.set(
        legacyPrivateKey,
        for: "identity-ed25519-private-key"
    )
    try legacyStore.set(
        stored.certificateDER,
        for: "identity-ed25519-leaf-certificate"
    )
    let migrated = try AppleIdentityManager(store: legacyStore).loadOrCreate()
    #expect(migrated.serverID == first.serverID)
    #expect(migrated.peerID == first.peerID)
    #expect(migrated.certificateDER == first.certificateDER)
    #expect(
        legacyStore.value(
            for: "identity-ed25519-pkcs8-and-certificate"
        ) != nil
    )

    let partialLegacyStore = MemorySecureStore()
    try partialLegacyStore.set(
        legacyPrivateKey,
        for: "identity-ed25519-private-key"
    )
    #expect(throwsError {
        _ = try AppleIdentityManager(store: partialLegacyStore).loadOrCreate()
    })

    let certificate = try #require(
        SecCertificateCreateWithData(nil, first.certificateDER as CFData)
    )
    var trust: SecTrust?
    #expect(
        SecTrustCreateWithCertificates(
            certificate,
            SecPolicyCreateBasicX509(),
            &trust
        ) == errSecSuccess
    )
    let certificateTrust = try #require(trust)
    #expect(SecTrustSetAnchorCertificates(certificateTrust, [certificate] as CFArray) == errSecSuccess)
    #expect(SecTrustSetAnchorCertificatesOnly(certificateTrust, true) == errSecSuccess)
    #expect(SecTrustEvaluateWithError(certificateTrust, nil))

    let tlsPeer = try AppleOutputIdentity.ephemeral()
    let exporterContext = try ProtocolCore.exporterContext(
        ExporterContextInput(
            sessionID: data(hex: vectors.tlsExporter.sessionIDHex),
            streamID: vectors.tlsExporter.streamID,
            direction: .windowsToApple,
            keyEpoch: vectors.tlsExporter.keyEpoch,
            senderSPKIDigest: first.spkiDigest,
            receiverSPKIDigest: tlsPeer.spkiDigest
        )
    )
    let exporter = try AppleRuntimeTLS.exporterPair(
        client: first,
        server: tlsPeer,
        clientExpectedServerSPKIDigest: tlsPeer.spkiDigest,
        serverExpectedClientSPKIDigest: first.spkiDigest,
        context: exporterContext
    )
    #expect(exporter.client == exporter.server)
    #expect(exporter.client.count == ProtocolCore.tlsExporterOutputLength)
    var wrongServerPin = tlsPeer.spkiDigest
    wrongServerPin[wrongServerPin.startIndex] ^= 1
    #expect(throwsError {
        _ = try AppleRuntimeTLS.exporterPair(
            client: first,
            server: tlsPeer,
            clientExpectedServerSPKIDigest: wrongServerPin,
            serverExpectedClientSPKIDigest: first.spkiDigest,
            context: exporterContext
        )
    })

    let trustStore = AppleTrustStore(store: store)
    let trustRecord = StoredTrustRecord(
        peerSPKIDigest: first.spkiDigest,
        permissions: [.connect, .receiveSystemAudio]
    )
    try trustStore.save(trustRecord)
    #expect(try trustStore.record(for: first.spkiDigest) == trustRecord)
    let revoked = StoredTrustRecord(
        peerSPKIDigest: first.spkiDigest,
        permissions: [.connect],
        isRevoked: true
    )
    try trustStore.save(revoked)
    #expect(try trustStore.record(for: first.spkiDigest) == revoked)

    let corruptIdentityStore = MemorySecureStore()
    try corruptIdentityStore.set(Data("not-a-uuid".utf8), for: "server-id")
    #expect(throwsError {
        _ = try AppleIdentityManager(store: corruptIdentityStore).loadOrCreate()
    })

    let corruptCertificateStore = MemorySecureStore()
    _ = try AppleIdentityManager(store: corruptCertificateStore).loadOrCreate()
    try corruptCertificateStore.set(
        Data([0x01, 0x02]),
        for: "identity-ed25519-pkcs8-and-certificate"
    )
    #expect(throwsError {
        _ = try AppleIdentityManager(store: corruptCertificateStore).loadOrCreate()
    })
}

@Test
func trustStoreApprovalAndRevocationFailClosed() throws {
    let store = MemorySecureStore()
    let trustStore = AppleTrustStore(store: store)
    let peer = Data(repeating: 0x5a, count: 32)

    #expect(try !trustStore.authorizes(
        peerSPKIDigest: peer,
        permission: .connect
    ))
    #expect(try !trustStore.authorizes(
        peerSPKIDigest: Data(repeating: 0x5a, count: 31),
        permission: .connect
    ))

    try trustStore.approve(
        peerSPKIDigest: peer,
        permissions: [.connect, .receiveSystemAudio]
    )
    #expect(try trustStore.authorizes(peerSPKIDigest: peer, permission: .connect))
    #expect(try trustStore.authorizes(
        peerSPKIDigest: peer,
        permission: .receiveSystemAudio
    ))
    #expect(try !trustStore.authorizes(
        peerSPKIDigest: peer,
        permission: .provideMicrophone
    ))

    try trustStore.revoke(peerSPKIDigest: peer)
    #expect(try !trustStore.authorizes(peerSPKIDigest: peer, permission: .connect))
    let revoked = try #require(try trustStore.record(for: peer))
    #expect(revoked.isRevoked)
}

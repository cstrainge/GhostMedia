import CryptoKit
import Foundation
import GhostMediaProtocolBridge
import Security

public struct AppleOutputIdentity: Sendable {
    public let serverID: UUID
    public let peerID: String
    public let spkiDER: Data
    public let spkiDigest: Data
    public let certificateDER: Data

    private let privateKey: Curve25519.Signing.PrivateKey

    init(
        serverID: UUID,
        privateKey: Curve25519.Signing.PrivateKey,
        certificateDER: Data
    ) throws {
        let spkiDER = DER.ed25519SubjectPublicKeyInfo(
            rawPublicKey: privateKey.publicKey.rawRepresentation
        )
        let digest = Data(SHA256.hash(data: spkiDER))
        self.serverID = serverID
        self.privateKey = privateKey
        self.spkiDER = spkiDER
        self.spkiDigest = digest
        self.peerID = try ProtocolCore.peerID(forSPKIDigest: digest)
        self.certificateDER = certificateDER
    }

    public func signature(for data: Data) throws -> Data {
        try privateKey.signature(for: data)
    }
}

public struct AppleIdentityManager: Sendable {
    private enum Key {
        static let serverID = "server-id"
        static let signingKey = "identity-ed25519-private-key"
        static let certificate = "identity-ed25519-leaf-certificate"
    }

    private let store: any SecureValueStore

    public init(store: any SecureValueStore = KeychainSecureStore()) {
        self.store = store
    }

    public func loadOrCreate() throws -> AppleOutputIdentity {
        let serverID = try loadOrCreateServerID()
        let privateKey = try loadOrCreatePrivateKey()
        let certificateDER: Data
        if let storedCertificate = try store.data(for: Key.certificate) {
            certificateDER = storedCertificate
            try validateCertificate(certificateDER, privateKey: privateKey)
        } else {
            certificateDER = try SelfSignedCertificate.make(
                privateKey: privateKey,
                commonName: "GhostMedia Output Server"
            )
            try validateCertificate(certificateDER, privateKey: privateKey)
            try store.set(certificateDER, for: Key.certificate)
        }
        return try AppleOutputIdentity(
            serverID: serverID,
            privateKey: privateKey,
            certificateDER: certificateDER
        )
    }

    private func loadOrCreateServerID() throws -> UUID {
        if let stored = try store.data(for: Key.serverID) {
            guard let text = String(data: stored, encoding: .utf8),
                  let serverID = UUID(uuidString: text) else {
                throw SecureStoreError.invalidStoredValue(Key.serverID)
            }
            return serverID
        }

        let serverID = UUID()
        try store.set(Data(serverID.uuidString.lowercased().utf8), for: Key.serverID)
        return serverID
    }

    private func loadOrCreatePrivateKey() throws -> Curve25519.Signing.PrivateKey {
        if let stored = try store.data(for: Key.signingKey) {
            do {
                return try Curve25519.Signing.PrivateKey(rawRepresentation: stored)
            } catch {
                throw SecureStoreError.invalidStoredValue(Key.signingKey)
            }
        }

        let privateKey = Curve25519.Signing.PrivateKey()
        try store.set(privateKey.rawRepresentation, for: Key.signingKey)
        return privateKey
    }

    private func validateCertificate(
        _ certificateDER: Data,
        privateKey: Curve25519.Signing.PrivateKey
    ) throws {
        guard let certificate = SecCertificateCreateWithData(
            nil,
            certificateDER as CFData
        ),
        let publicKey = SecCertificateCopyKey(certificate) else {
            throw SecureStoreError.invalidStoredValue(Key.certificate)
        }

        var error: Unmanaged<CFError>?
        guard let externalRepresentation = SecKeyCopyExternalRepresentation(publicKey, &error)
        else {
            throw SecureStoreError.invalidStoredValue(Key.certificate)
        }
        let keyBytes = externalRepresentation as Data
        guard keyBytes.suffix(privateKey.publicKey.rawRepresentation.count) ==
                privateKey.publicKey.rawRepresentation else {
            throw SecureStoreError.invalidStoredValue(Key.certificate)
        }
    }
}

public struct StoredTrustRecord: Codable, Equatable, Sendable {
    public let peerSPKIDigest: Data
    public let permissions: UInt32
    public let isRevoked: Bool

    public init(
        peerSPKIDigest: Data,
        permissions: TrustPermissions,
        isRevoked: Bool = false
    ) {
        self.peerSPKIDigest = peerSPKIDigest
        self.permissions = permissions.rawValue
        self.isRevoked = isRevoked
    }

    public var coreRecord: TrustRecord {
        TrustRecord(
            peerSPKIDigest: peerSPKIDigest,
            permissions: TrustPermissions(rawValue: permissions),
            isRevoked: isRevoked
        )
    }
}

public struct AppleTrustStore: Sendable {
    private let store: any SecureValueStore

    public init(store: any SecureValueStore = KeychainSecureStore()) {
        self.store = store
    }

    public func record(for peerSPKIDigest: Data) throws -> StoredTrustRecord? {
        guard let data = try store.data(for: key(for: peerSPKIDigest)) else {
            return nil
        }
        do {
            return try JSONDecoder().decode(StoredTrustRecord.self, from: data)
        } catch {
            throw SecureStoreError.invalidStoredValue(key(for: peerSPKIDigest))
        }
    }

    public func save(_ record: StoredTrustRecord) throws {
        let data = try JSONEncoder().encode(record)
        try store.set(data, for: key(for: record.peerSPKIDigest))
    }

    private func key(for digest: Data) -> String {
        "trust-\(digest.map { String(format: "%02x", $0) }.joined())"
    }
}

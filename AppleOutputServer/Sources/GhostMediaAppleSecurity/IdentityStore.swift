import Foundation
import GhostMediaProtocolBridge
import GhostMediaRuntime

fileprivate final class RuntimeIdentityHandle: @unchecked Sendable {
    let pointer: OpaquePointer

    init(pointer: OpaquePointer) {
        self.pointer = pointer
    }

    deinit {
        gm_runtime_identity_destroy(pointer)
    }
}

public struct AppleOutputIdentity: Sendable {
    public let serverID: UUID
    public let peerID: String
    public let spkiDER: Data
    public let spkiDigest: Data
    public let certificateDER: Data

    fileprivate let runtimeIdentity: RuntimeIdentityHandle

    fileprivate init(
        serverID: UUID,
        runtimeIdentity: RuntimeIdentityHandle
    ) throws {
        let spkiDER = try runtimeIdentity.copyVariableOutput(
            operation: "gm_runtime_identity_spki_der",
            gm_runtime_identity_spki_der
        )
        var digest = Data(count: 32)
        let digestStatus = digest.withUnsafeMutableBytes { bytes in
            gm_runtime_identity_spki_sha256(
                runtimeIdentity.pointer,
                gm_mut_bytes(
                    data: bytes.bindMemory(to: UInt8.self).baseAddress,
                    size: bytes.count
                )
            )
        }
        try requireRuntimeOK(
            digestStatus,
            operation: "gm_runtime_identity_spki_sha256"
        )
        let certificateDER = try runtimeIdentity.copyVariableOutput(
            operation: "gm_runtime_identity_certificate_der",
            gm_runtime_identity_certificate_der
        )
        self.serverID = serverID
        self.runtimeIdentity = runtimeIdentity
        self.spkiDER = spkiDER
        self.spkiDigest = digest
        self.peerID = try ProtocolCore.peerID(forSPKIDigest: digest)
        self.certificateDER = certificateDER
    }

    public static func ephemeral(serverID: UUID = UUID()) throws -> AppleOutputIdentity {
        var pointer: OpaquePointer?
        try requireRuntimeOK(
            gm_runtime_identity_generate(&pointer),
            operation: "gm_runtime_identity_generate"
        )
        guard let pointer else {
            throw AppleCryptoError.runtimeFailure(
                operation: "gm_runtime_identity_generate",
                status: "missing identity"
            )
        }
        return try AppleOutputIdentity(
            serverID: serverID,
            runtimeIdentity: RuntimeIdentityHandle(pointer: pointer)
        )
    }

    /// Creates a deterministic identity only for the explicit Phase 3 command-line
    /// fixture. Production callers must use AppleIdentityManager instead.
    public static func phase3TestIdentity(
        privateKeyRaw: Data,
        serverID: UUID = UUID()
    ) throws -> AppleOutputIdentity {
        guard privateKeyRaw.count == 32 else {
            throw AppleCryptoError.invalidKeyLength(privateKeyRaw.count)
        }
        var pointer: OpaquePointer?
        let status = privateKeyRaw.withUnsafeBytes { keyBytes in
            gm_runtime_identity_renew_raw_ed25519(
                gm_bytes(
                    data: keyBytes.bindMemory(to: UInt8.self).baseAddress,
                    size: keyBytes.count
                ),
                &pointer
            )
        }
        try requireRuntimeOK(status, operation: "gm_runtime_identity_renew_raw_ed25519")
        guard let pointer else {
            throw AppleCryptoError.runtimeFailure(
                operation: "gm_runtime_identity_renew_raw_ed25519",
                status: "missing identity"
            )
        }
        return try AppleOutputIdentity(
            serverID: serverID,
            runtimeIdentity: RuntimeIdentityHandle(pointer: pointer)
        )
    }

    public func signature(for data: Data) throws -> Data {
        try data.withUnsafeBytes { messageBytes in
            try runtimeIdentity.copyVariableOutput(
                operation: "gm_runtime_identity_sign"
            ) { identity, output, written in
                gm_runtime_identity_sign(
                    identity,
                    gm_bytes(
                        data: messageBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: messageBytes.count
                    ),
                    output,
                    written
                )
            }
        }
    }
}

public struct AppleIdentityManager: Sendable {
    private enum Key {
        static let serverID = "server-id"
        static let identity = "identity-ed25519-pkcs8-and-certificate"
        static let legacySigningKey = "identity-ed25519-private-key"
        static let legacyCertificate = "identity-ed25519-leaf-certificate"
    }

    private struct StoredIdentity: Codable {
        let privateKeyPKCS8: Data
        let certificateDER: Data
    }

    private let store: any SecureValueStore

    public init(store: any SecureValueStore = KeychainSecureStore()) {
        self.store = store
    }

    public func loadOrCreate() throws -> AppleOutputIdentity {
        let serverID = try loadOrCreateServerID()
        let runtimeIdentity: RuntimeIdentityHandle
        if let storedData = try store.data(for: Key.identity) {
            let stored: StoredIdentity
            do {
                stored = try PropertyListDecoder().decode(
                    StoredIdentity.self,
                    from: storedData
                )
            } catch {
                throw SecureStoreError.invalidStoredValue(Key.identity)
            }
            runtimeIdentity = try loadOrRenewIdentity(stored)
        } else {
            let legacyKey = try store.data(for: Key.legacySigningKey)
            let legacyCertificate = try store.data(for: Key.legacyCertificate)
            if let legacyKey, let legacyCertificate {
                runtimeIdentity = try loadLegacyIdentity(
                    privateKeyRaw: legacyKey,
                    certificateDER: legacyCertificate
                )
                try persist(runtimeIdentity)
            } else if legacyKey != nil || legacyCertificate != nil {
                throw SecureStoreError.invalidStoredValue(Key.identity)
            } else {
                runtimeIdentity = try generateIdentity()
                try persist(runtimeIdentity)
            }
        }
        return try AppleOutputIdentity(
            serverID: serverID,
            runtimeIdentity: runtimeIdentity
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

    private func generateIdentity() throws -> RuntimeIdentityHandle {
        var pointer: OpaquePointer?
        try requireRuntimeOK(
            gm_runtime_identity_generate(&pointer),
            operation: "gm_runtime_identity_generate"
        )
        guard let pointer else {
            throw AppleCryptoError.runtimeFailure(
                operation: "gm_runtime_identity_generate",
                status: "missing identity"
            )
        }
        return RuntimeIdentityHandle(pointer: pointer)
    }

    private func loadOrRenewIdentity(_ stored: StoredIdentity) throws -> RuntimeIdentityHandle {
        var pointer: OpaquePointer?
        let status = stored.privateKeyPKCS8.withUnsafeBytes { keyBytes in
            stored.certificateDER.withUnsafeBytes { certificateBytes in
                gm_runtime_identity_load(
                    gm_bytes(
                        data: keyBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: keyBytes.count
                    ),
                    gm_bytes(
                        data: certificateBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: certificateBytes.count
                    ),
                    &pointer
                )
            }
        }
        if status == GM_STATE_CONFLICT {
            let renewed = try renewIdentity(privateKeyPKCS8: stored.privateKeyPKCS8)
            try persist(renewed)
            return renewed
        }
        guard status == GM_OK, let pointer else {
            throw SecureStoreError.invalidStoredValue(Key.identity)
        }
        return RuntimeIdentityHandle(pointer: pointer)
    }

    private func loadLegacyIdentity(
        privateKeyRaw: Data,
        certificateDER: Data
    ) throws -> RuntimeIdentityHandle {
        var pointer: OpaquePointer?
        let status = privateKeyRaw.withUnsafeBytes { keyBytes in
            certificateDER.withUnsafeBytes { certificateBytes in
                gm_runtime_identity_load_raw_ed25519(
                    gm_bytes(
                        data: keyBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: keyBytes.count
                    ),
                    gm_bytes(
                        data: certificateBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: certificateBytes.count
                    ),
                    &pointer
                )
            }
        }
        if status == GM_STATE_CONFLICT {
            return try renewLegacyIdentity(privateKeyRaw: privateKeyRaw)
        }
        guard status == GM_OK, let pointer else {
            throw SecureStoreError.invalidStoredValue(Key.identity)
        }
        return RuntimeIdentityHandle(pointer: pointer)
    }

    private func renewLegacyIdentity(privateKeyRaw: Data) throws -> RuntimeIdentityHandle {
        var pointer: OpaquePointer?
        let status = privateKeyRaw.withUnsafeBytes { keyBytes in
            gm_runtime_identity_renew_raw_ed25519(
                gm_bytes(
                    data: keyBytes.bindMemory(to: UInt8.self).baseAddress,
                    size: keyBytes.count
                ),
                &pointer
            )
        }
        guard status == GM_OK, let pointer else {
            throw SecureStoreError.invalidStoredValue(Key.identity)
        }
        return RuntimeIdentityHandle(pointer: pointer)
    }

    private func renewIdentity(privateKeyPKCS8: Data) throws -> RuntimeIdentityHandle {
        var pointer: OpaquePointer?
        let status = privateKeyPKCS8.withUnsafeBytes { keyBytes in
            gm_runtime_identity_renew_certificate(
                gm_bytes(
                    data: keyBytes.bindMemory(to: UInt8.self).baseAddress,
                    size: keyBytes.count
                ),
                &pointer
            )
        }
        guard status == GM_OK, let pointer else {
            throw SecureStoreError.invalidStoredValue(Key.identity)
        }
        return RuntimeIdentityHandle(pointer: pointer)
    }

    private func persist(_ identity: RuntimeIdentityHandle) throws {
        let stored = StoredIdentity(
            privateKeyPKCS8: try identity.copyVariableOutput(
                operation: "gm_runtime_identity_private_key_pkcs8",
                gm_runtime_identity_private_key_pkcs8
            ),
            certificateDER: try identity.copyVariableOutput(
                operation: "gm_runtime_identity_certificate_der",
                gm_runtime_identity_certificate_der
            )
        )
        try store.set(
            try PropertyListEncoder().encode(stored),
            for: Key.identity
        )
    }

}

public enum AppleRuntimeTLS {
    public static func exporterPair(
        client: AppleOutputIdentity,
        server: AppleOutputIdentity,
        clientExpectedServerSPKIDigest: Data,
        serverExpectedClientSPKIDigest: Data,
        context: Data
    ) throws -> (client: Data, server: Data) {
        guard context.count == ProtocolCore.tlsExporterContextLength else {
            throw AppleCryptoError.invalidExporterContextLength(context.count)
        }
        var clientOutput = Data(count: ProtocolCore.tlsExporterOutputLength)
        var serverOutput = Data(count: ProtocolCore.tlsExporterOutputLength)
        let status = clientExpectedServerSPKIDigest.withUnsafeBytes { serverPinBytes in
            serverExpectedClientSPKIDigest.withUnsafeBytes { clientPinBytes in
                context.withUnsafeBytes { contextBytes in
                    clientOutput.withUnsafeMutableBytes { clientBytes in
                        serverOutput.withUnsafeMutableBytes { serverBytes in
                            gm_runtime_tls13_exporter_pair(
                                client.runtimeIdentity.pointer,
                                server.runtimeIdentity.pointer,
                                gm_bytes(
                                    data: serverPinBytes.bindMemory(to: UInt8.self).baseAddress,
                                    size: serverPinBytes.count
                                ),
                                gm_bytes(
                                    data: clientPinBytes.bindMemory(to: UInt8.self).baseAddress,
                                    size: clientPinBytes.count
                                ),
                                gm_bytes(
                                    data: contextBytes.bindMemory(to: UInt8.self).baseAddress,
                                    size: contextBytes.count
                                ),
                                gm_mut_bytes(
                                    data: clientBytes.bindMemory(to: UInt8.self).baseAddress,
                                    size: clientBytes.count
                                ),
                                gm_mut_bytes(
                                    data: serverBytes.bindMemory(to: UInt8.self).baseAddress,
                                    size: serverBytes.count
                                )
                            )
                        }
                    }
                }
            }
        }
        try requireRuntimeOK(
            status,
            operation: "gm_runtime_tls13_exporter_pair"
        )
        return (clientOutput, serverOutput)
    }
}

public final class AppleRuntimeTLSSession: @unchecked Sendable {
    private let pointer: OpaquePointer

    private init(pointer: OpaquePointer) {
        self.pointer = pointer
    }

    deinit {
        gm_runtime_tls_session_destroy(pointer)
    }

    public static func accept(
        connection: OpaquePointer,
        identity: AppleOutputIdentity,
        expectedClientSPKIDigest: Data
    ) throws -> AppleRuntimeTLSSession {
        var pointer: OpaquePointer?
        let status = expectedClientSPKIDigest.withUnsafeBytes { digestBytes in
            gm_runtime_tls_server_create(
                connection,
                identity.runtimeIdentity.pointer,
                gm_bytes(
                    data: digestBytes.bindMemory(to: UInt8.self).baseAddress,
                    size: digestBytes.count
                ),
                &pointer
            )
        }
        try requireRuntimeOK(status, operation: "gm_runtime_tls_server_create")
        guard let pointer else {
            throw AppleCryptoError.runtimeFailure(
                operation: "gm_runtime_tls_server_create",
                status: "missing session"
            )
        }
        return AppleRuntimeTLSSession(pointer: pointer)
    }

    public func handshake() throws {
        try requireRuntimeOK(
            gm_runtime_tls_handshake(pointer),
            operation: "gm_runtime_tls_handshake"
        )
    }

    public func sendAll(_ data: Data) throws {
        let status = data.withUnsafeBytes { bytes in
            gm_runtime_tls_send_all(
                pointer,
                gm_bytes(
                    data: bytes.bindMemory(to: UInt8.self).baseAddress,
                    size: bytes.count
                )
            )
        }
        try requireRuntimeOK(status, operation: "gm_runtime_tls_send_all")
    }

    public func receive(into output: inout [UInt8]) throws -> Int {
        var received = 0
        let status = output.withUnsafeMutableBytes { bytes in
            gm_runtime_tls_receive(
                pointer,
                gm_mut_bytes(
                    data: bytes.bindMemory(to: UInt8.self).baseAddress,
                    size: bytes.count
                ),
                &received
            )
        }
        try requireRuntimeOK(status, operation: "gm_runtime_tls_receive")
        return received
    }

    public func exporter(context: Data) throws -> Data {
        var output = Data(count: ProtocolCore.tlsExporterOutputLength)
        let status = context.withUnsafeBytes { contextBytes in
            output.withUnsafeMutableBytes { outputBytes in
                gm_runtime_tls_export(
                    pointer,
                    gm_bytes(
                        data: contextBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: contextBytes.count
                    ),
                    gm_mut_bytes(
                        data: outputBytes.bindMemory(to: UInt8.self).baseAddress,
                        size: outputBytes.count
                    )
                )
            }
        }
        try requireRuntimeOK(status, operation: "gm_runtime_tls_export")
        return output
    }
}

private extension RuntimeIdentityHandle {
    func copyVariableOutput(
        operation: String,
        _ call: (
            OpaquePointer?,
            gm_mut_bytes,
            UnsafeMutablePointer<Int>?
        ) -> gm_status
    ) throws -> Data {
        var required = 0
        let sizeStatus = call(
            pointer,
            gm_mut_bytes(data: nil, size: 0),
            &required
        )
        guard sizeStatus == GM_BUFFER_TOO_SMALL, required > 0 else {
            try requireRuntimeOK(sizeStatus, operation: operation)
            return Data()
        }
        var output = Data(count: required)
        let status = output.withUnsafeMutableBytes { bytes in
            call(
                pointer,
                gm_mut_bytes(
                    data: bytes.bindMemory(to: UInt8.self).baseAddress,
                    size: bytes.count
                ),
                &required
            )
        }
        try requireRuntimeOK(status, operation: operation)
        output.removeSubrange(required..<output.count)
        return output
    }
}

private func requireRuntimeOK(
    _ status: gm_status,
    operation: String
) throws {
    guard status == GM_OK else {
        throw AppleCryptoError.runtimeFailure(
            operation: operation,
            status: String(cString: gm_status_string(status))
        )
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

    /// Returns `true` only when an existing, non-revoked record grants the
    /// requested permission. Unknown, malformed-length, and revoked peers fail
    /// closed; callers must not start TLS control or derive media keys otherwise.
    public func authorizes(
        peerSPKIDigest: Data,
        permission: TrustPermissions
    ) throws -> Bool {
        guard peerSPKIDigest.count == 32,
              let record = try record(for: peerSPKIDigest) else {
            return false
        }
        return try ProtocolCore.trustRecord(record.coreRecord, authorizes: permission)
    }

    /// Persists a local pairing decision. The caller is responsible for showing
    /// the peer's full fingerprint and obtaining user approval before this call.
    public func approve(
        peerSPKIDigest: Data,
        permissions: TrustPermissions
    ) throws {
        guard peerSPKIDigest.count == 32 else {
            throw SecureStoreError.invalidStoredValue("peer SPKI digest")
        }
        try save(StoredTrustRecord(
            peerSPKIDigest: peerSPKIDigest,
            permissions: permissions
        ))
    }

    /// Revocation is retained rather than deleted, preventing a revoked peer
    /// from being treated as an unknown pairing by a later approval workflow.
    public func revoke(peerSPKIDigest: Data) throws {
        guard peerSPKIDigest.count == 32 else {
            throw SecureStoreError.invalidStoredValue("peer SPKI digest")
        }
        let permissions = try record(for: peerSPKIDigest)?.coreRecord.permissions ?? []
        try save(StoredTrustRecord(
            peerSPKIDigest: peerSPKIDigest,
            permissions: permissions,
            isRevoked: true
        ))
    }

    private func key(for digest: Data) -> String {
        "trust-\(digest.map { String(format: "%02x", $0) }.joined())"
    }
}

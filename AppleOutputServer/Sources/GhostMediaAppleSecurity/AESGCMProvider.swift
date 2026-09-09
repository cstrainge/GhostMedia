import CryptoKit
import Foundation
import GhostMediaProtocolBridge

public struct AESGCMSealedPayload: Equatable, Sendable {
    public let ciphertext: Data
    public let tag: Data

    public init(ciphertext: Data, tag: Data) {
        self.ciphertext = ciphertext
        self.tag = tag
    }
}

public enum AppleCryptoError: Error, Equatable, Sendable {
    case invalidKeyLength(Int)
    case invalidNonceLength(Int)
    case invalidAADLength(Int)
    case invalidTagLength(Int)
    case payloadTooLarge(Int)
    case authenticationFailed
    case exporterUnavailable
    case invalidExporterContextLength(Int)
    case exporterLength(Int)
}

public enum AppleAESGCM {
    public static func seal(
        _ plaintext: Data,
        key: Data,
        nonce: Data,
        authenticating aad: Data
    ) throws -> AESGCMSealedPayload {
        try validate(key: key, nonce: nonce, aad: aad, payload: plaintext, tag: nil)
        let sealed = try AES.GCM.seal(
            plaintext,
            using: SymmetricKey(data: key),
            nonce: try AES.GCM.Nonce(data: nonce),
            authenticating: aad
        )
        return AESGCMSealedPayload(ciphertext: sealed.ciphertext, tag: sealed.tag)
    }

    public static func open(
        _ sealed: AESGCMSealedPayload,
        key: Data,
        nonce: Data,
        authenticating aad: Data
    ) throws -> Data {
        try validate(
            key: key,
            nonce: nonce,
            aad: aad,
            payload: sealed.ciphertext,
            tag: sealed.tag
        )
        do {
            return try AES.GCM.open(
                AES.GCM.SealedBox(
                    nonce: try AES.GCM.Nonce(data: nonce),
                    ciphertext: sealed.ciphertext,
                    tag: sealed.tag
                ),
                using: SymmetricKey(data: key),
                authenticating: aad
            )
        } catch {
            throw AppleCryptoError.authenticationFailed
        }
    }

    private static func validate(
        key: Data,
        nonce: Data,
        aad: Data,
        payload: Data,
        tag: Data?
    ) throws {
        guard key.count == 32 else {
            throw AppleCryptoError.invalidKeyLength(key.count)
        }
        guard nonce.count == 12 else {
            throw AppleCryptoError.invalidNonceLength(nonce.count)
        }
        guard aad.count <= 64 else {
            throw AppleCryptoError.invalidAADLength(aad.count)
        }
        guard payload.count <= 1_420 else {
            throw AppleCryptoError.payloadTooLarge(payload.count)
        }
        if let tag, tag.count != 16 {
            throw AppleCryptoError.invalidTagLength(tag.count)
        }
    }
}

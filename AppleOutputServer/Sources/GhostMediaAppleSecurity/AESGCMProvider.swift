import Foundation
import GhostMediaProtocolBridge
import GhostMediaRuntime

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
    case runtimeFailure(operation: String, status: String)
}

public enum AppleAESGCM {
    public static func seal(
        _ plaintext: Data,
        key: Data,
        nonce: Data,
        authenticating aad: Data
    ) throws -> AESGCMSealedPayload {
        try validate(key: key, nonce: nonce, aad: aad, payload: plaintext, tag: nil)
        var ciphertext = Data(count: plaintext.count)
        var tag = Data(count: 16)
        let status = withBytes(key) { keyBytes in
            withBytes(nonce) { nonceBytes in
                withBytes(aad) { aadBytes in
                    withBytes(plaintext) { plaintextBytes in
                        ciphertext.withUnsafeMutableBytes { ciphertextBytes in
                            tag.withUnsafeMutableBytes { tagBytes in
                                gm_runtime_aes256_gcm_encrypt(
                                    keyBytes,
                                    nonceBytes,
                                    aadBytes,
                                    plaintextBytes,
                                    mutableBytes(ciphertextBytes),
                                    mutableBytes(tagBytes)
                                )
                            }
                        }
                    }
                }
            }
        }
        try requireRuntimeOK(status, operation: "gm_runtime_aes256_gcm_encrypt")
        return AESGCMSealedPayload(ciphertext: ciphertext, tag: tag)
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
        var plaintext = Data(count: sealed.ciphertext.count)
        let status = withBytes(key) { keyBytes in
            withBytes(nonce) { nonceBytes in
                withBytes(aad) { aadBytes in
                    withBytes(sealed.ciphertext) { ciphertextBytes in
                        withBytes(sealed.tag) { tagBytes in
                            plaintext.withUnsafeMutableBytes { plaintextBytes in
                                gm_runtime_aes256_gcm_decrypt(
                                    keyBytes,
                                    nonceBytes,
                                    aadBytes,
                                    ciphertextBytes,
                                    tagBytes,
                                    mutableBytes(plaintextBytes)
                                )
                            }
                        }
                    }
                }
            }
        }
        if status == GM_BAD_MESSAGE {
            throw AppleCryptoError.authenticationFailed
        }
        try requireRuntimeOK(status, operation: "gm_runtime_aes256_gcm_decrypt")
        return plaintext
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

    private static func withBytes<T>(
        _ data: Data,
        _ body: (gm_bytes) throws -> T
    ) rethrows -> T {
        try data.withUnsafeBytes { buffer in
            try body(
                gm_bytes(
                    data: buffer.bindMemory(to: UInt8.self).baseAddress,
                    size: buffer.count
                )
            )
        }
    }

    private static func mutableBytes(_ buffer: UnsafeMutableRawBufferPointer) -> gm_mut_bytes {
        gm_mut_bytes(
            data: buffer.bindMemory(to: UInt8.self).baseAddress,
            size: buffer.count
        )
    }

    private static func requireRuntimeOK(
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
}

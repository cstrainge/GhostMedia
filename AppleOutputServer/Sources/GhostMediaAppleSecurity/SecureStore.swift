import Foundation
import Security

public protocol SecureValueStore: Sendable {
    func data(for key: String) throws -> Data?
    func set(_ data: Data, for key: String) throws
}

public enum SecureStoreError: Error, Equatable, Sendable {
    case keychainStatus(OSStatus)
    case invalidStoredValue(String)
}

public struct KeychainSecureStore: SecureValueStore, Sendable {
    public let service: String

    public init(service: String = "com.ghostmedia.output-server") {
        self.service = service
    }

    public func data(for key: String) throws -> Data? {
        var query = baseQuery(for: key)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne

        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound {
            return nil
        }
        guard status == errSecSuccess, let data = result as? Data else {
            throw SecureStoreError.keychainStatus(status)
        }
        return data
    }

    public func set(_ data: Data, for key: String) throws {
        let query = baseQuery(for: key)
        let attributes: [String: Any] = [
            kSecValueData as String: data,
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
        ]
        let updateStatus = SecItemUpdate(query as CFDictionary, attributes as CFDictionary)
        if updateStatus == errSecSuccess {
            return
        }
        guard updateStatus == errSecItemNotFound else {
            throw SecureStoreError.keychainStatus(updateStatus)
        }

        var addition = query
        attributes.forEach { addition[$0.key] = $0.value }
        let addStatus = SecItemAdd(addition as CFDictionary, nil)
        guard addStatus == errSecSuccess else {
            throw SecureStoreError.keychainStatus(addStatus)
        }
    }

    private func baseQuery(for key: String) -> [String: Any] {
        [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: key,
            kSecUseDataProtectionKeychain as String: true,
        ]
    }
}

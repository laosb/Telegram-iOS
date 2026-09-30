import Foundation
import Security

// Custody lives outside Postbox, account directories and transport logout.
@available(iOS 18.0, macOS 15.0, *)
enum BlahKeychain {
    static let service = "ing.blah.identity.v1"

    static func read(_ key: String, sync: Bool = false) throws -> Data? {
        var query = attributes(key, sync: sync)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw BlahIdentityError.keychain(status) }
        return data
    }

    static func write(_ key: String, data: Data, sync: Bool = false) throws {
        let query = attributes(key, sync: sync)
        let update = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = sync ? kSecAttrAccessibleWhenUnlocked : kSecAttrAccessibleWhenUnlockedThisDeviceOnly
            let added = SecItemAdd(item as CFDictionary, nil)
            guard added == errSecSuccess else { throw BlahIdentityError.keychain(added) }
        } else if status != errSecSuccess { throw BlahIdentityError.keychain(status) }
    }

    static func remove(_ key: String, sync: Bool = false) throws {
        let status = SecItemDelete(attributes(key, sync: sync) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw BlahIdentityError.keychain(status) }
    }

    static func keys(sync: Bool = false) throws -> [String] {
        let query: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service, kSecAttrSynchronizable as String: sync,
            kSecReturnAttributes as String: true, kSecMatchLimit as String: kSecMatchLimitAll]
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw BlahIdentityError.keychain(status) }
        return (result as? [[String: Any]] ?? []).compactMap { $0[kSecAttrAccount as String] as? String }
    }

    private static func attributes(_ key: String, sync: Bool) -> [String: Any] {
        return [kSecClass as String: kSecClassGenericPassword, kSecAttrService as String: service,
            kSecAttrAccount as String: key, kSecAttrSynchronizable as String: sync]
    }
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahIdentityError: Error, LocalizedError {
    case keychain(OSStatus), unavailable, locked, invalidProfile, wrongHome, staleProfile, publicationRequired, duplicate

    public var errorDescription: String? {
        switch self {
        case .keychain: return "Identity storage is unavailable or access was cancelled."
        case .unavailable: return "Secure Enclave is required to create or recover an identity on this device."
        case .locked: return "Unlock your identity to continue."
        case .invalidProfile: return "The identity or DC profile is invalid."
        case .wrongHome: return "This account belongs to another identity or home. Add another account."
        case .staleProfile: return "The profile is older than the saved revision or conflicts with it."
        case .publicationRequired: return "Publish the latest profile at every listed domain, then sign in again."
        case .duplicate: return "This identity is already saved. Unlock its current copy."
        }
    }
}

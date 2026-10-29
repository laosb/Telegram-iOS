import Foundation
import Security

// Custody lives outside Postbox, account directories and transport logout.
@available(iOS 18.0, macOS 15.0, *)
enum BlahKeychain {
    static let service = "ing.blah.identity.v1"

    static func read(_ key: String, sync: Bool = false, accessGroup: String? = nil) throws -> Data? {
        var query = attributes(key, sync: sync, accessGroup: accessGroup)
        query[kSecReturnData as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitOne
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return nil }
        guard status == errSecSuccess, let data = result as? Data else { throw BlahIdentityError.keychain(status) }
        return data
    }

    static func write(_ key: String, data: Data, sync: Bool = false, accessGroup: String? = nil) throws {
        let query = attributes(key, sync: sync, accessGroup: accessGroup)
        let update = [kSecValueData as String: data]
        let status = SecItemUpdate(query as CFDictionary, update as CFDictionary)
        if status == errSecItemNotFound {
            var item = query
            item[kSecValueData as String] = data
            item[kSecAttrAccessible as String] = accessGroup != nil ? kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
                : (sync ? kSecAttrAccessibleWhenUnlocked : kSecAttrAccessibleWhenUnlockedThisDeviceOnly)
            let added = SecItemAdd(item as CFDictionary, nil)
            guard added == errSecSuccess else { throw BlahIdentityError.keychain(added) }
        } else if status != errSecSuccess { throw BlahIdentityError.keychain(status) }
    }

    static func remove(_ key: String, sync: Bool = false, accessGroup: String? = nil) throws {
        let status = SecItemDelete(attributes(key, sync: sync, accessGroup: accessGroup) as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else { throw BlahIdentityError.keychain(status) }
    }

    static func keys(sync: Bool = false, accessGroup: String? = nil) throws -> [String] {
        var query = attributes(nil, sync: sync, accessGroup: accessGroup)
        query[kSecReturnAttributes as String] = true
        query[kSecMatchLimit as String] = kSecMatchLimitAll
        var result: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        if status == errSecItemNotFound { return [] }
        guard status == errSecSuccess else { throw BlahIdentityError.keychain(status) }
        return (result as? [[String: Any]] ?? []).compactMap { $0[kSecAttrAccount as String] as? String }
    }

    private static func attributes(_ key: String?, sync: Bool, accessGroup: String?) -> [String: Any] {
        var result: [String: Any] = [kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: accessGroup == nil ? service : "ing.blah.identity.restore.v1",
            kSecAttrSynchronizable as String: sync]
        if let key { result[kSecAttrAccount as String] = key }
        if let accessGroup { result[kSecAttrAccessGroup as String] = accessGroup }
        return result
    }
}

@available(iOS 18.0, macOS 15.0, *)
struct BlahRestoreKeychain {
    let accessGroup: String
    let isAppExtension: Bool

    func read(_ key: String) throws -> Data? {
        if let data = try BlahKeychain.read(key, accessGroup: accessGroup) { return data }
        guard !isAppExtension, let data = try BlahKeychain.read(key) else { return nil }
        try write(key, data: data)
        return data
    }

    func write(_ key: String, data: Data) throws {
        try BlahKeychain.write(key, data: data, accessGroup: accessGroup)
    }

    func remove(_ key: String) throws {
        try BlahKeychain.remove(key)
        try BlahKeychain.remove(key, accessGroup: accessGroup)
    }

    func keys() throws -> Set<String> {
        var keys = Set(try BlahKeychain.keys(accessGroup: accessGroup))
        if !isAppExtension { keys.formUnion(try BlahKeychain.keys()) }
        return keys
    }
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahIdentityError: Error, LocalizedError {
    case keychain(OSStatus), unavailable, locked, invalidProfile, wrongHome, staleProfile, publicationRequired, duplicate, profileUnavailable
    case profileVerificationFailed, managementRequired

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
        case .profileUnavailable: return "The profile server could not be reached."
        case .profileVerificationFailed: return "This domain serves an identity profile whose signature or validity could not be verified."
        case .managementRequired: return "This device does not hold permission to manage the identity."
        }
    }
}

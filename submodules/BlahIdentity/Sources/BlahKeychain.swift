import Foundation
import Security
import BlahDiem

// Slot custody lives outside Postbox; logout removes its opaque Secure Enclave references.
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
        return try BlahKeychain.read(key, accessGroup: accessGroup)
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
    case hosting(String)

    public var errorDescription: String? {
        switch self {
        case .keychain: return "Identity storage is unavailable or access was cancelled."
        case .unavailable: return "Secure Enclave is required to create or recover an identity on this device."
        case .locked: return "Identity custody is unavailable. Try again."
        case .invalidProfile: return "The identity or DC profile is invalid."
        case .wrongHome: return "This account belongs to another identity or home. Add another account."
        case .staleProfile: return "The profile is older than the saved revision or conflicts with it."
        case .publicationRequired: return "Publish the latest profile at every listed domain, then check publication again."
        case .duplicate: return "This account slot already has an identity. Add another account."
        case .profileUnavailable: return "The profile server could not be reached."
        case .profileVerificationFailed: return "This domain serves an identity profile whose signature or validity could not be verified."
        case .managementRequired: return "Enter the recovery words on this device to manage the identity."
        case let .hosting(message): return message
        }
    }
}

/// Describes hosting errors, which do not provide LocalizedError messages in Diem.
@available(iOS 18.0, macOS 15.0, *)
public func blahIdentityErrorDescription(_ error: Error) -> String {
    guard let error = error as? ProfileHostingError else { return error.localizedDescription }
    switch error {
    case .cancelled: return "Profile publication was cancelled."
    case .invalidResponse: return "The profile hosting service returned an invalid response."
    case let .unexpectedStatus(status): return "The profile hosting service returned HTTP \(status)."
    case .domainMismatch: return "The profile hosting service does not match the requested domain."
    case let .unsupportedAlgorithm(algorithm): return "The profile hosting service does not support \(algorithm)."
    case let .invalidLabel(label): return "The profile hosting name \(label) is invalid."
    case let .nameTaken(label): return "The profile hosting name \(label) is already taken."
    case let .unsolvable(label): return "The proof of work required to publish \(label) could not be completed."
    case let .invalidProof(label): return "The hosting proof for \(label) is invalid."
    case .noHostedName: return "The profile has no name on this hosting service."
    case .hostNotListed: return "The hosting service is not listed in the profile."
    case .tooLarge: return "The profile is too large for the hosting service."
    case .domainsMismatch: return "The profile domains do not match the hosting request."
    case .publishedMismatch: return "The hosting service is not serving the exact saved profile."
    case let .problem(problem):
        let detail = problem.detail.isEmpty ? problem.title : problem.detail
        return "The profile hosting service refused publication: \(detail) (HTTP \(problem.status))."
    }
}

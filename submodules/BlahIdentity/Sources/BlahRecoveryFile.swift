import Foundation
import CommonCrypto
import BlahDiem
import DiemSwiftCrypto

@available(iOS 18.0, macOS 15.0, *)
enum BlahRecoveryFile {
    static func seal(profile: Profile, identityKey: IdentityPrivateKey, password: String) async throws -> Data {
        guard let secret = identityKey.rawRepresentation else { throw BlahIdentityError.locked }
        let backend = SwiftCryptoBackend()
        let salt = backend.randomBytes(count: 16)
        let recipient = try await KeyFile.passwordRecipient(password, salt: salt, using: backend, pbkdf2: derivePassword)
        let contents = try KeyFileContents(profile: profile, keys: [
            KeyFilePrivateKey(publicKey: identityKey.publicKey.key, secret: secret)
        ])
        return Data(try await KeyFile.seal(contents, salt: salt, to: recipient.publicKey, using: backend).encoding)
    }

    static func open(_ data: Data, password: String) async throws -> KeyFileContents {
        guard data.count <= KeyFile.maximumBytes else { throw BlahIdentityError.invalidProfile }
        let file = try KeyFile(encoding: Array(data))
        let backend = SwiftCryptoBackend()
        let recipient = try await KeyFile.passwordRecipient(password, salt: file.salt, using: backend, pbkdf2: derivePassword)
        return try await file.open(with: recipient, using: backend)
    }

    private static func derivePassword(_ password: [UInt8], _ salt: [UInt8], _ iterations: UInt32) async throws -> [UInt8] {
        var derived = [UInt8](repeating: 0, count: 32)
        let status = derived.withUnsafeMutableBytes { output in
            salt.withUnsafeBytes { saltBytes in
                password.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.bindMemory(to: Int8.self).baseAddress, password.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), iterations,
                        output.bindMemory(to: UInt8.self).baseAddress, 32)
                }
            }
        }
        guard status == kCCSuccess else { throw BlahIdentityError.invalidProfile }
        return derived
    }
}

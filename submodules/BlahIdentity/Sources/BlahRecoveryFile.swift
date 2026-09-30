import Foundation
import CryptoKit
import CommonCrypto
import BlahDiem

@available(iOS 18.0, macOS 15.0, *)
enum BlahRecoveryFile {
    private struct Envelope: Codable {
        let format: String
        let salt: Data
        let nonce: Data
        let ciphertext: Data
    }

    static func seal(_ plaintext: Data, password: String) throws -> Data {
        let salt = Data((0..<16).map { _ in UInt8.random(in: .min ... .max) })
        let key = try passwordKey(password, salt: salt)
        let box = try AES.GCM.seal(plaintext, using: key, authenticating: Data("Blah/iOS/recovery/1".utf8))
        return try JSONEncoder().encode(Envelope(format: "Blah/iOS/recovery/1", salt: salt,
            nonce: Data(box.nonce), ciphertext: box.ciphertext + box.tag))
    }

    static func open(_ data: Data, password: String) throws -> Data {
        guard data.count < 600000 else { throw BlahIdentityError.invalidProfile }
        guard let envelope = try? JSONDecoder().decode(Envelope.self, from: data) else {
            return try openBrowser(data, password: password)
        }
        guard envelope.format == "Blah/iOS/recovery/1", envelope.salt.count == 16,
            envelope.nonce.count == 12, envelope.ciphertext.count >= 16 else { throw BlahIdentityError.invalidProfile }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: envelope.nonce),
            ciphertext: envelope.ciphertext.dropLast(16), tag: envelope.ciphertext.suffix(16))
        return try AES.GCM.open(box, using: passwordKey(password, salt: envelope.salt),
            authenticating: Data(envelope.format.utf8))
    }

    // Browser v1 exports carry a software Ed25519 root in PKCS#8. Import only
    // that recovery authority; the phone always enrolls a fresh hardware device.
    private struct BrowserEnvelope: Decodable {
        let version: Int
        let id: String
        let salt: Data
        let iv: Data
        let ciphertext: Data
    }
    private struct BrowserSecret: Decodable {
        struct Key: Decodable { let privateKey: Data }
        let identity: Key
        let profile: Data
    }
    private struct Recovery: Encodable {
        let version = 1
        let secret: Data
        let profile: Data
    }
    private static func openBrowser(_ data: Data, password: String) throws -> Data {
        let envelope = try JSONDecoder().decode(BrowserEnvelope.self, from: data)
        guard envelope.version == 1, envelope.id.count == 64,
            envelope.id.allSatisfy({ "0123456789abcdef".contains($0) }),
            envelope.salt.count == 16, envelope.iv.count == 12, envelope.ciphertext.count >= 16 else {
            throw BlahIdentityError.invalidProfile
        }
        let box = try AES.GCM.SealedBox(nonce: AES.GCM.Nonce(data: envelope.iv),
            ciphertext: envelope.ciphertext.dropLast(16), tag: envelope.ciphertext.suffix(16))
        let plaintext = try AES.GCM.open(box, using: passwordKey(password, salt: envelope.salt),
            authenticating: Data("Blah/browser-identity/1:\(envelope.id)".utf8))
        let secret = try JSONDecoder().decode(BrowserSecret.self, from: plaintext)
        let prefix = Data([0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20])
        guard secret.identity.privateKey.count == 48, secret.identity.privateKey.prefix(16) == prefix,
            try Profile(encoding: Array(secret.profile)).id.description == envelope.id else {
            throw BlahIdentityError.invalidProfile
        }
        return try JSONEncoder().encode(Recovery(secret: Data(secret.identity.privateKey.suffix(32)), profile: secret.profile))
    }

    private static func passwordKey(_ password: String, salt: Data) throws -> SymmetricKey {
        guard password.utf16.count >= 12 else { throw BlahIdentityError.invalidProfile }
        let passwordBytes = Array(password.utf8)
        var derived = Data(count: 32)
        let status = derived.withUnsafeMutableBytes { output in
            salt.withUnsafeBytes { saltBytes in
                passwordBytes.withUnsafeBytes { secretBytes in
                    CCKeyDerivationPBKDF(CCPBKDFAlgorithm(kCCPBKDF2),
                        secretBytes.bindMemory(to: Int8.self).baseAddress, passwordBytes.count,
                        saltBytes.bindMemory(to: UInt8.self).baseAddress, salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256), 600000,
                        output.bindMemory(to: UInt8.self).baseAddress, 32)
                }
            }
        }
        guard status == kCCSuccess else { throw BlahIdentityError.invalidProfile }
        defer { derived.resetBytes(in: 0..<derived.count) }
        return SymmetricKey(data: derived)
    }
}

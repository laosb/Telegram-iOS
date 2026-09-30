import Crypto
import Diem
import Foundation

/// A ``Diem/CryptoBackend`` on Swift Crypto. ML-DSA-65 and X-Wing need OS 26 on Apple platforms.
public struct SwiftCryptoBackend: CryptoBackend {
  public init() {}

  public var now: UInt64 { UInt64(Date().timeIntervalSince1970) }

  public func randomBytes(count: Int) -> [UInt8] {
    var generator = SystemRandomNumberGenerator()
    return (0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) }
  }

  public func makePrivateKey(
    _ algorithm: PublicKey.Algorithm, for purpose: PublicKey.Purpose, restoring raw: [UInt8]?
  ) async throws -> PrivateKey {
    try normalized(.invalidKey) {
      switch algorithm {
      case .ed25519:
        let key = try raw.map { try Curve25519.Signing.PrivateKey(rawRepresentation: $0) }
          ?? Curve25519.Signing.PrivateKey()
        return try PrivateKey(
          publicKey: PublicKey(purpose: purpose, algorithm: algorithm, rawRepresentation: Array(key.publicKey.rawRepresentation)),
          protection: .software, rawRepresentation: Array(key.rawRepresentation)
        ) { try Array(key.signature(for: $0)) }
      case .p256:
        let key = try raw.map { try P256.Signing.PrivateKey(rawRepresentation: $0) }
          ?? P256.Signing.PrivateKey()
        return try PrivateKey(
          publicKey: PublicKey(purpose: purpose, algorithm: algorithm, rawRepresentation: Array(key.publicKey.x963Representation)),
          protection: .software, rawRepresentation: Array(key.rawRepresentation)
        ) { try Array(key.signature(for: $0).rawRepresentation) }
      case .mlDSA65:
        guard #available(macOS 26, iOS 26, watchOS 26, tvOS 26, visionOS 26, *) else {
          throw DiemError.unsupportedAlgorithm
        }
        let key = try raw.map { try MLDSA65.PrivateKey(seedRepresentation: Data($0), publicKey: nil) }
          ?? MLDSA65.PrivateKey()
        return try PrivateKey(
          publicKey: PublicKey(purpose: purpose, algorithm: algorithm, rawRepresentation: Array(key.publicKey.rawRepresentation)),
          protection: .software, rawRepresentation: Array(key.seedRepresentation)
        ) { try Array(key.signature(for: $0)) }
      }
    }
  }

  public func isValidSignature(_ signature: [UInt8], for message: [UInt8], by key: PublicKey)
    async throws -> Bool
  {
    try normalized(.invalidKey) {
      switch key.algorithm {
      case .ed25519:
        return try Curve25519.Signing.PublicKey(rawRepresentation: key.rawRepresentation)
          .isValidSignature(signature, for: message)
      case .p256:
        guard let ecdsa = try? P256.Signing.ECDSASignature(rawRepresentation: signature) else {
          return false
        }
        return try P256.Signing.PublicKey(x963Representation: key.rawRepresentation)
          .isValidSignature(ecdsa, for: message)
      case .mlDSA65:
        guard #available(macOS 26, iOS 26, watchOS 26, tvOS 26, visionOS 26, *) else {
          throw DiemError.unsupportedAlgorithm
        }
        return try MLDSA65.PublicKey(rawRepresentation: key.rawRepresentation)
          .isValidSignature(signature, for: message)
      }
    }
  }

  public func makeEncryptionKey(
    _ algorithm: EncryptionPublicKey.Algorithm, restoring raw: [UInt8]?
  ) async throws -> EncryptionPrivateKey {
    try normalized(.invalidKey) {
      switch algorithm {
      case .x25519:
        let key = try raw.map { try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: $0) }
          ?? Curve25519.KeyAgreement.PrivateKey()
        return try EncryptionPrivateKey(
          publicKey: EncryptionPublicKey(algorithm: algorithm, rawRepresentation: Array(key.publicKey.rawRepresentation)),
          protection: .software, rawRepresentation: Array(key.rawRepresentation)
        ) { box, context in
          try HPKEOpen.open(box, context: context) {
            try HPKE.Recipient(
              privateKey: key, ciphersuite: .Curve25519_SHA256_ChachaPoly, info: Data(context),
              encapsulatedKey: Data(box.encapsulatedKey))
          }
        }
      case .p256:
        let key = try raw.map { try P256.KeyAgreement.PrivateKey(rawRepresentation: $0) }
          ?? P256.KeyAgreement.PrivateKey()
        return try EncryptionPrivateKey(
          publicKey: EncryptionPublicKey(algorithm: algorithm, rawRepresentation: Array(key.publicKey.x963Representation)),
          protection: .software, rawRepresentation: Array(key.rawRepresentation)
        ) { box, context in
          try HPKEOpen.open(box, context: context) {
            try HPKE.Recipient(
              privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: Data(context),
              encapsulatedKey: Data(box.encapsulatedKey))
          }
        }
      case .xWing:
        guard #available(macOS 26, iOS 26, watchOS 26, tvOS 26, visionOS 26, *) else {
          throw DiemError.unsupportedAlgorithm
        }
        let key = try raw.map {
          try XWingMLKEM768X25519.PrivateKey(seedRepresentation: Data($0), publicKey: nil)
        } ?? XWingMLKEM768X25519.PrivateKey()
        return try EncryptionPrivateKey(
          publicKey: EncryptionPublicKey(algorithm: algorithm, rawRepresentation: Array(key.publicKey.rawRepresentation)),
          protection: .software, rawRepresentation: Array(key.seedRepresentation)
        ) { box, context in
          try HPKEOpen.open(box, context: context) {
            try HPKE.Recipient(
              privateKey: key, ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256,
              info: Data(context), encapsulatedKey: Data(box.encapsulatedKey))
          }
        }
      }
    }
  }

  public func seal(_ plaintext: [UInt8], to key: EncryptionPublicKey, context: [UInt8])
    async throws -> SealedBox
  {
    try normalized(.encryptionFailed) {
      var sender: HPKE.Sender
      switch key.algorithm {
      case .x25519:
        sender = try HPKE.Sender(
          recipientKey: Curve25519.KeyAgreement.PublicKey(rawRepresentation: key.rawRepresentation),
          ciphersuite: .Curve25519_SHA256_ChachaPoly, info: Data(context))
      case .p256:
        sender = try HPKE.Sender(
          recipientKey: P256.KeyAgreement.PublicKey(x963Representation: key.rawRepresentation),
          ciphersuite: .P256_SHA256_AES_GCM_256, info: Data(context))
      case .xWing:
        guard #available(macOS 26, iOS 26, watchOS 26, tvOS 26, visionOS 26, *) else {
          throw DiemError.unsupportedAlgorithm
        }
        sender = try HPKE.Sender(
          recipientKey: XWingMLKEM768X25519.PublicKey(rawRepresentation: key.rawRepresentation),
          ciphersuite: .XWingMLKEM768X25519_SHA256_AES_GCM_256, info: Data(context))
      }
      return try SealedBox(
        encapsulatedKey: Array(sender.encapsulatedKey),
        ciphertext: Array(sender.seal(plaintext, authenticating: context)))
    }
  }
}

enum HPKEOpen {
  static func open(
    _ box: SealedBox, context: [UInt8], recipient: () throws -> HPKE.Recipient
  ) throws -> [UInt8] {
    try normalized(.decryptionFailed) {
      var opener = try recipient()
      return try Array(opener.open(box.ciphertext, authenticating: context))
    }
  }
}

/// Rethrows ``DiemError`` unchanged and replaces any other error with `failure`.
func normalized<T>(_ failure: DiemError, _ body: () throws -> T) throws(DiemError) -> T {
  do { return try body() } catch { throw error as? DiemError ?? failure }
}

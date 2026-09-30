#if canImport(CryptoKit) && canImport(Security)
  import CryptoKit
  import Diem
  import Foundation
  import Security

  extension PrivateKey {
    /// A new P-256 signing key for `purpose` generated inside the Secure Enclave, and the
    /// opaque reference that restores it on this device. P-256 is not post-quantum.
    public static func secureEnclave(
      for purpose: PublicKey.Purpose, accessControl: SecAccessControl
    ) throws -> (key: PrivateKey, reference: Data) {
      guard SecureEnclave.isAvailable else { throw DiemError.unsupportedAlgorithm }
      let key = try SecureEnclave.P256.Signing.PrivateKey(accessControl: accessControl)
      return (try PrivateKey(key, purpose: purpose), key.dataRepresentation)
    }

    /// The Secure Enclave signing key for `purpose` that `reference` names on this device.
    public init(secureEnclaveReference reference: Data, for purpose: PublicKey.Purpose) throws {
      try self.init(
        SecureEnclave.P256.Signing.PrivateKey(dataRepresentation: reference), purpose: purpose)
    }

    private init(_ key: SecureEnclave.P256.Signing.PrivateKey, purpose: PublicKey.Purpose) throws {
      try self.init(
        publicKey: PublicKey(purpose: purpose, algorithm: .p256, rawRepresentation: Array(key.publicKey.x963Representation)),
        protection: .hardware, rawRepresentation: nil
      ) { try Array(key.signature(for: $0).rawRepresentation) }
    }
  }

  extension EncryptionPrivateKey {
    /// A new P-256 encryption key generated inside the Secure Enclave, and the opaque
    /// reference that restores it on this device. P-256 is not post-quantum.
    public static func secureEnclave(accessControl: SecAccessControl) throws
      -> (key: EncryptionPrivateKey, reference: Data)
    {
      guard SecureEnclave.isAvailable else { throw DiemError.unsupportedAlgorithm }
      let key = try SecureEnclave.P256.KeyAgreement.PrivateKey(accessControl: accessControl)
      return (try EncryptionPrivateKey(key), key.dataRepresentation)
    }

    /// The Secure Enclave encryption key that `reference` names on this device.
    public init(secureEnclaveReference reference: Data) throws {
      try self.init(SecureEnclave.P256.KeyAgreement.PrivateKey(dataRepresentation: reference))
    }

    private init(_ key: SecureEnclave.P256.KeyAgreement.PrivateKey) throws {
      try self.init(
        publicKey: EncryptionPublicKey(algorithm: .p256, rawRepresentation: Array(key.publicKey.x963Representation)),
        protection: .hardware, rawRepresentation: nil
      ) { box, context in
        try HPKEOpen.open(box, context: context) {
          try HPKE.Recipient(
            privateKey: key, ciphersuite: .P256_SHA256_AES_GCM_256, info: Data(context),
            encapsulatedKey: Data(box.encapsulatedKey))
        }
      }
    }
  }
#endif

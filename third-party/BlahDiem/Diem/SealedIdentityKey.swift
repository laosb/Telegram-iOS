/// An identity private key encrypted to one encryption key, for storage or transfer.
public struct SealedIdentityKey: Hashable, Sendable {
  private var extensionFields: [UInt64: CBOR] = [:]

  public let identityKey: IdentityPublicKey
  /// The key that can open this box.
  public let recipient: EncryptionPublicKey
  public let box: SealedBox

  /// Decodes a sealed key from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try CBOR(decoding: encoding).recordValue(requiredKeys: 0..<6)
    guard a[0]! == .text("Diem/sealed-identity-key"), a[1]! == .unsigned(3) else {
      throw .invalidEncoding
    }
    identityKey = try IdentityPublicKey(PublicKey(encoding: a[2]!.bytesValue()))
    recipient = try EncryptionPublicKey(encoding: a[3]!.bytesValue())
    box = try SealedBox(encapsulatedKey: a[4]!.bytesValue(), ciphertext: a[5]!.bytesValue())
    extensionFields = a.filter { $0.key >= 6 }
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    CBOR.record([
      0: .text("Diem/sealed-identity-key"), 1: .unsigned(3), 2: .bytes(identityKey.key.encoding),
      3: .bytes(recipient.encoding), 4: .bytes(box.encapsulatedKey), 5: .bytes(box.ciphertext),
    ], extensions: extensionFields).encoded
  }

  /// The identity private key, decrypted with the recipient's `key`.
  public func open(with key: EncryptionPrivateKey, using backend: some CryptoBackend) async throws
    -> IdentityPrivateKey
  {
    guard key.publicKey == recipient else { throw DiemError.identityMismatch }
    let secret = try await key.open(
      box, context: Self.context(identityKey: identityKey, recipient: recipient))
    let restored = try await backend.makePrivateKey(
      identityKey.key.algorithm, for: .identity, restoring: secret)
    guard restored.publicKey == identityKey.key else { throw DiemError.decryptionFailed }
    return try IdentityPrivateKey(restored)
  }

  fileprivate init(identityKey: IdentityPublicKey, recipient: EncryptionPublicKey, box: SealedBox) {
    self.identityKey = identityKey
    self.recipient = recipient
    self.box = box
  }

  fileprivate static func context(identityKey: IdentityPublicKey, recipient: EncryptionPublicKey)
    -> [UInt8]
  {
    CBOR.record([
      0: .text("Diem/sealed-identity-key"), 1: .unsigned(3), 2: .bytes(identityKey.key.encoding),
      3: .bytes(recipient.encoding),
    ]).encoded
  }
}

extension IdentityPrivateKey {
  /// This key encrypted to `recipient`. Only software keys can be sealed; a hardware key
  /// throws ``DiemError/invalidKey``.
  public func sealed(to recipient: EncryptionPublicKey, using backend: some CryptoBackend)
    async throws -> SealedIdentityKey
  {
    guard let secret = key.rawRepresentation else { throw DiemError.invalidKey }
    let context = SealedIdentityKey.context(identityKey: publicKey, recipient: recipient)
    return SealedIdentityKey(
      identityKey: publicKey, recipient: recipient,
      box: try await backend.seal(secret, to: recipient, context: context))
  }
}

/// An identity private key encrypted to one encryption key, for storage or transfer.
public struct SealedIdentityKey: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyIdentityKey: UInt64 = 2
  public static let cborKeyRecipient: UInt64 = 3
  public static let cborKeyEncapsulatedKey: UInt64 = 4
  public static let cborKeyCiphertext: UInt64 = 5

  private var extensionFields: [UInt64: CBOR] = [:]

  public let identityKey: IdentityPublicKey
  /// The key that can open this box.
  public let recipient: EncryptionPublicKey
  public let box: SealedBox

  /// Decodes a sealed key from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try CBOR(decoding: encoding).recordValue(
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyCiphertext + 1))
    guard a[Self.cborKeyTag]! == .text("Diem/sealed-identity-key"),
      a[Self.cborKeyVersion]! == .unsigned(3)
    else {
      throw .invalidEncoding
    }
    identityKey = try IdentityPublicKey(
      PublicKey(encoding: a[Self.cborKeyIdentityKey]!.bytesValue()))
    recipient = try EncryptionPublicKey(encoding: a[Self.cborKeyRecipient]!.bytesValue())
    box = try SealedBox(
      encapsulatedKey: a[Self.cborKeyEncapsulatedKey]!.bytesValue(),
      ciphertext: a[Self.cborKeyCiphertext]!.bytesValue())
    extensionFields = a.filter { $0.key > Self.cborKeyCiphertext }
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .text("Diem/sealed-identity-key"), Self.cborKeyVersion: .unsigned(3),
        Self.cborKeyIdentityKey: .bytes(identityKey.key.encoding),
        Self.cborKeyRecipient: .bytes(recipient.encoding),
        Self.cborKeyEncapsulatedKey: .bytes(box.encapsulatedKey),
        Self.cborKeyCiphertext: .bytes(box.ciphertext),
      ], extensions: extensionFields
    ).encoded
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
      Self.cborKeyTag: .text("Diem/sealed-identity-key"), Self.cborKeyVersion: .unsigned(3),
      Self.cborKeyIdentityKey: .bytes(identityKey.key.encoding),
      Self.cborKeyRecipient: .bytes(recipient.encoding),
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

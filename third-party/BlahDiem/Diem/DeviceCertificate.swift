/// An identity's signed statement that a device key acts for it.
///
/// Certificates of one ``generation`` form the identity's device set. A profile lists
/// certificates of a single generation.
public struct DeviceCertificate: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = 0
  public static let cborKeyVersion: UInt64 = 1
  public static let cborKeyIdentityID: UInt64 = 2
  public static let cborKeyGeneration: UInt64 = 3
  public static let cborKeyDevice: UInt64 = 4
  public static let cborKeyNotBefore: UInt64 = 5
  public static let cborKeyExpiresAt: UInt64 = 6

  /// Default certificate lifetime. Applications may choose a different interval.
  public static let defaultLifetime: UInt64 = 30 * 24 * 60 * 60
  /// The wire timestamp bound. The identity owner chooses certificate validity.
  public static let maximumLifetime = UInt64(Int64.max)

  /// The identity's signed message.
  public let signedMessage: SignedMessage
  public let identityID: Digest
  public let generation: UInt64
  public let device: DevicePublicKey
  public let validity: Validity

  /// Decodes a certificate from the identity's signed message.
  public init(_ signedMessage: SignedMessage) throws(DiemError) {
    let a = try CBOR(decoding: signedMessage.message).recordValue(
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyExpiresAt + 1))
    guard a[Self.cborKeyTag]! == .text("Diem/device"), a[Self.cborKeyVersion]! == .unsigned(3)
    else { throw .invalidEncoding }
    identityID = try Digest(bytes: a[Self.cborKeyIdentityID]!.bytesValue())
    generation = try a[Self.cborKeyGeneration]!.unsignedValue()
    guard generation > 0, generation <= UInt64(Int64.max) else { throw .invalidEncoding }
    device = try DevicePublicKey(PublicKey(encoding: a[Self.cborKeyDevice]!.bytesValue()))
    validity = try Validity(
      notBefore: a[Self.cborKeyNotBefore]!.unsignedValue(),
      expiresAt: a[Self.cborKeyExpiresAt]!.unsignedValue())
    self.signedMessage = signedMessage
  }

  /// Decodes a certificate from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    try self.init(SignedMessage(encoding: encoding))
  }

  /// The canonical encoding.
  public var encoding: [UInt8] { signedMessage.encoding }

  static func issue(
    by identityKey: IdentityPrivateKey, for device: DevicePublicKey, generation: UInt64,
    validity: Validity
  ) async throws -> Self {
    let message = CBOR.record([
      Self.cborKeyTag: .text("Diem/device"), Self.cborKeyVersion: .unsigned(3),
      Self.cborKeyIdentityID: .bytes(identityKey.publicKey.id.bytes),
      Self.cborKeyGeneration: .unsigned(generation),
      Self.cborKeyDevice: .bytes(device.key.encoding),
      Self.cborKeyNotBefore: .unsigned(validity.notBefore),
      Self.cborKeyExpiresAt: .unsigned(validity.expiresAt),
    ]).encoded
    return try Self(await SignedMessage(signing: message, with: identityKey.key))
  }

  func verify(identityKey: IdentityPublicKey, at time: UInt64, using backend: some CryptoBackend)
    async throws
  {
    guard identityID == identityKey.id, !device.key.hasSameMaterial(as: identityKey.key) else {
      throw DiemError.identityMismatch
    }
    try validity.require(at: time, maximumLifetime: Self.maximumLifetime)
    try await signedMessage.verify(by: identityKey.key, using: backend)
  }
}

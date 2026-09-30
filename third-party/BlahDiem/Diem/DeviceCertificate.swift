/// An identity's signed statement that a device key acts for it.
///
/// Certificates of one ``generation`` form the identity's device set. A profile lists
/// certificates of a single generation.
public struct DeviceCertificate: Hashable, Sendable {
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
    let a = try CBOR(decoding: signedMessage.message).arrayValue(count: 7)
    guard a[0] == .text("Diem/device"), a[1] == .unsigned(3) else { throw .invalidEncoding }
    identityID = try Digest(bytes: a[2].bytesValue())
    generation = try a[3].unsignedValue()
    guard generation > 0, generation <= UInt64(Int64.max) else { throw .invalidEncoding }
    device = try DevicePublicKey(PublicKey(encoding: a[4].bytesValue()))
    validity = try Validity(notBefore: a[5].unsignedValue(), expiresAt: a[6].unsignedValue())
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
    let message = CBOR.array([
      .text("Diem/device"), .unsigned(3), .bytes(identityKey.publicKey.id.bytes),
      .unsigned(generation), .bytes(device.key.encoding), .unsigned(validity.notBefore),
      .unsigned(validity.expiresAt),
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

/// A device's signed statement of data on behalf of an identity.
public struct Proof: Hashable, Sendable {
  /// The device's signed message.
  public let signedMessage: SignedMessage
  public let identityID: Digest
  public let deviceID: Digest
  public let data: [UInt8]

  /// Decodes a proof from the device's signed message.
  public init(_ signedMessage: SignedMessage) throws(DiemError) {
    let a = try CBOR(decoding: signedMessage.message).arrayValue(count: 5)
    guard a[0] == .text("Diem/proof"), a[1] == .unsigned(3) else { throw .invalidEncoding }
    identityID = try Digest(bytes: a[2].bytesValue())
    deviceID = try Digest(bytes: a[3].bytesValue())
    data = try a[4].bytesValue()
    self.signedMessage = signedMessage
  }

  /// Decodes a proof from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    try self.init(SignedMessage(encoding: encoding))
  }

  /// The canonical encoding.
  public var encoding: [UInt8] { signedMessage.encoding }

  /// Verifies `profile`, then that its identity and one of its devices signed this proof.
  public func verify(
    against profile: Profile, using backend: some CryptoBackend, at time: UInt64? = nil
  ) async throws {
    try await profile.verify(using: backend, at: time)
    guard identityID == profile.id else { throw DiemError.identityMismatch }
    guard let device = profile.device(deviceID) else { throw DiemError.deviceNotListed }
    try await signedMessage.verify(by: device.key, using: backend)
  }

  static func sign(_ data: [UInt8], identityID: Digest, by device: DevicePrivateKey) async throws
    -> Self
  {
    let message = CBOR.array([
      .text("Diem/proof"), .unsigned(3), .bytes(identityID.bytes),
      .bytes(device.publicKey.id.bytes), .bytes(data),
    ]).encoded
    return try Self(await SignedMessage(signing: message, with: device.key))
  }
}

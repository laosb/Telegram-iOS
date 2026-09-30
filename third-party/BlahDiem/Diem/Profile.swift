/// An identity's public statement: its key, its certified devices, and application data
/// signed by one of those devices.
public struct Profile: Hashable, Sendable {
  /// Default publishing lifetime. Applications may choose a different interval.
  public static let defaultLifetime: UInt64 = 24 * 60 * 60
  /// The wire timestamp bound; a profile must also fit its signing certificate.
  public static let maximumLifetime = UInt64(Int64.max)
  /// The most devices one profile may list.
  public static let maximumDevices = 128

  public let identityKey: IdentityPublicKey
  /// The identity's certificates for its devices, all of one generation.
  public let devices: [DeviceCertificate]
  /// The content, signed by ``signer``.
  public let content: SignedMessage

  /// The device generation of every listed certificate.
  public let generation: UInt64
  /// The device that signed ``content``.
  public let signer: DevicePublicKey
  /// The content revision, starting at 1.
  public let revision: UInt64
  /// The ``digest`` of the previous revision; `nil` for revision 1.
  public let previousDigest: Digest?
  public let validity: Validity
  /// The application data.
  public let data: [UInt8]

  /// The identity ID.
  public var id: Digest { identityKey.id }
  /// The digest of this revision's content.
  public var digest: Digest { content.digest }

  /// Decodes a well-formed profile from its ``encoding``. ``verify(using:at:)`` checks its
  /// signatures and validity.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try CBOR(decoding: encoding).arrayValue(count: 5)
    guard a[0] == .text("Diem/profile"), a[1] == .unsigned(3) else { throw .invalidEncoding }
    let certificates = try a[3].arrayValue()
    var devices: [DeviceCertificate] = []
    for certificate in certificates {
      devices.append(try DeviceCertificate(encoding: certificate.bytesValue()))
    }
    try self.init(
      identityKey: IdentityPublicKey(PublicKey(encoding: a[2].bytesValue())), devices: devices,
      content: SignedMessage(encoding: a[4].bytesValue()))
  }

  private init(identityKey: IdentityPublicKey, devices: [DeviceCertificate], content: SignedMessage)
    throws(DiemError)
  {
    let c = try CBOR(decoding: content.message).arrayValue(count: 10)
    guard c[0] == .text("Diem/profile-content"), c[1] == .unsigned(3) else {
      throw .invalidEncoding
    }
    guard try Digest(bytes: c[2].bytesValue()) == identityKey.id else { throw .identityMismatch }
    generation = try c[3].unsignedValue()
    let signerID = try Digest(bytes: c[4].bytesValue())
    revision = try c[5].unsignedValue()
    let previous = try c[6].bytesValue()
    validity = try Validity(notBefore: c[7].unsignedValue(), expiresAt: c[8].unsignedValue())
    data = try c[9].bytesValue()
    guard revision > 0, revision <= UInt64(Int64.max),
      previous.count == (revision == 1 ? 0 : 32)
    else { throw .invalidEncoding }
    previousDigest = revision == 1 ? nil : try Digest(bytes: previous)

    guard (1...Self.maximumDevices).contains(devices.count),
      Set(devices.map { $0.device }).count == devices.count
    else { throw .invalidEncoding }
    for certificate in devices {
      guard certificate.identityID == identityKey.id, certificate.generation == generation,
        !certificate.device.key.hasSameMaterial(as: identityKey.key)
      else { throw .identityMismatch }
    }
    guard let certificate = devices.first(where: { $0.device.id == signerID }) else {
      throw .deviceNotListed
    }
    guard validity.isWithin(certificate.validity) else { throw .invalidValidity }
    signer = certificate.device
    self.identityKey = identityKey
    self.devices = devices
    self.content = content
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    CBOR.array([
      .text("Diem/profile"), .unsigned(3), .bytes(identityKey.key.encoding),
      .array(devices.map { .bytes($0.encoding) }), .bytes(content.encoding),
    ]).encoded
  }

  /// The listed device with `id`, if any.
  public func device(_ id: Digest) -> DevicePublicKey? {
    devices.first { $0.device.id == id }?.device
  }

  /// Verifies every certificate and the content signature, and that all are valid at
  /// `time` (the backend's current time by default).
  public func verify(using backend: some CryptoBackend, at time: UInt64? = nil) async throws {
    let time = time ?? backend.now
    for certificate in devices {
      try await certificate.verify(identityKey: identityKey, at: time, using: backend)
    }
    try validity.require(at: time, maximumLifetime: Self.maximumLifetime)
    try await content.verify(by: signer.key, using: backend)
  }

  static func sign(
    identityKey: IdentityPublicKey, devices: [DeviceCertificate], by signer: DevicePrivateKey,
    revision: UInt64, previousDigest: Digest?, validity: Validity, data: [UInt8]
  ) async throws -> Self {
    guard let generation = devices.first?.generation else { throw DiemError.deviceNotListed }
    let message = CBOR.array([
      .text("Diem/profile-content"), .unsigned(3), .bytes(identityKey.id.bytes),
      .unsigned(generation), .bytes(signer.publicKey.id.bytes), .unsigned(revision),
      .bytes(previousDigest?.bytes ?? []), .unsigned(validity.notBefore),
      .unsigned(validity.expiresAt), .bytes(data),
    ]).encoded
    return try Self(
      identityKey: identityKey, devices: devices,
      content: await SignedMessage(signing: message, with: signer.key))
  }
}

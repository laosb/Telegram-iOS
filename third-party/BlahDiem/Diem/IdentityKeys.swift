/// The public key of an identity. Its ``id`` is the identity's ID.
public struct IdentityPublicKey: Hashable, Sendable {
  public let key: PublicKey

  /// Wraps an ``PublicKey/Purpose/identity`` key; any other purpose throws
  /// ``DiemError/invalidKey``.
  public init(_ key: PublicKey) throws(DiemError) {
    guard key.purpose == .identity else { throw .invalidKey }
    self.key = key
  }

  fileprivate init(unchecked key: PublicKey) { self.key = key }

  /// The identity ID: the SHA-256 digest of the key's encoding.
  public var id: Digest { key.id }
}

/// The private key of an identity. It certifies devices and signs nothing else.
public struct IdentityPrivateKey: Sendable {
  let key: PrivateKey

  /// Wraps an ``PublicKey/Purpose/identity`` key; any other purpose throws
  /// ``DiemError/invalidKey``.
  public init(_ key: PrivateKey) throws(DiemError) {
    guard key.publicKey.purpose == .identity else { throw .invalidKey }
    self.key = key
  }

  /// A new software identity key, ML-DSA-65 by default.
  public static func generate(
    _ algorithm: PublicKey.Algorithm = .mlDSA65, using backend: some CryptoBackend
  ) async throws -> Self {
    try Self(await backend.makePrivateKey(algorithm, for: .identity))
  }

  public var publicKey: IdentityPublicKey { IdentityPublicKey(unchecked: key.publicKey) }
  public var protection: KeyProtection { key.protection }
}

/// The public key of a device. Its ``id`` is the device's ID.
public struct DevicePublicKey: Hashable, Sendable {
  public let key: PublicKey

  /// Wraps a ``PublicKey/Purpose/device`` key; any other purpose throws
  /// ``DiemError/invalidKey``.
  public init(_ key: PublicKey) throws(DiemError) {
    guard key.purpose == .device else { throw .invalidKey }
    self.key = key
  }

  fileprivate init(unchecked key: PublicKey) { self.key = key }

  /// The device ID: the SHA-256 digest of the key's encoding.
  public var id: Digest { key.id }
}

/// The private key of a device. It signs profile content and proofs.
public struct DevicePrivateKey: Sendable {
  let key: PrivateKey

  /// Wraps a ``PublicKey/Purpose/device`` key; any other purpose throws
  /// ``DiemError/invalidKey``.
  public init(_ key: PrivateKey) throws(DiemError) {
    guard key.publicKey.purpose == .device else { throw .invalidKey }
    self.key = key
  }

  /// A new software device key, ML-DSA-65 by default.
  public static func generate(
    _ algorithm: PublicKey.Algorithm = .mlDSA65, using backend: some CryptoBackend
  ) async throws -> Self {
    try Self(await backend.makePrivateKey(algorithm, for: .device))
  }

  public var publicKey: DevicePublicKey { DevicePublicKey(unchecked: key.publicKey) }
  public var protection: KeyProtection { key.protection }
  /// The exportable secret of a software key; `nil` for hardware keys.
  public var rawRepresentation: [UInt8]? { key.rawRepresentation }
}

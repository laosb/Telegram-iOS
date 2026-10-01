/// A message and a signature over it.
public struct SignedMessage: Hashable, Sendable {
  private var extensionFields: [UInt64: CBOR] = [:]

  public let message: [UInt8]
  public let signature: [UInt8]

  public init(message: [UInt8], signature: [UInt8]) {
    self.message = message
    self.signature = signature
  }

  /// `message` signed with `key`.
  public init(signing message: [UInt8], with key: PrivateKey) async throws {
    self.init(message: message, signature: try await key.signature(for: message))
  }

  /// Decodes a signed message from its ``encoding``.
  public init(encoding: [UInt8]) throws(DiemError) {
    let a = try CBOR(decoding: encoding).recordValue(requiredKeys: 0..<2)
    try self.init(message: a[0]!.bytesValue(), signature: a[1]!.bytesValue())
    extensionFields = a.filter { $0.key >= 2 }
  }

  /// The canonical encoding.
  public var encoding: [UInt8] { CBOR.record([0: .bytes(message), 1: .bytes(signature)], extensions: extensionFields).encoded }

  /// The SHA-256 digest of ``message``.
  public var digest: Digest { Digest(hashing: message) }

  /// Throws ``DiemError/invalidSignature`` unless `key` signed ``message``.
  public func verify(by key: PublicKey, using backend: some CryptoBackend) async throws {
    guard try await backend.isValidSignature(signature, for: message, by: key) else {
      throw DiemError.invalidSignature
    }
  }
}

/// A period from ``notBefore`` until, but excluding, ``expiresAt``, in Unix seconds.
public struct Validity: Hashable, Sendable {
  public let notBefore: UInt64
  public let expiresAt: UInt64

  /// A non-empty period.
  public init(notBefore: UInt64, expiresAt: UInt64) throws(DiemError) {
    guard notBefore < expiresAt, expiresAt <= UInt64(Int64.max) else { throw .invalidValidity }
    self.notBefore = notBefore
    self.expiresAt = expiresAt
  }

  /// The period of `lifetime` seconds starting at `start`.
  public init(starting start: UInt64, lifetime: UInt64) throws(DiemError) {
    guard lifetime <= UInt64(Int64.max), start <= UInt64(Int64.max) - lifetime else {
      throw .invalidValidity
    }
    try self.init(notBefore: start, expiresAt: start + lifetime)
  }

  /// The period's length in seconds.
  public var lifetime: UInt64 { expiresAt - notBefore }

  /// Whether `time` is within the period.
  public func contains(_ time: UInt64) -> Bool { notBefore <= time && time < expiresAt }

  /// Whether this period lies entirely within `other`.
  public func isWithin(_ other: Validity) -> Bool {
    other.notBefore <= notBefore && expiresAt <= other.expiresAt
  }

  func require(at time: UInt64, maximumLifetime: UInt64) throws(DiemError) {
    guard lifetime <= maximumLifetime else { throw .invalidValidity }
    guard contains(time) else { throw .expired }
  }
}

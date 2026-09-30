/// DC-issued data that a device signs as a ``BlahProof``.
public protocol BlahStatement: Sendable, Hashable {
  /// Decodes a statement from its ``encoding``.
  init(encoding: [UInt8]) throws(BlahError)
  /// The canonical encoding.
  var encoding: [UInt8] { get }
  /// Checks that `identity` may sign this statement now.
  func validate(for identity: Identity) throws(BlahError)
}

/// A Diem proof whose data is a ``BlahStatement``.
public struct BlahProof<Statement: BlahStatement>: Hashable, Sendable {
  public let proof: Proof
  public let statement: Statement

  /// Decodes the statement that `proof` signs.
  public init(_ proof: Proof) throws(BlahError) {
    self.proof = proof
    statement = try Statement(encoding: proof.data)
  }

  /// Decodes a proof from its ``encoding``.
  public init(encoding: [UInt8]) throws(BlahError) {
    guard let proof = try? Proof(encoding: encoding) else { throw .invalidChallenge }
    try self.init(proof)
  }

  /// The canonical encoding.
  public var encoding: [UInt8] { proof.encoding }

  /// Verifies the proof against `profile`, as `Proof.verify(against:using:at:)`.
  public func verify(
    against profile: Profile, using backend: some CryptoBackend, at time: UInt64? = nil
  ) async throws {
    try await proof.verify(against: profile, using: backend, at: time)
  }
}

extension Identity {
  /// Creates an identity publishing `profile`, with new software identity and device keys.
  public init(_ profile: some BlahProfile, using backend: some CryptoBackend) async throws {
    try await self.init(data: profile.encoded(), using: backend)
  }

  /// Creates an identity publishing `profile`, whose only device is `deviceKey`.
  public init(
    _ profile: some BlahProfile, identityKey: IdentityPrivateKey, deviceKey: DevicePrivateKey,
    using backend: some CryptoBackend
  ) async throws {
    try await self.init(
      data: profile.encoded(), identityKey: identityKey, deviceKey: deviceKey, using: backend)
  }

  /// Publishes `profile` as the next revision.
  @discardableResult
  public mutating func update(_ profile: some BlahProfile) async throws -> Profile {
    try await update(data: profile.encoded())
  }

  /// A proof of `statement` by this device, after the statement's own checks.
  public func prove<Statement: BlahStatement>(_ statement: Statement) async throws
    -> BlahProof<Statement>
  {
    try statement.validate(for: self)
    return try BlahProof(await prove(statement.encoding))
  }
}

/// Signing-time checks shared by DC challenges.
extension Identity {
  /// The longest time before its expiry that a device signs a challenge.
  static let challengeWindow: UInt64 = 120

  func requireLive(until expiresAt: UInt64) throws(BlahError) {
    let now = backend.now
    guard now < expiresAt, expiresAt - now <= Self.challengeWindow else {
      throw .challengeExpired
    }
  }

  func requireHome(_ dc: Digest) throws(BlahError) {
    guard (try? AnyBlahProfile(profile))?.home?.dc == dc else { throw .wrongHome }
  }
}

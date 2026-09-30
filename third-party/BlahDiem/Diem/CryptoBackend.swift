/// Platform cryptography and wall-clock time for Diem.
///
/// A backend creates and restores private keys, verifies signatures and seals data to
/// encryption keys. Failures throw ``DiemError``.
public protocol CryptoBackend: Sendable {
  /// The current time in seconds since the Unix epoch.
  var now: UInt64 { get }

  /// `count` cryptographically secure random bytes.
  func randomBytes(count: Int) -> [UInt8]

  /// A new software signing key for `purpose`, or the one whose secret is
  /// `rawRepresentation`.
  func makePrivateKey(
    _ algorithm: PublicKey.Algorithm, for purpose: PublicKey.Purpose,
    restoring rawRepresentation: [UInt8]?
  ) async throws -> PrivateKey

  /// Whether `signature` is `key`'s signature over `message`.
  func isValidSignature(_ signature: [UInt8], for message: [UInt8], by key: PublicKey)
    async throws -> Bool

  /// A new software encryption key, or the one whose secret is `rawRepresentation`.
  func makeEncryptionKey(
    _ algorithm: EncryptionPublicKey.Algorithm, restoring rawRepresentation: [UInt8]?
  ) async throws -> EncryptionPrivateKey

  /// `plaintext` sealed to `key`. `context` is both the HPKE info and the associated data.
  func seal(_ plaintext: [UInt8], to key: EncryptionPublicKey, context: [UInt8]) async throws
    -> SealedBox
}

extension CryptoBackend {
  /// A new software signing key for `purpose`, ML-DSA-65 by default.
  public func makePrivateKey(
    _ algorithm: PublicKey.Algorithm = .mlDSA65, for purpose: PublicKey.Purpose
  ) async throws -> PrivateKey {
    try await makePrivateKey(algorithm, for: purpose, restoring: nil)
  }

  /// A new software encryption key, X-Wing by default.
  public func makeEncryptionKey(_ algorithm: EncryptionPublicKey.Algorithm = .xWing)
    async throws -> EncryptionPrivateKey
  {
    try await makeEncryptionKey(algorithm, restoring: nil)
  }
}

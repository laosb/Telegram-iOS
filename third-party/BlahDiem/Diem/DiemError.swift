/// An error from a Diem operation.
public enum DiemError: Error, Sendable, Equatable {
  /// Bytes are not the canonical encoding of the expected record.
  case invalidEncoding
  /// Key bytes do not form a key of the stated algorithm.
  case invalidKey
  /// A signature does not verify against the expected key.
  case invalidSignature
  /// The backend cannot perform this algorithm.
  case unsupportedAlgorithm
  /// A validity period is empty or longer than its record allows.
  case invalidValidity
  /// The time is outside a record's validity period.
  case expired
  /// Records name different identities, devices or keys.
  case identityMismatch
  /// The device is not certified in the profile.
  case deviceNotListed
  /// The operation needs the identity private key.
  case identityKeyRequired
  /// The backend failed to encrypt.
  case encryptionFailed
  /// The ciphertext, context or key does not decrypt.
  case decryptionFailed
}

/// An error from a BlahDiem operation.
public enum BlahError: Error, Sendable, Equatable {
  /// Profile data is not a well-formed Blah profile of the expected kind.
  case invalidProfile
  /// A domain or username is malformed or not allowed for the profile kind.
  case invalidName
  /// The profile's home is a different DC.
  case wrongHome
  /// A challenge or statement is malformed or names a different identity, device or DC.
  case invalidChallenge
  /// A challenge is outside its signing window.
  case challengeExpired
  /// A profile belongs to a different client namespace.
  case wrongNamespace
}

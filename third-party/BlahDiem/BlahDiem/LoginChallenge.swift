/// A DC's one-attempt challenge for a device to sign up or sign in over one MTProto session.
public struct LoginChallenge: BlahStatement {
  public enum Operation: UInt64, Hashable, Sendable {
    case signUp = 1
    case signIn = 2
  }

  public let operation: Operation
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let identityID: Digest
  public let deviceID: Digest
  /// The `Profile.digest` of the profile the device signs in with.
  public let profileDigest: Digest
  public let dc: DCAddress
  public let authKeyID: Int64
  public let sessionID: UInt64

  public init(
    operation: Operation, nonce: [UInt8], expiresAt: UInt64, identityID: Digest,
    deviceID: Digest, profileDigest: Digest, dc: DCAddress, authKeyID: Int64, sessionID: UInt64
  ) throws(BlahError) {
    guard nonce.count == 32, expiresAt <= UInt64(Int64.max), authKeyID != 0, sessionID != 0 else {
      throw .invalidChallenge
    }
    self.operation = operation
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.identityID = identityID
    self.deviceID = deviceID
    self.profileDigest = profileDigest
    self.dc = dc
    self.authKeyID = authKeyID
    self.sessionID = sessionID
  }

  public init(encoding: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidChallenge
    let a = try CBOR.record(encoding, tag: .login, count: 12, error: e)
    guard let operation = Operation(rawValue: try a[2].unsigned(e)) else { throw e }
    try self.init(
      operation: operation, nonce: a[3].bytes(e), expiresAt: a[4].unsigned(e),
      identityID: a[5].digest(e), deviceID: a[6].digest(e), profileDigest: a[7].digest(e),
      dc: DCAddress(domain: a[8].text(e), id: a[9].digest(e)),
      authKeyID: Int64(bitPattern: a[10].unsigned(e)), sessionID: a[11].unsigned(e))
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsigned(BlahTag.login.rawValue), .unsigned(1), .unsigned(operation.rawValue),
      .bytes(nonce), .unsigned(expiresAt), .bytes(identityID.bytes), .bytes(deviceID.bytes),
      .bytes(profileDigest.bytes), .text(dc.domain), .bytes(dc.id.bytes),
      .unsigned(UInt64(bitPattern: authKeyID)), .unsigned(sessionID),
    ]).encoded
  }

  /// Requires a live challenge for this identity, device and profile, from its home DC.
  public func validate(for identity: Identity) throws(BlahError) {
    try identity.requireLive(until: expiresAt)
    guard identityID == identity.id, deviceID == identity.deviceKey.publicKey.id,
      profileDigest == identity.profile.digest
    else { throw .invalidChallenge }
    try identity.requireHome(dc.id)
  }
}

/// A DC's one-attempt challenge for a device to sign up or sign in over one MTProto session.
public struct LoginChallenge: BlahStatement {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyOperation: UInt64 = 2
  public static let cborKeyNonce: UInt64 = 3
  public static let cborKeyExpiresAt: UInt64 = 4
  public static let cborKeyIdentityID: UInt64 = 5
  public static let cborKeyDeviceID: UInt64 = 6
  public static let cborKeyProfileDigest: UInt64 = 7
  public static let cborKeyDCDomain: UInt64 = 8
  public static let cborKeyDCID: UInt64 = 9
  public static let cborKeyAuthKeyID: UInt64 = 10
  public static let cborKeySessionID: UInt64 = 11

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
  private var extensionFields: [UInt64: CBOR] = [:]

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
    let a = try CBOR.record(
      encoding, tag: .login, requiredKeys: Self.cborKeyTag..<(Self.cborKeySessionID + 1), error: e)
    guard let operation = Operation(rawValue: try a[Self.cborKeyOperation]!.unsigned(e)) else {
      throw e
    }
    try self.init(
      operation: operation, nonce: a[Self.cborKeyNonce]!.bytes(e),
      expiresAt: a[Self.cborKeyExpiresAt]!.unsigned(e),
      identityID: a[Self.cborKeyIdentityID]!.digest(e),
      deviceID: a[Self.cborKeyDeviceID]!.digest(e),
      profileDigest: a[Self.cborKeyProfileDigest]!.digest(e),
      dc: DCAddress(domain: a[Self.cborKeyDCDomain]!.text(e), id: a[Self.cborKeyDCID]!.digest(e)),
      authKeyID: Int64(bitPattern: a[Self.cborKeyAuthKeyID]!.unsigned(e)),
      sessionID: a[Self.cborKeySessionID]!.unsigned(e))
    extensionFields = a.filter { $0.key > Self.cborKeySessionID }
  }

  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .unsigned(BlahTag.login.rawValue), Self.cborKeyVersion: .unsigned(1),
        Self.cborKeyOperation: .unsigned(operation.rawValue),
        Self.cborKeyNonce: .bytes(nonce), Self.cborKeyExpiresAt: .unsigned(expiresAt),
        Self.cborKeyIdentityID: .bytes(identityID.bytes),
        Self.cborKeyDeviceID: .bytes(deviceID.bytes),
        Self.cborKeyProfileDigest: .bytes(profileDigest.bytes),
        Self.cborKeyDCDomain: .text(dc.domain), Self.cborKeyDCID: .bytes(dc.id.bytes),
        Self.cborKeyAuthKeyID: .unsigned(UInt64(bitPattern: authKeyID)),
        Self.cborKeySessionID: .unsigned(sessionID),
      ], extensions: extensionFields
    ).encoded
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

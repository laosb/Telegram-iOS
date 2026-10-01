/// A DC's one-use challenge for an identity-proven MTProto call. ``domain`` serves the
/// profile the DC verifies the proof against.
public struct InvocationChallenge: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyDomain: UInt64 = 2
  public static let cborKeyNonce: UInt64 = 3
  public static let cborKeyExpiresAt: UInt64 = 4
  public static let cborKeyDC: UInt64 = 5
  public static let cborKeyTransportKeyID: UInt64 = 6
  public static let cborKeySessionID: UInt64 = 7

  private var extensionFields: [UInt64: CBOR] = [:]

  public let domain: String
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  /// The issuing DC's identity ID.
  public let dc: Digest
  public let transportKeyID: Int64
  public let sessionID: UInt64

  public init(
    domain: String, nonce: [UInt8], expiresAt: UInt64, dc: Digest, transportKeyID: Int64,
    sessionID: UInt64
  ) throws(BlahError) {
    guard DomainName.isValid(domain), nonce.count == 32, expiresAt <= UInt64(Int64.max),
      transportKeyID != 0, sessionID != 0
    else { throw .invalidChallenge }
    self.domain = domain
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.dc = dc
    self.transportKeyID = transportKeyID
    self.sessionID = sessionID
  }

  public init(encoding: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidChallenge
    let a = try CBOR.record(
      encoding, tag: .invocationChallenge,
      requiredKeys: Self.cborKeyTag..<(Self.cborKeySessionID + 1), error: e)
    try self.init(
      domain: a[Self.cborKeyDomain]!.text(e), nonce: a[Self.cborKeyNonce]!.bytes(e),
      expiresAt: a[Self.cborKeyExpiresAt]!.unsigned(e), dc: a[Self.cborKeyDC]!.digest(e),
      transportKeyID: Int64(bitPattern: a[Self.cborKeyTransportKeyID]!.unsigned(e)),
      sessionID: a[Self.cborKeySessionID]!.unsigned(e))
    extensionFields = a.filter { $0.key > Self.cborKeySessionID }
  }

  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .unsigned(BlahTag.invocationChallenge.rawValue),
        Self.cborKeyVersion: .unsigned(1), Self.cborKeyDomain: .text(domain),
        Self.cborKeyNonce: .bytes(nonce),
        Self.cborKeyExpiresAt: .unsigned(expiresAt), Self.cborKeyDC: .bytes(dc.bytes),
        Self.cborKeyTransportKeyID: .unsigned(UInt64(bitPattern: transportKeyID)),
        Self.cborKeySessionID: .unsigned(sessionID),
      ], extensions: extensionFields
    ).encoded
  }
}

/// A challenge and the SHA-512 digest of the exact wrapped MTProto query it authorizes.
public struct InvocationStatement: BlahStatement {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyChallenge: UInt64 = 2
  public static let cborKeyDigestAlgorithm: UInt64 = 3
  public static let cborKeyPayloadDigest: UInt64 = 4

  private var extensionFields: [UInt64: CBOR] = [:]

  public let challenge: InvocationChallenge
  public let payloadDigest: [UInt8]

  /// The statement authorizing `payload` under `challenge`.
  public init(challenge: InvocationChallenge, payload: [UInt8]) {
    self.challenge = challenge
    payloadDigest = SHA2.sha512(payload)
  }

  public init(encoding: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidChallenge
    let a = try CBOR.record(
      encoding, tag: .invocationStatement,
      requiredKeys: Self.cborKeyTag..<(Self.cborKeyPayloadDigest + 1), error: e)
    // Digest algorithm code 1 is SHA-512.
    guard a[Self.cborKeyDigestAlgorithm]! == .unsigned(1) else { throw e }
    challenge = try InvocationChallenge(encoding: a[Self.cborKeyChallenge]!.bytes(e))
    payloadDigest = try a[Self.cborKeyPayloadDigest]!.bytes(e, count: 64)
    extensionFields = a.filter { $0.key > Self.cborKeyPayloadDigest }
  }

  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .unsigned(BlahTag.invocationStatement.rawValue),
        Self.cborKeyVersion: .unsigned(1), Self.cborKeyChallenge: .bytes(challenge.encoding),
        Self.cborKeyDigestAlgorithm: .unsigned(1), Self.cborKeyPayloadDigest: .bytes(payloadDigest),
      ], extensions: extensionFields
    ).encoded
  }

  /// Whether this statement authorizes exactly `payload`.
  public func matches(_ payload: [UInt8]) -> Bool { payloadDigest == SHA2.sha512(payload) }

  /// Requires a live challenge for a domain that serves this identity's profile.
  public func validate(for identity: Identity) throws(BlahError) {
    try identity.requireLive(until: challenge.expiresAt)
    guard (try? AnyBlahProfile(identity.profile))?.domains.contains(challenge.domain) == true
    else { throw .invalidChallenge }
  }
}

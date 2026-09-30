/// A DC's one-use challenge for an identity-proven MTProto call. ``domain`` serves the
/// profile the DC verifies the proof against.
public struct InvocationChallenge: Hashable, Sendable {
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
    let a = try CBOR.record(encoding, tag: .invocationChallenge, count: 8, error: e)
    try self.init(
      domain: a[2].text(e), nonce: a[3].bytes(e), expiresAt: a[4].unsigned(e), dc: a[5].digest(e),
      transportKeyID: Int64(bitPattern: a[6].unsigned(e)), sessionID: a[7].unsigned(e))
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsigned(BlahTag.invocationChallenge.rawValue), .unsigned(1), .text(domain), .bytes(nonce),
      .unsigned(expiresAt), .bytes(dc.bytes), .unsigned(UInt64(bitPattern: transportKeyID)),
      .unsigned(sessionID),
    ]).encoded
  }
}

/// A challenge and the SHA-512 digest of the exact wrapped MTProto query it authorizes.
public struct InvocationStatement: BlahStatement {
  public let challenge: InvocationChallenge
  public let payloadDigest: [UInt8]

  /// The statement authorizing `payload` under `challenge`.
  public init(challenge: InvocationChallenge, payload: [UInt8]) {
    self.challenge = challenge
    payloadDigest = SHA2.sha512(payload)
  }

  public init(encoding: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidChallenge
    let a = try CBOR.record(encoding, tag: .invocationStatement, count: 5, error: e)
    // Field 3 names the digest algorithm: 1 is SHA-512.
    guard a[3] == .unsigned(1) else { throw e }
    challenge = try InvocationChallenge(encoding: a[2].bytes(e))
    payloadDigest = try a[4].bytes(e, count: 64)
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsigned(BlahTag.invocationStatement.rawValue), .unsigned(1), .bytes(challenge.encoding),
      .unsigned(1), .bytes(payloadDigest),
    ]).encoded
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

/// A one-attempt consent to an OAuth authorization-code request.
///
/// The device signs it only when it equals the app and permissions the user reviewed.
public struct OAuthConsentChallenge: BlahStatement {
  public let dc: DCAddress
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let appID: UInt64
  public let appName: String
  public let appVersion: UInt64
  public let redirectURI: String
  /// Distinct scopes in ascending order.
  public let scopes: [String]
  /// The PKCE code challenge: 43 base64url characters.
  public let codeChallenge: String
  public let state: String
  public let oidcNonce: String

  public init(
    dc: DCAddress, nonce: [UInt8], expiresAt: UInt64, appID: UInt64, appName: String,
    appVersion: UInt64, redirectURI: String, scopes: [String], codeChallenge: String,
    state: String, oidcNonce: String
  ) throws(BlahError) {
    guard nonce.count == 32, expiresAt <= UInt64(Int64.max), appID > 0,
      appID <= UInt64(Int32.max), appVersion <= UInt64(Int64.max),
      !appName.isEmpty, appName.utf8.count <= 256, !redirectURI.isEmpty,
      redirectURI.utf8.count <= 2048, !scopes.isEmpty, scopes.count <= 16,
      scopes == Array(Set(scopes)).sorted(),
      scopes.allSatisfy({ !$0.isEmpty && $0.utf8.count <= 64 }),
      codeChallenge.utf8.count == 43,
      codeChallenge.utf8.allSatisfy({
        (65...90).contains($0) || (97...122).contains($0) || (48...57).contains($0)
          || $0 == 45 || $0 == 95
      }), state.utf8.count <= 1024, oidcNonce.utf8.count <= 1024
    else { throw .invalidChallenge }
    self.dc = dc
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.appID = appID
    self.appName = appName
    self.appVersion = appVersion
    self.redirectURI = redirectURI
    self.scopes = scopes
    self.codeChallenge = codeChallenge
    self.state = state
    self.oidcNonce = oidcNonce
  }

  public init(encoding: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidChallenge
    let a = try CBOR.record(encoding, tag: .oauthConsent, count: 14, error: e)
    var scopes: [String] = []
    for scope in try a[10].array(e) { scopes.append(try scope.text(e)) }
    try self.init(
      dc: DCAddress(domain: a[2].text(e), id: a[3].digest(e)), nonce: a[4].bytes(e),
      expiresAt: a[5].unsigned(e), appID: a[6].unsigned(e), appName: a[7].text(e),
      appVersion: a[8].unsigned(e), redirectURI: a[9].text(e), scopes: scopes,
      codeChallenge: a[11].text(e), state: a[12].text(e), oidcNonce: a[13].text(e))
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsigned(BlahTag.oauthConsent.rawValue), .unsigned(1), .text(dc.domain), .bytes(dc.id.bytes),
      .bytes(nonce), .unsigned(expiresAt), .unsigned(appID), .text(appName),
      .unsigned(appVersion), .text(redirectURI), .array(scopes.map(CBOR.text)),
      .text(codeChallenge), .text(state), .text(oidcNonce),
    ]).encoded
  }

  /// Requires a live challenge from the identity's home DC.
  public func validate(for identity: Identity) throws(BlahError) {
    try identity.requireLive(until: expiresAt)
    try identity.requireHome(dc.id)
  }
}

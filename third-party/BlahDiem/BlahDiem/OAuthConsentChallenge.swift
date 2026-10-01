/// A one-attempt consent to an OAuth authorization-code request.
///
/// The device signs it only when it equals the app and permissions the user reviewed.
public struct OAuthConsentChallenge: BlahStatement {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyDCDomain: UInt64 = 2
  public static let cborKeyDCID: UInt64 = 3
  public static let cborKeyNonce: UInt64 = 4
  public static let cborKeyExpiresAt: UInt64 = 5
  public static let cborKeyAppID: UInt64 = 6
  public static let cborKeyAppName: UInt64 = 7
  public static let cborKeyAppVersion: UInt64 = 8
  public static let cborKeyRedirectURI: UInt64 = 9
  public static let cborKeyScopes: UInt64 = 10
  public static let cborKeyCodeChallenge: UInt64 = 11
  public static let cborKeyState: UInt64 = 12
  public static let cborKeyOIDCNonce: UInt64 = 13

  private var extensionFields: [UInt64: CBOR] = [:]

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
    let a = try CBOR.record(
      encoding, tag: .oauthConsent, requiredKeys: Self.cborKeyTag..<(Self.cborKeyOIDCNonce + 1),
      error: e)
    var scopes: [String] = []
    for scope in try a[Self.cborKeyScopes]!.array(e) { scopes.append(try scope.text(e)) }
    try self.init(
      dc: DCAddress(domain: a[Self.cborKeyDCDomain]!.text(e), id: a[Self.cborKeyDCID]!.digest(e)),
      nonce: a[Self.cborKeyNonce]!.bytes(e),
      expiresAt: a[Self.cborKeyExpiresAt]!.unsigned(e), appID: a[Self.cborKeyAppID]!.unsigned(e),
      appName: a[Self.cborKeyAppName]!.text(e),
      appVersion: a[Self.cborKeyAppVersion]!.unsigned(e),
      redirectURI: a[Self.cborKeyRedirectURI]!.text(e), scopes: scopes,
      codeChallenge: a[Self.cborKeyCodeChallenge]!.text(e), state: a[Self.cborKeyState]!.text(e),
      oidcNonce: a[Self.cborKeyOIDCNonce]!.text(e))
    extensionFields = a.filter { $0.key > Self.cborKeyOIDCNonce }
  }

  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .unsigned(BlahTag.oauthConsent.rawValue),
        Self.cborKeyVersion: .unsigned(1), Self.cborKeyDCDomain: .text(dc.domain),
        Self.cborKeyDCID: .bytes(dc.id.bytes),
        Self.cborKeyNonce: .bytes(nonce), Self.cborKeyExpiresAt: .unsigned(expiresAt),
        Self.cborKeyAppID: .unsigned(appID), Self.cborKeyAppName: .text(appName),
        Self.cborKeyAppVersion: .unsigned(appVersion), Self.cborKeyRedirectURI: .text(redirectURI),
        Self.cborKeyScopes: .array(scopes.map(CBOR.text)),
        Self.cborKeyCodeChallenge: .text(codeChallenge), Self.cborKeyState: .text(state),
        Self.cborKeyOIDCNonce: .text(oidcNonce),
      ], extensions: extensionFields
    ).encoded
  }

  /// Requires a live challenge from the identity's home DC.
  public func validate(for identity: Identity) throws(BlahError) {
    try identity.requireLive(until: expiresAt)
    try identity.requireHome(dc.id)
  }
}

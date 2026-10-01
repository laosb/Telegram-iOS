/// A device's approval of one read or change of an external-account link.
///
/// The device signs it only when it equals the request the user reviewed.
public struct AccountLinkChallenge: BlahStatement {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyDCDomain: UInt64 = 2
  public static let cborKeyDCID: UInt64 = 3
  public static let cborKeyNonce: UInt64 = 4
  public static let cborKeyExpiresAt: UInt64 = 5
  public static let cborKeyOperation: UInt64 = 6
  public static let cborKeyProvider: UInt64 = 7
  public static let cborKeyIdentityID: UInt64 = 8
  public static let cborKeyRequestID: UInt64 = 9
  public static let cborKeyExternalID: UInt64 = 10
  public static let cborKeyPreviousExternalID: UInt64 = 11
  public static let cborKeyLabel: UInt64 = 12

  public enum Operation: UInt64, Hashable, Sendable {
    case read = 1
    case start = 2
    /// Binds the provider-verified ``AccountLinkChallenge/externalID``, replacing
    /// ``AccountLinkChallenge/previousExternalID``.
    case confirm = 3
    case unlink = 4
  }

  private var extensionFields: [UInt64: CBOR] = [:]

  public let dc: DCAddress
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let operation: Operation
  /// The identity the confirmation binds.
  public let identityID: Digest?
  /// The provider request being confirmed: 32 bytes.
  public let requestID: [UInt8]?
  /// A decimal external account number.
  public let externalID: String?
  public let previousExternalID: String?
  public let label: String?

  public init(
    dc: DCAddress, nonce: [UInt8], expiresAt: UInt64, operation: Operation,
    identityID: Digest? = nil, requestID: [UInt8]? = nil, externalID: String? = nil,
    previousExternalID: String? = nil, label: String? = nil
  ) throws(BlahError) {
    func isAccountNumber(_ value: String?) -> Bool {
      guard let value else { return true }
      guard let number = Int64(value), number > 0 else { return false }
      return String(number) == value
    }
    let fields = (identityID != nil, requestID != nil, externalID != nil, previousExternalID != nil, label != nil)
    let shape = switch operation {
    case .read: fields == (false, false, false, false, false)
    case .start: fields.0 == false && fields.1 == false && fields.2 == false && fields.4 == false
    case .unlink: fields == (false, false, true, false, false)
    case .confirm: fields.0 && fields.1 && fields.2
    }
    guard shape, nonce.count == 32, expiresAt <= UInt64(Int64.max),
      requestID.map({ $0.count == 32 }) ?? true, (label?.utf8.count ?? 0) <= 256,
      isAccountNumber(externalID), isAccountNumber(previousExternalID),
      label != "", requestID != []
    else { throw .invalidChallenge }
    self.dc = dc
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.operation = operation
    self.identityID = identityID
    self.requestID = requestID
    self.externalID = externalID
    self.previousExternalID = previousExternalID
    self.label = label
  }

  public init(encoding: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidChallenge
    let a = try CBOR.record(
      encoding, tag: .accountLink, requiredKeys: Self.cborKeyTag..<(Self.cborKeyLabel + 1), error: e
    )
    guard let operation = Operation(rawValue: try a[Self.cborKeyOperation]!.unsigned(e)),
      a[Self.cborKeyProvider]! == .unsigned(1)
    else {
      throw e
    }
    func text(_ value: CBOR) throws(BlahError) -> String? {
      let text = try value.text(e)
      return text.isEmpty ? nil : text
    }
    let identity = try a[Self.cborKeyIdentityID]!.bytes(e)
    let request = try a[Self.cborKeyRequestID]!.bytes(e)
    try self.init(
      dc: DCAddress(domain: a[Self.cborKeyDCDomain]!.text(e), id: a[Self.cborKeyDCID]!.digest(e)),
      nonce: a[Self.cborKeyNonce]!.bytes(e),
      expiresAt: a[Self.cborKeyExpiresAt]!.unsigned(e), operation: operation,
      identityID: identity.isEmpty ? nil : a[Self.cborKeyIdentityID]!.digest(e),
      requestID: request.isEmpty ? nil : request,
      externalID: text(a[Self.cborKeyExternalID]!),
      previousExternalID: text(a[Self.cborKeyPreviousExternalID]!),
      label: text(a[Self.cborKeyLabel]!))
    extensionFields = a.filter { $0.key > Self.cborKeyLabel }
  }

  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .unsigned(BlahTag.accountLink.rawValue), Self.cborKeyVersion: .unsigned(1),
        Self.cborKeyDCDomain: .text(dc.domain), Self.cborKeyDCID: .bytes(dc.id.bytes),
        Self.cborKeyNonce: .bytes(nonce), Self.cborKeyExpiresAt: .unsigned(expiresAt),
        Self.cborKeyOperation: .unsigned(operation.rawValue), Self.cborKeyProvider: .unsigned(1),
        Self.cborKeyIdentityID: .bytes(identityID?.bytes ?? []),
        Self.cborKeyRequestID: .bytes(requestID ?? []),
        Self.cborKeyExternalID: .text(externalID ?? ""),
        Self.cborKeyPreviousExternalID: .text(previousExternalID ?? ""),
        Self.cborKeyLabel: .text(label ?? ""),
      ], extensions: extensionFields
    ).encoded
  }

  /// Requires a live challenge from the identity's home DC, naming this identity if any.
  public func validate(for identity: Identity) throws(BlahError) {
    try identity.requireLive(until: expiresAt)
    guard identityID == nil || identityID == identity.id else { throw .invalidChallenge }
    try identity.requireHome(dc.id)
  }
}

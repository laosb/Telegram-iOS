/// A device's approval of one read or change of an external-account link.
///
/// The device signs it only when it equals the request the user reviewed.
public struct AccountLinkChallenge: BlahStatement {
  public enum Operation: UInt64, Hashable, Sendable {
    case read = 1
    case start = 2
    /// Binds the provider-verified ``AccountLinkChallenge/externalID``, replacing
    /// ``AccountLinkChallenge/previousExternalID``.
    case confirm = 3
    case unlink = 4
  }

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
    let a = try CBOR.record(encoding, tag: .accountLink, count: 13, error: e)
    guard let operation = Operation(rawValue: try a[6].unsigned(e)), a[7] == .unsigned(1) else {
      throw e
    }
    func text(_ value: CBOR) throws(BlahError) -> String? {
      let text = try value.text(e)
      return text.isEmpty ? nil : text
    }
    let identity = try a[8].bytes(e)
    let request = try a[9].bytes(e)
    try self.init(
      dc: DCAddress(domain: a[2].text(e), id: a[3].digest(e)), nonce: a[4].bytes(e),
      expiresAt: a[5].unsigned(e), operation: operation,
      identityID: identity.isEmpty ? nil : a[8].digest(e), requestID: request.isEmpty ? nil : request,
      externalID: text(a[10]), previousExternalID: text(a[11]), label: text(a[12]))
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsigned(BlahTag.accountLink.rawValue), .unsigned(1), .text(dc.domain), .bytes(dc.id.bytes),
      .bytes(nonce), .unsigned(expiresAt), .unsigned(operation.rawValue), .unsigned(1),
      .bytes(identityID?.bytes ?? []), .bytes(requestID ?? []), .text(externalID ?? ""),
      .text(previousExternalID ?? ""), .text(label ?? ""),
    ]).encoded
  }

  /// Requires a live challenge from the identity's home DC, naming this identity if any.
  public func validate(for identity: Identity) throws(BlahError) {
    try identity.requireLive(until: expiresAt)
    guard identityID == nil || identityID == identity.id else { throw .invalidChallenge }
    try identity.requireHome(dc.id)
  }
}

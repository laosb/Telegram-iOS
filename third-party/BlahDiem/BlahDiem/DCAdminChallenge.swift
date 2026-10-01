/// A one-use approval of one DC administration request.
///
/// The device signs it only when it equals the request the user reviewed.
public struct DCAdminChallenge: BlahStatement {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyDCDomain: UInt64 = 2
  public static let cborKeyDCID: UInt64 = 3
  public static let cborKeyNonce: UInt64 = 4
  public static let cborKeyExpiresAt: UInt64 = 5
  public static let cborKeyOperation: UInt64 = 6
  public static let cborKeyRevision: UInt64 = 7
  public static let cborKeyDocument: UInt64 = 8

  public enum Operation: UInt64, Hashable, Sendable {
    /// Reads the administration document.
    case read = 1
    /// Replaces the document at ``DCAdminChallenge/revision``.
    case replace = 2
    /// Asks a bot's owner to let the bot speak for the application the document names.
    case linkBot = 3
  }

  public static let maximumDocumentBytes = 131_072

  private var extensionFields: [UInt64: CBOR] = [:]

  public let dc: DCAddress
  public let nonce: [UInt8]
  public let expiresAt: UInt64
  public let operation: Operation
  public let revision: UInt64
  public let document: [UInt8]

  public init(
    dc: DCAddress, nonce: [UInt8], expiresAt: UInt64, operation: Operation, revision: UInt64 = 0,
    document: [UInt8] = []
  ) throws(BlahError) {
    let shape = switch operation {
    case .read: document.isEmpty && revision == 0
    case .replace: revision > 0 && !document.isEmpty
    case .linkBot: revision == 0 && !document.isEmpty
    }
    guard shape, nonce.count == 32, expiresAt <= UInt64(Int64.max), revision < UInt64(Int64.max),
      document.count <= Self.maximumDocumentBytes
    else { throw .invalidChallenge }
    self.dc = dc
    self.nonce = nonce
    self.expiresAt = expiresAt
    self.operation = operation
    self.revision = revision
    self.document = document
  }

  public init(encoding: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidChallenge
    let a = try CBOR.record(
      encoding, tag: .dcAdmin, requiredKeys: Self.cborKeyTag..<(Self.cborKeyDocument + 1), error: e)
    guard let operation = Operation(rawValue: try a[Self.cborKeyOperation]!.unsigned(e)) else {
      throw e
    }
    try self.init(
      dc: DCAddress(domain: a[Self.cborKeyDCDomain]!.text(e), id: a[Self.cborKeyDCID]!.digest(e)),
      nonce: a[Self.cborKeyNonce]!.bytes(e),
      expiresAt: a[Self.cborKeyExpiresAt]!.unsigned(e), operation: operation,
      revision: a[Self.cborKeyRevision]!.unsigned(e),
      document: a[Self.cborKeyDocument]!.bytes(e))
    extensionFields = a.filter { $0.key > Self.cborKeyDocument }
  }

  public var encoding: [UInt8] {
    CBOR.record(
      [
        Self.cborKeyTag: .unsigned(BlahTag.dcAdmin.rawValue), Self.cborKeyVersion: .unsigned(1),
        Self.cborKeyDCDomain: .text(dc.domain), Self.cborKeyDCID: .bytes(dc.id.bytes),
        Self.cborKeyNonce: .bytes(nonce), Self.cborKeyExpiresAt: .unsigned(expiresAt),
        Self.cborKeyOperation: .unsigned(operation.rawValue),
        Self.cborKeyRevision: .unsigned(revision),
        Self.cborKeyDocument: .bytes(document),
      ], extensions: extensionFields
    ).encoded
  }

  /// Requires a live challenge from the identity's home DC.
  public func validate(for identity: Identity) throws(BlahError) {
    try identity.requireLive(until: expiresAt)
    try identity.requireHome(dc.id)
  }
}

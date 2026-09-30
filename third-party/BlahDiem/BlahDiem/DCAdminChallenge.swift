/// A one-use approval of one DC administration request.
///
/// The device signs it only when it equals the request the user reviewed.
public struct DCAdminChallenge: BlahStatement {
  public enum Operation: UInt64, Hashable, Sendable {
    /// Reads the administration document.
    case read = 1
    /// Replaces the document at ``DCAdminChallenge/revision``.
    case replace = 2
    /// Asks a bot's owner to let the bot speak for the application the document names.
    case linkBot = 3
  }

  public static let maximumDocumentBytes = 131_072

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
    let a = try CBOR.record(encoding, tag: .dcAdmin, count: 9, error: e)
    guard let operation = Operation(rawValue: try a[6].unsigned(e)) else { throw e }
    try self.init(
      dc: DCAddress(domain: a[2].text(e), id: a[3].digest(e)), nonce: a[4].bytes(e),
      expiresAt: a[5].unsigned(e), operation: operation, revision: a[7].unsigned(e),
      document: a[8].bytes(e))
  }

  public var encoding: [UInt8] {
    CBOR.array([
      .unsigned(BlahTag.dcAdmin.rawValue), .unsigned(1), .text(dc.domain), .bytes(dc.id.bytes),
      .bytes(nonce), .unsigned(expiresAt), .unsigned(operation.rawValue), .unsigned(revision),
      .bytes(document),
    ]).encoded
  }

  /// Requires a live challenge from the identity's home DC.
  public func validate(for identity: Identity) throws(BlahError) {
    try identity.requireLive(until: expiresAt)
    try identity.requireHome(dc.id)
  }
}

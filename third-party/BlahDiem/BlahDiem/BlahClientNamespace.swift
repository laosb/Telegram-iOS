/// The boundary of a client's cached state for one account: one identity, hosted by one
/// DC database generation in one home epoch.
public struct ClientNamespace: Hashable, Sendable {
  public let identityID: Digest
  public let dc: DCAddress
  /// The DC's database generation, pinned by the application.
  public let generation: UInt64
  public let homeEpoch: UInt64

  /// The namespace of `profile`'s account at `dc`. `profile` is a verified profile whose
  /// home is `dc`.
  public init(profile: Profile, dc: DCAddress, generation: UInt64) throws(BlahError) {
    guard (1...UInt64(Int64.max)).contains(generation) else { throw .wrongNamespace }
    guard let home = (try? AnyBlahProfile(profile))?.home, home.dc == dc.id else {
      throw .wrongHome
    }
    identityID = profile.id
    self.dc = dc
    self.generation = generation
    homeEpoch = home.epoch
  }

  /// The canonical encoding.
  public var encoding: [UInt8] {
    CBOR.array([
      .unsigned(BlahTag.clientNamespace.rawValue), .unsigned(1), .bytes(identityID.bytes),
      .text(dc.domain), .bytes(dc.id.bytes), .unsigned(generation), .unsigned(homeEpoch),
    ]).encoded
  }

  /// A stable name for the namespace's storage: the hex SHA-256 digest of ``encoding``.
  public var identifier: String { Digest(hashing: encoding).description }

  /// Throws unless `profile` belongs to this namespace.
  public func require(_ profile: Profile) throws(BlahError) {
    guard let home = (try? AnyBlahProfile(profile))?.home, home.dc == dc.id else {
      throw .wrongHome
    }
    guard profile.id == identityID, home.epoch == homeEpoch else { throw .wrongNamespace }
  }
}

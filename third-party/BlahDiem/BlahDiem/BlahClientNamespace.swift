/// The boundary of a client's cached state for one account: one identity, hosted by one
/// DC database generation in one home epoch.
public struct ClientNamespace: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyIdentityID: UInt64 = 2
  public static let cborKeyDCDomain: UInt64 = 3
  public static let cborKeyDCID: UInt64 = 4
  public static let cborKeyGeneration: UInt64 = 5
  public static let cborKeyHomeEpoch: UInt64 = 6

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
    CBOR.record([
      Self.cborKeyTag: .unsigned(BlahTag.clientNamespace.rawValue),
      Self.cborKeyVersion: .unsigned(1), Self.cborKeyIdentityID: .bytes(identityID.bytes),
      Self.cborKeyDCDomain: .text(dc.domain), Self.cborKeyDCID: .bytes(dc.id.bytes),
      Self.cborKeyGeneration: .unsigned(generation), Self.cborKeyHomeEpoch: .unsigned(homeEpoch),
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

/// Blah data carried in a Diem `Profile`.
public protocol BlahProfile: Sendable, Hashable {
  /// Decodes Blah profile data.
  init(data: [UInt8]) throws(BlahError)
  /// The canonical profile data.
  func encoded() throws(BlahError) -> [UInt8]
}

extension BlahProfile {
  /// Decodes the Blah data of `profile`.
  public init(_ profile: Profile) throws(BlahError) { try self.init(data: profile.data) }
}

/// The DC hosting an account, and the account it allocated there.
public struct Home: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyDC: UInt64 = 0
  public static let cborKeyEpoch: UInt64 = 1
  public static let cborKeyExpiresAt: UInt64 = 2
  public static let cborKeyAccount: UInt64 = 3

  /// The home DC's identity ID.
  public var dc: Digest
  /// The hosting's epoch. A later epoch is a new account.
  public var epoch: UInt64
  /// The end of this home delegation, in Unix seconds.
  public var expiresAt: UInt64
  /// The account number the home allocated, once known.
  public var account: Int64?

  public init(dc: Digest, epoch: UInt64, expiresAt: UInt64, account: Int64? = nil) {
    self.dc = dc
    self.epoch = epoch
    self.expiresAt = expiresAt
    self.account = account
  }

  /// Whether the delegation is in force at `time`.
  public func isActive(at time: UInt64) -> Bool { time < expiresAt }
}

/// A person's profile.
public struct UserProfile: BlahProfile {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyKind: UInt64 = 2
  public static let cborKeyHome: UInt64 = 3
  public static let cborKeyDomains: UInt64 = 4

  public var home: Home?
  /// The domains that serve this profile.
  public var domains: [ProfileDomain]

  public init(home: Home?, domains: [ProfileDomain] = []) {
    self.home = home
    self.domains = domains
  }

  public init(data: [UInt8]) throws(BlahError) {
    (home, domains) = try HostedRecord.decode(data, kind: .user)
  }

  public func encoded() throws(BlahError) -> [UInt8] {
    try HostedRecord.encode(kind: .user, home: home, domains: domains)
  }

  /// The first domain. Setting this replaces the domain list with that one name.
  public var username: String? {
    get { domains.username }
    set { domains.username = newValue }
  }
}

/// A bot's profile.
public struct BotProfile: BlahProfile {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = UserProfile.cborKeyTag
  public static let cborKeyVersion: UInt64 = UserProfile.cborKeyVersion
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind
  public static let cborKeyHome: UInt64 = UserProfile.cborKeyHome
  public static let cborKeyDomains: UInt64 = UserProfile.cborKeyDomains

  public var home: Home?
  /// The domains that serve this profile.
  public var domains: [ProfileDomain]

  public init(home: Home?, domains: [ProfileDomain] = []) {
    self.home = home
    self.domains = domains
  }

  public init(data: [UInt8]) throws(BlahError) {
    (home, domains) = try HostedRecord.decode(data, kind: .bot)
  }

  public func encoded() throws(BlahError) -> [UInt8] {
    try HostedRecord.encode(kind: .bot, home: home, domains: domains)
  }

  /// The first domain. Setting this replaces the domain list with that one name.
  public var username: String? {
    get { domains.username }
    set { domains.username = newValue }
  }
}

/// A channel's or supergroup's profile.
public struct ChannelProfile: BlahProfile {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = UserProfile.cborKeyTag
  public static let cborKeyVersion: UInt64 = UserProfile.cborKeyVersion
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind
  public static let cborKeyHome: UInt64 = UserProfile.cborKeyHome
  public static let cborKeyDomains: UInt64 = UserProfile.cborKeyDomains

  public var home: Home?
  /// The domains that serve this profile.
  public var domains: [ProfileDomain]

  public init(home: Home?, domains: [ProfileDomain] = []) {
    self.home = home
    self.domains = domains
  }

  public init(data: [UInt8]) throws(BlahError) {
    (home, domains) = try HostedRecord.decode(data, kind: .channel)
  }

  public func encoded() throws(BlahError) -> [UInt8] {
    try HostedRecord.encode(kind: .channel, home: home, domains: domains)
  }

  /// The first domain. Setting this replaces the domain list with that one name.
  public var username: String? {
    get { domains.username }
    set { domains.username = newValue }
  }
}

/// A sticker or custom-emoji set's profile.
public struct StickerSetProfile: BlahProfile {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = UserProfile.cborKeyTag
  public static let cborKeyVersion: UInt64 = UserProfile.cborKeyVersion
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind
  public static let cborKeyHome: UInt64 = UserProfile.cborKeyHome
  public static let cborKeyDomains: UInt64 = UserProfile.cborKeyDomains

  public var home: Home?
  /// The set's short name: the one domain that serves this profile.
  public var shortName: String

  public init(home: Home?, shortName: String) {
    self.home = home
    self.shortName = shortName
  }

  public init(data: [UInt8]) throws(BlahError) {
    let (home, domains) = try HostedRecord.decode(data, kind: .stickerSet)
    self.home = home
    shortName = domains[0].name
  }

  public func encoded() throws(BlahError) -> [UInt8] {
    try HostedRecord.encode(
      kind: .stickerSet, home: home, domains: [ProfileDomain(shortName)])
  }
}

/// Any Blah profile, by kind.
public enum AnyBlahProfile: Hashable, Sendable {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = UserProfile.cborKeyTag
  public static let cborKeyVersion: UInt64 = UserProfile.cborKeyVersion
  public static let cborKeyKind: UInt64 = UserProfile.cborKeyKind

  case user(UserProfile)
  case bot(BotProfile)
  case channel(ChannelProfile)
  case stickerSet(StickerSetProfile)
  case dc(DCProfile)

  /// Decodes the Blah data of `profile`.
  public init(_ profile: Profile) throws(BlahError) {
    let fields = try CBOR.record(
      profile.data, tag: .profile, requiredKeys: Self.cborKeyTag..<(Self.cborKeyKind + 1),
      error: .invalidProfile)
    switch ProfileKind(rawValue: try fields[Self.cborKeyKind]!.unsigned(.invalidProfile)) {
    case .user: self = .user(try UserProfile(profile))
    case .bot: self = .bot(try BotProfile(profile))
    case .channel: self = .channel(try ChannelProfile(profile))
    case .stickerSet: self = .stickerSet(try StickerSetProfile(profile))
    case .dc: self = .dc(try DCProfile(profile))
    case nil: throw .invalidProfile
    }
  }

  /// The home of a hosted identity; `nil` for DCs and unhosted identities.
  public var home: Home? {
    switch self {
    case .user(let p): p.home
    case .bot(let p): p.home
    case .channel(let p): p.home
    case .stickerSet(let p): p.home
    case .dc: nil
    }
  }

  /// The domains that serve this profile.
  public var domains: [String] {
    switch self {
    case .user(let p): p.domains.map { $0.name }
    case .bot(let p): p.domains.map { $0.name }
    case .channel(let p): p.domains.map { $0.name }
    case .stickerSet(let p): [p.shortName]
    case .dc(let p): p.domains
    }
  }
}

extension [ProfileDomain] {
  fileprivate var username: String? {
    get { first?.name }
    set {
      self = newValue.map { [ProfileDomain(unchecked: $0)] } ?? []
    }
  }
}

/// Integer-keyed profile and home records; domains are a list of domain records.
enum HostedRecord {
  static let maximumDomains = 16

  static func encode(kind: ProfileKind, home: Home?, domains: [ProfileDomain]) throws(BlahError)
    -> [UInt8]
  {
    try validate(kind: kind, home: home, domains: domains)
    let homeValue: CBOR =
      home.map {
        .record([
          Home.cborKeyDC: .bytes($0.dc.bytes), Home.cborKeyEpoch: .unsigned($0.epoch),
          Home.cborKeyExpiresAt: .unsigned($0.expiresAt),
          Home.cborKeyAccount: $0.account.map { .unsigned(UInt64($0)) } ?? .null,
        ])
      } ?? .null
    return CBOR.record([
      UserProfile.cborKeyTag: .unsigned(BlahTag.profile.rawValue),
      UserProfile.cborKeyVersion: .unsigned(1), UserProfile.cborKeyKind: .unsigned(kind.rawValue),
      UserProfile.cborKeyHome: homeValue,
      UserProfile.cborKeyDomains: .array(
        domains.map { .record([ProfileDomain.cborKeyName: .text($0.name)]) }),
    ]).encoded
  }

  static func decode(_ data: [UInt8], kind: ProfileKind) throws(BlahError)
    -> (Home?, [ProfileDomain])
  {
    let e = BlahError.invalidProfile
    let fields = try CBOR.record(
      data, tag: .profile, requiredKeys: UserProfile.cborKeyTag..<(UserProfile.cborKeyDomains + 1),
      error: e)
    guard fields[UserProfile.cborKeyKind]! == .unsigned(kind.rawValue) else { throw e }
    var home: Home?
    if fields[UserProfile.cborKeyHome]! != .null {
      let h = try fields[UserProfile.cborKeyHome]!.record(
        e, requiredKeys: Home.cborKeyDC..<(Home.cborKeyAccount + 1))
      home = Home(
        dc: try h[Home.cborKeyDC]!.digest(e), epoch: try h[Home.cborKeyEpoch]!.unsigned(e),
        expiresAt: try h[Home.cborKeyExpiresAt]!.unsigned(e),
        account: h[Home.cborKeyAccount]! == .null
          ? nil : Int64(exactly: try h[Home.cborKeyAccount]!.unsigned(e)) ?? 0)
    }
    var domains: [ProfileDomain] = []
    for entry in try fields[UserProfile.cborKeyDomains]!.array(e) {
      let domain = try entry.record(
        e, requiredKeys: ProfileDomain.cborKeyName..<(ProfileDomain.cborKeyName + 1))
      domains.append(try ProfileDomain(domain[ProfileDomain.cborKeyName]!.text(e)))
    }
    try validate(kind: kind, home: home, domains: domains)
    return (home, domains)
  }

  static func validate(kind: ProfileKind, home: Home?, domains: [ProfileDomain]) throws(BlahError)
  {
    if let home {
      let accountLimit: Int64 = switch kind {
      case .user, .bot, .dc: 9_007_199_254_740_991
      case .channel: 997_852_516_352
      case .stickerSet: .max
      }
      guard (1...UInt64(Int64.max)).contains(home.epoch), home.expiresAt <= UInt64(Int64.max),
        home.account.map({ $0 > 0 && $0 < accountLimit }) ?? true
      else { throw .invalidProfile }
    }
    guard domains.count <= maximumDomains, Set(domains.map { $0.name }).count == domains.count,
      domains.allSatisfy({ DomainName.isValid($0.name) })
    else { throw .invalidName }
    switch kind {
    case .stickerSet:
      guard domains.count == 1 else { throw .invalidName }
    default: break
    }
  }
}

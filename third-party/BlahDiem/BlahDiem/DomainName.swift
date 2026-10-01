/// Validation for names that cross DCs: DNS domains of at least two lowercase
/// letter-digit-hyphen labels, 253 bytes at most.
public enum DomainName {
  public static let maximumLength = 253

  /// `raw` lowercased, or `nil` when it is not a domain.
  public static func normalized(_ raw: String) -> String? {
    let value = raw.lowercased()
    return isValid(value) ? value : nil
  }

  /// Whether `value` is a lowercase domain.
  public static func isValid(_ value: String) -> Bool {
    let bytes = value.utf8
    guard bytes.count <= maximumLength, bytes.contains(46) else {
      return false
    }
    // DNS wire names are ASCII. Byte validation avoids Unicode casing and grapheme tables.
    return bytes.split(separator: 46, omittingEmptySubsequences: false).allSatisfy { label in
      !label.isEmpty && label.count <= 63 && label.first != 45 && label.last != 45
        && label.allSatisfy { (97...122).contains($0) || (48...57).contains($0) || $0 == 45 }
    }
  }
}

/// A domain that serves a profile and is a candidate for a public username.
public struct ProfileDomain: Hashable, Sendable {
  public let name: String
  public init(_ name: String) throws(BlahError) {
    guard DomainName.isValid(name) else { throw .invalidName }
    self.init(unchecked: name)
  }

  /// A domain that profile encoding validates.
  init(unchecked name: String) {
    self.name = name
  }
}

/// A DC's discovery domain and identity ID.
public struct DCAddress: Hashable, Sendable {
  public let domain: String
  public let id: Digest

  public init(domain: String, id: Digest) throws(BlahError) {
    guard DomainName.isValid(domain) else { throw .invalidName }
    self.domain = domain
    self.id = id
  }
}

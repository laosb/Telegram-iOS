/// A SHA-256 digest that names a key, an identity or a record.
public struct Digest: Hashable, Comparable, Sendable, CustomStringConvertible {
  /// The 32 digest bytes.
  public let bytes: [UInt8]

  /// A digest with the given 32 bytes.
  public init(bytes: [UInt8]) throws(DiemError) {
    guard bytes.count == 32 else { throw .invalidEncoding }
    self.bytes = bytes
  }

  /// The SHA-256 digest of `message`.
  public init(hashing message: some Collection<UInt8>) {
    bytes = SHA2.sha256(message)
  }

  /// Lowercase hexadecimal digest bytes.
  public var description: String {
    let digits = Array("0123456789abcdef".utf8)
    var text: [UInt8] = []
    text.reserveCapacity(64)
    for byte in bytes {
      text.append(digits[Int(byte >> 4)])
      text.append(digits[Int(byte & 15)])
    }
    return String(decoding: text, as: UTF8.self)
  }

  public static func < (lhs: Digest, rhs: Digest) -> Bool {
    lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
  }
}

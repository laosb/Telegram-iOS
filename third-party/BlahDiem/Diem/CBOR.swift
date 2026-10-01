/// A value in Diem's deterministic CBOR subset.
///
/// Encoding is canonical: shortest-form heads, definite lengths and maps ordered by
/// encoded key (length first, then bytes). Decoding accepts only that form.
public indirect enum CBOR: Hashable, Sendable {
  case unsigned(UInt64)
  /// A negative integer; the associated value is always below zero.
  case negative(Int64)
  case bytes([UInt8])
  case text(String)
  case array([CBOR])
  case map([CBOR: CBOR])
  case bool(Bool)
  case null

  /// The largest encoding ``init(decoding:)`` accepts.
  public static let maximumBytes = 262_144
  /// The deepest container nesting ``init(decoding:)`` accepts.
  public static let maximumDepth = 16
  /// The most values one encoding may contain.
  public static let maximumItems = 8_192

  /// Decodes one canonical value that occupies all of `bytes`.
  public init(decoding bytes: [UInt8]) throws(DiemError) {
    guard bytes.count <= Self.maximumBytes else { throw .invalidEncoding }
    var reader = Reader(bytes: bytes)
    self = try reader.value(depth: 0)
    guard reader.offset == bytes.count else { throw .invalidEncoding }
  }

  /// The canonical encoding.
  public var encoded: [UInt8] {
    var output: [UInt8] = []
    append(to: &output)
    return output
  }

  /// The unsigned integer, or ``DiemError/invalidEncoding``.
  public func unsignedValue() throws(DiemError) -> UInt64 {
    guard case .unsigned(let value) = self else { throw .invalidEncoding }
    return value
  }

  /// The byte string, optionally of exactly `count` bytes, or ``DiemError/invalidEncoding``.
  public func bytesValue(count: Int? = nil) throws(DiemError) -> [UInt8] {
    guard case .bytes(let value) = self, count == nil || value.count == count else {
      throw .invalidEncoding
    }
    return value
  }

  /// The text string, or ``DiemError/invalidEncoding``.
  public func textValue() throws(DiemError) -> String {
    guard case .text(let value) = self else { throw .invalidEncoding }
    return value
  }

  /// The Boolean, or ``DiemError/invalidEncoding``.
  public func boolValue() throws(DiemError) -> Bool {
    guard case .bool(let value) = self else { throw .invalidEncoding }
    return value
  }

  /// The array, optionally of exactly `count` elements, or ``DiemError/invalidEncoding``.
  public func arrayValue(count: Int? = nil) throws(DiemError) -> [CBOR] {
    guard case .array(let value) = self, count == nil || value.count == count else {
      throw .invalidEncoding
    }
    return value
  }

  /// The map, or ``DiemError/invalidEncoding``.
  public func mapValue() throws(DiemError) -> [CBOR: CBOR] {
    guard case .map(let value) = self else { throw .invalidEncoding }
    return value
  }

  /// An extensible record with unsigned integer keys. Required fields must be present;
  /// unknown integer keys are retained so callers can preserve the original record.
  public func recordValue(requiredKeys: Range<UInt64>) throws(DiemError) -> [UInt64: CBOR] {
    let entries = try mapValue()
    var fields: [UInt64: CBOR] = [:]
    for (key, value) in entries {
      fields[try key.unsignedValue()] = value
    }
    guard requiredKeys.allSatisfy({ fields[$0] != nil }) else { throw .invalidEncoding }
    return fields
  }

  /// Encodes a record, retaining unrecognized fields from a decoded record.
  /// Explicit fields take precedence over extensions.
  public static func record(_ fields: [UInt64: CBOR], extensions: [UInt64: CBOR] = [:]) -> CBOR {
    .map(Dictionary(uniqueKeysWithValues: extensions.merging(fields) { _, known in known }
      .map { (.unsigned($0.key), $0.value) }))
  }

  private func append(to output: inout [UInt8]) {
    func head(_ major: UInt8, _ n: UInt64) {
      if n < 24 {
        output.append(major << 5 | UInt8(n))
        return
      }
      let length = n <= 0xff ? 1 : n <= 0xffff ? 2 : n <= 0xffff_ffff ? 4 : 8
      let info: UInt8 = length == 1 ? 24 : length == 2 ? 25 : length == 4 ? 26 : 27
      output.append(major << 5 | info)
      for index in (0..<length).reversed() {
        output.append(UInt8(truncatingIfNeeded: n >> (index * 8)))
      }
    }
    switch self {
    case .unsigned(let n): head(0, n)
    case .negative(let n):
      precondition(n < 0, "CBOR.negative requires a negative value")
      head(1, UInt64(-(n + 1)))
    case .bytes(let b):
      head(2, UInt64(b.count))
      output += b
    case .text(let s):
      let b = Array(s.utf8)
      head(3, UInt64(b.count))
      output += b
    case .array(let values):
      head(4, UInt64(values.count))
      for value in values { value.append(to: &output) }
    case .map(let entries):
      let sorted = entries.map { ($0.key.encoded, $0.value) }.sorted { Self.precedes($0.0, $1.0) }
      head(5, UInt64(sorted.count))
      for (key, value) in sorted {
        output += key
        value.append(to: &output)
      }
    case .bool(let b): output.append(b ? 0xf5 : 0xf4)
    case .null: output.append(0xf6)
    }
  }

  private static func precedes(_ a: some Collection<UInt8>, _ b: some Collection<UInt8>) -> Bool {
    a.count != b.count ? a.count < b.count : a.lexicographicallyPrecedes(b)
  }

  private struct Reader {
    let bytes: [UInt8]
    var offset = 0
    var items = 0

    mutating func byte() throws(DiemError) -> UInt8 {
      guard offset < bytes.count else { throw .invalidEncoding }
      defer { offset += 1 }
      return bytes[offset]
    }

    mutating func value(depth: Int) throws(DiemError) -> CBOR {
      items += 1
      guard depth <= CBOR.maximumDepth, items <= CBOR.maximumItems else { throw .invalidEncoding }
      let first = try byte()
      let major = first >> 5
      let info = first & 31
      if major == 7 {
        switch info {
        case 20: return .bool(false)
        case 21: return .bool(true)
        case 22: return .null
        default: throw .invalidEncoding
        }
      }
      guard info <= 27 else { throw .invalidEncoding }
      var n = UInt64(info)
      if info >= 24 {
        n = 0
        for _ in 0..<(1 << (info - 24)) { n = n << 8 | UInt64(try byte()) }
        let minimum: [UInt64] = [24, 0x100, 0x1_0000, 0x1_0000_0000]
        guard n >= minimum[Int(info - 24)] else { throw .invalidEncoding }
      }
      switch major {
      case 0: return .unsigned(n)
      case 1:
        guard n <= UInt64(Int64.max) else { throw .invalidEncoding }
        return .negative(-1 - Int64(n))
      case 2, 3:
        guard n <= UInt64(bytes.count - offset) else { throw .invalidEncoding }
        let raw = Array(bytes[offset..<(offset + Int(n))])
        offset += Int(n)
        if major == 2 { return .bytes(raw) }
        let text = String(decoding: raw, as: UTF8.self)
        guard Array(text.utf8) == raw else { throw .invalidEncoding }
        return .text(text)
      case 4:
        guard n <= UInt64(bytes.count - offset) else { throw .invalidEncoding }
        var values: [CBOR] = []
        for _ in 0..<n { values.append(try value(depth: depth + 1)) }
        return .array(values)
      case 5:
        guard n <= UInt64(bytes.count - offset) else { throw .invalidEncoding }
        var entries: [CBOR: CBOR] = [:]
        var previous: ArraySlice<UInt8>?
        for _ in 0..<n {
          let start = offset
          let key = try value(depth: depth + 1)
          let encodedKey = bytes[start..<offset]
          if let previous, !CBOR.precedes(previous, encodedKey) { throw .invalidEncoding }
          previous = encodedKey
          entries[key] = try value(depth: depth + 1)
        }
        return .map(entries)
      default: throw .invalidEncoding
      }
    }
  }
}

/// Tags of Blah records, stored at integer key 0; key 1 holds the version.
enum BlahTag: UInt64 {
  case login = 3
  case invocationChallenge = 4
  case invocationStatement = 5
  case oauthConsent = 6
  case accountLink = 8
  case dcAdmin = 9
  case clientNamespace = 10
  case profile = 13
}

/// Profile kind codes in Blah profile data.
enum ProfileKind: UInt64 {
  case user = 1
  case channel = 2
  case bot = 3
  case stickerSet = 4
  case dc = 5
}

/// Decoding helpers that map Diem encoding errors to one Blah error.
extension CBOR {
  static func record(_ bytes: [UInt8], tag: BlahTag, requiredKeys: Range<UInt64>, error: BlahError)
    throws(BlahError) -> [UInt64: CBOR]
  {
    guard let fields = try? CBOR(decoding: bytes).recordValue(requiredKeys: requiredKeys),
      fields[0] == .unsigned(tag.rawValue), fields[1] == .unsigned(1)
    else { throw error }
    return fields
  }

  func record(_ error: BlahError, requiredKeys: Range<UInt64>) throws(BlahError) -> [UInt64: CBOR] {
    try field(error) { value throws(DiemError) in try value.recordValue(requiredKeys: requiredKeys) }
  }

  func field<T>(_ failure: BlahError, _ read: (CBOR) throws(DiemError) -> T) throws(BlahError) -> T {
    do { return try read(self) } catch { throw failure }
  }

  func digest(_ error: BlahError) throws(BlahError) -> Digest {
    try field(error) { value throws(DiemError) in try Digest(bytes: value.bytesValue()) }
  }

  func unsigned(_ error: BlahError) throws(BlahError) -> UInt64 {
    try field(error) { value throws(DiemError) in try value.unsignedValue() }
  }

  func bytes(_ error: BlahError, count: Int? = nil) throws(BlahError) -> [UInt8] {
    try field(error) { value throws(DiemError) in try value.bytesValue(count: count) }
  }

  func text(_ error: BlahError) throws(BlahError) -> String {
    try field(error) { value throws(DiemError) in try value.textValue() }
  }

  func array(_ error: BlahError, count: Int? = nil) throws(BlahError) -> [CBOR] {
    try field(error) { value throws(DiemError) in try value.arrayValue(count: count) }
  }
}

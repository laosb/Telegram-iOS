/// A DC's public profile: where clients and peer DCs reach it.
public struct DCProfile: BlahProfile {
  /// CBOR field keys.
  public static let cborKeyTag: UInt64 = BlahTag.cborKeyTag
  public static let cborKeyVersion: UInt64 = BlahTag.cborKeyVersion
  public static let cborKeyKind: UInt64 = 2
  public static let cborKeyDomains: UInt64 = 3
  public static let cborKeyEndpoints: UInt64 = 4
  public static let cborKeyBIDCOMEndpoints: UInt64 = 5
  public static let cborKeyTransportPublicKey: UInt64 = 6
  public static let cborKeyNamespaceGeneration: UInt64 = 7

  /// The transport carrying MTProto; TLS is independent of the transport.
  public enum Transport: UInt64, Sendable {
    case tcp = 0
    case webSocket = 1
  }

  /// A network address and, for WebSocket, its exact HTTP request path.
  public struct Endpoint: Hashable, Sendable {
    /// CBOR field keys.
    public static let cborKeyHost: UInt64 = 0
    public static let cborKeyPort: UInt64 = 1
    public static let cborKeyTLS: UInt64 = 2
    public static let cborKeyTransport: UInt64 = 3
    public static let cborKeyPath: UInt64 = 4

    public var host: String
    public var port: UInt16
    public var tls: Bool
    public var transport: Transport
    public var path: String?

    public init(host: String, port: UInt16, tls: Bool,
      transport: Transport = .tcp, path: String? = nil) {
      self.host = host
      self.port = port
      self.tls = tls
      self.transport = transport
      self.path = path
    }
  }

  public static let maximumEndpoints = 8

  /// The DC's discovery domains.
  public var domains: [String]
  /// MTProto endpoints for clients.
  public var endpoints: [Endpoint]
  /// BIDCOM endpoints for peer DCs.
  public var bidcomEndpoints: [Endpoint]
  /// The MTProto RSA public key, PEM-encoded.
  public var transportPublicKey: String
  /// The DC's database generation. A new generation starts a new client namespace.
  public var namespaceGeneration: UInt64?

  public init(
    domains: [String], endpoints: [Endpoint], bidcomEndpoints: [Endpoint],
    transportPublicKey: String, namespaceGeneration: UInt64? = nil
  ) {
    self.domains = domains
    self.endpoints = endpoints
    self.bidcomEndpoints = bidcomEndpoints
    self.transportPublicKey = transportPublicKey
    self.namespaceGeneration = namespaceGeneration
  }

  public init(data: [UInt8]) throws(BlahError) {
    let e = BlahError.invalidProfile
    let fields = try CBOR.record(
      data, tag: .profile, requiredKeys: Self.cborKeyTag..<(Self.cborKeyNamespaceGeneration + 1),
      error: e)
    guard fields[Self.cborKeyKind]! == .unsigned(ProfileKind.dc.rawValue) else { throw e }
    func endpoints(_ value: CBOR) throws(BlahError) -> [Endpoint] {
      var result: [Endpoint] = []
      for entry in try value.array(e) {
        let a = try entry.record(e, requiredKeys: Endpoint.cborKeyHost..<(Endpoint.cborKeyPath + 1))
        guard let port = UInt16(exactly: try a[Endpoint.cborKeyPort]!.unsigned(e)),
          case .bool(let tls) = a[Endpoint.cborKeyTLS]!,
          let transport = Transport(rawValue: try a[Endpoint.cborKeyTransport]!.unsigned(e))
        else {
          throw e
        }
        result.append(
          Endpoint(
            host: try a[Endpoint.cborKeyHost]!.text(e), port: port, tls: tls,
            transport: transport,
            path: a[Endpoint.cborKeyPath]! == .null ? nil : try a[Endpoint.cborKeyPath]!.text(e)))
      }
      return result
    }
    var domains: [String] = []
    for domain in try fields[Self.cborKeyDomains]!.array(e) { domains.append(try domain.text(e)) }
    self.domains = domains
    self.endpoints = try endpoints(fields[Self.cborKeyEndpoints]!)
    self.bidcomEndpoints = try endpoints(fields[Self.cborKeyBIDCOMEndpoints]!)
    self.transportPublicKey = try fields[Self.cborKeyTransportPublicKey]!.text(e)
    self.namespaceGeneration =
      fields[Self.cborKeyNamespaceGeneration]! == .null
      ? nil : try fields[Self.cborKeyNamespaceGeneration]!.unsigned(e)
    try validate()
  }

  public func encoded() throws(BlahError) -> [UInt8] {
    try validate()
    func encode(_ endpoints: [Endpoint]) -> CBOR {
      .array(
        endpoints.map {
          .record([
            Endpoint.cborKeyHost: .text($0.host), Endpoint.cborKeyPort: .unsigned(UInt64($0.port)),
            Endpoint.cborKeyTLS: .bool($0.tls),
            Endpoint.cborKeyTransport: .unsigned($0.transport.rawValue),
            Endpoint.cborKeyPath: $0.path.map(CBOR.text) ?? .null,
          ])
        })
    }
    return CBOR.record([
      Self.cborKeyTag: .unsigned(BlahTag.profile.rawValue), Self.cborKeyVersion: .unsigned(1),
      Self.cborKeyKind: .unsigned(ProfileKind.dc.rawValue),
      Self.cborKeyDomains: .array(domains.map(CBOR.text)), Self.cborKeyEndpoints: encode(endpoints),
      Self.cborKeyBIDCOMEndpoints: encode(bidcomEndpoints),
      Self.cborKeyTransportPublicKey: .text(transportPublicKey),
      Self.cborKeyNamespaceGeneration: namespaceGeneration.map(CBOR.unsigned) ?? .null,
    ]).encoded
  }

  private func validate() throws(BlahError) {
    guard (1...HostedRecord.maximumDomains).contains(domains.count),
      Set(domains).count == domains.count, domains.allSatisfy(DomainName.isValid)
    else { throw .invalidName }
    let valid = [endpoints, bidcomEndpoints].allSatisfy { list in
      list.count <= Self.maximumEndpoints && Set(list).count == list.count
        && list.allSatisfy { $0.isValid }
    }
    guard valid, !endpoints.isEmpty, bidcomEndpoints.allSatisfy({ $0.transport == .tcp }),
      !transportPublicKey.isEmpty, transportPublicKey.utf8.count <= 8192,
      namespaceGeneration.map({ (1...UInt64(Int64.max)).contains($0) }) ?? true
    else { throw .invalidProfile }
  }
}

extension DCProfile.Endpoint {
  /// Shared validation for profile publishers and configuration editors.
  public var isValid: Bool {
    guard !host.isEmpty, host.utf8.count <= DomainName.maximumLength, port > 0,
      host.utf8.allSatisfy({
        (48...57).contains($0) || (65...90).contains($0) || (97...122).contains($0)
          || [45, 46, 58].contains($0)
      })
    else { return false }
    switch transport {
    case .tcp: return path == nil
    case .webSocket:
      guard let path, path.hasPrefix("/"), !path.hasPrefix("//"), path.utf8.count <= 2048,
        path.utf8.allSatisfy({ $0 > 32 && $0 < 127 && $0 != 35 && $0 != 92 })
      else { return false }
      return true
    }
  }
}

/// A DC's public profile: where clients and peer DCs reach it.
public struct DCProfile: BlahProfile {
  /// The transport carrying MTProto; TLS is independent of the transport.
  public enum Transport: UInt64, Sendable {
    case tcp = 0
    case webSocket = 1
  }

  /// A network address and, for WebSocket, its exact HTTP request path.
  public struct Endpoint: Hashable, Sendable {
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
    let fields = try CBOR.record(data, tag: .profile, count: 8, error: e)
    guard fields[2] == .unsigned(ProfileKind.dc.rawValue) else { throw e }
    func endpoints(_ value: CBOR) throws(BlahError) -> [Endpoint] {
      var result: [Endpoint] = []
      for entry in try value.array(e) {
        let a = try entry.array(e, count: 5)
        guard let port = UInt16(exactly: try a[1].unsigned(e)), case .bool(let tls) = a[2],
          let transport = Transport(rawValue: try a[3].unsigned(e)) else {
          throw e
        }
        result.append(Endpoint(host: try a[0].text(e), port: port, tls: tls,
          transport: transport, path: a[4] == .null ? nil : try a[4].text(e)))
      }
      return result
    }
    var domains: [String] = []
    for domain in try fields[3].array(e) { domains.append(try domain.text(e)) }
    self.domains = domains
    self.endpoints = try endpoints(fields[4])
    self.bidcomEndpoints = try endpoints(fields[5])
    self.transportPublicKey = try fields[6].text(e)
    self.namespaceGeneration = fields[7] == .null ? nil : try fields[7].unsigned(e)
    try validate()
  }

  public func encoded() throws(BlahError) -> [UInt8] {
    try validate()
    func encode(_ endpoints: [Endpoint]) -> CBOR {
      .array(endpoints.map { .array([
        .text($0.host), .unsigned(UInt64($0.port)), .bool($0.tls),
        .unsigned($0.transport.rawValue), $0.path.map(CBOR.text) ?? .null,
      ]) })
    }
    return CBOR.array([
      .unsigned(BlahTag.profile.rawValue), .unsigned(1), .unsigned(ProfileKind.dc.rawValue),
      .array(domains.map(CBOR.text)), encode(endpoints), encode(bidcomEndpoints),
      .text(transportPublicKey), namespaceGeneration.map(CBOR.unsigned) ?? .null,
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

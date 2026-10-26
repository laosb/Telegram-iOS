import BlahDiem
import DiemSwiftCrypto
import Foundation
import Testing

@Test func upstreamProfileAndRecoveryRoundTrip() async throws {
    let backend = SwiftCryptoBackend()
    let root = try await IdentityPrivateKey.generate(.ed25519, using: backend)
    let secret = try #require(root.rawRepresentation)
    let recipient = try await backend.makeEncryptionKey(.p256)
    let sealed = try await root.sealed(to: recipient.publicKey, using: backend)
    let reopened = try await SealedIdentityKey(encoding: sealed.encoding).open(with: recipient, using: backend)
    #expect(reopened.rawRepresentation == secret)

    let restored = try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity, restoring: secret))
    #expect(restored.publicKey == root.publicKey)
    let user = HostedContent(home: nil, domains: [try DomainName("identity.example")])
    let identity = try await BasicIdentity<AnyBlahProfile>(.user(user), identityKey: restored,
        deviceKey: .generate(.ed25519, using: backend), using: backend)
    let profile = try AnyBlahProfile(encoding: identity.profile.encoding)
    try await profile.verify(using: backend)
    #expect(profile.content == .user(user))
}

@Test func hardwareIdentityDoesNotExposeRecoveryBytes() async throws {
    let software = try await SwiftCryptoBackend().makePrivateKey(.ed25519, for: .identity)
    // Model a backend that mistakenly supplies bytes for a hardware key. The
    // Diem accessor must still enforce the protection boundary.
    let hardware = PrivateKey(publicKey: software.publicKey, protection: .hardware,
        rawRepresentation: software.rawRepresentation, sign: { _ in throw DiemError.invalidKey })
    #expect(try IdentityPrivateKey(hardware).rawRepresentation == nil)
}

private func nativeIdentity() async throws -> BasicIdentity<AnyBlahProfile> {
    let backend = SwiftCryptoBackend()
    return try await BasicIdentity<AnyBlahProfile>(
        .user(HostedContent(home: Home(dc: Digest(hashing: [1]), epoch: 1, expiresAt: backend.now + 86400),
            domains: [DomainName("alice.identity.example")])),
        identityKey: .generate(.ed25519, using: backend),
        deviceKey: .generate(.p256, using: backend), using: backend)
}

@Test func nativeDeviceProofPreservesTransportBindingAndExactQuery() async throws {
    let identity = try await nativeIdentity()
    let query: [UInt8] = [0xa6, 0x91, 0xcf, 0xa6, 0, 0, 0, 0]
    let challenge = try InvocationChallenge(domain: DomainName("alice.identity.example"),
        nonce: [UInt8](repeating: 7, count: 32), expiresAt: identity.backend.now + 60,
        dc: identity.profile.home!.dc, transportKeyID: -123, sessionID: UInt64.max - 12)
    let proof = try await identity.prove(InvocationStatement(challenge: challenge, payload: query))
    let decoded = try BlahProof<InvocationStatement>(encoding: proof.encoding)
    try await decoded.verify(against: identity.profile, using: SwiftCryptoBackend())
    #expect(decoded.statement.challenge == challenge)
    #expect(decoded.statement.matches(query))
    #expect(!decoded.statement.matches(query + [0]))
    let fields = try CBOR(decoding: challenge.encoding).recordValue(requiredKeys: 0..<8)
    #expect(fields[InvocationChallenge.cborKeyTransportKeyID] == .unsigned(UInt64(bitPattern: -123)))
}

@Test func signupNumberingPreservesNamespaceAndRevocationRejectsRemovedDevice() async throws {
    var identity = try await nativeIdentity()
    let dc = DCAddress(domain: try DomainName("dc.example"), id: identity.profile.home!.dc)
    let namespace = try ClientNamespace(profile: identity.profile, dc: dc, generation: 19)
    guard case .user(var content) = identity.profile.content else { Issue.record("Expected user"); return }
    content.home?.account = 12345
    try await identity.update(.user(content))
    #expect(try ClientNamespace(profile: identity.profile, dc: dc, generation: 19) == namespace)
    #expect(try ClientNamespace(profile: identity.profile, dc: dc, generation: 20).identifier != namespace.identifier)

    let key = try await DevicePrivateKey.generate(.p256, using: SwiftCryptoBackend())
    try await identity.add(key.publicKey)
    let other = try await BasicIdentity(profile: identity.profile, deviceKey: key, using: SwiftCryptoBackend())
    let proof = try await other.prove([1, 2, 3])
    try await proof.verify(against: identity.profile, using: SwiftCryptoBackend())
    try await identity.remove(key.publicKey.id)
    await #expect(throws: DiemError.deviceNotListed) {
        try await proof.verify(against: identity.profile, using: SwiftCryptoBackend())
    }
    content.home?.epoch = 2
    content.home?.account = nil
    try await identity.update(.user(content))
    #expect(throws: BlahError.wrongNamespace) { try namespace.require(identity.profile) }
}

@Test func recoveryEnrollsANativeDeviceWithoutReplacingIdentity() async throws {
    let identity = try await nativeIdentity()
    let device = try await DevicePrivateKey.generate(.p256, using: SwiftCryptoBackend())
    let recovered = try await BasicIdentity<AnyBlahProfile>.enrolling(device, in: identity.profile,
        identityKey: #require(identity.identityKey), using: SwiftCryptoBackend())
    #expect(recovered.id == identity.id)
    #expect(recovered.profile.revision > identity.profile.revision)
    #expect(recovered.profile.device(device.publicKey.id) != nil)
    #expect(recovered.profile.device(identity.deviceKey.publicKey.id) != nil)
    try await recovered.profile.verify(using: SwiftCryptoBackend())
}

private actor PublicationHost: HostingHTTPClient {
    private var bodies: [[UInt8]] = []
    func send(_ request: HostingHTTPRequest) async throws -> HostingHTTPResponse {
        #expect(request.method == .put)
        #expect(request.url == "https://alice.identity.example/.well-known/diem/profile.cbor")
        let body = try #require(request.body)
        bodies.append(body)
        if bodies.count == 1 { throw URLError(.networkConnectionLost) }
        let profile = try AnyBlahProfile(encoding: body)
        try await profile.verify(using: SwiftCryptoBackend())
        let id = Data(profile.id.bytes).base64EncodedString().replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
        return HostingHTTPResponse(status: 200, body: Array("{\"identity\":\"\(id)\",\"revision\":\(profile.revision),\"domains\":[\"alice.identity.example\"]}".utf8))
    }
    func snapshots() -> [[UInt8]] { bodies }
}

@Test func hostedPublicationRetriesIdenticalSignedBytes() async throws {
    let identity = try await nativeIdentity()
    let transport = PublicationHost()
    let client = ProfileHostingClient(domain: try DomainName("identity.example"), http: transport)
    let saved = identity.profile.encoding
    do {
        try await client.publish(identity.profile, solver: PortableProofOfWorkSolver())
        Issue.record("The first publication should lose its response")
    } catch is URLError {}
    try await client.publish(AnyBlahProfile(encoding: saved), solver: PortableProofOfWorkSolver())
    #expect(await transport.snapshots() == [saved, saved])
}

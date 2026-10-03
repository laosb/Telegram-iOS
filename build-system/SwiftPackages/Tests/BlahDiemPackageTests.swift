import BlahDiem
import DiemSwiftCrypto
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
    let user = try UserProfile(home: nil, domains: [ProfileDomain("identity.example")])
    let identity = try await Identity(data: user.encoded(), identityKey: restored,
        deviceKey: .generate(.ed25519, using: backend), using: backend)
    let profile = try Profile(encoding: identity.profile.encoding)
    try await profile.verify(using: backend)
    #expect(try UserProfile(profile) == user)
}

@Test func hardwareIdentityDoesNotExposeRecoveryBytes() async throws {
    let software = try await SwiftCryptoBackend().makePrivateKey(.ed25519, for: .identity)
    // Model a backend that mistakenly supplies bytes for a hardware key. The
    // Diem accessor must still enforce the protection boundary.
    let hardware = PrivateKey(publicKey: software.publicKey, protection: .hardware,
        rawRepresentation: software.rawRepresentation, sign: { _ in throw DiemError.invalidKey })
    #expect(try IdentityPrivateKey(hardware).rawRepresentation == nil)
}

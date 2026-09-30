/// Enrolls a new device using a recovered identity key and the latest trusted profile.
/// The caller fetches and checks the profile's monotonic version before recovery and
/// durably stores and publishes the returned revision before using the new device.
extension Identity {
  public static func enrolling(
    _ device: DevicePrivateKey, in profile: Profile, identityKey: IdentityPrivateKey,
    profileLifetime: UInt64 = Profile.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws -> Identity {
    try await profile.verify(using: backend, at: profile.validity.notBefore)
    guard profile.identityKey == identityKey.publicKey,
      !device.publicKey.key.hasSameMaterial(as: identityKey.publicKey.key)
    else { throw DiemError.identityMismatch }
    let validity = try Validity(starting: backend.now, lifetime: deviceLifetime)
    let contentValidity = try Validity(starting: backend.now, lifetime: profileLifetime)
    guard contentValidity.expiresAt <= validity.expiresAt else { throw DiemError.invalidValidity }
    let keys = profile.devices.map(\.device).filter { $0 != device.publicKey } + [device.publicKey]
    var certificates: [DeviceCertificate] = []
    for key in keys {
      certificates.append(try await DeviceCertificate.issue(
        by: identityKey, for: key, generation: profile.generation, validity: validity))
    }
    let next = try await Profile.sign(
      identityKey: profile.identityKey, devices: certificates, by: device,
      revision: profile.revision + 1, previousDigest: profile.digest,
      validity: contentValidity, data: profile.data)
    return try await Identity(profile: next, deviceKey: device, identityKey: identityKey,
      profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
  }
}

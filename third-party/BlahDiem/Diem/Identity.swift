/// An identity as one of its devices holds it: the current profile, this device's key and,
/// on devices that manage the device set, the identity private key.
public struct Identity: Sendable {
  /// The current profile. Each operation replaces it with a new signed revision.
  public private(set) var profile: Profile
  public let deviceKey: DevicePrivateKey
  /// The identity private key, if this device holds it.
  public let identityKey: IdentityPrivateKey?
  public let backend: any CryptoBackend
  /// Lifetimes used when this instance publishes content or certifies devices.
  public let profileLifetime: UInt64
  public let deviceLifetime: UInt64

  /// The identity ID.
  public var id: Digest { profile.id }

  /// Creates an identity whose only device is `deviceKey`, publishing `data` at revision 1.
  public init(
    data: [UInt8], identityKey: IdentityPrivateKey, deviceKey: DevicePrivateKey,
    profileLifetime: UInt64 = Profile.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws {
    guard !deviceKey.publicKey.key.hasSameMaterial(as: identityKey.publicKey.key) else {
      throw DiemError.identityMismatch
    }
    _ = try Validity(starting: backend.now, lifetime: profileLifetime)
    let certificate = try await DeviceCertificate.issue(
      by: identityKey, for: deviceKey.publicKey, generation: 1,
      validity: Validity(starting: backend.now, lifetime: deviceLifetime))
    self.profile = try await Profile.sign(
      identityKey: identityKey.publicKey, devices: [certificate], by: deviceKey, revision: 1,
      previousDigest: nil, validity: Self.contentValidity(for: certificate, at: backend.now, lifetime: profileLifetime),
      data: data)
    self.deviceKey = deviceKey
    self.identityKey = identityKey
    self.backend = backend
    self.profileLifetime = profileLifetime
    self.deviceLifetime = deviceLifetime
  }

  /// Creates an identity with new ML-DSA-65 software identity and device keys.
  public init(data: [UInt8], profileLifetime: UInt64 = Profile.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime, using backend: some CryptoBackend) async throws {
    try await self.init(
      data: data, identityKey: .generate(using: backend), deviceKey: .generate(using: backend),
      profileLifetime: profileLifetime, deviceLifetime: deviceLifetime, using: backend)
  }

  /// Opens an existing identity on a device that `profile` lists.
  public init(
    profile: Profile, deviceKey: DevicePrivateKey, identityKey: IdentityPrivateKey? = nil,
    profileLifetime: UInt64 = Profile.defaultLifetime,
    deviceLifetime: UInt64 = DeviceCertificate.defaultLifetime,
    using backend: some CryptoBackend
  ) async throws {
    _ = try Validity(starting: backend.now, lifetime: profileLifetime)
    _ = try Validity(starting: backend.now, lifetime: deviceLifetime)
    try await profile.verify(using: backend, at: profile.validity.notBefore)
    guard profile.device(deviceKey.publicKey.id) != nil else { throw DiemError.deviceNotListed }
    if let identityKey, identityKey.publicKey != profile.identityKey {
      throw DiemError.identityMismatch
    }
    self.profile = profile
    self.deviceKey = deviceKey
    self.identityKey = identityKey
    self.backend = backend
    self.profileLifetime = profileLifetime
    self.deviceLifetime = deviceLifetime
  }

  /// Publishes `data` as the next revision. With the identity key, expired device
  /// certificates are reissued first.
  @discardableResult
  public mutating func update(data: [UInt8]) async throws -> Profile {
    var devices = profile.devices
    if identityKey != nil, devices.contains(where: { !$0.validity.contains(backend.now) }) {
      devices = try await certify(devices.map { $0.device }, generation: profile.generation)
    }
    return try await publish(devices: devices, data: data)
  }

  /// Publishes the current data as the next revision with a fresh validity. With the
  /// identity key, also reissues every device certificate.
  @discardableResult
  public mutating func renew() async throws -> Profile {
    var devices = profile.devices
    if identityKey != nil {
      devices = try await certify(devices.map { $0.device }, generation: profile.generation)
    }
    return try await publish(devices: devices, data: profile.data)
  }

  /// Certifies `device` in the current generation. Requires the identity key.
  @discardableResult
  public mutating func add(_ device: DevicePublicKey) async throws -> Profile {
    guard !device.key.hasSameMaterial(as: profile.identityKey.key) else {
      throw DiemError.identityMismatch
    }
    let keys = profile.devices.map { $0.device }.filter { $0 != device } + [device]
    let devices = try await certify(keys, generation: profile.generation)
    return try await publish(devices: devices, data: profile.data)
  }

  /// Removes the device with `id` by certifying the others in a new generation, which
  /// retires every older certificate. Requires the identity key.
  @discardableResult
  public mutating func remove(_ id: Digest) async throws -> Profile {
    guard profile.device(id) != nil else { throw DiemError.deviceNotListed }
    guard id != deviceKey.publicKey.id else { throw DiemError.identityMismatch }
    let keys = profile.devices.map { $0.device }.filter { $0.id != id }
    let devices = try await certify(keys, generation: profile.generation + 1)
    return try await publish(devices: devices, data: profile.data)
  }

  /// A proof of `data` by this device for this identity.
  public func prove(_ data: [UInt8]) async throws -> Proof {
    try await Proof.sign(data, identityID: id, by: deviceKey)
  }

  private func certify(_ keys: [DevicePublicKey], generation: UInt64) async throws
    -> [DeviceCertificate]
  {
    guard let identityKey else { throw DiemError.identityKeyRequired }
    let validity = try Validity(starting: backend.now, lifetime: deviceLifetime)
    var devices: [DeviceCertificate] = []
    for key in keys {
      devices.append(
        try await .issue(by: identityKey, for: key, generation: generation, validity: validity))
    }
    return devices
  }

  private mutating func publish(devices: [DeviceCertificate], data: [UInt8]) async throws
    -> Profile
  {
    let now = backend.now
    // Expired certificates cannot act; listing them would make the profile unverifiable.
    let live = devices.filter { $0.validity.contains(now) }
    guard let certificate = live.first(where: { $0.device == deviceKey.publicKey }) else {
      throw devices.contains { $0.device == deviceKey.publicKey }
        ? DiemError.expired : DiemError.deviceNotListed
    }
    let next = try await Profile.sign(
      identityKey: profile.identityKey, devices: live, by: deviceKey,
      revision: profile.revision + 1, previousDigest: profile.digest,
      validity: Self.contentValidity(for: certificate, at: now, lifetime: profileLifetime), data: data)
    profile = next
    return next
  }

  private static func contentValidity(for certificate: DeviceCertificate, at now: UInt64, lifetime: UInt64) throws
    -> Validity
  {
    let requested = try Validity(starting: now, lifetime: lifetime)
    let end = min(requested.expiresAt, certificate.validity.expiresAt)
    return try Validity(notBefore: now, expiresAt: end)
  }
}

import Foundation
import CryptoKit
import Security
import BlahDiem
import DiemSwiftCrypto

@available(iOS 18.0, macOS 15.0, *)
public struct BlahIdentitySummary: Sendable {
    public let id: String
    public let domain: String
}

@available(iOS 18.0, macOS 15.0, *)
public struct BlahIdentityView: Sendable {
    public let id: String
    public let profile: Profile
    public let user: UserProfile
    public let device: DevicePublicKey
    public let biometrics: Bool
    public let sync: Bool
    public let profileDays: UInt64
    public let deviceDays: UInt64
    public let autoRenew: Bool
}

@available(iOS 18.0, macOS 15.0, *)
public actor BlahIdentityStore {
    public static let shared = BlahIdentityStore()
    private let backend = SwiftCryptoBackend()
    private var sessions: [String: Session] = [:]
    private var renewalTasks: [String: Task<Void, Never>] = [:]
    private var isBusy = false
    private var shouldLock = false
    private static let day: UInt64 = 86400
    private static let timeout: UInt64 = 900

    private struct Record: Codable {
        var profile: Data
        let rootBox: Data
        let encryptionReference: Data
        let deviceReference: Data
        var biometrics: Bool
        var sync: Bool
        var profileDays: UInt64 = 180
        var deviceDays: UInt64 = 180
        var autoRenew: Bool = true
    }
    private struct Recovery: Codable {
        let version: Int
        let secret: Data
        let profile: Data
    }
    private struct Session {
        var identity: Identity
        var record: Record
        var expires: UInt64
    }

    public func list() throws -> [BlahIdentitySummary] {
        return try BlahKeychain.keys().filter { $0.hasPrefix("identity:") }.map { key in
            let record = try readRecord(String(key.dropFirst(9)))
            let profile = try Profile(encoding: Array(record.profile))
            return BlahIdentitySummary(id: profile.id.description, domain: try UserProfile(profile).domains.first?.name ?? profile.id.description)
        }.sorted { $0.domain < $1.domain }
    }

    public func cloudIdentities() throws -> [BlahIdentitySummary] {
        return try BlahKeychain.keys(sync: true).filter { $0.hasPrefix("recovery:") }.map { key in
            let recovery = try JSONDecoder().decode(Recovery.self, from: BlahKeychain.read(key, sync: true)!)
            let profile = try Profile(encoding: Array(recovery.profile))
            return BlahIdentitySummary(id: profile.id.description, domain: try UserProfile(profile).domains.first?.name ?? profile.id.description)
        }
    }

    public func home(slot: String) throws -> BlahHome? {
        guard let data = try BlahKeychain.read("home:" + slot) else { return nil }
        return try JSONDecoder().decode(BlahHome.self, from: data)
    }

    public func connect(domain: String, slot: String) async throws -> BlahHome {
        try begin(); defer { finish() }
        let home = try await BlahHome.discover(domain, previous: self.home(slot: slot))
        try BlahKeychain.write("home:" + slot, data: JSONEncoder().encode(home))
        return home
    }

    public func create(domain: String, slot: String, biometrics: Bool, sync: Bool) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        guard let home = try self.home(slot: slot) else { throw BlahIdentityError.wrongHome }
        let (dc, _) = try await home.verified()
        let root = try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity))
        let device = try makeDevice()
        let user = try UserProfile(home: Home(dc: dc.id, epoch: 1, expiresAt: backend.now + 180 * Self.day),
            domains: [ProfileDomain(domain.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())])
        let identity = try await Identity(data: user.encoded(), identityKey: root, deviceKey: device.key,
            profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        let record = try await makeRecord(identity: identity, deviceReference: device.reference, biometrics: biometrics, sync: sync)
        try await save(identity: identity, record: record)
        setSession(slot, identity: identity, record: record)
        return try view(identity, record)
    }

    public func unlock(id: String, slot: String) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        let record = try readRecord(id)
        let recipient = try EncryptionPrivateKey(secureEnclaveReference: record.encryptionReference)
        let root = try await SealedIdentityKey(encoding: Array(record.rootBox)).open(with: recipient, using: backend)
        let device = try DevicePrivateKey(PrivateKey(secureEnclaveReference: record.deviceReference, for: .device))
        var identity = try await Identity(profile: Profile(encoding: Array(record.profile)), deviceKey: device, identityKey: root,
            profileLifetime: record.profileDays * Self.day, deviceLifetime: record.deviceDays * Self.day, using: backend)
        // The hosted profile can revoke this device. Network errors do not rewrite the saved revision.
        let domain = try UserProfile(identity.profile).domains[0].name
        if let hosted = try? await BlahProfileHost.fetch(domain), let profile = try? Profile(encoding: Array(hosted)) {
            try await profile.verify(using: backend, at: profile.validity.notBefore)
            guard profile.id == identity.id else { throw BlahIdentityError.invalidProfile }
            if profile.generation > identity.profile.generation || profile.revision >= identity.profile.revision {
                try BlahProfileHost.requireMonotonic(profile, after: identity.profile)
                identity = try await Identity(profile: profile, deviceKey: device, identityKey: root,
                    profileLifetime: record.profileDays * Self.day, deviceLifetime: record.deviceDays * Self.day, using: backend)
            }
        }
        if record.autoRenew && isRenewalDue(identity.profile) { try await renew(&identity) }
        try await save(identity: identity, record: record)
        var current = record
        current.profile = Data(identity.profile.encoding)
        setSession(slot, identity: identity, record: current)
        return try view(identity, current)
    }

    public func lock() {
        if isBusy { shouldLock = true; return }
        sessions.removeAll()
        for task in renewalTasks.values { task.cancel() }
        renewalTasks.removeAll()
    }

    public func inspect(slot: String) throws -> BlahIdentityView {
        let current = try session(slot)
        return try view(current.identity, current.record)
    }

    public func bind(slot: String) async throws -> String {
        try begin(); defer { finish() }
        let current = try session(slot)
        guard let home = try self.home(slot: slot) else { throw BlahIdentityError.wrongHome }
        let (profile, dc) = try await home.verified()
        let namespace = try ClientNamespace(profile: current.identity.profile,
            dc: DCAddress(domain: home.domain, id: profile.id), generation: dc.namespaceGeneration!)
        if let saved = try BlahKeychain.read("binding:" + slot), saved != Data(namespace.identifier.utf8) {
            throw BlahIdentityError.wrongHome
        }
        try BlahKeychain.write("binding:" + slot, data: Data(namespace.identifier.utf8))
        return try UserProfile(current.identity.profile).domains[0].name
    }

    public func prove(slot: String, challenge: Data, expires: Int32, query: Data, keyID: Int64, sessionID: Int64) async throws -> Data {
        try begin(); defer { finish() }
        let current = try session(slot)
        let parsed = try InvocationChallenge(encoding: Array(challenge))
        let user = try UserProfile(current.identity.profile)
        guard let home = user.home, home.isActive(at: backend.now), parsed.dc == home.dc,
            parsed.domain == user.domains[0].name, parsed.transportKeyID == keyID,
            parsed.sessionID == UInt64(bitPattern: sessionID), expires > 0, parsed.expiresAt == UInt64(expires) else {
            throw BlahIdentityError.invalidProfile
        }
        return Data(try await current.identity.prove(InvocationStatement(challenge: parsed, payload: Array(query))).encoding)
    }

    public func number(slot: String, account: Int64) async throws {
        try begin(); defer { finish() }
        var current = try session(slot)
        var user = try UserProfile(current.identity.profile)
        guard let home = user.home, home.account == nil || home.account == account else { throw BlahIdentityError.wrongHome }
        if home.account == nil {
            user.home?.account = account
            try await current.identity.update(user)
            try await save(identity: current.identity, record: current.record)
            current.record.profile = Data(current.identity.profile.encoding)
            sessions[slot] = current
        }
        try await requirePublication(current.identity.profile)
    }

    public enum Change: Sendable {
        case renew
        case domains([ProfileDomain])
        case addDevice(Data)
        case removeDevice(BlahDiem.Digest)
        case renewal(profileDays: UInt64, deviceDays: UInt64, automatic: Bool)
        case sync(Bool)
        case biometrics(Bool)
    }

    public func change(slot: String, change: Change) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        var current = try session(slot)
        switch change {
        case .renew: try await renew(&current.identity)
        case let .domains(domains):
            var user = try UserProfile(current.identity.profile)
            guard !domains.isEmpty else { throw BlahIdentityError.invalidProfile }
            user.domains = domains
            try await current.identity.update(user)
        case let .addDevice(data): try await current.identity.add(DevicePublicKey(PublicKey(encoding: Array(data))))
        case let .removeDevice(id): try await current.identity.remove(id)
        case let .renewal(profileDays, deviceDays, automatic):
            guard profileDays > 0, deviceDays >= profileDays, deviceDays < 36500 else { throw BlahIdentityError.invalidProfile }
            current.record.profileDays = profileDays; current.record.deviceDays = deviceDays; current.record.autoRenew = automatic
            current.identity = try await Identity(profile: current.identity.profile, deviceKey: current.identity.deviceKey,
                identityKey: current.identity.identityKey, profileLifetime: profileDays * Self.day,
                deviceLifetime: deviceDays * Self.day, using: backend)
        case let .sync(enabled):
            current.record.sync = enabled
            if !enabled { try BlahKeychain.remove("recovery:" + current.identity.id.description, sync: true) }
        case let .biometrics(enabled):
            let record = try await makeRecord(identity: current.identity, deviceReference: current.record.deviceReference,
                biometrics: enabled, sync: current.record.sync)
            current.record = Record(profile: record.profile, rootBox: record.rootBox,
                encryptionReference: record.encryptionReference, deviceReference: record.deviceReference,
                biometrics: enabled, sync: record.sync, profileDays: current.record.profileDays,
                deviceDays: current.record.deviceDays, autoRenew: current.record.autoRenew)
        }
        try await save(identity: current.identity, record: current.record)
        current.record.profile = Data(current.identity.profile.encoding)
        sessions[slot] = current
        return try view(current.identity, current.record)
    }

    public func checkPublication(slot: String) async throws {
        let profile = try session(slot).identity.profile
        try await requirePublication(profile)
    }

    public func restoreCloud(id: String, slot: String, biometrics: Bool) async throws -> BlahIdentityView {
        guard let data = try BlahKeychain.read("recovery:" + id, sync: true) else { throw BlahIdentityError.invalidProfile }
        return try await restoreRecovery(data, slot: slot, biometrics: biometrics, sync: true)
    }

    // File recovery carries the exportable root; hardware device keys stay on this phone.
    public func exportRecovery(slot: String, password: String) async throws -> Data {
        let current = try session(slot)
        guard let root = current.identity.identityKey else { throw BlahIdentityError.locked }
        return try await BlahRecoveryFile.seal(profile: current.identity.profile, identityKey: root, password: password)
    }

    public func importRecovery(_ data: Data, password: String, slot: String, biometrics: Bool) async throws -> BlahIdentityView {
        let contents = try await BlahRecoveryFile.open(data, password: password)
        guard let root = contents.keys.first(where: { $0.publicKey.purpose == .identity }) else {
            throw BlahIdentityError.invalidProfile
        }
        let recovery = Recovery(version: 1, secret: Data(root.secret), profile: Data(contents.profile.encoding))
        return try await restoreRecovery(JSONEncoder().encode(recovery), slot: slot, biometrics: biometrics, sync: false)
    }

    private func restoreRecovery(_ data: Data, slot: String, biometrics: Bool, sync: Bool) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        guard data.count <= 600000 else { throw BlahIdentityError.invalidProfile }
        let recovery = try JSONDecoder().decode(Recovery.self, from: data)
        guard recovery.version == 1 else { throw BlahIdentityError.invalidProfile }
        let saved = try Profile(encoding: Array(recovery.profile))
        guard try BlahKeychain.read("identity:" + saved.id.description) == nil else { throw BlahIdentityError.duplicate }
        let root = try await IdentityPrivateKey(backend.makePrivateKey(saved.identityKey.key.algorithm, for: .identity, restoring: Array(recovery.secret)))
        let domain = try UserProfile(saved).domains[0].name
        let profile = try Profile(encoding: Array(try await BlahProfileHost.fetch(domain)))
        try await profile.verify(using: backend, at: profile.validity.notBefore)
        try BlahProfileHost.requireMonotonic(profile, after: saved)
        let device = try makeDevice()
        var identity = try await Identity.enrolling(device.key, in: profile, identityKey: root,
            profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        try await renew(&identity)
        let record = try await makeRecord(identity: identity, deviceReference: device.reference, biometrics: biometrics, sync: sync)
        try await save(identity: identity, record: record)
        setSession(slot, identity: identity, record: record)
        return try view(identity, record)
    }

    private func readRecord(_ id: String) throws -> Record {
        guard let data = try BlahKeychain.read("identity:" + id) else { throw BlahIdentityError.locked }
        return try JSONDecoder().decode(Record.self, from: data)
    }

    private func makeDevice() throws -> (key: DevicePrivateKey, reference: Data) {
        guard SecureEnclave.isAvailable else { throw BlahIdentityError.unavailable }
        let created = try PrivateKey.secureEnclave(for: .device, accessControl: accessControl(biometrics: false))
        return (try DevicePrivateKey(created.key), created.reference)
    }

    private func accessControl(biometrics: Bool) throws -> SecAccessControl {
        var error: Unmanaged<CFError>?
        var flags: SecAccessControlCreateFlags = [.privateKeyUsage]
        if biometrics { flags.insert(.biometryAny) }
        guard let control = SecAccessControlCreateWithFlags(nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, flags, &error) else {
            throw BlahIdentityError.unavailable
        }
        return control
    }

    private func makeRecord(identity: Identity, deviceReference: Data, biometrics: Bool, sync: Bool) async throws -> Record {
        guard let root = identity.identityKey else { throw BlahIdentityError.locked }
        let recipient = try EncryptionPrivateKey.secureEnclave(accessControl: accessControl(biometrics: biometrics))
        let sealed = try await root.sealed(to: recipient.key.publicKey, using: backend)
        return Record(profile: Data(identity.profile.encoding), rootBox: Data(sealed.encoding),
            encryptionReference: recipient.reference, deviceReference: deviceReference, biometrics: biometrics, sync: sync)
    }

    private func save(identity: Identity, record: Record) async throws {
        var record = record
        record.profile = Data(identity.profile.encoding)
        try BlahKeychain.write("identity:" + identity.id.description, data: JSONEncoder().encode(record))
        for (slot, current) in sessions where current.identity.id == identity.id {
            sessions[slot] = Session(identity: identity, record: record, expires: current.expires)
        }
        if record.sync, let secret = identity.identityKey?.rawRepresentation {
            let recovery = Recovery(version: 1, secret: Data(secret), profile: record.profile)
            try BlahKeychain.write("recovery:" + identity.id.description, data: JSONEncoder().encode(recovery), sync: true)
        }
    }

    private func session(_ slot: String, touch: Bool = true) throws -> Session {
        guard var current = sessions[slot], current.expires > backend.now else {
            sessions.removeValue(forKey: slot)
            renewalTasks.removeValue(forKey: slot)?.cancel()
            throw BlahIdentityError.locked
        }
        if touch { current.expires = backend.now + Self.timeout; sessions[slot] = current }
        return current
    }

    private func setSession(_ slot: String, identity: Identity, record: Record) {
        sessions[slot] = Session(identity: identity, record: record, expires: backend.now + Self.timeout)
        renewalTasks[slot]?.cancel()
        renewalTasks[slot] = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 60_000_000_000) } catch { return }
                await self?.maintain(slot)
            }
        }
    }

    private func maintain(_ slot: String) async {
        guard !isBusy, var current = try? session(slot, touch: false) else { return }
        isBusy = true; defer { finish() }
        do {
            if current.record.autoRenew && isRenewalDue(current.identity.profile) {
                try await renew(&current.identity)
                try await save(identity: current.identity, record: current.record)
                current.record.profile = Data(current.identity.profile.encoding)
                sessions[slot] = current
            }
        } catch { /* The current signed revision stays available for explicit retry. */ }
    }

    private func isRenewalDue(_ profile: Profile) -> Bool {
        return ([profile.validity] + profile.devices.map(\.validity)).contains {
            backend.now >= $0.notBefore + ($0.expiresAt - $0.notBefore) * 4 / 5
        }
    }

    private func renew(_ identity: inout Identity) async throws {
        var user = try UserProfile(identity.profile)
        user.home?.expiresAt = backend.now + identity.deviceLifetime
        try await identity.renew()
        try await identity.update(user)
    }

    private func requirePublication(_ profile: Profile) async throws {
        for domain in try UserProfile(profile).domains {
            guard try await BlahProfileHost.fetch(domain.name) == Data(profile.encoding) else {
                throw BlahIdentityError.publicationRequired
            }
        }
    }

    private func view(_ identity: Identity, _ record: Record) throws -> BlahIdentityView {
        return BlahIdentityView(id: identity.id.description, profile: identity.profile, user: try UserProfile(identity.profile),
            device: identity.deviceKey.publicKey, biometrics: record.biometrics, sync: record.sync,
            profileDays: record.profileDays, deviceDays: record.deviceDays, autoRenew: record.autoRenew)
    }

    private func begin() throws {
        guard !isBusy else { throw BlahIdentityError.locked }
        isBusy = true
    }
    private func finish() {
        isBusy = false
        if shouldLock { shouldLock = false; lock() }
    }
}

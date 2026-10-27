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
    public let profile: AnyBlahProfile
    public let user: HostedContent
    public let device: DevicePublicKey
    public let biometrics: Bool
    public let sync: Bool
    public let profileDays: UInt64
    public let deviceDays: UInt64
    public let autoRenew: Bool
    public let hostingDomain: String?
    public let publicationPending: Bool
}

@available(iOS 18.0, macOS 15.0, *)
public actor BlahIdentityStore {
    public static let shared: BlahIdentityStore = {
        let isAppExtension = Bundle.main.bundlePath.hasSuffix(".appex")
        var baseAppBundleId = Bundle.main.bundleIdentifier!
        if isAppExtension, let dot = baseAppBundleId.range(of: ".", options: .backwards) {
            baseAppBundleId = String(baseAppBundleId[..<dot.lowerBound])
        }
        return BlahIdentityStore(accessGroup: "group." + baseAppBundleId, isAppExtension: isAppExtension)
    }()
    private let backend = SwiftCryptoBackend()
    private let restoreKeychain: BlahRestoreKeychain
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
        var hostingDomain: String?
        var publishedProfile: Data?
        var checkedProfile: Data?
    }
    private struct Recovery: Codable {
        let version: Int
        let secret: Data
        let profile: Data
        var hostingDomain: String?
    }
    private struct Binding: Codable {
        let namespace: String
        let identityID: String
        let deviceID: Data
        var profile: Data?
    }
    private struct Session {
        var identity: BasicIdentity<AnyBlahProfile>
        var record: Record
        var expires: UInt64
    }

    init(accessGroup: String, isAppExtension: Bool) {
        restoreKeychain = BlahRestoreKeychain(accessGroup: accessGroup, isAppExtension: isAppExtension)
    }

    public func list() throws -> [BlahIdentitySummary] {
        return try BlahKeychain.keys().filter { $0.hasPrefix("identity:") }.map { key in
            let record = try readRecord(String(key.dropFirst(9)))
            let profile = try AnyBlahProfile(encoding: Array(record.profile))
            return BlahIdentitySummary(id: profile.id.description, domain: profile.domains.first?.name ?? profile.id.description)
        }.sorted { $0.domain < $1.domain }
    }

    public func cloudIdentities() throws -> [BlahIdentitySummary] {
        return try BlahKeychain.keys(sync: true).filter { $0.hasPrefix("recovery:") }.map { key in
            let recovery = try JSONDecoder().decode(Recovery.self, from: BlahKeychain.read(key, sync: true)!)
            let profile = try AnyBlahProfile(encoding: Array(recovery.profile))
            return BlahIdentitySummary(id: profile.id.description, domain: profile.domains.first?.name ?? profile.id.description)
        }
    }

    public func home(slot: String) throws -> BlahHome? {
        guard let data = try restoreKeychain.read("home:" + slot) else { return nil }
        return try JSONDecoder().decode(BlahHome.self, from: data)
    }

    public func connect(domain: String, slot: String) async throws -> BlahHome {
        try begin(); defer { finish() }
        let home = try await BlahHome.discover(domain, previous: self.home(slot: slot))
        try restoreKeychain.write("home:" + slot, data: JSONEncoder().encode(home))
        return home
    }

    public func restoreHome(slot: String, refresh: Bool) async throws -> BlahHome? {
        guard let saved = try home(slot: slot) else { return nil }
        if !refresh {
            _ = try await saved.verified()
            return saved
        }
        try begin(); defer { finish() }
        let home = try await BlahHome.discover(saved.domain, previous: saved, allowOffline: true)
        try restoreKeychain.write("home:" + slot, data: JSONEncoder().encode(home))
        return home
    }

    public func remove(slot: String) throws {
        try begin(); defer { finish() }
        for prefix in ["home:", "binding-v2:", "binding:"] {
            try restoreKeychain.remove(prefix + slot)
        }
        sessions.removeValue(forKey: slot)
        renewalTasks.removeValue(forKey: slot)?.cancel()
    }

    public func create(domain: String, slot: String, biometrics: Bool, sync: Bool) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        return try await create(domain: BlahProfileHost.domain(domain), hostingDomain: nil,
            slot: slot, biometrics: biometrics, sync: sync)
    }

    public func createHosted(domain: String, label: String, slot: String, biometrics: Bool, sync: Bool) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        let host = try BlahProfileHost.domain(domain)
        guard !label.contains("."), let name = DomainName(normalizing: label + "." + host.name) else {
            throw BlahIdentityError.invalidProfile
        }
        let client = ProfileHostingClient(domain: host, http: BlahHostingHTTPClient())
        _ = try await client.policy()
        let hostedLabel = String(name.name.dropLast(host.name.count + 1))
        switch try await client.name(hostedLabel).status {
        case .available: break
        case .claimed: throw ProfileHostingError.nameTaken(hostedLabel)
        case .invalid: throw ProfileHostingError.invalidLabel(hostedLabel)
        }
        return try await create(domain: name, hostingDomain: host.name, slot: slot, biometrics: biometrics, sync: sync)
    }

    private func create(domain: DomainName, hostingDomain: String?, slot: String, biometrics: Bool, sync: Bool) async throws -> BlahIdentityView {
        guard let home = try self.home(slot: slot) else { throw BlahIdentityError.wrongHome }
        let (dc, _) = try await home.verified()
        let root = try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity))
        let device = try makeDevice()
        let user = HostedContent(home: Home(dc: dc.id, epoch: 1, expiresAt: backend.now + 180 * Self.day), domains: [domain])
        let identity = try await BasicIdentity<AnyBlahProfile>(.user(user), identityKey: root, deviceKey: device.key,
            profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        var record = try await makeRecord(identity: identity, deviceReference: device.reference, biometrics: biometrics, sync: sync)
        record.hostingDomain = hostingDomain
        try await save(identity: identity, record: record)
        setSession(slot, identity: identity, record: record)
        var current = try session(slot)
        try await publishHosted(&current)
        return try view(current.identity, current.record)
    }

    public func unlock(id: String, slot: String) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        var record = try readRecord(id)
        let recipient = try EncryptionPrivateKey(secureEnclaveReference: record.encryptionReference)
        let root = try await SealedIdentityKey(encoding: Array(record.rootBox)).open(with: recipient, using: backend)
        let device = try DevicePrivateKey(PrivateKey(secureEnclaveReference: record.deviceReference, for: .device))
        var identity = try await BasicIdentity<AnyBlahProfile>(profile: AnyBlahProfile(encoding: Array(record.profile)), deviceKey: device, identityKey: root,
            profileLifetime: record.profileDays * Self.day, deviceLifetime: record.deviceDays * Self.day, using: backend)
        try requireAccount(identity.profile)
        // The hosted profile can revoke this device. Network errors do not rewrite the saved revision.
        let domain = identity.profile.domains[0].name
        if let hosted = try? await BlahProfileHost.fetch(domain) {
            let profile = try AnyBlahProfile(encoding: Array(hosted))
            try await profile.verify(using: backend, at: profile.validity.notBefore)
            try requireAccount(profile)
            guard profile.id == identity.id else { throw BlahIdentityError.invalidProfile }
            if profile.generation > identity.profile.generation || profile.revision >= identity.profile.revision {
                try BlahProfileHost.requireMonotonic(profile, after: identity.profile)
                identity = try await BasicIdentity<AnyBlahProfile>(profile: profile, deviceKey: device, identityKey: root,
                    profileLifetime: record.profileDays * Self.day, deviceLifetime: record.deviceDays * Self.day, using: backend)
            }
        }
        try await save(identity: identity, record: record)
        record.profile = Data(identity.profile.encoding)
        setSession(slot, identity: identity, record: record)
        var current = try session(slot)
        // A failed PUT retains custody and the exact signed revision for an explicit retry.
        // Never create a new revision until the preceding hosted publication is acknowledged.
        do {
            let shouldRenew = record.autoRenew && isRenewalDue(current.identity.profile)
            try await publishHosted(&current, allowExpired: shouldRenew)
            if shouldRenew {
                try await renew(&current.identity)
                try await persist(&current)
                try await publishHosted(&current)
            }
        } catch { /* Unlock still exposes the durable profile and publication controls. */ }
        return try view(current.identity, current.record)
    }

    public func lock() {
        for task in renewalTasks.values { task.cancel() }
        renewalTasks.removeAll()
        if isBusy { shouldLock = true; return }
        sessions.removeAll()
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
        try await current.identity.profile.verify(using: backend)
        guard current.identity.profile.home?.isActive(at: backend.now) == true else { throw BlahIdentityError.wrongHome }
        let namespace = try ClientNamespace(profile: current.identity.profile,
            dc: DCAddress(domain: try DomainName(home.domain), id: profile.id), generation: dc.namespaceGeneration!)
        if let saved = try restoreKeychain.read("binding:" + slot), saved != Data(namespace.identifier.utf8) {
            throw BlahIdentityError.wrongHome
        }
        try restoreKeychain.write("binding:" + slot, data: Data(namespace.identifier.utf8))
        try restoreKeychain.write("binding-v2:" + slot, data: JSONEncoder().encode(Binding(namespace: namespace.identifier,
            identityID: current.identity.id.description, deviceID: Data(current.identity.deviceKey.publicKey.id.bytes),
            profile: Data(current.identity.profile.encoding))))
        return current.identity.profile.domains[0].name
    }

    /// Stored MTProto authorizations must pass this check before reconnecting. A legacy
    /// unbound slot is deliberately not adopted by whichever identity is selected next.
    public func validateRestoredBinding(slot: String, required: Bool = true) async throws {
        guard let data = try restoreKeychain.read("binding-v2:" + slot) else {
            if !required, try restoreKeychain.read("binding:" + slot) == nil { return }
            throw BlahIdentityError.wrongHome
        }
        guard let home = try self.home(slot: slot) else {
            throw BlahIdentityError.wrongHome
        }
        var binding = try JSONDecoder().decode(Binding.self, from: data)
        let encoding: Data
        if restoreKeychain.isAppExtension {
            guard let snapshot = binding.profile else { throw BlahIdentityError.wrongHome }
            encoding = snapshot
        } else {
            encoding = try readRecord(binding.identityID).profile
        }
        let profile = try AnyBlahProfile(encoding: Array(encoding))
        try requireAccount(profile)
        try await profile.verify(using: backend)
        let (dc, content) = try await home.verified()
        guard let generation = content.namespaceGeneration else { throw BlahIdentityError.wrongHome }
        let namespace = try ClientNamespace(profile: profile, dc: DCAddress(domain: DomainName(home.domain), id: dc.id), generation: generation)
        guard profile.id.description == binding.identityID, namespace.identifier == binding.namespace,
            profile.home?.isActive(at: backend.now) == true,
            profile.device(try BlahDiem.Digest(bytes: Array(binding.deviceID))) != nil,
            try restoreKeychain.read("binding:" + slot) == Data(namespace.identifier.utf8) else {
            throw BlahIdentityError.wrongHome
        }
        if !restoreKeychain.isAppExtension, binding.profile != encoding,
            try restoreKeychain.read("binding-v2:" + slot) == data,
            try readRecord(binding.identityID).profile == encoding {
            binding.profile = encoding
            try restoreKeychain.write("binding-v2:" + slot, data: JSONEncoder().encode(binding))
        }
    }

    public func prove(slot: String, challenge: Data, expires: Int32, query: Data, keyID: Int64, sessionID: Int64) async throws -> Data {
        try begin(); defer { finish() }
        let current = try session(slot)
        let parsed = try InvocationChallenge(encoding: Array(challenge))
        let profile = current.identity.profile
        try await profile.verify(using: backend)
        guard let home = profile.home, home.isActive(at: backend.now), parsed.dc == home.dc,
            parsed.domain == profile.domains[0], parsed.transportKeyID == keyID,
            parsed.sessionID == UInt64(bitPattern: sessionID), expires > 0, parsed.expiresAt == UInt64(expires) else {
            throw BlahIdentityError.invalidProfile
        }
        return Data(try await current.identity.prove(InvocationStatement(challenge: parsed, payload: Array(query))).encoding)
    }

    public func number(slot: String, account: Int64) async throws {
        try begin(); defer { finish() }
        var current = try session(slot)
        try await publishHosted(&current)
        guard let home = current.identity.profile.home, home.account == nil || home.account == account else { throw BlahIdentityError.wrongHome }
        if home.account == nil {
            guard case .user(var user) = current.identity.profile.content else { throw BlahIdentityError.invalidProfile }
            user.home?.account = account
            try await current.identity.update(.user(user))
            try await persist(&current)
            try await publishHosted(&current)
        }
        try await requirePublication(current.identity.profile)
        current.record.publishedProfile = Data(current.identity.profile.encoding)
        current.record.checkedProfile = current.record.publishedProfile
        try await persist(&current)
    }

    public enum Change: Sendable {
        case renew
        case domains([DomainName])
        case addDevice(Data)
        case removeDevice(BlahDiem.Digest)
        case renewal(profileDays: UInt64, deviceDays: UInt64, automatic: Bool)
        case sync(Bool)
        case biometrics(Bool)
    }

    public func change(slot: String, change: Change) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        var current = try session(slot)
        let publishes: Bool
        switch change {
        case .renew:
            publishes = true
            try await publishHosted(&current, allowExpired: true)
        case .domains, .addDevice, .removeDevice:
            publishes = true
            try await publishHosted(&current)
        case .renewal, .sync, .biometrics:
            publishes = false
        }
        switch change {
        case .renew: try await renew(&current.identity)
        case let .domains(domains):
            guard !domains.isEmpty else { throw BlahIdentityError.invalidProfile }
            // Keep at least one route through the selected host so publication remains
            // retryable; moving hosts is a separate custody workflow.
            if let host = current.record.hostingDomain,
                !domains.contains(where: { $0.name.hasSuffix("." + host) && !$0.name.dropLast(host.count + 1).contains(".") }) {
                throw BlahIdentityError.invalidProfile
            }
            try await current.identity.update(current.identity.profile.content.replacingDomains(domains))
        case let .addDevice(data): try await current.identity.add(DevicePublicKey(PublicKey(encoding: Array(data))))
        case let .removeDevice(id): try await current.identity.remove(id)
        case let .renewal(profileDays, deviceDays, automatic):
            guard profileDays > 0, deviceDays >= profileDays, deviceDays < 36500 else { throw BlahIdentityError.invalidProfile }
            current.record.profileDays = profileDays; current.record.deviceDays = deviceDays; current.record.autoRenew = automatic
            current.identity = try await BasicIdentity<AnyBlahProfile>(profile: current.identity.profile, deviceKey: current.identity.deviceKey,
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
                deviceDays: current.record.deviceDays, autoRenew: current.record.autoRenew,
                hostingDomain: current.record.hostingDomain, publishedProfile: current.record.publishedProfile,
                checkedProfile: current.record.checkedProfile)
        }
        try await persist(&current)
        if publishes { try await publishHosted(&current) }
        return try view(current.identity, current.record)
    }

    public func checkPublication(slot: String) async throws {
        try begin(); defer { finish() }
        var current = try session(slot)
        try await requirePublication(current.identity.profile)
        current.record.publishedProfile = Data(current.identity.profile.encoding)
        current.record.checkedProfile = current.record.publishedProfile
        try await persist(&current)
    }

    public func publish(slot: String) async throws {
        try begin(); defer { finish() }
        var current = try session(slot)
        try await publishHosted(&current)
        try await requirePublication(current.identity.profile)
        current.record.publishedProfile = Data(current.identity.profile.encoding)
        current.record.checkedProfile = current.record.publishedProfile
        try await persist(&current)
    }

    public func restoreCloud(id: String, slot: String, biometrics: Bool) async throws -> BlahIdentityView {
        guard let data = try BlahKeychain.read("recovery:" + id, sync: true) else { throw BlahIdentityError.invalidProfile }
        return try await restoreRecovery(data, slot: slot, biometrics: biometrics, sync: true)
    }

    // File recovery carries the exportable root; hardware device keys stay on this phone.
    public func exportRecovery(slot: String, password: String) async throws -> Data {
        let current = try session(slot)
        guard let root = current.identity.identityKey else { throw BlahIdentityError.locked }
        var metadata: [UInt64: CBOR] = [0: .text(current.identity.profile.domains[0].name),
            3: .unsigned(current.record.profileDays), 4: .unsigned(current.record.deviceDays),
            5: .bool(current.record.autoRenew)]
        if let host = current.record.hostingDomain {
            let client = ProfileHostingClient(domain: try DomainName(host), http: BlahHostingHTTPClient())
            metadata[7] = .record([0: .text(host), 1: .array(client.labels(in: current.identity.profile).map(CBOR.text)), 2: .array([])])
        }
        return try await BlahRecoveryFile.seal(profile: current.identity.profile, identityKey: root, password: password,
            metadata: .record(metadata))
    }

    public func importRecovery(_ data: Data, password: String, slot: String, biometrics: Bool) async throws -> BlahIdentityView {
        let contents = try await BlahRecoveryFile.open(data, password: password)
        guard let root = contents.keys.first(where: { $0.publicKey.purpose == .identity }) else {
            throw BlahIdentityError.invalidProfile
        }
        let metadata = try contents.metadata.recordValue(requiredKeys: 0..<0)
        let hosting = try metadata[7].map { try $0.recordValue(requiredKeys: 0..<3)[0]!.textValue() }
        if let hosting {
            let host = ProfileHostingClient(domain: try DomainName(hosting), http: BlahHostingHTTPClient())
            guard !host.labels(in: contents.profile).isEmpty else { throw BlahIdentityError.invalidProfile }
        }
        let recovery = Recovery(version: 1, secret: Data(root.secret), profile: Data(contents.profile.encoding), hostingDomain: hosting)
        return try await restoreRecovery(JSONEncoder().encode(recovery), slot: slot, biometrics: biometrics, sync: false)
    }

    private func restoreRecovery(_ data: Data, slot: String, biometrics: Bool, sync: Bool) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        guard data.count <= 600000 else { throw BlahIdentityError.invalidProfile }
        let recovery = try JSONDecoder().decode(Recovery.self, from: data)
        guard recovery.version == 1 else { throw BlahIdentityError.invalidProfile }
        let saved = try AnyBlahProfile(encoding: Array(recovery.profile))
        try requireAccount(saved)
        guard try BlahKeychain.read("identity:" + saved.id.description) == nil else { throw BlahIdentityError.duplicate }
        let root = try await IdentityPrivateKey(backend.makePrivateKey(saved.identityKey.key.algorithm, for: .identity, restoring: Array(recovery.secret)))
        let domain = saved.domains[0].name
        let profile = try AnyBlahProfile(encoding: Array(try await BlahProfileHost.fetch(domain)))
        try requireAccount(profile)
        try await profile.verify(using: backend, at: profile.validity.notBefore)
        try BlahProfileHost.requireMonotonic(profile, after: saved)
        let device = try makeDevice()
        var identity = try await BasicIdentity<AnyBlahProfile>.enrolling(device.key, in: profile, identityKey: root,
            profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        try await renew(&identity)
        var record = try await makeRecord(identity: identity, deviceReference: device.reference, biometrics: biometrics, sync: sync)
        record.hostingDomain = recovery.hostingDomain
        try await save(identity: identity, record: record)
        setSession(slot, identity: identity, record: record)
        var current = try session(slot)
        try await publishHosted(&current)
        return try view(current.identity, current.record)
    }

    private func readRecord(_ id: String) throws -> Record {
        guard let data = try BlahKeychain.read("identity:" + id) else { throw BlahIdentityError.locked }
        let record = try JSONDecoder().decode(Record.self, from: data)
        guard record.profileDays > 0, record.deviceDays >= record.profileDays, record.deviceDays < 36500 else {
            throw BlahIdentityError.invalidProfile
        }
        return record
    }

    private func requireAccount(_ profile: AnyBlahProfile) throws {
        guard !profile.domains.isEmpty else { throw BlahIdentityError.invalidProfile }
        switch profile {
        case .user, .dc: break
        default: throw BlahIdentityError.invalidProfile
        }
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

    private func makeRecord(identity: BasicIdentity<AnyBlahProfile>, deviceReference: Data, biometrics: Bool, sync: Bool) async throws -> Record {
        guard let root = identity.identityKey else { throw BlahIdentityError.locked }
        let recipient = try EncryptionPrivateKey.secureEnclave(accessControl: accessControl(biometrics: biometrics))
        let sealed = try await root.sealed(to: recipient.key.publicKey, using: backend)
        return Record(profile: Data(identity.profile.encoding), rootBox: Data(sealed.encoding),
            encryptionReference: recipient.reference, deviceReference: deviceReference, biometrics: biometrics, sync: sync)
    }

    private func save(identity: BasicIdentity<AnyBlahProfile>, record: Record) async throws {
        var record = record
        record.profile = Data(identity.profile.encoding)
        try BlahKeychain.write("identity:" + identity.id.description, data: JSONEncoder().encode(record))
        for (slot, current) in sessions where current.identity.id == identity.id {
            sessions[slot] = Session(identity: identity, record: record, expires: current.expires)
        }
        for key in try restoreKeychain.keys() where key.hasPrefix("binding-v2:") {
            guard let data = try restoreKeychain.read(key) else { continue }
            var binding = try JSONDecoder().decode(Binding.self, from: data)
            if binding.identityID == identity.id.description {
                binding.profile = record.profile
                try restoreKeychain.write(key, data: JSONEncoder().encode(binding))
            }
        }
        if record.sync, let secret = identity.identityKey?.rawRepresentation {
            let recovery = Recovery(version: 1, secret: Data(secret), profile: record.profile, hostingDomain: record.hostingDomain)
            try BlahKeychain.write("recovery:" + identity.id.description, data: JSONEncoder().encode(recovery), sync: true)
        }
    }

    private func persist(_ current: inout Session) async throws {
        current.record.profile = Data(current.identity.profile.encoding)
        try await save(identity: current.identity, record: current.record)
    }

    /// Every caller saves first, and retries this exact revision before signing another.
    /// A host cannot accept expired bytes: renewal may supersede that saved revision,
    /// retaining its revision chain, rather than blocking recovery on an impossible PUT.
    private func publishHosted(_ current: inout Session, allowExpired: Bool = false) async throws {
        guard let domain = current.record.hostingDomain,
            current.record.publishedProfile != Data(current.identity.profile.encoding) else { return }
        if allowExpired, ([current.identity.profile.validity] + current.identity.profile.devices.map(\.validity))
            .contains(where: { $0.expiresAt <= backend.now }) { return }
        let host = ProfileHostingClient(domain: try DomainName(domain), http: BlahHostingHTTPClient())
        try await host.publish(current.identity.profile, solver: BlahHostingProofOfWork())
        current.record.publishedProfile = Data(current.identity.profile.encoding)
        try await persist(&current)
        try await requirePublication(current.identity.profile)
        current.record.checkedProfile = current.record.publishedProfile
        try await persist(&current)
    }

    private func session(_ slot: String, touch: Bool = true) throws -> Session {
        guard !shouldLock, var current = sessions[slot], current.expires > backend.now else {
            sessions.removeValue(forKey: slot)
            renewalTasks.removeValue(forKey: slot)?.cancel()
            throw BlahIdentityError.locked
        }
        if touch { current.expires = backend.now + Self.timeout; sessions[slot] = current }
        return current
    }

    private func setSession(_ slot: String, identity: BasicIdentity<AnyBlahProfile>, record: Record) {
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
            let shouldRenew = current.record.autoRenew && isRenewalDue(current.identity.profile)
            try await publishHosted(&current, allowExpired: shouldRenew)
            if shouldRenew {
                try await renew(&current.identity)
                try await persist(&current)
                try await publishHosted(&current)
            }
        } catch { /* The current signed revision stays available for explicit retry. */ }
    }

    private func isRenewalDue(_ profile: AnyBlahProfile) -> Bool {
        return ([profile.validity] + profile.devices.map(\.validity)).contains {
            backend.now >= $0.expiresAt - ($0.expiresAt - $0.notBefore) / 5
        }
    }

    private func renew(_ identity: inout BasicIdentity<AnyBlahProfile>) async throws {
        try await identity.renew()
        if case .user(var user) = identity.profile.content {
            user.home?.expiresAt = backend.now + identity.deviceLifetime
            try await identity.update(.user(user))
        }
    }

    private func requirePublication(_ profile: AnyBlahProfile) async throws {
        for domain in profile.domains {
            guard try await BlahProfileHost.fetch(domain.name) == Data(profile.encoding) else {
                throw BlahIdentityError.publicationRequired
            }
        }
    }

    private func view(_ identity: BasicIdentity<AnyBlahProfile>, _ record: Record) throws -> BlahIdentityView {
        return BlahIdentityView(id: identity.id.description, profile: identity.profile, user: HostedContent(home: identity.profile.home, domains: identity.profile.domains),
            device: identity.deviceKey.publicKey, biometrics: record.biometrics, sync: record.sync,
            profileDays: record.profileDays, deviceDays: record.deviceDays, autoRenew: record.autoRenew,
            hostingDomain: record.hostingDomain, publicationPending: record.checkedProfile != Data(identity.profile.encoding))
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

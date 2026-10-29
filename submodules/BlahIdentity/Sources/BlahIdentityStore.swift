import Foundation
import CryptoKit
import Security
import BlahDiem
import DiemSwiftCrypto

@available(iOS 18.0, macOS 15.0, *)
public struct BlahIdentitySummary: Sendable {
    public let id: String
    public let domain: String
    public let homeDomain: String?
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
    public let canManageIdentity: Bool
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
    private var linkGeneration: UInt64 = 0
    private var deviceLinks: [UUID: PendingDeviceLink] = [:]
    private var installedDeviceLinks: [UUID: (slot: String, device: BlahDiem.Digest, identityID: String)] = [:]

    private struct PendingDeviceLink {
        let generation: UInt64
        let slot: String
        let home: BlahHome
        let expectedDomain: DomainName?
        let request: DeviceLinkRequest
        let code: DeviceLinkCode
        let device: DevicePrivateKey
        let deviceReference: Data
        let recipient: EncryptionPrivateKey
        let encryptionReference: Data
        let expires: UInt64
    }
    private static let day: UInt64 = 86400
    private static let timeout: UInt64 = 900

    private struct Record: Codable {
        var profile: Data
        let rootBox: Data?
        let encryptionReference: Data
        let deviceReference: Data
        var biometrics: Bool
        var sync: Bool
        var profileDays: UInt64 = 180
        var deviceDays: UInt64 = 180
        var autoRenew: Bool = true
        var homeDomain: String?
        var home: BlahHome?
        var hostingDomain: String?
        var publishedProfile: Data?
        var checkedProfile: Data?
    }
    private struct Recovery: Codable {
        let version: Int
        let secret: Data
        let profile: Data
        var homeDomain: String?
        var home: BlahHome?
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
        return try BlahKeychain.keys().filter { $0.hasPrefix("identity:") || $0.hasPrefix("device-identity:") }.compactMap { key -> BlahIdentitySummary? in
            guard let data = try BlahKeychain.read(key) else { return nil }
            do {
                let record = try decodeRecord(data)
                let profile = try AnyBlahProfile(encoding: Array(record.profile))
                return BlahIdentitySummary(id: profile.id.description, domain: profile.domains.first?.name ?? profile.id.description, homeDomain: record.homeDomain)
            } catch {
                // Do not log custody bytes, identifiers or decoder payloads.
                NSLog("BlahIdentity: skipping unreadable identity record")
                return nil
            }
        }.sorted { $0.domain < $1.domain }
    }

    public func cloudIdentities() throws -> [BlahIdentitySummary] {
        return try BlahKeychain.keys(sync: true).filter { $0.hasPrefix("recovery:") }.map { key in
            let recovery = try JSONDecoder().decode(Recovery.self, from: BlahKeychain.read(key, sync: true)!)
            let profile = try AnyBlahProfile(encoding: Array(recovery.profile))
            return BlahIdentitySummary(id: profile.id.description, domain: profile.domains.first?.name ?? profile.id.description, homeDomain: recovery.homeDomain)
        }
    }

    public func home(slot: String) throws -> BlahHome? {
        guard let data = try restoreKeychain.read("home:" + slot) else { return nil }
        return try JSONDecoder().decode(BlahHome.self, from: data)
    }

    public func connect(domain: String, slot: String) async throws -> BlahHome {
        try begin(); defer { finish() }
        let home = try await BlahHome.discover(domain, previous: self.home(slot: slot))
        try checkActive()
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
        try checkActive()
        try restoreKeychain.write("home:" + slot, data: JSONEncoder().encode(home))
        return home
    }

    public func remove(slot: String) throws {
        try begin(); defer { finish() }
        try removeSlot(slot)
    }

    public func boundSlots(id: String) throws -> [String] {
        return try restoreKeychain.keys().filter { $0.hasPrefix("binding-v2:") }.compactMap { key in
            guard let data = try restoreKeychain.read(key),
                try JSONDecoder().decode(Binding.self, from: data).identityID == id else { return nil }
            return String(key.dropFirst("binding-v2:".count))
        }.sorted()
    }

    public func hasCloudRecovery(id: String) throws -> Bool {
        return try BlahKeychain.read("recovery:" + id, sync: true) != nil
    }

    /// Call after the bound accounts have finished logging out.
    public func removeIdentity(id: String, fromCloud: Bool) throws {
        try begin(); defer { finish() }
        var slots = Set(try boundSlots(id: id))
        slots.formUnion(sessions.compactMap { $0.value.identity.id.description == id ? $0.key : nil })
        slots.formUnion(installedDeviceLinks.values.compactMap { $0.identityID == id ? $0.slot : nil })
        for slot in slots { try removeSlot(slot) }
        try BlahKeychain.remove("identity:" + id)
        try BlahKeychain.remove("device-identity:" + id)
        if fromCloud { try BlahKeychain.remove("recovery:" + id, sync: true) }
    }

    public func removeCloud(id: String) throws {
        try begin(); defer { finish() }
        try BlahKeychain.remove("recovery:" + id, sync: true)
    }

    private func removeSlot(_ slot: String) throws {
        sessions.removeValue(forKey: slot)
        renewalTasks.removeValue(forKey: slot)?.cancel()
        deviceLinks = deviceLinks.filter { $0.value.slot != slot }
        installedDeviceLinks = installedDeviceLinks.filter { $0.value.slot != slot }
        for prefix in ["home:", "binding:", "binding-v2:"] {
            try restoreKeychain.remove(prefix + slot)
        }
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
        record.homeDomain = home.domain
        record.home = home
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
        let root: IdentityPrivateKey?
        if let box = record.rootBox {
            root = try await SealedIdentityKey(encoding: Array(box)).open(with: recipient, using: backend)
        } else {
            root = nil
        }
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
            let shouldRenew = current.identity.identityKey != nil && record.autoRenew && isRenewalDue(current.identity.profile)
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
        linkGeneration &+= 1
        deviceLinks.removeAll()
        installedDeviceLinks.removeAll()
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
        try checkActive()
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

    public func prove(slot: String, challenge: Data, expires: Int32, query: Data, keyID: Int64, sessionID: Int64,
        expectedProfile: Data? = nil) async throws -> Data {
        try begin(); defer { finish() }
        let current = try session(slot)
        let parsed = try InvocationChallenge(encoding: Array(challenge))
        let profile = current.identity.profile
        if let expectedProfile, expectedProfile != Data(profile.encoding) { throw BlahIdentityError.staleProfile }
        try await profile.verify(using: backend)
        guard let home = profile.home, home.isActive(at: backend.now), parsed.dc == home.dc,
            parsed.domain == profile.domains[0], parsed.transportKeyID == keyID,
            parsed.sessionID == UInt64(bitPattern: sessionID), expires > 0, parsed.expiresAt == UInt64(expires) else {
            throw BlahIdentityError.invalidProfile
        }
        let proof = try await current.identity.prove(InvocationStatement(challenge: parsed, payload: Array(query)))
        try checkActive()
        return Data(proof.encoding)
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
        guard current.identity.identityKey != nil else { throw BlahIdentityError.managementRequired }
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
                homeDomain: current.record.homeDomain, home: current.record.home,
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
        return try await restoreRecovery(data, slot: slot, home: self.home(slot: slot), biometrics: biometrics, sync: true)
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
        let recovery = try await recoveryFile(data, password: password)
        return try await restoreRecovery(JSONEncoder().encode(recovery), slot: slot, home: self.home(slot: slot), biometrics: biometrics, sync: false)
    }

    public func importRecovery(_ data: Data, password: String, home: BlahHome, biometrics: Bool) async throws -> String {
        let recovery = try await recoveryFile(data, password: password)
        return try await restoreRecovery(JSONEncoder().encode(recovery), home: home, biometrics: biometrics, sync: false).id
    }

    public func restoreCloud(id: String, home: BlahHome?, biometrics: Bool) async throws -> String {
        guard let data = try BlahKeychain.read("recovery:" + id, sync: true) else { throw BlahIdentityError.invalidProfile }
        let recovery = try JSONDecoder().decode(Recovery.self, from: data)
        guard try AnyBlahProfile(encoding: Array(recovery.profile)).id.description == id else { throw BlahIdentityError.invalidProfile }
        return try await restoreRecovery(data, home: home, biometrics: biometrics, sync: true).id
    }

    private func recoveryFile(_ data: Data, password: String) async throws -> Recovery {
        let contents = try await BlahRecoveryFile.open(data, password: password)
        guard let root = contents.keys.first(where: { $0.publicKey.purpose == .identity }) else {
            throw BlahIdentityError.managementRequired
        }
        let metadata = try contents.metadata.recordValue(requiredKeys: 0..<0)
        let hosting = try metadata[7].map { try $0.recordValue(requiredKeys: 0..<3)[0]!.textValue() }
        if let hosting {
            let host = ProfileHostingClient(domain: try DomainName(hosting), http: BlahHostingHTTPClient())
            guard !host.labels(in: contents.profile).isEmpty else { throw BlahIdentityError.invalidProfile }
        }
        return Recovery(version: 1, secret: Data(root.secret), profile: Data(contents.profile.encoding), hostingDomain: hosting)
    }

    private func restoreRecovery(_ data: Data, slot: String? = nil, home: BlahHome? = nil, biometrics: Bool, sync: Bool) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        guard data.count <= 600000 else { throw BlahIdentityError.invalidProfile }
        let recovery = try JSONDecoder().decode(Recovery.self, from: data)
        guard recovery.version == 1 else { throw BlahIdentityError.invalidProfile }
        let saved = try AnyBlahProfile(encoding: Array(recovery.profile))
        try requireAccount(saved)
        try await saved.verify(using: backend, at: saved.validity.notBefore)
        guard try recordData(saved.id.description) == nil else { throw BlahIdentityError.duplicate }
        let root = try await IdentityPrivateKey(backend.makePrivateKey(saved.identityKey.key.algorithm, for: .identity, restoring: Array(recovery.secret)))
        let domain = saved.domains[0].name
        let profile = try AnyBlahProfile(encoding: Array(try await BlahProfileHost.fetch(domain)))
        try requireAccount(profile)
        try await profile.verify(using: backend, at: profile.validity.notBefore)
        try BlahProfileHost.requireMonotonic(profile, after: saved)
        let selectedHome: BlahHome?
        if let home { selectedHome = home }
        else if let domain = recovery.homeDomain {
            selectedHome = try await BlahHome.discover(domain, previous: recovery.home)
        } else { selectedHome = recovery.home }
        if let selectedHome {
            let (dc, _) = try await selectedHome.verified()
            guard profile.home?.dc == dc.id else { throw BlahIdentityError.wrongHome }
        }
        let device = try makeDevice()
        var identity = try await BasicIdentity<AnyBlahProfile>.enrolling(device.key, in: profile, identityKey: root,
            profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        try await renew(&identity)
        var record = try await makeRecord(identity: identity, deviceReference: device.reference, biometrics: biometrics, sync: sync)
        record.homeDomain = recovery.homeDomain
        record.home = recovery.home
        if let selectedHome { try rememberHome(selectedHome, profile: identity.profile, record: &record) }
        record.hostingDomain = recovery.hostingDomain
        try await save(identity: identity, record: record)
        if let slot { setSession(slot, identity: identity, record: record) }
        var current = Session(identity: identity, record: record, expires: backend.now + Self.timeout)
        try await publishHosted(&current)
        return try view(current.identity, current.record)
    }

    private func readRecord(_ id: String) throws -> Record {
        guard let data = try recordData(id) else { throw BlahIdentityError.locked }
        return try decodeRecord(data)
    }

    private func recordData(_ id: String) throws -> Data? {
        return try BlahKeychain.read("identity:" + id) ?? BlahKeychain.read("device-identity:" + id)
    }

    private func writeRecord(_ record: Record, id: String) throws {
        // Older apps enumerate identity: and require a sealed root in every record.
        let prefix = record.rootBox == nil ? "device-identity:" : "identity:"
        try BlahKeychain.write(prefix + id, data: JSONEncoder().encode(record))
    }

    private func decodeRecord(_ data: Data) throws -> Record {
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
        try checkActive()
        var record = record
        record.profile = Data(identity.profile.encoding)
        try writeRecord(record, id: identity.id.description)
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
            let recovery = Recovery(version: 1, secret: Data(secret), profile: record.profile,
                homeDomain: record.homeDomain, home: record.home, hostingDomain: record.hostingDomain)
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
        let host = ProfileHostingClient(domain: try DomainName(domain), http: BlahHostingHTTPClient(detectUnsupportedHosting: true))
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
            let shouldRenew = current.identity.identityKey != nil && current.record.autoRenew && isRenewalDue(current.identity.profile)
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
            hostingDomain: record.hostingDomain, publicationPending: record.checkedProfile != Data(identity.profile.encoding),
            canManageIdentity: identity.identityKey != nil)
    }

    private func checkActive() throws {
        try Task.checkCancellation()
        guard !shouldLock else { throw BlahIdentityError.locked }
    }

    private func begin() throws {
        try checkActive()
        guard !isBusy else { throw BlahIdentityError.locked }
        isBusy = true
    }
    private func finish() {
        isBusy = false
        if shouldLock { shouldLock = false; lock() }
    }
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahDomainProbe: Sendable {
    case available(domain: String)
    case existing(domain: String, id: String, sameHome: Bool)
    case saved(id: String)
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahPublication: Sendable {
    case published
    case manual(profile: Data, url: String)
}

@available(iOS 18.0, macOS 15.0, *)
public struct BlahMintResult: Sendable {
    public let id: String
    public let publication: BlahPublication
}

@available(iOS 18.0, macOS 15.0, *)
extension BlahIdentityStore {
    public func discoverHome(_ input: String) async throws -> BlahHome {
        return try await BlahHome.discover(input, previous: nil)
    }

    public func boundIdentityID(slot: String) throws -> String? {
        guard let data = try restoreKeychain.read("binding-v2:" + slot) else { return nil }
        return try JSONDecoder().decode(Binding.self, from: data).identityID
    }

    /// A routing check only; connect/bind still verify the signed DC and namespace.
    public func canUseSlot(slot: String, homeDomain: String, identityID: String?) throws -> Bool {
        let domain = try BlahProfileHost.homeDomain(homeDomain).name
        let home = try home(slot: slot)
        if let home, home.domain != domain { return false }
        if let bound = try boundIdentityID(slot: slot) { return home != nil && bound == identityID }
        // An older binding without its identity metadata cannot safely be reused.
        return try restoreKeychain.read("binding:" + slot) == nil
    }

    public func savedIdentityID(domain: String) throws -> String? {
        let name = try BlahProfileHost.domain(domain)
        for entry in try list() {
            let profile = try AnyBlahProfile(encoding: Array(readRecord(entry.id).profile))
            if profile.domains.contains(name) { return entry.id }
        }
        return nil
    }

    public func setHomeDomain(id: String, home: BlahHome) throws {
        try begin(); defer { finish() }
        var record = try readRecord(id)
        let profile = try AnyBlahProfile(encoding: Array(record.profile))
        try rememberHome(home, profile: profile, record: &record)
        try writeRecord(record, id: id)
        for (slot, var current) in sessions where current.identity.id.description == id {
            current.record = record
            sessions[slot] = current
        }
        if record.sync, let data = try BlahKeychain.read("recovery:" + id, sync: true) {
            var recovery = try JSONDecoder().decode(Recovery.self, from: data)
            recovery.homeDomain = home.domain
            recovery.home = home
            try BlahKeychain.write("recovery:" + id, data: JSONEncoder().encode(recovery), sync: true)
        }
    }

    private func rememberHome(_ home: BlahHome, profile: AnyBlahProfile, record: inout Record) throws {
        let dc = try DCProfile(encoding: Array(home.profile))
        guard dc.serves(home.domain), dc.namespaceGeneration != nil, profile.home?.dc == dc.id else {
            throw BlahIdentityError.wrongHome
        }
        if let previous = record.home {
            let before = try DCProfile(encoding: Array(previous.profile))
            guard previous.domain == home.domain, before.namespaceGeneration == dc.namespaceGeneration else {
                throw BlahIdentityError.wrongHome
            }
            try BlahProfileHost.requireMonotonic(dc, after: before)
        }
        record.homeDomain = home.domain
        record.home = home
    }

    public func probe(domain: String, home: BlahHome) async throws -> BlahDomainProbe {
        let name = try BlahProfileHost.domain(domain)
        let (dc, _) = try await home.verified()
        if let id = try savedIdentityID(domain: name.name) { return .saved(id: id) }
        let response: HostingHTTPResponse
        do {
            response = try await BlahHostingHTTPClient(serverErrorsAreUnavailable: true).send(HostingHTTPRequest(method: .get,
                url: "https://\(name.name)/.well-known/blah/profile.cbor", headers: ["Accept": "application/cbor"]))
        } catch let error as URLError where error.code == .cannotFindHost {
            return .available(domain: name.name)
        }
        if response.status == 404 { return .available(domain: name.name) }
        guard response.status == 200 else { throw BlahIdentityError.profileUnavailable }
        guard (try? CBOR(decoding: response.body)) != nil else { return .available(domain: name.name) }
        // A CBOR profile-shaped object with broken authority must never invite replacement.
        let profile: AnyBlahProfile
        do {
            profile = try AnyBlahProfile(encoding: response.body)
            try requireAccount(profile)
            try await profile.verify(using: backend)
            guard profile.domains.contains(name), profile.home?.isActive(at: backend.now) == true else {
                throw BlahIdentityError.invalidProfile
            }
        } catch { throw BlahIdentityError.profileVerificationFailed }
        if try recordData(profile.id.description) != nil {
            return .saved(id: profile.id.description)
        }
        return .existing(domain: name.name, id: profile.id.description, sameHome: profile.home?.dc == dc.id)
    }

    public func mint(domain: String, home: BlahHome, biometrics: Bool, sync: Bool) async throws -> BlahMintResult {
        try begin(); defer { finish() }
        let name = try BlahProfileHost.domain(domain)
        guard case .available = try await probe(domain: name.name, home: home) else { throw BlahIdentityError.duplicate }
        let (dc, _) = try await home.verified()
        let host = try await availableHosting(for: name)
        let root = try await IdentityPrivateKey(backend.makePrivateKey(.ed25519, for: .identity))
        let device = try makeDevice()
        let user = HostedContent(home: Home(dc: dc.id, epoch: 1, expiresAt: backend.now + 180 * Self.day), domains: [name])
        let identity = try await BasicIdentity<AnyBlahProfile>(.user(user), identityKey: root, deviceKey: device.key,
            profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        var record = try await makeRecord(identity: identity, deviceReference: device.reference, biometrics: biometrics, sync: sync)
        try rememberHome(home, profile: identity.profile, record: &record)
        record.hostingDomain = host
        try await save(identity: identity, record: record)
        var current = Session(identity: identity, record: record, expires: backend.now + Self.timeout)
        let publication = try await publication(&current)
        return BlahMintResult(id: identity.id.description, publication: publication)
    }

    public func confirmPublication(id: String) async throws {
        try begin(); defer { finish() }
        var record = try readRecord(id)
        let profile = try AnyBlahProfile(encoding: Array(record.profile))
        try await profile.verify(using: backend)
        try await requirePublication(profile)
        try checkActive()
        record.publishedProfile = record.profile
        record.checkedProfile = record.profile
        try writeRecord(record, id: id)
        for (slot, var current) in sessions where current.identity.id.description == id {
            current.record = record
            sessions[slot] = current
        }
    }

    private func availableHosting(for domain: DomainName) async throws -> String? {
        let labels = domain.name.split(separator: ".", maxSplits: 1)
        guard labels.count == 2, let host = DomainName(normalizing: String(labels[1])) else { return nil }
        let client = ProfileHostingClient(domain: host, http: BlahHostingHTTPClient(detectUnsupportedHosting: true))
        do {
            _ = try await client.policy()
        } catch {
            if hostingUnavailable(error, policy: true) { return nil }
            throw error
        }
        do {
            switch try await client.name(String(labels[0])).status {
            case .available: return host.name
            case .claimed: throw ProfileHostingError.nameTaken(String(labels[0]))
            case .invalid: throw ProfileHostingError.invalidLabel(String(labels[0]))
            }
        } catch {
            if hostingUnavailable(error) { return nil }
            throw error
        }
    }

    private func hostingUnavailable(_ error: Error, policy: Bool = false) -> Bool {
        if let error = error as? URLError {
            return [.cannotFindHost, .cannotConnectToHost, .dnsLookupFailed, .timedOut,
                .networkConnectionLost, .notConnectedToInternet, .secureConnectionFailed,
                .serverCertificateHasBadDate, .serverCertificateUntrusted, .serverCertificateHasUnknownRoot,
                .serverCertificateNotYetValid, .clientCertificateRejected, .clientCertificateRequired].contains(error.code)
        }
        guard let error = error as? ProfileHostingError else { return false }
        switch error {
        case let .unexpectedStatus(status): return [404, 405, 501].contains(status)
        case .invalidResponse, .domainMismatch, .unsupportedAlgorithm: return policy
        default: return false
        }
    }

    private func publication(_ current: inout Session) async throws -> BlahPublication {
        if current.record.hostingDomain != nil {
            do {
                try await publishHosted(&current)
                try await requirePublication(current.identity.profile)
                current.record.checkedProfile = Data(current.identity.profile.encoding)
                try await persist(&current)
                return .published
            } catch {
                // A failed read-back after an accepted PUT is an error, not unavailable hosting.
                guard current.record.publishedProfile != Data(current.identity.profile.encoding), hostingUnavailable(error) else { throw error }
            }
        }
        return .manual(profile: Data(current.identity.profile.encoding),
            url: "https://\(current.identity.profile.domains[0].name)/.well-known/blah/profile.cbor")
    }
}

@available(iOS 18.0, macOS 15.0, *)
public struct BlahDeviceLinkRequestData: Sendable {
    public let id: UUID
    public let request: Data
    public let parameter: String
}

@available(iOS 18.0, macOS 15.0, *)
public struct BlahDeviceLinkPreparation: Sendable {
    public let profile: Data
    public let publication: BlahPublication
}

@available(iOS 18.0, macOS 15.0, *)
extension BlahIdentityStore {
    public func beginDeviceLink(id: UUID = UUID(), slot: String, label: String, expectedDomain: String?) async throws -> BlahDeviceLinkRequestData {
        try begin(); defer { finish() }
        guard let home = try self.home(slot: slot) else { throw BlahIdentityError.wrongHome }
        _ = try await home.verified()
        let generation = linkGeneration
        deviceLinks = deviceLinks.filter { $0.value.expires > backend.now && $0.value.slot != slot }
        let device = try makeDevice()
        let recipient = try EncryptionPrivateKey.secureEnclave(accessControl: accessControl(biometrics: false))
        // Advertise only the algorithms supported by this device’s crypto backend.
        var verifies: [PublicKey.Algorithm] = [.ed25519, .p256]
        if #available(iOS 26.0, macOS 26.0, *) { verifies.append(.mlDSA65) }
        let request = try DeviceLinkRequest(device: device.key.publicKey, recipient: recipient.key.publicKey,
            label: label, verifies: verifies)
        let code = try DeviceLinkCode(request: request, using: backend)
        try checkActive()
        guard generation == linkGeneration else { throw BlahIdentityError.locked }
        deviceLinks[id] = PendingDeviceLink(generation: generation, slot: slot, home: home,
            expectedDomain: try expectedDomain.map { try BlahProfileHost.domain($0) }, request: request, code: code,
            device: device.key, deviceReference: device.reference, recipient: recipient.key,
            encryptionReference: recipient.reference, expires: backend.now + 600)
        return BlahDeviceLinkRequestData(id: id, request: Data(request.encoding), parameter: code.parameter)
    }

    public func cancelDeviceLink(id: UUID) {
        deviceLinks.removeValue(forKey: id)
        if let installed = installedDeviceLinks.removeValue(forKey: id),
            sessions[installed.slot]?.identity.deviceKey.publicKey.id == installed.device {
            sessions.removeValue(forKey: installed.slot)
            renewalTasks.removeValue(forKey: installed.slot)?.cancel()
        }
    }

    public func finishDeviceLink(id: UUID) {
        deviceLinks.removeValue(forKey: id)
        installedDeviceLinks.removeValue(forKey: id)
    }

    public func installDeviceLink(id: UUID, request: Data, response: Data) async throws -> String {
        try begin(); defer { finish() }
        guard let pending = deviceLinks[id], pending.expires > backend.now,
            pending.generation == linkGeneration, request == Data(pending.request.encoding) else { throw BlahIdentityError.locked }
        let (dc, content) = try await pending.home.verified()
        guard let currentHome = try home(slot: pending.slot), currentHome.domain == pending.home.domain,
            let namespaceGeneration = content.namespaceGeneration else { throw BlahIdentityError.wrongHome }
        let (currentDC, _) = try await currentHome.verified()
        try BlahProfileHost.requireMonotonic(currentDC, after: dc)
        let opened = try await DeviceLinkResponse.open(Array(response), recipientKey: pending.recipient,
            request: pending.request, code: pending.code, expectedDC: dc.id, using: backend)
        try await opened.grant.verify(for: pending.request, expectedDC: dc.id, using: backend)
        if let expected = pending.expectedDomain {
            guard opened.profile.domains.contains(expected) else { throw BlahIdentityError.wrongHome }
        }
        let identity = try await BasicIdentity<AnyBlahProfile>(profile: opened.profile, deviceKey: pending.device,
            identityKey: opened.identityKey, profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        let namespace = try ClientNamespace(profile: opened.profile,
            dc: DCAddress(domain: DomainName(pending.home.domain), id: dc.id), generation: namespaceGeneration)
        if let binding = try restoreKeychain.read("binding:" + pending.slot), binding != Data(namespace.identifier.utf8) {
            throw BlahIdentityError.wrongHome
        }
        guard try recordData(identity.id.description) == nil else { throw BlahIdentityError.duplicate }
        try await requirePublication(opened.profile)
        var record = Record(profile: Data(opened.grant.profile), rootBox: opened.grant.identityKey.map { Data($0.encoding) },
            encryptionReference: pending.encryptionReference, deviceReference: pending.deviceReference,
            biometrics: false, sync: false, autoRenew: opened.identityKey != nil,
            homeDomain: pending.home.domain, home: currentHome,
            publishedProfile: Data(opened.grant.profile), checkedProfile: Data(opened.grant.profile))
        if let metadata = opened.grant.metadata {
            let fields = try CBOR(decoding: metadata).recordValue(requiredKeys: 0..<0)
            if let hosting = fields[7] {
                let host = try hosting.recordValue(requiredKeys: 0..<3)[0]!.textValue()
                let client = ProfileHostingClient(domain: try DomainName(host), http: BlahHostingHTTPClient())
                guard !client.labels(in: opened.profile).isEmpty else { throw BlahIdentityError.invalidProfile }
                record.hostingDomain = host
            }
        }
        try checkActive()
        guard deviceLinks[id] != nil, pending.generation == linkGeneration else { throw BlahIdentityError.locked }
        try await save(identity: identity, record: record)
        setSession(pending.slot, identity: identity, record: record)
        installedDeviceLinks[id] = (pending.slot, identity.deviceKey.publicKey.id, identity.id.description)
        deviceLinks.removeValue(forKey: id)
        return identity.id.description
    }

    public func prepareDeviceLinkApproval(slot: String, id: String, account: Int64, request: Data) async throws -> BlahDeviceLinkPreparation {
        try begin(); defer { finish() }
        var current = try session(slot)
        try requireApprover(current, slot: slot, id: id, account: account)
        let request = try DeviceLinkRequest(encoding: Array(request))
        try request.requireCompatible(identityKey: current.identity.profile.identityKey, device: current.identity.deviceKey.publicKey)
        if !current.identity.profile.devices.contains(where: { $0.device == request.device && $0.validity.contains(backend.now) }) {
            try await publishHosted(&current)
            try await current.identity.add(request.device)
            try await persist(&current)
        }
        let result = try await publication(&current)
        return BlahDeviceLinkPreparation(profile: Data(current.identity.profile.encoding), publication: result)
    }

    public func sealDeviceLinkApproval(slot: String, id: String, account: Int64, request: Data, parameter: String,
        profile: Data, transferIdentity: Bool) async throws -> Data {
        try begin(); defer { finish() }
        var current = try session(slot)
        try requireApprover(current, slot: slot, id: id, account: account)
        guard profile == Data(current.identity.profile.encoding) else { throw BlahIdentityError.staleProfile }
        let request = try DeviceLinkRequest(encoding: Array(request))
        let code = try DeviceLinkCode(parameter: parameter)
        guard code.matches(request.encoding) else { throw BlahIdentityError.invalidProfile }
        try await requirePublication(current.identity.profile)
        current.record.publishedProfile = profile
        current.record.checkedProfile = profile
        try await persist(&current)
        let sealed: SealedIdentityKey?
        var metadata: [UInt64: CBOR] = [:]
        if transferIdentity {
            guard let root = current.identity.identityKey else { throw BlahIdentityError.managementRequired }
            sealed = try await root.sealed(to: request.recipient, using: backend)
            if let host = current.record.hostingDomain {
                let client = ProfileHostingClient(domain: try DomainName(host), http: BlahHostingHTTPClient())
                metadata[7] = .record([0: .text(host), 1: .array(client.labels(in: current.identity.profile).map(CBOR.text)), 2: .array([])])
            }
        } else { sealed = nil }
        let grant = try DeviceLinkGrant(profile: current.identity.profile, domain: current.identity.profile.domains[0],
            identityKey: sealed, metadata: transferIdentity ? CBOR.record(metadata).encoded : nil)
        let response = try await DeviceLinkResponse.seal(grant, for: request, code: code, using: backend)
        try checkActive()
        return Data(response)
    }

    private func requireApprover(_ current: Session, slot: String, id: String, account: Int64) throws {
        guard try boundIdentityID(slot: slot) == id, current.identity.id.description == id,
            case .user = current.identity.profile, current.identity.profile.home?.account == account else {
            throw BlahIdentityError.wrongHome
        }
        guard current.identity.identityKey != nil else { throw BlahIdentityError.managementRequired }
    }
}

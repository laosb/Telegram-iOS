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
public struct BlahPendingPublication: Sendable {
    public let id: String
    public let hostingDomain: String?
    public let profile: Data
    public let url: String
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
    private var removedSlots = Set<String>()
    private var mutationGeneration: UInt64 = 0
    private var activeGeneration: UInt64 = 0
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

    private struct Record: Codable {
        let slot: String
        var profile: Data
        var seedBox: Data?
        var encryptionReference: Data
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
        var refreshedProfile: Data?
    }
    private struct Recovery: Codable {
        let version: Int
        let entropy: Data
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
        var seed: IdentitySeed?
    }

    init(accessGroup: String, isAppExtension: Bool) {
        restoreKeychain = BlahRestoreKeychain(accessGroup: accessGroup, isAppExtension: isAppExtension)
    }

    /// Legacy raw-root custody is deliberately not migrated.
    public func discardLegacyCustody() throws {
        let localKeys = try BlahKeychain.keys()
        let legacyKeys = localKeys.filter { $0.hasPrefix("identity:") || $0.hasPrefix("device-identity:") }
        let legacyIDs = Set(legacyKeys.compactMap { $0.split(separator: ":", maxSplits: 1).last.map(String.init) })
        let restoreKeys = try restoreKeychain.keys()
        func metadata(_ key: String) throws -> Data? {
            return try restoreKeychain.read(key) ?? BlahKeychain.read(key)
        }
        var slots = Set(restoreKeys.filter { $0.hasPrefix("legacy-logout:") }.map { String($0.dropFirst("legacy-logout:".count)) })
        for key in restoreKeys {
            let prefix: String
            if key.hasPrefix("binding-v2:") { prefix = "binding-v2:" }
            else if key.hasPrefix("binding:") { prefix = "binding:" }
            else { continue }
            let slot = String(key.dropFirst(prefix.count))
            if prefix == "binding-v2:", let data = try metadata(key),
                let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                let id = fields["identityID"] as? String, legacyIDs.contains(id) {
                slots.insert(slot)
            } else if prefix == "binding:", let namespace = try metadata(key), let data = try metadata("home:" + slot) {
                let home = try JSONDecoder().decode(BlahHome.self, from: data)
                let dc = try DCProfile(encoding: Array(home.profile))
                if let generation = dc.namespaceGeneration {
                    for legacyKey in legacyKeys {
                        guard let data = try BlahKeychain.read(legacyKey),
                            let fields = try JSONSerialization.jsonObject(with: data) as? [String: Any],
                            let encoded = fields["profile"] as? String, let bytes = Data(base64Encoded: encoded) else { continue }
                        let profile = try AnyBlahProfile(encoding: Array(bytes))
                        guard let candidate = try? ClientNamespace(profile: profile,
                            dc: DCAddress(domain: DomainName(home.domain), id: dc.id), generation: generation) else { continue }
                        if namespace == Data(candidate.identifier.utf8) { slots.insert(slot); break }
                    }
                }
            }
        }
        // Persist the logout obligation before deleting the metadata that identifies its slot.
        for slot in slots { try restoreKeychain.write("legacy-logout:" + slot, data: Data()) }
        for slot in slots { try invalidate(slot: slot) }
        for key in legacyKeys {
            try BlahKeychain.remove(key)
        }
        for key in try BlahKeychain.keys(sync: true) where key.hasPrefix("recovery:") {
            try BlahKeychain.remove(key, sync: true)
        }
    }

    public func pendingLegacyLogouts() throws -> [String] {
        return try restoreKeychain.keys().filter { $0.hasPrefix("legacy-logout:") }
            .map { String($0.dropFirst("legacy-logout:".count)) }.sorted()
    }

    public func acknowledgeLegacyLogout(slot: String) throws {
        try restoreKeychain.remove("legacy-logout:" + slot)
    }

    public func cloudIdentities() throws -> [BlahIdentitySummary] {
        return try BlahKeychain.keys(sync: true).filter { $0.hasPrefix("seed-recovery:") }.compactMap { key in
            guard let data = try BlahKeychain.read(key, sync: true) else { return nil }
            let recovery = try JSONDecoder().decode(Recovery.self, from: data)
            guard recovery.version == 2 else { return nil }
            let profile = try AnyBlahProfile(encoding: Array(recovery.profile))
            try requireAccount(profile)
            return BlahIdentitySummary(id: profile.id.description, domain: profile.domains[0].name, homeDomain: recovery.homeDomain)
        }.sorted { $0.domain < $1.domain }
    }

    public func identity(slot: String) throws -> BlahIdentitySummary? {
        guard let data = try recordData(slot) else { return nil }
        let record = try decodeRecord(data)
        let profile = try AnyBlahProfile(encoding: Array(record.profile))
        try requireAccount(profile)
        return BlahIdentitySummary(id: profile.id.description, domain: profile.domains[0].name, homeDomain: record.homeDomain)
    }

    public func isHolder(slot: String) throws -> Bool {
        return try recordData(slot).map { try decodeRecord($0).seedBox != nil } ?? false
    }

    public func home(slot: String) throws -> BlahHome? {
        guard let data = try restoreKeychain.read("home:" + slot) else { return nil }
        return try JSONDecoder().decode(BlahHome.self, from: data)
    }

    public func connect(domain: String, slot: String) async throws -> BlahHome {
        try begin(); defer { finish() }
        guard try restoreKeychain.read("removed-slot:" + slot) == nil else { throw BlahIdentityError.locked }
        let home = try await BlahHome.discover(domain, previous: self.home(slot: slot))
        try checkActive()
        try restoreKeychain.write("home:" + slot, data: JSONEncoder().encode(home))
        removedSlots.remove(slot)
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
        try removeSlot(slot)
    }

    /// The caller must own an unused authorization; its transport keeps the same home.
    public func restartAuthorization(slot: String) async throws -> BlahHome {
        try begin(); defer { finish() }
        guard let saved = try home(slot: slot) else { throw BlahIdentityError.wrongHome }
        let home = try await BlahHome.discover(saved.domain, previous: saved)
        try checkActive()
        try restoreKeychain.write("home:" + slot, data: JSONEncoder().encode(home))
        try invalidate(slot: slot)
        for prefix in ["binding:", "binding-v2:"] {
            try restoreKeychain.remove(prefix + slot)
        }
        try restoreKeychain.remove("removed-slot:" + slot)
        removedSlots.remove(slot)
        return home
    }

    /// Retain only public routing metadata for a bounded, ordinary logout request.
    public func invalidate(slot: String) throws {
        removedSlots.insert(slot)
        mutationGeneration &+= 1
        sessions.removeValue(forKey: slot)
        renewalTasks.removeValue(forKey: slot)?.cancel()
        deviceLinks = deviceLinks.filter { $0.value.slot != slot }
        installedDeviceLinks = installedDeviceLinks.filter { $0.value.slot != slot }
        if try BlahKeychain.read("slot-seed:" + slot) == nil,
            try restoreKeychain.read("home:" + slot) == nil,
            try restoreKeychain.read("binding:" + slot) == nil,
            try restoreKeychain.read("binding-v2:" + slot) == nil { return }
        try restoreKeychain.write("removed-slot:" + slot, data: Data())
        try BlahKeychain.remove("slot-seed:" + slot)
    }

    private func removeSlot(_ slot: String) throws {
        try invalidate(slot: slot)
        for prefix in ["home:", "binding:", "binding-v2:"] {
            try restoreKeychain.remove(prefix + slot)
        }
        try restoreKeychain.remove("removed-slot:" + slot)
    }

    public func unlock(slot: String) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        let record = try readRecord(slot)
        if var current = sessions[slot] {
            try await reconcile(&current, required: false)
            return try view(current.identity, current.record)
        }
        let seed: IdentitySeed?
        if let box = record.seedBox {
            let recipient = try EncryptionPrivateKey(secureEnclaveReference: record.encryptionReference)
            seed = try await SealedIdentitySeed(encoding: Array(box)).open(with: recipient, using: backend)
        } else { seed = nil }
        let saved = try AnyBlahProfile(encoding: Array(record.profile))
        let root = try await seed?.identityKey(matching: saved.identityKey, using: backend)
        let device = try DevicePrivateKey(PrivateKey(secureEnclaveReference: record.deviceReference, for: .device))
        let identity = try await BasicIdentity<AnyBlahProfile>(profile: saved, deviceKey: device, identityKey: root,
            profileLifetime: record.profileDays * Self.day, deviceLifetime: record.deviceDays * Self.day, using: backend)
        try requireAccount(identity.profile)
        try setSession(slot, identity: identity, record: record, seed: seed)
        var current = try session(slot)
        try await reconcile(&current, required: false)
        // A failed PUT retains custody and the exact signed revision for an explicit retry.
        // Never create a new revision until the preceding hosted publication is acknowledged.
        do {
            let shouldRenew = current.identity.identityKey != nil && record.autoRenew && isRenewalDue(current.identity.profile)
            try await publishHosted(&current, allowExpired: shouldRenew)
            if shouldRenew {
                try await reconcile(&current)
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
        _ = try await unlock(slot: slot)
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
    public func validateRestoredBinding(slot: String, required: Bool = true, allowRemoved: Bool = false) async throws {
        guard let data = try restoreKeychain.read("binding-v2:" + slot) else {
            if !required, try restoreKeychain.read("binding:" + slot) == nil { return }
            throw BlahIdentityError.wrongHome
        }
        guard let home = try self.home(slot: slot) else {
            throw BlahIdentityError.wrongHome
        }
        var binding = try JSONDecoder().decode(Binding.self, from: data)
        let encoding: Data
        let removed = try restoreKeychain.read("removed-slot:" + slot) != nil
        if restoreKeychain.isAppExtension || (allowRemoved && removed) {
            guard let snapshot = binding.profile else { throw BlahIdentityError.wrongHome }
            encoding = snapshot
        } else {
            encoding = try readRecord(slot).profile
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
            try readRecord(slot).profile == encoding {
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
        _ = try await unlock(slot: slot)
        try begin(); defer { finish() }
        var current = try session(slot)
        try await reconcile(&current)
        try requireAccount(current.identity.profile)
        try await current.identity.profile.verify(using: backend)
        guard let selectedHome = try self.home(slot: slot), let home = current.identity.profile.home,
            home.isActive(at: backend.now), home.account == nil || home.account == account else { throw BlahIdentityError.wrongHome }
        let (dc, _) = try await selectedHome.verified()
        guard home.dc == dc.id else { throw BlahIdentityError.wrongHome }
        if home.account == nil {
            guard case .user(var user) = current.identity.profile.content else { throw BlahIdentityError.invalidProfile }
            user.home?.account = account
            try await current.identity.update(.user(user))
            try await persist(&current)
        }
        // Publication runs after login, outside auth.sendCode's request timeout.
        try checkActive()
    }

    public enum Change: Sendable {
        case renew
        case domains([DomainName])
        case renewal(profileDays: UInt64, deviceDays: UInt64, automatic: Bool)
        case sync(Bool)
        case biometrics(Bool)
    }

    public func change(slot: String, change: Change) async throws -> BlahIdentityView {
        _ = try await unlock(slot: slot)
        try begin(); defer { finish() }
        var current = try session(slot)
        guard current.identity.identityKey != nil else { throw BlahIdentityError.managementRequired }
        let publishes: Bool
        switch change {
        case .renew:
            publishes = true
            try await reconcile(&current)
            try await publishHosted(&current, allowExpired: true)
        case .domains:
            publishes = true
            try await reconcile(&current)
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
                !domains.contains(where: { $0.name == host || ($0.name.hasSuffix("." + host) && !$0.name.dropLast(host.count + 1).contains(".")) }) {
                throw BlahIdentityError.invalidProfile
            }
            try await current.identity.update(current.identity.profile.content.replacingDomains(domains))
        case let .renewal(profileDays, deviceDays, automatic):
            guard profileDays > 0, deviceDays >= profileDays, deviceDays < 36500 else { throw BlahIdentityError.invalidProfile }
            current.record.profileDays = profileDays; current.record.deviceDays = deviceDays; current.record.autoRenew = automatic
            current.identity = try await BasicIdentity<AnyBlahProfile>(profile: current.identity.profile, deviceKey: current.identity.deviceKey,
                identityKey: current.identity.identityKey, profileLifetime: profileDays * Self.day,
                deviceLifetime: deviceDays * Self.day, using: backend)
        case let .sync(enabled):
            current.record.sync = enabled
            if !enabled { try BlahKeychain.remove("seed-recovery:" + current.identity.id.description, sync: true) }
        case let .biometrics(enabled):
            let record = try await makeRecord(slot: slot, seed: current.seed!, identity: current.identity, deviceReference: current.record.deviceReference,
                biometrics: enabled, sync: current.record.sync)
            current.record = Record(slot: slot, profile: record.profile, seedBox: record.seedBox,
                encryptionReference: record.encryptionReference, deviceReference: record.deviceReference,
                biometrics: enabled, sync: record.sync, profileDays: current.record.profileDays,
                deviceDays: current.record.deviceDays, autoRenew: current.record.autoRenew,
                homeDomain: current.record.homeDomain, home: current.record.home,
                hostingDomain: current.record.hostingDomain, publishedProfile: current.record.publishedProfile,
                checkedProfile: current.record.checkedProfile, refreshedProfile: current.record.refreshedProfile)
        }
        try await persist(&current)
        if publishes { try await publishHosted(&current) }
        return try view(current.identity, current.record)
    }

    public func checkPublication(slot: String) async throws {
        _ = try await unlock(slot: slot)
        try begin(); defer { finish() }
        var current = try session(slot)
        try await requirePublication(current.identity.profile)
        current.record.publishedProfile = Data(current.identity.profile.encoding)
        current.record.checkedProfile = current.record.publishedProfile
        try await persist(&current)
    }

    public func publish(slot: String) async throws {
        _ = try await unlock(slot: slot)
        try begin(); defer { finish() }
        var current = try session(slot)
        try await publishHosted(&current)
        try await requirePublication(current.identity.profile)
        current.record.publishedProfile = Data(current.identity.profile.encoding)
        current.record.checkedProfile = current.record.publishedProfile
        try await persist(&current)
    }

    public func restoreCloud(id: String, slot: String, biometrics: Bool) async throws -> BlahIdentityView {
        guard let data = try BlahKeychain.read("seed-recovery:" + id, sync: true) else { throw BlahIdentityError.invalidProfile }
        let recovery = try JSONDecoder().decode(Recovery.self, from: data)
        guard recovery.version == 2 else { throw BlahIdentityError.invalidProfile }
        let saved = try AnyBlahProfile(encoding: Array(recovery.profile))
        try requireAccount(saved)
        guard saved.id.description == id else { throw BlahIdentityError.invalidProfile }
        return try await restore(seed: IdentitySeed(entropy: Array(recovery.entropy)), domain: saved.domains[0].name,
            slot: slot, biometrics: biometrics, sync: true, hostingDomain: recovery.hostingDomain, previous: saved)
    }

    public func generateWords() throws -> [String] {
        return try IdentitySeed.generate(using: backend).words
    }

    public func restoreWords(_ words: [String], domain: String, slot: String, biometrics: Bool = false) async throws -> BlahIdentityView {
        return try await restore(seed: IdentitySeed(phrase: words.joined(separator: " ")), domain: domain,
            slot: slot, biometrics: biometrics, sync: false)
    }

    private func restore(seed: IdentitySeed, domain: String, slot: String, biometrics: Bool, sync: Bool,
        hostingDomain: String? = nil, previous: AnyBlahProfile? = nil) async throws -> BlahIdentityView {
        try begin(); defer { finish() }
        guard try recordData(slot) == nil, let home = try self.home(slot: slot) else { throw BlahIdentityError.wrongHome }
        let domain = try BlahProfileHost.domain(domain)
        let profile = try AnyBlahProfile(encoding: Array(try await BlahProfileHost.fetch(domain.name)))
        try requireAccount(profile)
        try await profile.verify(using: backend, at: profile.validity.notBefore)
        guard profile.domains.contains(domain) else { throw BlahIdentityError.invalidProfile }
        if let previous { try BlahProfileHost.requireMonotonic(profile, after: previous) }
        let (dc, _) = try await home.verified()
        guard profile.home?.dc == dc.id else { throw BlahIdentityError.wrongHome }
        let root = try await seed.identityKey(matching: profile.identityKey, using: backend)
        let device = try makeDevice()
        var identity = try await BasicIdentity<AnyBlahProfile>.enrolling(device.key, in: profile, identityKey: root,
            profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        try await renew(&identity)
        var record = try await makeRecord(slot: slot, seed: seed, identity: identity, deviceReference: device.reference, biometrics: biometrics, sync: sync)
        try rememberHome(home, profile: identity.profile, record: &record)
        record.publishedProfile = Data(profile.encoding)
        record.hostingDomain = try await hostingDomainForRestoration(profile, preferred: hostingDomain)
        try setSession(slot, identity: identity, record: record, seed: seed)
        try await save(identity: identity, record: record)
        var current = try session(slot)
        _ = try await publication(&current)
        return try view(current.identity, current.record)
    }

    private func hostingDomainForRestoration(_ profile: AnyBlahProfile, preferred: String?) async throws -> String? {
        if let preferred { return preferred }
        let domain = profile.domains[0]
        // Discover capabilities, regardless of profile kind: the domain itself may
        // host its apex, while a parent must explicitly offer child names.
        do {
            let policy = try await ProfileHostingClient(domain: domain, http: BlahHostingHTTPClient()).policy()
            if policy.apex { return domain.name }
        } catch {
            // Own-domain servers may reject hosting probes; only cancellation prevents parent discovery.
            if error is CancellationError || (error as? ProfileHostingError) == .cancelled { throw error }
        }
        let labels = domain.name.split(separator: ".", maxSplits: 1)
        guard labels.count == 2 else { return nil }
        let host = String(labels[1])
        do {
            let policy = try await ProfileHostingClient(domain: DomainName(host), http: BlahHostingHTTPClient()).policy()
            return policy.servesChildNames ? host : nil
        } catch {
            if hostingUnavailable(error, policy: true) { return nil }
            throw error
        }
    }

    public func recoveryWords(slot: String) async throws -> [String] {
        _ = try await unlock(slot: slot)
        guard let seed = try session(slot).seed else { throw BlahIdentityError.managementRequired }
        return seed.words
    }

    public func enterRecoveryWords(_ words: [String], slot: String) async throws -> BlahIdentityView {
        _ = try await unlock(slot: slot)
        try begin(); defer { finish() }
        var current = try session(slot)
        let seed = try IdentitySeed(phrase: words.joined(separator: " "))
        let root = try await seed.identityKey(matching: current.identity.profile.identityKey, using: backend)
        current.record.hostingDomain = try await hostingDomainForRestoration(current.identity.profile, preferred: current.record.hostingDomain)
        current.identity = try await BasicIdentity(profile: current.identity.profile, deviceKey: current.identity.deviceKey,
            identityKey: root, profileLifetime: current.record.profileDays * Self.day,
            deviceLifetime: current.record.deviceDays * Self.day, using: backend)
        let custody = try await makeRecord(slot: slot, seed: seed, identity: current.identity,
            deviceReference: current.record.deviceReference, biometrics: false, sync: false)
        current.record.seedBox = custody.seedBox
        current.record.encryptionReference = custody.encryptionReference
        current.record.biometrics = false
        current.record.autoRenew = true
        current.seed = seed
        try await persist(&current)
        return try view(current.identity, current.record)
    }

    public func removeRecoveryWords(slot: String) async throws -> BlahIdentityView {
        _ = try await unlock(slot: slot)
        try begin(); defer { finish() }
        var current = try session(slot)
        current.identity = try await BasicIdentity(profile: current.identity.profile, deviceKey: current.identity.deviceKey,
            identityKey: nil, profileLifetime: current.record.profileDays * Self.day,
            deviceLifetime: current.record.deviceDays * Self.day, using: backend)
        current.seed = nil
        current.record.seedBox = nil
        current.record.encryptionReference = Data()
        current.record.autoRenew = false
        current.record.biometrics = false
        current.record.sync = false
        try await persist(&current)
        return try view(current.identity, current.record)
    }

    /// Publishes revocation before the caller performs the ordinary session reset.
    public func removeDevices(slot: String, ids: [Data]) async throws {
        _ = try await unlock(slot: slot)
        try begin(); defer { finish() }
        var current = try session(slot)
        guard current.seed != nil else { throw BlahIdentityError.managementRequired }
        try await reconcile(&current)
        try await publishHosted(&current)
        for bytes in ids {
            let id = try BlahDiem.Digest(bytes: Array(bytes))
            if current.identity.profile.device(id) != nil { try await current.identity.remove(id) }
        }
        try await persist(&current)
        _ = try await publication(&current)
        try await requirePublication(current.identity.profile)
    }

    public func pruneDevices(slot: String, retired: [Data]) async throws {
        _ = try await unlock(slot: slot)
        let current = try session(slot)
        guard current.seed != nil else { return }
        let listed = Set(current.identity.profile.devices.map { Data($0.device.id.bytes) })
        let own = Data(current.identity.deviceKey.publicKey.id.bytes)
        let victims = retired.filter { listed.contains($0) && $0 != own }
        if !victims.isEmpty { try await removeDevices(slot: slot, ids: victims) }
    }

    private func readRecord(_ id: String) throws -> Record {
        guard let data = try recordData(id) else { throw BlahIdentityError.locked }
        let record = try decodeRecord(data)
        guard record.slot == id else { throw BlahIdentityError.wrongHome }
        return record
    }

    private func recordData(_ id: String) throws -> Data? {
        guard !removedSlots.contains(id), try restoreKeychain.read("removed-slot:" + id) == nil else { throw BlahIdentityError.locked }
        return try BlahKeychain.read("slot-seed:" + id)
    }

    private func writeRecord(_ record: Record, id: String) throws {
        try checkActive()
        guard !removedSlots.contains(record.slot), record.slot == id else { throw BlahIdentityError.locked }
        try BlahKeychain.write("slot-seed:" + id, data: JSONEncoder().encode(record))
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

    private func makeRecord(slot: String, seed: IdentitySeed, identity: BasicIdentity<AnyBlahProfile>, deviceReference: Data, biometrics: Bool, sync: Bool) async throws -> Record {
        let recipient = try EncryptionPrivateKey.secureEnclave(accessControl: accessControl(biometrics: biometrics))
        let sealed = try await seed.sealed(to: recipient.key.publicKey, identity: identity.profile.identityKey, using: backend)
        return Record(slot: slot, profile: Data(identity.profile.encoding), seedBox: Data(sealed.encoding),
            encryptionReference: recipient.reference, deviceReference: deviceReference, biometrics: biometrics, sync: sync)
    }

    private func save(identity: BasicIdentity<AnyBlahProfile>, record: Record) async throws {
        try checkActive()
        var record = record
        record.profile = Data(identity.profile.encoding)
        guard !removedSlots.contains(record.slot) else { throw BlahIdentityError.locked }
        try writeRecord(record, id: record.slot)
        if var current = sessions[record.slot] {
            current.identity = identity
            current.record = record
            sessions[record.slot] = current
        }
        let key = "binding-v2:" + record.slot
        if let data = try restoreKeychain.read(key) {
            var binding = try JSONDecoder().decode(Binding.self, from: data)
            guard binding.identityID == identity.id.description else { throw BlahIdentityError.wrongHome }
            binding.profile = record.profile
            try restoreKeychain.write(key, data: JSONEncoder().encode(binding))
        }
        if record.sync, let seed = sessions[record.slot]?.seed {
            let recovery = Recovery(version: 2, entropy: Data(seed.entropy), profile: record.profile,
                homeDomain: record.homeDomain, home: record.home, hostingDomain: record.hostingDomain)
            try BlahKeychain.write("seed-recovery:" + identity.id.description, data: JSONEncoder().encode(recovery), sync: true)
        }
    }

    private func persist(_ current: inout Session) async throws {
        current.record.profile = Data(current.identity.profile.encoding)
        try await save(identity: current.identity, record: current.record)
        try checkActive()
        guard !removedSlots.contains(current.record.slot) else { throw BlahIdentityError.locked }
        sessions[current.record.slot] = current
    }

    /// Cache custody, but reconcile public authority before signing a new revision.
    private func reconcile(_ current: inout Session, required: Bool = true) async throws {
        let bytes: Data
        do {
            bytes = try await BlahProfileHost.fetch(current.identity.profile.domains[0].name)
        } catch BlahIdentityError.profileUnavailable {
            if required { throw BlahIdentityError.profileUnavailable }
            return
        }
        try checkActive()
        let profile = try AnyBlahProfile(encoding: Array(bytes))
        try requireAccount(profile)
        try await profile.verify(using: backend, at: profile.validity.notBefore)
        guard profile.id == current.identity.id else { throw BlahIdentityError.invalidProfile }
        let local = current.identity.profile
        if profile.digest == local.digest {
            if current.record.publishedProfile != bytes {
                current.record.publishedProfile = bytes
                try await persist(&current)
            }
            return
        }
        if let published = current.record.publishedProfile, published != Data(local.encoding) {
            // Keep a pending revision only while the public authority is still its baseline.
            if bytes == published { return }
            try BlahProfileHost.requireMonotonic(profile, after: AnyBlahProfile(encoding: Array(published)))
        } else {
            try BlahProfileHost.requireMonotonic(profile, after: local)
        }
        current.identity = try await BasicIdentity(profile: profile, deviceKey: current.identity.deviceKey,
            identityKey: current.identity.identityKey, profileLifetime: current.record.profileDays * Self.day,
            deviceLifetime: current.record.deviceDays * Self.day, using: backend)
        current.record.publishedProfile = bytes
        current.record.checkedProfile = nil
        try await persist(&current)
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

    private func session(_ slot: String) throws -> Session {
        guard !shouldLock, !removedSlots.contains(slot), let current = sessions[slot] else { throw BlahIdentityError.locked }
        return current
    }

    private func setSession(_ slot: String, identity: BasicIdentity<AnyBlahProfile>, record: Record, seed: IdentitySeed?) throws {
        try checkActive()
        guard !removedSlots.contains(slot) else { throw BlahIdentityError.locked }
        sessions[slot] = Session(identity: identity, record: record, seed: seed)
        renewalTasks[slot]?.cancel()
        renewalTasks[slot] = Task { [weak self] in
            while !Task.isCancelled {
                do { try await Task.sleep(nanoseconds: 60_000_000_000) } catch { return }
                await self?.maintain(slot)
            }
        }
    }

    private func maintain(_ slot: String) async {
        guard !isBusy, var current = try? session(slot) else { return }
        isBusy = true; activeGeneration = mutationGeneration; defer { finish() }
        do {
            try await reconcile(&current)
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

    private func publishProfile(_ profile: AnyBlahProfile, hosting: DomainName?) async throws {
        if let hosting {
            let host = ProfileHostingClient(domain: hosting, http: BlahHostingHTTPClient(detectUnsupportedHosting: true))
            try await host.publish(profile, solver: BlahHostingProofOfWork())
        }
        try await requirePublication(profile)
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
        guard !shouldLock, !isBusy || activeGeneration == mutationGeneration else { throw BlahIdentityError.locked }
    }

    private func begin() throws {
        try checkActive()
        guard !isBusy else { throw BlahIdentityError.locked }
        isBusy = true
        activeGeneration = mutationGeneration
    }
    private func finish() {
        isBusy = false
        if shouldLock { shouldLock = false; lock() }
    }
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahDomainProbe: Sendable {
    case available(domain: String)
    case existing
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
    public func boundIdentityID(slot: String) throws -> String? {
        guard let data = try restoreKeychain.read("binding-v2:" + slot) else { return nil }
        return try JSONDecoder().decode(Binding.self, from: data).identityID
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
        _ = try await home.verified()
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
        return .existing
    }

    public func mint(words: [String], domain: String, slot: String, home: BlahHome, biometrics: Bool, sync: Bool) async throws -> BlahMintResult {
        try begin(); defer { finish() }
        let name = try BlahProfileHost.domain(domain)
        guard case .available = try await probe(domain: name.name, home: home) else { throw BlahIdentityError.duplicate }
        let (dc, _) = try await home.verified()
        let host = try await availableHosting(for: name)
        guard try recordData(slot) == nil else { throw BlahIdentityError.duplicate }
        let seed = try IdentitySeed(phrase: words.joined(separator: " "))
        let root = try await seed.identityKey(.ed25519, using: backend)
        let device = try makeDevice()
        let user = HostedContent(home: Home(dc: dc.id, epoch: 1, expiresAt: backend.now + 180 * Self.day), domains: [name])
        let identity = try await BasicIdentity<AnyBlahProfile>(.user(user), identityKey: root, deviceKey: device.key,
            profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        var record = try await makeRecord(slot: slot, seed: seed, identity: identity, deviceReference: device.reference, biometrics: biometrics, sync: sync)
        try rememberHome(home, profile: identity.profile, record: &record)
        record.hostingDomain = host
        try setSession(slot, identity: identity, record: record, seed: seed)
        try await save(identity: identity, record: record)
        var current = try session(slot)
        let publication = try await publication(&current)
        return BlahMintResult(id: identity.id.description, publication: publication)
    }

    public func confirmPublication(slot: String) async throws {
        try await confirmPublication(slot: slot, retryHosted: false)
    }

    /// Reads the saved revision without unlocking the identity's private keys.
    public func pendingPublication(slot: String) async throws -> BlahPendingPublication? {
        guard try recordData(slot) != nil else { return nil }
        return try pendingPublicationForSlot(slot)
    }

    private func pendingPublicationForSlot(_ slot: String) throws -> BlahPendingPublication? {
        let record = try readRecord(slot)
        guard record.checkedProfile != record.profile else { return nil }
        let profile = try AnyBlahProfile(encoding: Array(record.profile))
        try requireAccount(profile)
        guard profile.id.description == (try boundIdentityID(slot: slot) ?? profile.id.description) else { throw BlahIdentityError.invalidProfile }
        return BlahPendingPublication(id: profile.id.description, hostingDomain: record.hostingDomain, profile: record.profile,
            url: "https://\(profile.domains[0].name)/.well-known/blah/profile.cbor")
    }

    public func refreshPending(slot: String) throws -> String? {
        guard let id = try boundIdentityID(slot: slot) else { return nil }
        let record = try readRecord(slot)
        guard record.checkedProfile == record.profile, record.refreshedProfile != record.profile else { return nil }
        let profile = try AnyBlahProfile(encoding: Array(record.profile))
        try requireAccount(profile)
        guard profile.id.description == (try boundIdentityID(slot: slot) ?? profile.id.description) else { throw BlahIdentityError.invalidProfile }
        return profile.home?.account == nil ? nil : id
    }

    public func markRefreshed(slot: String, profile: Data) throws {
        try begin(); defer { finish() }
        var record = try readRecord(slot)
        guard record.profile == profile else { return }
        record.refreshedProfile = profile
        try writeRecord(record, id: slot)
        for (key, var current) in sessions where key == slot {
            current.record.refreshedProfile = profile
            sessions[key] = current
        }
    }

    /// Publishes the already signed revision and verifies every domain, even while locked.
    public func retryPublication(slot: String) async throws {
        try await confirmPublication(slot: slot, retryHosted: true)
    }

    private func confirmPublication(slot: String, retryHosted: Bool) async throws {
        try begin(); defer { finish() }
        var record = try readRecord(slot)
        let profile = try AnyBlahProfile(encoding: Array(record.profile))
        try requireAccount(profile)
        guard profile.id.description == (try boundIdentityID(slot: slot) ?? profile.id.description) else { throw BlahIdentityError.invalidProfile }
        try await profile.verify(using: backend)
        let hosting = try (retryHosted ? record.hostingDomain.map { try DomainName($0) } : nil)
        do {
            try await publishProfile(profile, hosting: hosting)
        } catch let error as ProfileHostingError {
            throw BlahIdentityError.hosting(blahIdentityErrorDescription(error))
        }
        try checkActive()
        record.publishedProfile = record.profile
        record.checkedProfile = record.profile
        try writeRecord(record, id: slot)
        for (key, var current) in sessions where key == slot {
            current.record = record
            sessions[key] = current
        }
    }

    private func availableHosting(for domain: DomainName) async throws -> String? {
        let labels = domain.name.split(separator: ".", maxSplits: 1)
        guard labels.count == 2, let host = DomainName(normalizing: String(labels[1])) else { return nil }
        let client = ProfileHostingClient(domain: host, http: BlahHostingHTTPClient(detectUnsupportedHosting: true))
        do {
            let policy = try await client.policy()
            guard policy.servesChildNames else { return nil }
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
        guard try recordData(slot) == nil else { throw BlahIdentityError.wrongHome }
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
            identityKey: try await opened.seed?.identityKey(matching: opened.profile.identityKey, using: backend), profileLifetime: 180 * Self.day, deviceLifetime: 180 * Self.day, using: backend)
        let namespace = try ClientNamespace(profile: opened.profile,
            dc: DCAddress(domain: DomainName(pending.home.domain), id: dc.id), generation: namespaceGeneration)
        if let binding = try restoreKeychain.read("binding:" + pending.slot), binding != Data(namespace.identifier.utf8) {
            throw BlahIdentityError.wrongHome
        }
        guard try recordData(pending.slot) == nil else { throw BlahIdentityError.duplicate }
        try await requirePublication(opened.profile)
        var record = Record(slot: pending.slot, profile: Data(opened.grant.profile), seedBox: opened.grant.seed.map { Data($0.encoding) },
            encryptionReference: opened.seed == nil ? Data() : pending.encryptionReference, deviceReference: pending.deviceReference,
            biometrics: false, sync: false, autoRenew: opened.seed != nil,
            homeDomain: pending.home.domain, home: currentHome,
            publishedProfile: Data(opened.grant.profile), checkedProfile: Data(opened.grant.profile))
        if let metadata = opened.grant.metadata {
            let fields = try CBOR(decoding: metadata).recordValue(requiredKeys: 0..<0)
            if let hosting = fields[7] {
                let host = try hosting.recordValue(requiredKeys: 0..<3)[0]!.textValue()
                let domain = try DomainName(host)
                let client = ProfileHostingClient(domain: domain, http: BlahHostingHTTPClient())
                guard opened.profile.domains.contains(domain) || !client.labels(in: opened.profile).isEmpty else {
                    throw BlahIdentityError.invalidProfile
                }
                record.hostingDomain = host
            }
        }
        try checkActive()
        guard deviceLinks[id] != nil, pending.generation == linkGeneration else { throw BlahIdentityError.locked }
        try await save(identity: identity, record: record)
        try setSession(pending.slot, identity: identity, record: record, seed: opened.seed)
        installedDeviceLinks[id] = (pending.slot, identity.deviceKey.publicKey.id, identity.id.description)
        deviceLinks.removeValue(forKey: id)
        return identity.id.description
    }

    public func prepareDeviceLinkApproval(slot: String, id: String, account: Int64, request: Data) async throws -> BlahDeviceLinkPreparation {
        _ = try await unlock(slot: slot)
        try begin(); defer { finish() }
        var current = try session(slot)
        try await reconcile(&current)
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
        let sealed: SealedIdentitySeed?
        var metadata: [UInt64: CBOR] = [:]
        if transferIdentity {
            guard let seed = current.seed else { throw BlahIdentityError.managementRequired }
            sealed = try await seed.sealed(to: request.recipient, identity: current.identity.profile.identityKey, using: backend)
            if let host = current.record.hostingDomain {
                let client = ProfileHostingClient(domain: try DomainName(host), http: BlahHostingHTTPClient())
                metadata[7] = .record([0: .text(host), 1: .array(client.labels(in: current.identity.profile).map(CBOR.text)), 2: .array([])])
            }
        } else { sealed = nil }
        let grant = try DeviceLinkGrant(profile: current.identity.profile, domain: current.identity.profile.domains[0],
            seed: sealed, metadata: transferIdentity ? CBOR.record(metadata).encoded : nil)
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

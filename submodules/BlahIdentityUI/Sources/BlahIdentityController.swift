import Foundation
import UIKit
import UniformTypeIdentifiers
import BlahDiem
import BlahIdentity
import Display
import ItemListUI
import SwiftSignalKit
import TelegramCore
import TelegramPresentationData

// This observer survives the settings screen and the authorization sequence.
private let identityBackgroundLock = NotificationCenter.default.addObserver(
    forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
) { _ in Task { await BlahIdentityStore.shared.lock() } }

private struct IdentityRow: ItemListNodeEntry {
    let stableId: Int32
    let section: ItemListSectionId
    let title: String
    var detail: String? = nil
    var value: Bool? = nil
    var isText = false
    var isHeader = false
    var isDestructive = false
    var isEnabled = true
    static func <(lhs: IdentityRow, rhs: IdentityRow) -> Bool { lhs.stableId < rhs.stableId }

    func item(presentationData: ItemListPresentationData, arguments: Any) -> ListViewItem {
        let actions = arguments as! IdentityActions
        if isHeader {
            return ItemListSectionHeaderItem(presentationData: presentationData, text: title, sectionId: section)
        } else if isText {
            return ItemListTextItem(presentationData: presentationData, text: .plain(title), sectionId: section)
        } else if let detail {
            return ItemListDisclosureItem(presentationData: presentationData, systemStyle: .glass,
                title: title, enabled: isEnabled, label: detail, labelStyle: .detailText,
                sectionId: section, style: .blocks, action: { actions.invoke(self.stableId, nil) })
        } else if let value {
            return ItemListSwitchItem(presentationData: presentationData, systemStyle: .glass,
                title: title, value: value, enabled: isEnabled, sectionId: section, style: .blocks,
                updated: { actions.invoke(self.stableId, $0) })
        } else {
            return ItemListActionItem(presentationData: presentationData, systemStyle: .glass,
                title: title, kind: !isEnabled ? .disabled : isDestructive ? .destructive : .generic,
                alignment: .natural, sectionId: section, style: .blocks, action: { actions.invoke(self.stableId, nil) })
        }
    }
}

private final class IdentityActions {
    var invoke: (Int32, Bool?) -> Void = { _, _ in }
}

public func blahIdentityController(network: Network, presentationData: PresentationData,
    signIn: ((String, @escaping (String) -> Void) -> Void)? = nil, cancelSignIn: (() -> Void)? = nil) -> ViewController {
    _ = identityBackgroundLock
    let coordinator = IdentityCoordinator(network: network, presentationData: presentationData, signIn: signIn, cancelSignIn: cancelSignIn)
    let actions = IdentityActions()
    actions.invoke = { [weak coordinator] id, value in coordinator?.invoke(id, value) }
    let signal = coordinator.rows.get() |> map { rows -> (ItemListControllerState, (ItemListNodeState, IdentityActions)) in
        let presentation = ItemListPresentationData(presentationData)
        let state = ItemListControllerState(presentationData: presentation, title: .text(presentationData.strings.blah_Identity_Title),
            leftNavigationButton: nil, rightNavigationButton: nil,
            backNavigationButton: ItemListBackButton(title: presentationData.strings.Common_Back))
        return (state, (ItemListNodeState(presentationData: presentation, entries: rows, style: .blocks, animateChanges: true), actions))
    }
    let controller = ItemListController(presentationData: ItemListPresentationData(presentationData),
        updatedPresentationData: .single(ItemListPresentationData(presentationData)), state: signal, tabBarItem: nil)
    coordinator.controller = controller
    controller.attemptNavigation = { [weak coordinator] _ in
        coordinator?.cancel()
        return true
    }
    controller.didAppear = { [weak coordinator] firstTime in
        if !firstTime { coordinator?.reload() }
    }
    controller.didDisappear = { [coordinator] _ in
        if coordinator.controller?.presentedViewController == nil { coordinator.lockWhenLeaving() }
    }
    coordinator.reload()
    return controller
}

private final class IdentityCoordinator: NSObject, UIDocumentPickerDelegate {
    let rows = ValuePromise<[IdentityRow]>([], ignoreRepeated: true)
    weak var controller: ItemListController?
    private let network: Network
    private let presentationData: PresentationData
    private let signIn: ((String, @escaping (String) -> Void) -> Void)?
    private let cancelSignIn: (() -> Void)?
    private var identity: BlahIdentityView?
    private var actions: [Int32: (Bool?) -> Void] = [:]
    private var isBusy = false
    private var isSigningIn = false
    private var observer: NSObjectProtocol?
    private var task: Task<Void, Never>?
    private var generation = 0
    private var shareURL: URL?
    private var wantsBiometrics = false
    private var wantsSync = false
    private var admissionEmail = ""
    private var needsAdmissionEmail = false
    private var message: String?
    private var contentRows: [IdentityRow] = []
    private var saved: [BlahIdentitySummary] = []
    private var cloud: [BlahIdentitySummary] = []
    private var home: BlahHome?
    private var strings: PresentationStrings { presentationData.strings }
    private var slot: String { network.blahIdentitySlot }

    init(network: Network, presentationData: PresentationData, signIn: ((String, @escaping (String) -> Void) -> Void)?, cancelSignIn: (() -> Void)?) {
        self.network = network; self.presentationData = presentationData; self.signIn = signIn
        self.cancelSignIn = cancelSignIn
        self.message = network.takeBlahIdentityError()
        super.init()
        observer = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main) { [weak self] _ in
            self?.cancel()
            self?.reload()
        }
    }
    deinit {
        task?.cancel()
        if let observer { NotificationCenter.default.removeObserver(observer) }
        if let shareURL { try? FileManager.default.removeItem(at: shareURL.deletingLastPathComponent()) }
        if !isSigningIn { Task { await BlahIdentityStore.shared.lock() } }
    }

    func lockWhenLeaving() {
        guard !isSigningIn else { return }
        cancel()
    }
    func cancel() {
        if isSigningIn { cancelSignIn?() }
        stopWork()
        Task { await BlahIdentityStore.shared.lock() }
    }
    private func stopWork() {
        generation += 1
        task?.cancel()
        task = nil
        isBusy = false
        isSigningIn = false
        clearIdentity()
        refresh()
    }
    func invoke(_ id: Int32, _ value: Bool?) {
        guard !isBusy && !isSigningIn, contentRows.first(where: { $0.stableId == id })?.isEnabled == true else { return }
        actions[id]?(value)
    }

    func reload() {
        run(clearMessage: false) { [self] in
            let saved = try await BlahIdentityStore.shared.list()
            let cloud = try await BlahIdentityStore.shared.cloudIdentities()
            let home = try await BlahIdentityStore.shared.home(slot: slot)
            try Task.checkCancellation()
            await MainActor.run { if !Task.isCancelled { self.render(saved: saved, cloud: cloud, home: home) } }
        }
    }

    private func render(saved: [BlahIdentitySummary], cloud: [BlahIdentitySummary], home: BlahHome?) {
        self.saved = saved; self.cloud = cloud; self.home = home
        var entries: [IdentityRow] = []
        actions = [:]
        func row(_ title: String, section: Int32 = 0, detail: String? = nil, value: Bool? = nil, text: Bool = false,
            header: Bool = false, destructive: Bool = false, enabled: Bool = true, action: @escaping (Bool?) -> Void = { _ in }) {
            // Reserve a stable row beneath the DC for progress and errors.
            let id = Int32(entries.count < 2 ? entries.count : entries.count + 1)
            entries.append(IdentityRow(stableId: id, section: section, title: title, detail: detail, value: value,
                isText: text, isHeader: header, isDestructive: destructive, isEnabled: enabled))
            actions[id] = action
        }
        row(strings.blah_Identity_HomeSection, header: true)
        row(strings.blah_Identity_Home, detail: home?.domain ?? strings.blah_Identity_ChooseDC) { [weak self] _ in
            guard let self else { return }
            if self.signIn == nil, let home = self.home {
                self.reconnectHome(domain: home.domain)
            } else {
                self.chooseHome()
            }
        }
        if home == nil {
            row(strings.blah_Identity_ConnectNotice, text: true)
        }
        if let identity {
            row(identity.user.domains.first?.name ?? identity.id, detail: identity.id) { [weak self] _ in
                UIPasteboard.general.string = identity.id
                self?.message = self?.strings.blah_Identity_Copied
                self?.publishRows()
            }
            if signIn != nil {
                if needsAdmissionEmail {
                    row(strings.blah_Identity_AdmissionNotice, text: true)
                    row(strings.blah_Identity_AdmissionEmail, detail: admissionEmail) { [weak self] _ in
                        self?.requestAdmissionEmail()
                    }
                }
                row(strings.blah_Identity_SignIn, enabled: home != nil) { [weak self] _ in self?.beginSignIn() }
                row(strings.blah_Identity_SignInNotice, text: true)
            }
            row(strings.blah_Identity_FilesSection, section: 1, header: true)
            row(identity.hostingDomain == nil ? strings.blah_Identity_Publication : strings.blah_Identity_HostedPublication, section: 1, text: true)
            for domain in identity.user.domains {
                row("https://\(domain.name)/.well-known/blah/profile.cbor", section: 1, text: true)
            }
            if identity.hostingDomain != nil {
                row(identity.publicationPending ? strings.blah_Identity_PublicationPending : strings.blah_Identity_Published, section: 1, text: true)
                row(strings.blah_Identity_Publish, section: 1) { [weak self] _ in self?.publishProfile() }
            }
            row(strings.blah_Identity_ExportProfile, section: 1) { [weak self] _ in
                self?.share(Data(identity.profile.encoding), filename: "profile.cbor")
            }
            row(strings.blah_Identity_ExportBackup, section: 1) { [weak self] _ in self?.exportBackup() }
            row(strings.blah_Identity_CheckPublication, section: 1) { [weak self] _ in
                guard let self else { return }
                self.update {
                    try await BlahIdentityStore.shared.checkPublication(slot: self.slot)
                    try Task.checkCancellation()
                    await MainActor.run { if !Task.isCancelled { self.show(self.strings.blah_Identity_Published) } }
                    return try await BlahIdentityStore.shared.inspect(slot: self.slot)
                }
            }
            row(strings.blah_Identity_SecuritySection, section: 2, header: true)
            row(strings.blah_Identity_Biometrics, section: 2, value: identity.biometrics) { [weak self] in self?.change(.biometrics($0 ?? false)) }
            row(strings.blah_Identity_Sync, section: 2, value: identity.sync) { [weak self] in
                guard let self else { return }
                if $0 == true { self.confirm(self.strings.blah_Identity_SyncNotice) { self.change(.sync(true)) } }
                else { self.change(.sync(false)) }
            }
            row(strings.blah_Identity_SyncNotice, section: 2, text: true)
            row(strings.blah_Identity_RenewalSection, section: 3, header: true)
            row(strings.blah_Identity_AutoRenew, section: 3, value: identity.autoRenew) { [weak self] in
                self?.change(.renewal(profileDays: identity.profileDays, deviceDays: identity.deviceDays, automatic: $0 ?? false))
            }
            row("\(strings.blah_Identity_ProfileDays): \(identity.profileDays)", section: 3) { [weak self] _ in
                self?.prompt(title: self?.strings.blah_Identity_ProfileDays ?? "", secure: false) { [weak self] value in
                    if let days = UInt64(value) { self?.change(.renewal(profileDays: days, deviceDays: identity.deviceDays, automatic: identity.autoRenew)) }
                    else { self?.show(self?.strings.blah_Identity_InvalidValidity ?? "") }
                }
            }
            row("\(strings.blah_Identity_DeviceDays): \(identity.deviceDays)", section: 3) { [weak self] _ in
                self?.prompt(title: self?.strings.blah_Identity_DeviceDays ?? "", secure: false) { [weak self] value in
                    if let days = UInt64(value) { self?.change(.renewal(profileDays: identity.profileDays, deviceDays: days, automatic: identity.autoRenew)) }
                    else { self?.show(self?.strings.blah_Identity_InvalidValidity ?? "") }
                }
            }
            row(strings.blah_Identity_Renew, section: 3) { [weak self] _ in self?.change(.renew) }
            row(strings.blah_Identity_DomainsSection, section: 4, header: true)
            for domain in identity.user.domains {
                row(domain.name, section: 4, text: true)
                if case .user = identity.profile, identity.user.domains.count > 1 {
                    row("\(strings.blah_Identity_RemoveDomain): \(domain.name)", section: 4, destructive: true) { [weak self] _ in
                        self?.change(.domains(identity.user.domains.filter { $0.name != domain.name }))
                    }
                }
            }
            row(strings.blah_Identity_UsernameNotice, section: 4, text: true)
            if case .user = identity.profile {
                row(strings.blah_Identity_AddDomain, section: 4) { [weak self] _ in
                    self?.prompt(title: self?.strings.blah_Identity_AddDomain ?? "", secure: false) { [weak self] value in
                        do {
                            let domain = try DomainName(value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased())
                            self?.change(.domains(identity.user.domains + [domain]))
                        } catch { self?.show(error.localizedDescription) }
                    }
                }
            }
            row(strings.blah_Identity_DevicesSection, section: 5, header: true)
            for certificate in identity.profile.devices {
                let current = certificate.device == identity.device
                row("\(current ? strings.blah_Identity_ThisDevice : strings.blah_Identity_RevokeDevice)\n\(certificate.device.id.description)",
                    section: 5, text: current, destructive: !current) { [weak self] _ in
                    self?.confirm(self?.strings.blah_Identity_RevokeNotice ?? "") { self?.change(.removeDevice(certificate.device.id)) }
                }
            }
            row(strings.blah_Identity_CopyDevice, section: 5) { [weak self] _ in
                UIPasteboard.general.string = Data(identity.device.key.encoding).base64EncodedString()
                self?.message = self?.strings.blah_Identity_Copied
                self?.publishRows()
            }
            row(strings.blah_Identity_AddDevice, section: 5) { [weak self] _ in
                self?.prompt(title: self?.strings.blah_Identity_AddDevice ?? "", secure: false) { [weak self] value in
                    guard let data = Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                        self?.show(self?.strings.blah_Identity_InvalidDevice ?? ""); return
                    }
                    self?.change(.addDevice(data))
                }
            }
            row(strings.blah_Identity_Lock, section: 6) { [weak self] _ in self?.clearIdentity(); Task { await BlahIdentityStore.shared.lock() }; self?.reload() }
        } else {
            row(strings.blah_Identity_SavedSection, section: 1, header: true)
            if saved.isEmpty { row(strings.blah_Identity_NoSaved, section: 1, text: true) }
            for entry in saved {
                row(entry.domain, section: 1, detail: entry.id, enabled: home != nil) { [weak self] _ in self?.unlock(entry.id) }
            }
            row(strings.blah_Identity_Create, section: 2, header: true)
            row(strings.blah_Identity_CreateHosted, section: 2, enabled: home != nil) { [weak self] _ in self?.createHosted() }
            row(strings.blah_Identity_CreateOwnDomain, section: 2, enabled: home != nil) { [weak self] _ in self?.create() }
            row(strings.blah_Identity_Import, section: 2, enabled: home != nil) { [weak self] _ in self?.importFile() }
            row(strings.blah_Identity_Biometrics, section: 2, value: wantsBiometrics) { [weak self] in self?.wantsBiometrics = $0 ?? false; self?.reload() }
            row(strings.blah_Identity_Sync, section: 2, value: wantsSync) { [weak self] in
                guard let self else { return }
                if $0 == true { self.confirm(self.strings.blah_Identity_SyncNotice) { self.wantsSync = true; self.reload() } }
                else { self.wantsSync = false; self.reload() }
            }
            row(strings.blah_Identity_SyncNotice, section: 2, text: true)
            for entry in cloud where !saved.contains(where: { $0.id == entry.id }) {
                row("\(strings.blah_Identity_RestoreCloud): \(entry.domain)", section: 3, enabled: home != nil) { [weak self] _ in
                    guard let self else { return }
                    self.update { try await BlahIdentityStore.shared.restoreCloud(id: entry.id, slot: self.slot, biometrics: self.wantsBiometrics) }
                }
            }
        }
        contentRows = entries
        publishRows()
    }

    private func refresh() { render(saved: saved, cloud: cloud, home: home) }

    private func publishRows() {
        var entries = contentRows.map { entry -> IdentityRow in
            var entry = entry
            entry.isEnabled = entry.isEnabled && !isBusy && !isSigningIn
            return entry
        }
        let status = isSigningIn ? strings.blah_Identity_SigningIn : isBusy ? strings.blah_Identity_Working : message
        if let status {
            entries.insert(IdentityRow(stableId: 2, section: 0, title: status, isText: true), at: min(2, entries.count))
        }
        rows.set(entries)
    }

    private func clearIdentity() {
        identity = nil
        admissionEmail = ""
        needsAdmissionEmail = false
        message = nil
    }

    private func run(clearMessage: Bool = true, _ work: @escaping () async throws -> Void) {
        guard !isBusy && !isSigningIn else { return }
        isBusy = true
        if clearMessage { message = nil }
        publishRows()
        let generation = self.generation
        task = Task { [weak self] in
            do {
                try Task.checkCancellation()
                try await work()
            } catch {
                await MainActor.run {
                    guard let self, !Task.isCancelled, self.generation == generation else { return }
                    if let identityError = error as? BlahIdentityError, case .locked = identityError {
                        self.clearIdentity()
                        self.refresh()
                    }
                    self.message = error.localizedDescription
                }
            }
            await MainActor.run {
                guard let self, self.generation == generation else { return }
                self.isBusy = false
                self.publishRows()
            }
        }
    }
    private func update(_ work: @escaping () async throws -> BlahIdentityView) {
        run { [weak self] in
            let view: BlahIdentityView
            do {
                view = try await work()
            } catch {
                try Task.checkCancellation()
                // A hosted name can be saved before publication fails. Keep its
                // current revision visible so the user can retry publication.
                if let self {
                    let current = try? await BlahIdentityStore.shared.inspect(slot: self.slot)
                    let saved = try? await BlahIdentityStore.shared.list()
                    await MainActor.run {
                        guard !Task.isCancelled else { return }
                        if current == nil { self.clearIdentity() }
                        self.identity = current
                        if let saved { self.saved = saved }
                        self.refresh()
                    }
                }
                throw error
            }
            try Task.checkCancellation()
            await MainActor.run {
                guard !Task.isCancelled else { return }
                if self?.identity?.id != view.id {
                    self?.admissionEmail = ""
                    self?.needsAdmissionEmail = false
                }
                self?.identity = view
            }
            guard let self else { return }
            let home = try await BlahIdentityStore.shared.home(slot: self.slot)
            await MainActor.run { if !Task.isCancelled { self.render(saved: self.saved, cloud: self.cloud, home: home) } }
        }
    }
    private func chooseHome() {
        prompt(title: strings.blah_Identity_Home, secure: false, value: home?.domain ?? "", keyboard: .URL) { [weak self] domain in
            guard let self else { return }
            self.run {
                try await self.network.connectBlahHome(domain: domain)
                let home = try await BlahIdentityStore.shared.home(slot: self.slot)
                let saved = try await BlahIdentityStore.shared.list()
                try Task.checkCancellation()
                await MainActor.run { if !Task.isCancelled { self.render(saved: saved, cloud: [], home: home) } }
            }
        }
    }
    private func reconnectHome(domain: String) {
        run { [self] in
            try await network.connectBlahHome(domain: domain)
            try Task.checkCancellation()
            await MainActor.run {
                if !Task.isCancelled { message = strings.blah_Identity_Connected }
            }
        }
    }
    private func create() {
        prompt(title: strings.blah_Identity_ProfileDomain, secure: false) { [weak self] domain in
            guard let self else { return }
            self.update { try await BlahIdentityStore.shared.create(domain: domain, slot: self.slot, biometrics: self.wantsBiometrics, sync: self.wantsSync) }
        }
    }
    private func createHosted() {
        let alert = UIAlertController(title: strings.blah_Identity_CreateHosted, message: strings.blah_Identity_HostingNotice, preferredStyle: .alert)
        alert.addTextField { [self] field in
            field.placeholder = strings.blah_Identity_HostingDomain
            field.accessibilityLabel = strings.blah_Identity_HostingDomain
            field.text = home?.domain
            field.keyboardType = .URL
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
        }
        alert.addTextField { [self] field in
            field.placeholder = strings.blah_Identity_HostingName
            field.accessibilityLabel = strings.blah_Identity_HostingName
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
        }
        alert.addAction(UIAlertAction(title: strings.Common_Cancel, style: .cancel))
        alert.addAction(UIAlertAction(title: strings.blah_Identity_Create, style: .default) { [weak self, weak alert] _ in
            guard let self, let fields = alert?.textFields, fields.count == 2 else { return }
            let domain = (fields[0].text ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            let label = (fields[1].text ?? "").trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            self.update {
                try await BlahIdentityStore.shared.createHosted(domain: domain, label: label, slot: self.slot,
                    biometrics: self.wantsBiometrics, sync: self.wantsSync)
            }
        })
        controller?.present(alert, animated: true)
    }
    private func publishProfile() {
        update { [self] in
            try await BlahIdentityStore.shared.publish(slot: slot)
            return try await BlahIdentityStore.shared.inspect(slot: slot)
        }
    }
    private func beginSignIn() {
        guard let signIn else { return }
        if needsAdmissionEmail && admissionEmail.isEmpty { requestAdmissionEmail(); return }
        run { [self] in
            let domain = try await BlahIdentityStore.shared.bind(slot: slot)
            try Task.checkCancellation()
            await MainActor.run {
                guard !Task.isCancelled else { return }
                isSigningIn = true
                publishRows()
                let generation = self.generation
                signIn(needsAdmissionEmail ? admissionEmail : domain, { [weak self] error in
                    guard self?.generation == generation else { return }
                    self?.signInFailed(error)
                })
            }
        }
    }
    private func signInFailed(_ error: String) {
        isSigningIn = false
        if error == "SIGNUP_EMAIL_REQUIRED" {
            needsAdmissionEmail = true
            refresh()
            requestAdmissionEmail()
        } else {
            message = error
            publishRows()
            let id = identity?.id
            let generation = self.generation
            Task { [weak self] in
                guard let self, let current = try? await BlahIdentityStore.shared.inspect(slot: self.slot) else { return }
                await MainActor.run {
                    guard self.generation == generation, self.identity?.id == id else { return }
                    // Signup may have allocated an account before publication
                    // failed. Export the new signed revision on the retry screen.
                    self.identity = current
                    self.refresh()
                }
            }
        }
    }
    private func requestAdmissionEmail() {
        prompt(title: strings.blah_Identity_AdmissionEmail, secure: false, value: admissionEmail,
            keyboard: .emailAddress, message: strings.blah_Identity_AdmissionNotice) { [weak self] email in
            guard let self else { return }
            let email = email.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !email.isEmpty else { return }
            self.admissionEmail = email
            self.refresh()
            self.beginSignIn()
        }
    }
    private func unlock(_ id: String) {
        update { [self] in try await BlahIdentityStore.shared.unlock(id: id, slot: slot) }
    }
    private func change(_ change: BlahIdentityStore.Change) {
        update { [self] in try await BlahIdentityStore.shared.change(slot: slot, change: change) }
    }
    private func exportBackup() {
        prompt(title: strings.blah_Identity_BackupPassword, secure: true) { [weak self] password in
            guard let self else { return }
            self.run {
                let data = try await BlahIdentityStore.shared.exportRecovery(slot: self.slot, password: password)
                try Task.checkCancellation()
                await MainActor.run { if !Task.isCancelled { self.share(data, filename: "identity.cbor") } }
            }
        }
    }
    private func importFile() {
        let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
        picker.delegate = self
        controller?.present(picker, animated: true)
    }
    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first else { return }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 262144,
            let data = try? Data(contentsOf: url) else { show(strings.blah_Identity_InvalidFile); return }
        prompt(title: strings.blah_Identity_BackupPassword, secure: true) { [weak self] password in
            guard let self else { return }
            self.update { try await BlahIdentityStore.shared.importRecovery(data, password: password, slot: self.slot, biometrics: self.wantsBiometrics) }
        }
    }
    private func share(_ data: Data, filename: String) {
        do {
            let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            let url = folder.appendingPathComponent(filename)
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            shareURL = url
            let share = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            share.popoverPresentationController?.sourceView = controller?.view
            share.popoverPresentationController?.sourceRect = controller?.view.bounds ?? .zero
            share.completionWithItemsHandler = { _, _, _, _ in try? FileManager.default.removeItem(at: folder) }
            controller?.present(share, animated: true)
        } catch { show(error.localizedDescription) }
    }
    private func prompt(title: String, secure: Bool, value: String = "", keyboard: UIKeyboardType = .default,
        message: String? = nil, complete: @escaping (String) -> Void) {
        let alert = UIAlertController(title: title, message: message ?? (secure ? strings.blah_Identity_BackupNotice : nil), preferredStyle: .alert)
        alert.addTextField { field in
            field.isSecureTextEntry = secure; field.autocapitalizationType = .none; field.autocorrectionType = .no
            field.text = value
            field.keyboardType = keyboard
            field.accessibilityLabel = title
        }
        alert.addAction(UIAlertAction(title: strings.Common_Cancel, style: .cancel))
        alert.addAction(UIAlertAction(title: strings.Login_Continue, style: .default) { [weak alert] _ in complete(alert?.textFields?.first?.text ?? "") })
        controller?.present(alert, animated: true)
    }
    private func confirm(_ text: String, complete: @escaping () -> Void) {
        let alert = UIAlertController(title: strings.blah_Identity_Title, message: text, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: strings.Common_Cancel, style: .cancel))
        alert.addAction(UIAlertAction(title: strings.Login_Continue, style: .default) { _ in complete() })
        controller?.present(alert, animated: true)
    }
    private func show(_ text: String) {
        let alert = UIAlertController(title: strings.blah_Identity_Title, message: text, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: strings.Common_OK, style: .default))
        controller?.present(alert, animated: true)
    }
}

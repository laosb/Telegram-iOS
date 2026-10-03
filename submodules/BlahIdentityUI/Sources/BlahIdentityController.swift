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
    var value: Bool? = nil
    var isText = false
    var isDestructive = false
    var isEnabled = true
    static func <(lhs: IdentityRow, rhs: IdentityRow) -> Bool { lhs.stableId < rhs.stableId }

    func item(presentationData: ItemListPresentationData, arguments: Any) -> ListViewItem {
        let actions = arguments as! IdentityActions
        if isText {
            return ItemListTextItem(presentationData: presentationData, text: .plain(title), sectionId: section)
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
    signIn: ((String) -> Void)? = nil) -> ViewController {
    _ = identityBackgroundLock
    let coordinator = IdentityCoordinator(network: network, presentationData: presentationData, signIn: signIn)
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
    private let signIn: ((String) -> Void)?
    private var identity: BlahIdentityView?
    private var actions: [Int32: (Bool?) -> Void] = [:]
    private var isBusy = false
    private var isSigningIn = false
    private var observer: NSObjectProtocol?
    private var task: Task<Void, Never>?
    private var shareURL: URL?
    private var wantsBiometrics = false
    private var wantsSync = false
    private var admissionEmail = ""
    private var strings: PresentationStrings { presentationData.strings }
    private var slot: String { network.blahIdentitySlot }

    init(network: Network, presentationData: PresentationData, signIn: ((String) -> Void)?) {
        self.network = network; self.presentationData = presentationData; self.signIn = signIn
        super.init()
        observer = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main) { [weak self] _ in
            self?.identity = nil
            Task { await BlahIdentityStore.shared.lock() }
            self?.reload()
        }
    }
    deinit {
        if let observer { NotificationCenter.default.removeObserver(observer) }
        if let shareURL { try? FileManager.default.removeItem(at: shareURL.deletingLastPathComponent()) }
        if !isSigningIn { Task { await BlahIdentityStore.shared.lock() } }
    }

    func lockWhenLeaving() {
        guard !isSigningIn else { return }
        identity = nil
        Task { await BlahIdentityStore.shared.lock() }
    }
    func invoke(_ id: Int32, _ value: Bool?) { guard !isBusy else { return }; actions[id]?(value) }

    func reload() {
        run { [self] in
            let saved = try await BlahIdentityStore.shared.list()
            let cloud = try await BlahIdentityStore.shared.cloudIdentities()
            let home = try await BlahIdentityStore.shared.home(slot: slot)
            await MainActor.run { self.render(saved: saved, cloud: cloud, home: home) }
        }
    }

    private func render(saved: [BlahIdentitySummary], cloud: [BlahIdentitySummary], home: BlahHome?) {
        var entries: [IdentityRow] = []
        actions = [:]
        func row(_ title: String, section: Int32 = 0, value: Bool? = nil, text: Bool = false,
            destructive: Bool = false, action: @escaping (Bool?) -> Void = { _ in }) {
            let id = Int32(entries.count)
            entries.append(IdentityRow(stableId: id, section: section, title: title, value: value,
                isText: text, isDestructive: destructive))
            actions[id] = action
        }
        row(home?.domain ?? strings.blah_Identity_Home, action: { [weak self] _ in self?.chooseHome() })
        if let identity {
            row(identity.id, text: true)
            row(strings.blah_Identity_Publication, text: true)
            for domain in identity.user.domains {
                row("https://\(domain.name)/.well-known/blah/profile.cbor", text: true)
            }
            if signIn != nil {
                row(strings.blah_Identity_SignIn) { [weak self] _ in
                    self?.run { [weak self] in
                        guard let self else { return }
                        let domain = try await BlahIdentityStore.shared.bind(slot: self.slot)
                        await MainActor.run {
                            self.isSigningIn = true
                            self.signIn?(self.admissionEmail.isEmpty ? domain : self.admissionEmail)
                        }
                    }
                }
                row(strings.blah_Identity_AdmissionEmail) { [weak self] _ in
                    self?.prompt(title: self?.strings.blah_Identity_AdmissionEmail ?? "", secure: false) { [weak self] in self?.admissionEmail = $0 }
                }
            }
            row(strings.blah_Identity_ExportProfile) { [weak self] _ in
                self?.share(Data(identity.profile.encoding), filename: "profile.cbor")
            }
            row(strings.blah_Identity_ExportBackup) { [weak self] _ in self?.exportBackup() }
            row(strings.blah_Identity_CheckPublication) { [weak self] _ in
                self?.run { [weak self] in
                    guard let self else { return }
                    try await BlahIdentityStore.shared.checkPublication(slot: self.slot)
                    await MainActor.run { self.show(self.strings.blah_Identity_Published) }
                }
            }
            row(strings.blah_Identity_Biometrics, section: 1, value: identity.biometrics) { [weak self] in self?.change(.biometrics($0 ?? false)) }
            row(strings.blah_Identity_Sync, section: 1, value: identity.sync) { [weak self] in
                guard let self else { return }
                if $0 == true { self.confirm(self.strings.blah_Identity_SyncNotice) { self.change(.sync(true)) } }
                else { self.change(.sync(false)) }
            }
            row(strings.blah_Identity_SyncNotice, section: 1, text: true)
            row(strings.blah_Identity_AutoRenew, section: 2, value: identity.autoRenew) { [weak self] in
                self?.change(.renewal(profileDays: identity.profileDays, deviceDays: identity.deviceDays, automatic: $0 ?? false))
            }
            row("\(strings.blah_Identity_ProfileDays): \(identity.profileDays)", section: 2) { [weak self] _ in
                self?.prompt(title: self?.strings.blah_Identity_ProfileDays ?? "", secure: false) { [weak self] value in
                    if let days = UInt64(value) { self?.change(.renewal(profileDays: days, deviceDays: identity.deviceDays, automatic: identity.autoRenew)) }
                }
            }
            row("\(strings.blah_Identity_DeviceDays): \(identity.deviceDays)", section: 2) { [weak self] _ in
                self?.prompt(title: self?.strings.blah_Identity_DeviceDays ?? "", secure: false) { [weak self] value in
                    if let days = UInt64(value) { self?.change(.renewal(profileDays: identity.profileDays, deviceDays: days, automatic: identity.autoRenew)) }
                }
            }
            row(strings.blah_Identity_Renew, section: 2) { [weak self] _ in self?.change(.renew) }
            for domain in identity.user.domains {
                row(domain.name, section: 3, text: true)
                if identity.user.domains.count > 1 {
                    row("\(strings.blah_Identity_RemoveDomain): \(domain.name)", section: 3, destructive: true) { [weak self] _ in
                        self?.change(.domains(identity.user.domains.filter { $0.name != domain.name }))
                    }
                }
            }
            row(strings.blah_Identity_UsernameNotice, section: 3, text: true)
            row(strings.blah_Identity_AddDomain, section: 3) { [weak self] _ in
                self?.prompt(title: self?.strings.blah_Identity_AddDomain ?? "", secure: false) { [weak self] value in
                    guard let domain = try? ProfileDomain(value.lowercased()) else { return }
                    self?.change(.domains(identity.user.domains + [domain]))
                }
            }
            for certificate in identity.profile.devices {
                let current = certificate.device == identity.device
                row("\(current ? strings.blah_Identity_ThisDevice : strings.blah_Identity_RevokeDevice)\n\(certificate.device.id.description)",
                    section: 4, text: current, destructive: !current) { [weak self] _ in
                    self?.confirm(self?.strings.blah_Identity_RevokeNotice ?? "") { self?.change(.removeDevice(certificate.device.id)) }
                }
            }
            row(strings.blah_Identity_AddDevice, section: 4) { [weak self] _ in
                self?.prompt(title: self?.strings.blah_Identity_AddDevice ?? "", secure: false) { [weak self] value in
                    guard let data = Data(base64Encoded: value) else { return }
                    self?.change(.addDevice(data))
                }
            }
            row(strings.blah_Identity_Lock, section: 5) { [weak self] _ in self?.identity = nil; Task { await BlahIdentityStore.shared.lock() }; self?.reload() }
        } else {
            for entry in saved {
                row(entry.domain, section: 1) { [weak self] _ in self?.unlock(entry.id) }
            }
            row(strings.blah_Identity_Biometrics, section: 2, value: wantsBiometrics) { [weak self] in self?.wantsBiometrics = $0 ?? false; self?.reload() }
            row(strings.blah_Identity_Sync, section: 2, value: wantsSync) { [weak self] in
                guard let self else { return }
                if $0 == true { self.confirm(self.strings.blah_Identity_SyncNotice) { self.wantsSync = true; self.reload() } }
                else { self.wantsSync = false; self.reload() }
            }
            row(strings.blah_Identity_SyncNotice, section: 2, text: true)
            row(strings.blah_Identity_Create, section: 2) { [weak self] _ in self?.create() }
            row(strings.blah_Identity_Import, section: 2) { [weak self] _ in self?.importFile() }
            for entry in cloud where !saved.contains(where: { $0.id == entry.id }) {
                row("\(strings.blah_Identity_RestoreCloud): \(entry.domain)", section: 3) { [weak self] _ in
                    guard let self else { return }
                    self.update { try await BlahIdentityStore.shared.restoreCloud(id: entry.id, slot: self.slot, biometrics: self.wantsBiometrics) }
                }
            }
        }
        rows.set(entries)
    }

    private func run(_ work: @escaping () async throws -> Void) {
        guard !isBusy else { return }
        isBusy = true
        task = Task { [weak self] in
            do { try await work() }
            catch { await MainActor.run { self?.show(error.localizedDescription) } }
            await MainActor.run { self?.isBusy = false }
        }
    }
    private func update(_ work: @escaping () async throws -> BlahIdentityView) {
        run { [weak self] in
            let view = try await work()
            await MainActor.run { self?.identity = view }
            guard let self else { return }
            let home = try await BlahIdentityStore.shared.home(slot: self.slot)
            await MainActor.run { self.render(saved: [], cloud: [], home: home) }
        }
    }
    private func chooseHome() {
        prompt(title: strings.blah_Identity_Home, secure: false) { [weak self] domain in
            guard let self else { return }
            self.run {
                try await self.network.connectBlahHome(domain: domain)
                let home = try await BlahIdentityStore.shared.home(slot: self.slot)
                let saved = try await BlahIdentityStore.shared.list()
                await MainActor.run { self.render(saved: saved, cloud: [], home: home) }
            }
        }
    }
    private func create() {
        prompt(title: strings.blah_Identity_ProfileDomain, secure: false) { [weak self] domain in
            guard let self else { return }
            self.update { try await BlahIdentityStore.shared.create(domain: domain, slot: self.slot, biometrics: self.wantsBiometrics, sync: self.wantsSync) }
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
                await MainActor.run { self.share(data, filename: "identity.blahidentity") }
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
        guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 600000,
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
    private func prompt(title: String, secure: Bool, complete: @escaping (String) -> Void) {
        let alert = UIAlertController(title: title, message: secure ? strings.blah_Identity_BackupNotice : nil, preferredStyle: .alert)
        alert.addTextField { field in
            field.isSecureTextEntry = secure; field.autocapitalizationType = .none; field.autocorrectionType = .no
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

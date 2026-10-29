import Foundation
import UIKit
import BlahDiem
import BlahIdentity
import Display
import ItemListUI
import SwiftSignalKit
import TelegramPresentationData

func blahIdentityDetailsController(id: String, presentationData: PresentationData,
    remove: @escaping (ViewController, @escaping (Bool) -> Void) -> Void) -> ViewController {
    let coordinator = IdentityDetailsCoordinator(id: id, presentationData: presentationData, remove: remove)
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

private final class IdentityDetailsCoordinator: NSObject {
    let rows = ValuePromise<[IdentityRow]>([], ignoreRepeated: true)
    weak var controller: ItemListController?
    private let id: String
    private let slot = "identity-details:" + UUID().uuidString
    private let presentationData: PresentationData
    private let remove: (ViewController, @escaping (Bool) -> Void) -> Void
    private var identity: BlahIdentityView?
    private var actions: [Int32: (Bool?) -> Void] = [:]
    private var isBusy = false
    private var observer: NSObjectProtocol?
    private var task: Task<Void, Never>?
    private var generation = 0
    private var shareURL: URL?
    private var message: String?
    private var contentRows: [IdentityRow] = []
    private var strings: PresentationStrings { presentationData.strings }

    init(id: String, presentationData: PresentationData, remove: @escaping (ViewController, @escaping (Bool) -> Void) -> Void) {
        self.id = id
        self.presentationData = presentationData
        self.remove = remove
        super.init()
        observer = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main) { [weak self] _ in
            self?.cancel()
            self?.refresh()
        }
    }
    deinit {
        task?.cancel()
        if let observer { NotificationCenter.default.removeObserver(observer) }
        if let shareURL { try? FileManager.default.removeItem(at: shareURL.deletingLastPathComponent()) }
        Task { await BlahIdentityStore.shared.lock() }
    }

    func lockWhenLeaving() {
        cancel()
    }
    func cancel() {
        stopWork()
        Task { await BlahIdentityStore.shared.lock() }
    }
    private func stopWork() {
        generation += 1
        task?.cancel()
        task = nil
        isBusy = false
        clearIdentity()
        refresh()
    }
    func invoke(_ id: Int32, _ value: Bool?) {
        guard !isBusy, contentRows.first(where: { $0.index == id })?.isEnabled == true else { return }
        actions[id]?(value)
    }

    func reload() {
        update { [self] in
            if let current = try? await BlahIdentityStore.shared.inspect(slot: slot) { return current }
            return try await BlahIdentityStore.shared.unlock(id: id, slot: slot)
        }
    }

    private func render() {
        var entries: [IdentityRow] = []
        actions = [:]
        func row(_ title: String, section: Int32 = 0, detail: String? = nil, value: Bool? = nil, text: Bool = false,
            header: Bool = false, destructive: Bool = false, enabled: Bool = true, action: @escaping (Bool?) -> Void = { _ in }) {
            // Reserve a stable row for progress and errors.
            let id = Int32(entries.count + 1)
            entries.append(IdentityRow(index: id, section: section, title: title, detail: detail, value: value,
                isText: text, isHeader: header, isDestructive: destructive, isEnabled: enabled))
            actions[id] = action
        }
        if let identity {
            row(identity.user.domains.first?.name ?? identity.id, detail: identity.id) { [weak self] _ in
                UIPasteboard.general.string = identity.id
                self?.message = self?.strings.blah_Identity_Copied
                self?.publishRows()
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
            if identity.canManageIdentity {
                row(strings.blah_Identity_ExportBackup, section: 1) { [weak self] _ in self?.exportBackup() }
            }
            row(strings.blah_Identity_CheckPublication, section: 1) { [weak self] _ in
                guard let self else { return }
                self.update {
                    try await BlahIdentityStore.shared.checkPublication(slot: self.slot)
                    try Task.checkCancellation()
                    await MainActor.run { if !Task.isCancelled { self.show(self.strings.blah_Identity_Published) } }
                    return try await BlahIdentityStore.shared.inspect(slot: self.slot)
                }
            }
            if identity.canManageIdentity {
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
            }
            row(strings.blah_Identity_DomainsSection, section: 4, header: true)
            for domain in identity.user.domains {
                row(domain.name, section: 4, text: true)
                if identity.canManageIdentity, case .user = identity.profile, identity.user.domains.count > 1 {
                    row("\(strings.blah_Identity_RemoveDomain): \(domain.name)", section: 4, destructive: true) { [weak self] _ in
                        self?.change(.domains(identity.user.domains.filter { $0.name != domain.name }))
                    }
                }
            }
            row(strings.blah_Identity_UsernameNotice, section: 4, text: true)
            if identity.canManageIdentity, case .user = identity.profile {
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
                row("\(current ? strings.blah_Identity_ThisDevice : identity.canManageIdentity ? strings.blah_Identity_RevokeDevice : strings.blah_IdentityWizard_Device)\n\(certificate.device.id.description)",
                    section: 5, text: current || !identity.canManageIdentity, destructive: !current) { [weak self] _ in
                    self?.confirm(self?.strings.blah_Identity_RevokeNotice ?? "") { self?.change(.removeDevice(certificate.device.id)) }
                }
            }
            row(strings.blah_Identity_CopyDevice, section: 5) { [weak self] _ in
                UIPasteboard.general.string = Data(identity.device.key.encoding).base64EncodedString()
                self?.message = self?.strings.blah_Identity_Copied
                self?.publishRows()
            }
            if identity.canManageIdentity {
                row(strings.blah_Identity_AddDevice, section: 5) { [weak self] _ in
                    self?.prompt(title: self?.strings.blah_Identity_AddDevice ?? "", secure: false) { [weak self] value in
                        guard let data = Data(base64Encoded: value.trimmingCharacters(in: .whitespacesAndNewlines)) else {
                            self?.show(self?.strings.blah_Identity_InvalidDevice ?? ""); return
                        }
                        self?.change(.addDevice(data))
                    }
                }
            }
            row(strings.blah_Identity_Lock, section: 6) { [weak self] _ in self?.clearIdentity(); Task { await BlahIdentityStore.shared.lock() }; self?.refresh() }
        } else {
            row(strings.blah_IdentityWizard_Unlock) { [weak self] _ in self?.reload() }
        }
        row(strings.blah_Identity_Remove, section: 7, destructive: true) { [weak self] _ in
            guard let self, let controller = self.controller else { return }
            self.cancel()
            self.isBusy = true
            self.publishRows()
            let generation = self.generation
            self.remove(controller, { [weak self] removed in
                guard let self, self.generation == generation else { return }
                self.isBusy = false
                self.publishRows()
                if removed { self.controller?.dismiss() }
            })
        }
        contentRows = entries
        publishRows()
    }

    private func refresh() { render() }

    private func publishRows() {
        var entries = contentRows.map { entry -> IdentityRow in
            var entry = entry
            entry.isEnabled = entry.isEnabled && !isBusy
            return entry
        }
        let status = isBusy ? strings.blah_Identity_Working : message
        if let status {
            entries.insert(IdentityRow(index: 0, section: 0, title: status, isText: true), at: 0)
        }
        rows.set(entries)
    }

    private func clearIdentity() {
        identity = nil
        message = nil
    }

    private func run(clearMessage: Bool = true, _ work: @escaping () async throws -> Void) {
        guard !isBusy else { return }
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
                    await MainActor.run {
                        guard !Task.isCancelled else { return }
                        if current == nil { self.clearIdentity() }
                        self.identity = current
                        self.refresh()
                    }
                }
                throw error
            }
            try Task.checkCancellation()
            await MainActor.run {
                guard !Task.isCancelled else { return }
                self?.identity = view
            }
            guard let self else { return }
            await MainActor.run { if !Task.isCancelled { self.refresh() } }
        }
    }
    private func publishProfile() {
        update { [self] in
            try await BlahIdentityStore.shared.publish(slot: slot)
            return try await BlahIdentityStore.shared.inspect(slot: slot)
        }
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

import Foundation
import UIKit
import AccountContext
import BlahIdentity
import Display
import ItemListUI
import SwiftSignalKit
import TelegramCore
import TelegramPresentationData

// This observer survives the settings screen and the authorization sequence.
let identityBackgroundLock = NotificationCenter.default.addObserver(
    forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
) { _ in Task { await BlahIdentityStore.shared.lock() } }

public func blahIdentityController(network: Network, sourceAccountId: AccountRecordId, sharedContext: SharedAccountContext, presentationData: PresentationData,
    signIn: ((String, @escaping (String) -> Void) -> Void)? = nil, cancelSignIn: (() -> Void)? = nil,
    beginNewAuth: (() -> Void)? = nil, initialAction: BlahIdentitySignInAction? = nil,
    completeDeviceLink: ((BlahDeviceLinkState, @escaping (String?) -> Void) -> Void)? = nil) -> ViewController {
    _ = identityBackgroundLock
    let coordinator = IdentityListCoordinator(network: network, sourceAccountId: sourceAccountId, sharedContext: sharedContext, presentationData: presentationData,
        signIn: signIn, cancelSignIn: cancelSignIn, beginNewAuth: beginNewAuth, completeDeviceLink: completeDeviceLink)
    let actions = IdentityActions()
    actions.invoke = { [weak coordinator] id, _ in coordinator?.invoke(id) }
    actions.remove = { [weak coordinator] id in coordinator?.remove(id) }
    let signal = coordinator.rows.get() |> map { rows -> (ItemListControllerState, (ItemListNodeState, IdentityActions)) in
        let presentation = ItemListPresentationData(presentationData)
        return (ItemListControllerState(presentationData: presentation, title: .text(presentationData.strings.blah_Identity_Title),
            leftNavigationButton: nil, rightNavigationButton: nil,
            backNavigationButton: ItemListBackButton(title: presentationData.strings.Common_Back)),
            (ItemListNodeState(presentationData: presentation, entries: rows, style: .blocks, animateChanges: true), actions))
    }
    let controller = ItemListController(presentationData: ItemListPresentationData(presentationData),
        updatedPresentationData: .single(ItemListPresentationData(presentationData)), state: signal, tabBarItem: nil)
    coordinator.controller = controller
    controller.attemptNavigation = { [weak coordinator] _ in coordinator?.cancel(); return true }
    controller.didAppear = { [coordinator] firstTime in
        coordinator.reload(action: firstTime ? initialAction : nil)
    }
    return controller
}

private final class IdentityListCoordinator {
    let rows = ValuePromise<[IdentityRow]>([], ignoreRepeated: true)
    weak var controller: ItemListController?
    private let network: Network
    private let sourceAccountId: AccountRecordId
    private let sharedContext: SharedAccountContext
    private let presentationData: PresentationData
    private let signIn: ((String, @escaping (String) -> Void) -> Void)?
    private let cancelSignIn: (() -> Void)?
    private let beginNewAuth: (() -> Void)?
    private let completeDeviceLink: ((BlahDeviceLinkState, @escaping (String?) -> Void) -> Void)?
    private var saved: [BlahIdentitySummary] = []
    private var cloud: [BlahIdentitySummary] = []
    private var homeDomain: String?
    private var pendingAction: BlahIdentitySignInAction?
    private var pendingHandoffId: UUID?
    private var pendingDetailsID: String?
    private var admissionEmails: [String: String] = [:]
    private var actions: [Int32: () -> Void] = [:]
    private var removals: [Int32: () -> Void] = [:]
    private var removalCompletion: ((Bool) -> Void)?
    private weak var removalController: ViewController?
    private var isRemoving = false
    private var task: Task<Void, Never>?
    private var generation = 0
    private var isBusy = false
    private var isSigningIn = false
    private var message: String?
    private var observer: NSObjectProtocol?
    private var strings: PresentationStrings { presentationData.strings }

    init(network: Network, sourceAccountId: AccountRecordId, sharedContext: SharedAccountContext, presentationData: PresentationData,
        signIn: ((String, @escaping (String) -> Void) -> Void)?, cancelSignIn: (() -> Void)?, beginNewAuth: (() -> Void)?,
        completeDeviceLink: ((BlahDeviceLinkState, @escaping (String?) -> Void) -> Void)?) {
        self.network = network
        self.sourceAccountId = sourceAccountId
        self.sharedContext = sharedContext
        self.presentationData = presentationData
        self.signIn = signIn
        self.cancelSignIn = cancelSignIn
        self.beginNewAuth = beginNewAuth
        self.completeDeviceLink = completeDeviceLink
        self.message = network.takeBlahIdentityError()
        observer = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main) { [weak self] _ in self?.cancel() }
    }

    deinit {
        task?.cancel()
        if let observer { NotificationCenter.default.removeObserver(observer) }
    }

    func cancel() {
        generation += 1
        task?.cancel()
        task = nil
        pendingAction = nil
        // Back or background cancellation revokes only this list's unconsumed handoff; account creation continues.
        if let pendingHandoffId { BlahIdentitySignInHandoff.cancel(pendingHandoffId) }
        pendingHandoffId = nil
        pendingDetailsID = nil
        admissionEmails = [:]
        if isSigningIn { cancelSignIn?() }
        isSigningIn = false
        isBusy = isRemoving
        completeRemoval(false)
        Task { await BlahIdentityStore.shared.lock() }
        render()
    }

    func invoke(_ id: Int32) {
        guard !isBusy, !isSigningIn else { return }
        actions[id]?()
    }

    func remove(_ id: Int32) {
        guard !isBusy, !isSigningIn else { return }
        removals[id]?()
    }

    func reload(action: BlahIdentitySignInAction? = nil, detailsID: String? = nil) {
        if let action { pendingAction = action }
        if let detailsID { pendingDetailsID = detailsID }
        run { [self] in
            self.saved = try await BlahIdentityStore.shared.list()
            self.cloud = (try? await BlahIdentityStore.shared.cloudIdentities()) ?? []
            self.homeDomain = try await BlahIdentityStore.shared.home(slot: network.blahIdentitySlot)?.domain
            try Task.checkCancellation()
        } completed: { [weak self] in
            guard let self else { return }
            if let id = self.pendingDetailsID {
                self.pendingDetailsID = nil
                self.showDetails(id)
                return
            }
            guard let action = self.pendingAction else { return }
            self.pendingAction = nil
            switch action {
            case let .saved(id): self.select(id)
            case let .link(domain, homeDomain): self.wizard(start: .link(domain: domain, homeDomain: homeDomain))
            }
        }
    }

    private func render() {
        var entries: [IdentityRow] = []
        actions = [:]
        removals = [:]
        func row(_ title: String, section: Int32 = 0, detail: String? = nil, text: Bool = false,
            remove: (() -> Void)? = nil, action: @escaping () -> Void = {}) {
            let id = Int32(entries.count)
            entries.append(IdentityRow(index: id, section: section, title: title, detail: detail, isText: text,
                isEnabled: !isBusy && !isSigningIn, isRemovable: remove != nil))
            actions[id] = action
            removals[id] = remove
        }
        if let status = isSigningIn ? strings.blah_Identity_SigningIn : isBusy ? strings.blah_Identity_Working : message {
            row(status, text: true)
        }
        if saved.isEmpty { row(strings.blah_Identity_NoSaved, text: true) }
        for identity in saved {
            row(identity.domain, detail: identity.id + "\n" + (identity.homeDomain ?? strings.blah_Identity_ChooseDC), remove: { [weak self] in
                guard let self, let controller = self.controller else { return }
                self.confirmRemoval(identity.id, cloudOnly: false, from: controller)
            }) { [weak self] in
                self?.select(identity.id)
            }
        }
        for identity in cloud where !saved.contains(where: { $0.id == identity.id }) {
            row(identity.domain, section: 1, detail: strings.blah_IdentityWizard_InCloud + "\n" + identity.id + "\n" + (identity.homeDomain ?? strings.blah_Identity_ChooseDC), remove: { [weak self] in
                guard let self, let controller = self.controller else { return }
                self.confirmRemoval(identity.id, cloudOnly: true, from: controller)
            }) { [weak self] in
                self?.restore(identity.id)
            }
        }
        row(strings.blah_IdentityWizard_Add, section: 2) { [weak self] in self?.wizard(start: .home(legacyID: nil)) }
        rows.set(entries)
    }

    private func run(_ work: @escaping @MainActor () async throws -> Void, completed: (() -> Void)? = nil) {
        guard !isBusy, !isSigningIn else { return }
        isBusy = true
        render()
        let generation = self.generation
        task = Task { @MainActor [weak self] in
            do {
                try await work()
                try Task.checkCancellation()
                guard let self, self.generation == generation else { return }
                self.isBusy = false
                self.render()
                completed?()
            } catch {
                guard let self, !Task.isCancelled, self.generation == generation else { return }
                self.isBusy = false
                self.message = error.localizedDescription
                self.completeRemoval(false, error: error.localizedDescription)
                self.render()
            }
        }
    }

    private func restore(_ id: String) {
        var savedAfterFailure = false
        run { [self] in
            do {
                _ = try await BlahIdentityStore.shared.restoreCloud(id: id, home: nil, biometrics: false)
            } catch {
                self.saved = try await BlahIdentityStore.shared.list()
                guard self.saved.contains(where: { $0.id == id }) else { throw error }
                self.message = error.localizedDescription
                savedAfterFailure = true
            }
            self.saved = try await BlahIdentityStore.shared.list()
        } completed: { [weak self] in
            if savedAfterFailure { self?.showDetails(id) }
            else { self?.select(id) }
        }
    }

    private func showDetails(_ id: String) {
        (controller?.navigationController as? NavigationController)?.pushViewController(
            blahIdentityDetailsController(id: id, presentationData: presentationData, remove: { [weak self] controller, completed in
                guard let self else { completed(false); return }
                self.confirmRemoval(id, cloudOnly: false, from: controller, completed: completed)
            }))
    }

    private func completeRemoval(_ removed: Bool, error: String? = nil) {
        let completed = removalCompletion
        let controller = removalController
        removalCompletion = nil
        removalController = nil
        completed?(removed)
        if let error, let controller {
            let alert = UIAlertController(title: strings.blah_Identity_Remove, message: error, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: strings.Common_OK, style: .cancel))
            controller.present(alert, animated: true)
        }
    }

    private func confirmRemoval(_ id: String, cloudOnly: Bool, from controller: ViewController, completed: @escaping (Bool) -> Void = { _ in }) {
        guard !isBusy, !isSigningIn else { completed(false); return }
        removalCompletion = completed
        removalController = controller
        var hasCloud = false
        run {
            hasCloud = try await BlahIdentityStore.shared.hasCloudRecovery(id: id)
        } completed: { [weak self, weak controller] in
            guard let self, let controller else { self?.completeRemoval(false); return }
            let generation = self.generation
            let text = cloudOnly ? self.strings.blah_Identity_RemoveCloudNotice
                : hasCloud ? self.strings.blah_Identity_RemoveDeviceCloudNotice : self.strings.blah_Identity_RemoveDeviceNotice
            let alert = UIAlertController(title: self.strings.blah_Identity_Remove, message: text, preferredStyle: .alert)
            alert.addAction(UIAlertAction(title: self.strings.Common_Cancel, style: .cancel) { [weak self] _ in
                guard let self, self.generation == generation else { return }
                self.completeRemoval(false)
            })
            func option(_ title: String, fromCloud: Bool) {
                alert.addAction(UIAlertAction(title: title, style: .destructive) { [weak self] _ in
                    guard let self, self.generation == generation else { return }
                    self.removeIdentity(id, cloudOnly: cloudOnly, fromCloud: fromCloud)
                })
            }
            if cloudOnly { option(self.strings.blah_Identity_RemoveCloud, fromCloud: true) }
            else {
                option(self.strings.blah_Identity_RemoveDevice, fromCloud: false)
                if hasCloud { option(self.strings.blah_Identity_RemoveDeviceCloud, fromCloud: true) }
            }
            controller.present(alert, animated: true)
        }
    }

    private func removeIdentity(_ id: String, cloudOnly: Bool, fromCloud: Bool) {
        let accountManager = sharedContext.accountManager
        let sourceAccountId = self.sourceAccountId
        run { [weak self] in
            try Task.checkCancellation()
            self?.isRemoving = true
            // Logout can remove this screen. Confirmed custody cleanup must outlive it.
            let removal = Task { () -> (Bool, Error?) in
                var removedSource = false
                do {
                    if cloudOnly {
                        try await BlahIdentityStore.shared.removeCloud(id: id)
                        return (false, nil)
                    }
                    let slots = try await BlahIdentityStore.shared.boundSlots(id: id)
                    let view = await accountManager.accountRecords().get()
                    let records = view.records.filter {
                        $0.id != view.currentAuthAccount?.id && slots.contains(accountRecordIdPathName($0.id))
                    }
                    for record in records {
                        await logoutFromAccount(id: record.id, accountManager: accountManager, alreadyLoggedOutRemotely: false).get()
                        _ = await (accountManager.accountRecords() |> filter { view in
                            !view.records.contains(where: { $0.id == record.id })
                        }).get()
                        if record.id == sourceAccountId { removedSource = true }
                    }
                    try await BlahIdentityStore.shared.removeIdentity(id: id, fromCloud: fromCloud)
                    return (removedSource, nil)
                } catch {
                    return (removedSource, error)
                }
            }
            do {
                let (removedSource, error) = await removal.value
                guard let self else { return }
                self.isRemoving = false
                if removedSource { self.cancel(); return }
                if Task.isCancelled {
                    self.isBusy = false
                    if self.controller?.traceVisibility() == true { self.reload() }
                    return
                }
                if let error { throw error }
                self.saved = try await BlahIdentityStore.shared.list()
                self.cloud = (try? await BlahIdentityStore.shared.cloudIdentities()) ?? []
            } catch {
                self?.isRemoving = false
                if Task.isCancelled { self?.isBusy = false }
                throw error
            }
        } completed: { [weak self] in self?.completeRemoval(true) }
    }

    private func handoff(_ action: BlahIdentitySignInAction) {
        guard let beginNewAuth else { return }
        cancelSignIn?()
        isSigningIn = true
        pendingHandoffId = BlahIdentitySignInHandoff.put(action, sourceAccountId: sourceAccountId)
        beginNewAuth()
    }

    private func select(_ id: String, email: String? = nil) {
        guard let identity = saved.first(where: { $0.id == id }) else { return }
        if signIn == nil {
            showDetails(id)
            return
        }
        guard let domain = identity.homeDomain else {
            wizard(start: .home(legacyID: id))
            return
        }
        message = nil
        if let email { admissionEmails[id] = email }
        run { [self] in
            guard try await BlahIdentityStore.shared.canUseSlot(slot: network.blahIdentitySlot, homeDomain: domain, identityID: id) else {
                await BlahIdentityStore.shared.lock()
                try Task.checkCancellation()
                self.handoff(.saved(id: id))
                return
            }
            try Task.checkCancellation()
            try await network.connectBlahHome(domain: domain)
            try Task.checkCancellation()
            _ = try await BlahIdentityStore.shared.unlock(id: id, slot: network.blahIdentitySlot)
            try Task.checkCancellation()
            let name = try await BlahIdentityStore.shared.bind(slot: network.blahIdentitySlot)
            try Task.checkCancellation()
            isSigningIn = true
            let generation = self.generation
            signIn?(admissionEmails[id] ?? name, { [weak self] error in
                guard let self, self.generation == generation else { return }
                self.isSigningIn = false
                self.message = error
                self.render()
                if error == "SIGNUP_EMAIL_REQUIRED" { self.admissionEmail(id) }
                else { self.signInError(id: id, error: error) }
            })
        }
    }

    private func admissionEmail(_ id: String) {
        let alert = UIAlertController(title: strings.blah_Identity_AdmissionEmail, message: strings.blah_Identity_AdmissionNotice, preferredStyle: .alert)
        alert.addTextField {
            $0.keyboardType = .emailAddress
            $0.autocapitalizationType = .none
            $0.autocorrectionType = .no
            $0.accessibilityLabel = self.strings.blah_Identity_AdmissionEmail
        }
        alert.addAction(UIAlertAction(title: strings.Common_Cancel, style: .cancel))
        alert.addAction(UIAlertAction(title: strings.Login_Continue, style: .default) { [weak self, weak alert] _ in
            guard let email = alert?.textFields?.first?.text?.trimmingCharacters(in: .whitespacesAndNewlines), !email.isEmpty else { return }
            self?.select(id, email: email)
        })
        controller?.present(alert, animated: true)
    }

    private func signInError(id: String, error: String) {
        // Signup may have saved a numbered profile before publication failed.
        let alert = UIAlertController(title: strings.blah_Identity_Title, message: error, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: strings.Common_OK, style: .cancel))
        alert.addAction(UIAlertAction(title: strings.blah_IdentityWizard_Details, style: .default) { [weak self] _ in
            self?.showDetails(id)
        })
        controller?.present(alert, animated: true)
    }

    private func wizard(start: IdentityWizardStart) {
        guard let controller else { return }
        let wizard = identityWizardController(network: network, sharedContext: sharedContext, presentationData: presentationData,
            start: start, homeDomain: signIn == nil ? homeDomain : nil, isLogin: signIn != nil,
            completeDeviceLink: completeDeviceLink, cancelSignIn: cancelSignIn, completed: { [weak self] result in
                guard let self else { return }
                switch result {
                case let .saved(id): self.reload(action: .saved(id: id))
                case let .details(id): self.reload(detailsID: id)
                case let .handoff(action): self.reload(); self.handoff(action)
                case .dismissed, .signedIn: self.reload()
                }
            })
        controller.present(wizard, in: .window(.root))
    }
}

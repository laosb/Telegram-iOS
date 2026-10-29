import Foundation
import UIKit
import UniformTypeIdentifiers
import AsyncDisplayKit
import AccountContext
import BlahIdentity
import BlahDiem
import Display
import PresentationDataUtils
import QrCode
import QrCodeUI
import SwiftSignalKit
import TelegramCore
import TelegramPresentationData

enum IdentityWizardStart {
    case home(legacyID: String?)
    case link(domain: String, homeDomain: String)
}

enum IdentityWizardResult {
    case dismissed
    case saved(String)
    case details(String)
    case handoff(BlahIdentitySignInAction)
    case signedIn
}

private enum IdentityWizardQRRoute {
    case saved(String)
    case replaceAccount
    case connected
}

func identityWizardController(network: Network, sharedContext: SharedAccountContext, presentationData: PresentationData,
    start: IdentityWizardStart, homeDomain: String?, isLogin: Bool,
    completeDeviceLink: ((BlahDeviceLinkState, @escaping (String?) -> Void) -> Void)?, cancelSignIn: (() -> Void)?,
    completed: @escaping (IdentityWizardResult) -> Void) -> ViewController {
    let coordinator = IdentityWizardCoordinator(network: network, sharedContext: sharedContext, presentationData: presentationData,
        isLogin: isLogin, completeDeviceLink: completeDeviceLink, cancelSignIn: cancelSignIn, completed: completed)
    let navigation = NavigationController(mode: .single, theme: NavigationControllerTheme(presentationTheme: presentationData.theme))
    let host = IdentityWizardHostController(navigation: navigation, coordinator: coordinator, presentationData: presentationData)
    coordinator.host = host
    coordinator.navigation = navigation
    switch start {
    case let .home(legacyID): coordinator.showHome(value: homeDomain ?? "", legacyID: legacyID)
    case let .link(domain, homeDomain): coordinator.showQR(domain: domain, homeDomain: homeDomain)
    }
    return host
}

private final class IdentityWizardHostController: ViewController, StandalonePresentableController {
    private let navigation: NavigationController
    private let coordinator: IdentityWizardCoordinator
    private let presentationData: PresentationData
    private var currentLayout: ContainerViewLayout?
    private var isAppearing = false
    private var didAnimateIn = false
    private var isDismissing = false

    init(navigation: NavigationController, coordinator: IdentityWizardCoordinator, presentationData: PresentationData) {
        self.navigation = navigation
        self.coordinator = coordinator
        self.presentationData = presentationData
        super.init(navigationBarPresentationData: nil)
        self.statusBar.statusBarStyle = presentationData.theme.intro.statusBarStyle.style
        self.acceptsFocusWhenInOverlay = true
        self.supportedOrientations = ViewControllerSupportedOrientations(regularSize: .all, compactSize: .portrait)
    }
    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    deinit { self.coordinator.finish(.dismissed, dismiss: false) }
    override func loadDisplayNode() {
        self.displayNode = ASDisplayNode()
        self.displayNode.backgroundColor = self.presentationData.theme.list.plainBackgroundColor
        self.displayNodeDidLoad()
        self.navigation.setIgnoreAppearanceMethodInvocations(true)
        self.displayNode.view.addSubview(self.navigation.view)
        self.navigation.setIgnoreAppearanceMethodInvocations(false)
    }
    override func containerLayoutUpdated(_ layout: ContainerViewLayout, transition: ContainedViewLayoutTransition) {
        super.containerLayoutUpdated(layout, transition: transition)
        self.currentLayout = layout
        guard self.isAppearing else { return }
        transition.updateFrame(view: self.navigation.view, frame: CGRect(origin: .zero, size: layout.size))
        self.navigation.containerLayoutUpdated(layout, transition: transition)
    }
    override func viewWillAppear(_ animated: Bool) {
        super.viewWillAppear(animated)
        self.isAppearing = true
        if let layout = self.currentLayout {
            self.navigation.view.frame = CGRect(origin: .zero, size: layout.size)
            self.navigation.containerLayoutUpdated(layout, transition: .immediate)
        }
        self.navigation.viewWillAppear(animated)
    }
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        self.navigation.viewDidAppear(animated)
        if !self.didAnimateIn {
            self.didAnimateIn = true
            self.view.layer.animatePosition(from: CGPoint(x: 0.0, y: self.view.bounds.height), to: .zero,
                duration: 0.3, timingFunction: CAMediaTimingFunctionName.easeOut.rawValue, additive: true)
        }
    }
    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        self.navigation.viewWillDisappear(animated)
    }
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        self.navigation.viewDidDisappear(animated)
        if self.view.superview == nil || self.view.superview?.superview == nil {
            self.coordinator.finish(.dismissed, dismiss: false)
        }
    }

    override func dismiss(completion: (() -> Void)? = nil) {
        guard !self.isDismissing else { return }
        self.isDismissing = true
        self.view.endEditing(true)
        self.view.layer.animatePosition(from: .zero, to: CGPoint(x: 0.0, y: self.view.bounds.height),
            duration: 0.2, removeOnCompletion: false, additive: true, completion: { [weak self] _ in
                self?.presentingViewController?.dismiss(animated: false, completion: nil)
                completion?()
            })
    }
}

private final class IdentityWizardPageController: ViewController {
    let owner: IdentityWizardCoordinator
    let page: IdentityWizardPage
    private let presentationData: PresentationData
    var appeared: (() -> Void)?
    var disappeared: (() -> Void)?
    var custodyBaseline: Set<String>?
    var node: BlahIdentityWizardNode { displayNode as! BlahIdentityWizardNode }

    init(owner: IdentityWizardCoordinator, page: IdentityWizardPage, presentationData: PresentationData) {
        self.owner = owner
        self.page = page
        self.presentationData = presentationData
        let theme = presentationData.theme
        let navigationTheme = NavigationBarTheme(overallDarkAppearance: theme.overallDarkAppearance,
            buttonColor: theme.chat.inputPanel.panelControlColor, disabledButtonColor: theme.intro.disabledTextColor,
            primaryTextColor: theme.intro.primaryTextColor, badgeBackgroundColor: theme.rootController.navigationBar.badgeBackgroundColor,
            badgeTextColor: theme.rootController.navigationBar.badgeTextColor, edgeEffectColor: .clear,
            accentButtonColor: theme.list.itemCheckColors.fillColor, accentDisabledButtonColor: theme.chat.inputPanel.panelControlDisabledColor,
            accentForegroundColor: theme.list.itemCheckColors.foregroundColor)
        super.init(navigationBarPresentationData: NavigationBarPresentationData(theme: navigationTheme, strings: NavigationBarStrings(presentationStrings: presentationData.strings)))
        statusBar.statusBarStyle = theme.intro.statusBarStyle.style
        supportedOrientations = ViewControllerSupportedOrientations(regularSize: .all, compactSize: .portrait)
        hasActiveInput = page.placeholder != nil
        navigationItem.backBarButtonItem = UIBarButtonItem(title: presentationData.strings.Common_Back, style: .plain, target: nil, action: nil)
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: presentationData.strings.Common_Cancel, style: .plain, target: self, action: #selector(cancelPressed))
        attemptNavigation = { [weak owner] _ in owner?.cancelWork(); return true }
    }
    required init(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }
    override func loadDisplayNode() {
        displayNode = BlahIdentityWizardNode(page: page, presentationData: presentationData)
        displayNodeDidLoad()
    }
    override func viewDidAppear(_ animated: Bool) {
        super.viewDidAppear(animated)
        node.activateInput()
        appeared?()
    }
    override func viewDidDisappear(_ animated: Bool) {
        super.viewDidDisappear(animated)
        if owner.navigation?.viewControllers.contains(where: { $0 === self }) != true { disappeared?() }
    }
    override func containerLayoutUpdated(_ layout: ContainerViewLayout, transition: ContainedViewLayoutTransition) {
        super.containerLayoutUpdated(layout, transition: transition)
        node.containerLayoutUpdated(layout, navigationBarHeight: navigationLayout(layout: layout).navigationFrame.maxY, transition: transition)
    }
    @objc private func cancelPressed() { owner.cancel() }
}

private final class IdentityWizardCoordinator: NSObject, UIDocumentPickerDelegate {
    weak var navigation: NavigationController?
    weak var host: IdentityWizardHostController?
    private let network: Network
    private let sharedContext: SharedAccountContext
    private let presentationData: PresentationData
    private let isLogin: Bool
    private let completeDeviceLink: ((BlahDeviceLinkState, @escaping (String?) -> Void) -> Void)?
    private let cancelSignIn: (() -> Void)?
    private let completed: (IdentityWizardResult) -> Void
    private var task: Task<Void, Never>?
    private var generation = 0
    private var finished = false
    private var observer: NSObjectProtocol?
    private var attempt: BlahDeviceLinkAttempt?
    private var continuationState: BlahDeviceLinkState?
    private let linkDisposable = MetaDisposable()
    private let imageDisposable = MetaDisposable()
    private let accountsDisposable = MetaDisposable()
    private var expiration: DispatchWorkItem?
    private var importHome: BlahHome?
    private weak var importPage: IdentityWizardPageController?
    private var shareFolders: [URL] = []
    private var strings: PresentationStrings { presentationData.strings }
    private var current: IdentityWizardPageController? { navigation?.viewControllers.last as? IdentityWizardPageController }

    init(network: Network, sharedContext: SharedAccountContext, presentationData: PresentationData, isLogin: Bool,
        completeDeviceLink: ((BlahDeviceLinkState, @escaping (String?) -> Void) -> Void)?, cancelSignIn: (() -> Void)?,
        completed: @escaping (IdentityWizardResult) -> Void) {
        self.network = network
        self.sharedContext = sharedContext
        self.presentationData = presentationData
        self.isLogin = isLogin
        self.completeDeviceLink = completeDeviceLink
        self.cancelSignIn = cancelSignIn
        self.completed = completed
        super.init()
        _ = identityBackgroundLock
        observer = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main) { [weak self] _ in
            guard let self else { return }
            self.stopWork()
            self.current?.node.setStatus(self.strings.blah_IdentityWizard_Interrupted)
        }
    }
    deinit {
        task?.cancel()
        attempt?.cancel()
        linkDisposable.dispose()
        imageDisposable.dispose()
        accountsDisposable.dispose()
        expiration?.cancel()
        if let observer { NotificationCenter.default.removeObserver(observer) }
        for folder in shareFolders { try? FileManager.default.removeItem(at: folder) }
    }

    func stopWork(preserveSignIn: Bool = false) {
        generation += 1
        if continuationState != nil && !preserveSignIn { cancelSignIn?() }
        task?.cancel()
        task = nil
        attempt?.cancel()
        attempt = nil
        continuationState = nil
        linkDisposable.set(nil)
        imageDisposable.set(nil)
        accountsDisposable.set(nil)
        expiration?.cancel()
        expiration = nil
        if let page = current {
            page.node.busy = false
            if page.page.qr {
                page.node.setQRImage(nil)
                page.node.primaryHidden = false
            }
        }
    }

    func cancelWork() {
        stopWork()
        Task { await BlahIdentityStore.shared.lock() }
    }

    func cancel() {
        finish(.dismissed)
    }

    func finish(_ result: IdentityWizardResult, dismiss: Bool = true) {
        guard !finished else { return }
        finished = true
        let preserveIdentity: Bool
        if case .signedIn = result { preserveIdentity = true } else { preserveIdentity = false }
        stopWork(preserveSignIn: preserveIdentity)
        current?.view.endEditing(true)
        if dismiss { host?.dismiss() }
        // Cleanup survives removal/deinit; notify once, after locking, before another selection unlocks.
        Task { @MainActor [completed] in
            if !preserveIdentity { await BlahIdentityStore.shared.lock() }
            completed(result)
        }
    }

    private func push(_ model: IdentityWizardPage) -> IdentityWizardPageController {
        let page = IdentityWizardPageController(owner: self, page: model, presentationData: presentationData)
        if navigation?.viewControllers.isEmpty == true { navigation?.setViewControllers([page], animated: false) }
        else {
            current?.view.endEditing(true)
            navigation?.pushViewController(page)
        }
        _ = page.displayNode
        return page
    }

    private func run<T>(on page: IdentityWizardPageController, savingIdentity: Bool = false,
        work: @escaping () async throws -> T, completed: @escaping (T) -> Void) {
        guard !page.node.busy, !finished else { return }
        page.node.busy = true
        page.node.setStatus(nil)
        let generation = self.generation
        task = Task { @MainActor [weak self, weak page] in
            var previousIDs: Set<String>?
            do {
                if savingIdentity {
                    let saved = try await BlahIdentityStore.shared.list()
                    guard let self, let page, !Task.isCancelled, self.generation == generation, !self.finished else { return }
                    // Keep the baseline across background cancellation and back navigation.
                    if let baseline = page.custodyBaseline, let identity = saved.first(where: { !baseline.contains($0.id) }) {
                        self.finish(.details(identity.id))
                        return
                    }
                    previousIDs = Set(saved.map { $0.id })
                    page.custodyBaseline = previousIDs
                }
                try Task.checkCancellation()
                let result = try await work()
                try Task.checkCancellation()
                guard let self, let page, self.generation == generation, !self.finished else { return }
                page.node.busy = false
                completed(result)
            } catch {
                guard let self, let page, !Task.isCancelled, self.generation == generation else { return }
                if let previousIDs, let saved = try? await BlahIdentityStore.shared.list(),
                    let identity = saved.first(where: { !previousIDs.contains($0.id) }) {
                    guard !Task.isCancelled, self.generation == generation, !self.finished else { return }
                    self.finish(.details(identity.id))
                    return
                }
                guard !Task.isCancelled, self.generation == generation, !self.finished else { return }
                page.node.busy = false
                if page.page.qr { page.node.primaryHidden = false }
                page.node.setStatus(error.localizedDescription, error: true)
            }
        }
    }

    func showHome(value: String, legacyID: String?) {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_HomeTitle, text: strings.blah_IdentityWizard_HomeText,
            placeholder: strings.blah_IdentityWizard_HomePlaceholder, value: value, primary: strings.Login_Continue,
            secondary: legacyID == nil ? strings.blah_IdentityWizard_Import : nil, auxiliary: strings.blah_IdentityWizard_Scan))
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            let input = page.node.value
            self.run(on: page, work: {
                let home = try await BlahIdentityStore.shared.discoverHome(input)
                if let legacyID { try await BlahIdentityStore.shared.setHomeDomain(id: legacyID, home: home) }
                return home
            }, completed: { [weak self] home in
                if let legacyID { self?.finish(.saved(legacyID)) }
                else { self?.showDomain(home: home) }
            })
        }
        page.node.auxiliary = { [weak self, weak page] in
            guard let self, let page else { return }
            page.view.endEditing(true)
            let scanner = QrCodeScanScreen(sharedContext: self.sharedContext, info: self.strings.blah_IdentityWizard_ScanText,
                validate: { (try? BlahProfileHost.homeDomain($0)) != nil })
            scanner.completion = { [weak page, weak scanner] value in
                if let value, let domain = try? BlahProfileHost.homeDomain(value) { page?.node.value = domain.name }
                if value != nil { scanner?.dismissAnimated() }
            }
            page.present(scanner, in: .window(.root))
        }
        page.node.secondary = { [weak self, weak page] in
            guard let self, let page else { return }
            let input = page.node.value
            self.run(on: page, work: { try await BlahIdentityStore.shared.discoverHome(input) }, completed: { [weak self, weak page] home in
                guard let self, let page else { return }
                self.importHome = home
                self.importPage = page
                page.view.endEditing(true)
                let picker = UIDocumentPickerViewController(forOpeningContentTypes: [.data], asCopy: true)
                picker.delegate = self
                page.present(picker, animated: true)
            })
        }
    }

    private func showDomain(home: BlahHome) {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_DomainTitle, text: strings.blah_IdentityWizard_DomainText,
            placeholder: strings.blah_IdentityWizard_DomainPlaceholder, primary: strings.Login_Continue))
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            let domain = page.node.value
            self.run(on: page, work: { try await BlahIdentityStore.shared.probe(domain: domain, home: home) }, completed: { [weak self, weak page] result in
                guard let self else { return }
                switch result {
                case let .available(domain): self.showMint(domain: domain, home: home)
                case let .saved(id): self.finish(.saved(id))
                case let .existing(domain, _, sameHome):
                    guard sameHome else { page?.node.setStatus(self.strings.blah_IdentityWizard_WrongHome, error: true); return }
                    if self.isLogin { self.showQR(domain: domain, homeDomain: home.domain) }
                    else { self.finish(.handoff(.link(domain: domain, homeDomain: home.domain))) }
                }
            })
        }
    }

    private func showMint(domain: String, home: BlahHome) {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_MintTitle,
            text: strings.blah_IdentityWizard_MintText(domain).string, primary: strings.blah_IdentityWizard_Mint, mintOptions: true))
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            let biometrics = page.node.biometrics
            let sync = page.node.sync
            self.run(on: page, savingIdentity: true, work: { try await BlahIdentityStore.shared.mint(domain: domain, home: home, biometrics: biometrics, sync: sync) }, completed: { [weak self] result in
                guard let self else { return }
                switch result.publication {
                case .published: self.ready(id: result.id)
                case let .manual(profile, url): self.showPublication(id: result.id, profile: profile, url: url)
                }
            })
        }
    }

    private func showPublication(id: String, profile: Data, url: String) {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_PublishTitle,
            text: strings.blah_IdentityWizard_PublishText + "\n\n" + url, primary: strings.blah_IdentityWizard_Uploaded,
            auxiliary: strings.blah_IdentityWizard_Share))
        page.node.auxiliary = { [weak self, weak page] in if let page { self?.share(profile, from: page) } }
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            self.run(on: page, work: { try await BlahIdentityStore.shared.confirmPublication(id: id) }, completed: { [weak self] in self?.ready(id: id) })
        }
    }

    private func ready(id: String) {
        if isLogin { finish(.saved(id)); return }
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_ReadyTitle, text: strings.blah_IdentityWizard_ReadyText,
            primary: strings.blah_IdentityWizard_SignIn, secondary: strings.Common_Done))
        page.node.primary = { [weak self] in self?.finish(.handoff(.saved(id: id))) }
        page.node.secondary = { [weak self] in self?.finish(.dismissed) }
    }

    func showQR(domain: String, homeDomain: String) {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_QRTitle, text: strings.blah_IdentityWizard_QRText,
            primary: strings.blah_IdentityWizard_Retry, qr: true))
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            self.startQR(on: page, domain: domain, homeDomain: homeDomain)
        }
        page.appeared = { [weak self, weak page] in
            guard let self, let page, self.attempt == nil, !page.node.busy else { return }
            self.startQR(on: page, domain: domain, homeDomain: homeDomain)
        }
        page.disappeared = { [weak self] in self?.stopWork() }
    }

    private func startQR(on page: IdentityWizardPageController, domain: String, homeDomain: String) {
        stopWork()
        page.node.primaryHidden = true
        page.node.setStatus(strings.blah_Identity_Working)
        run(on: page, work: { [network] () async throws -> IdentityWizardQRRoute in
            // Installation can commit just before cancellation or a completion RPC failure.
            if let id = try await BlahIdentityStore.shared.savedIdentityID(domain: domain) { return .saved(id) }
            guard try await BlahIdentityStore.shared.canUseSlot(slot: network.blahIdentitySlot, homeDomain: homeDomain, identityID: nil) else {
                return .replaceAccount
            }
            try Task.checkCancellation()
            try await network.connectBlahHome(domain: homeDomain)
            return .connected
        }, completed: { [weak self, weak page] route in
            guard let self, let page else { return }
            switch route {
            case let .saved(id): self.finish(.saved(id)); return
            case .replaceAccount: self.finish(.handoff(.link(domain: domain, homeDomain: homeDomain))); return
            case .connected: break
            }
            let generation = self.generation
            self.accountsDisposable.set((self.sharedContext.activeAccountContexts |> take(1) |> deliverOnMainQueue).start(next: { [weak self, weak page] accounts in
                guard let self, let page, self.generation == generation else { return }
                var label = UIDevice.current.name
                while label.utf8.count > 64 { label.removeLast() }
                if label.isEmpty { label = "iPhone" }
                let attempt = BlahDeviceLinkAttempt(network: self.network, label: label,
                    exceptIds: accounts.accounts.map { $0.1.account.peerId.id._internalGetInt64Value() }, expectedDomain: domain)
                self.attempt = attempt
                self.linkDisposable.set((attempt.states |> deliverOnMainQueue).start(next: { [weak self, weak page] state in
                    guard let self, let page, self.generation == generation else { return }
                    self.handleLink(state, on: page, generation: generation)
                }))
            }))
        })
    }

    private func handleLink(_ state: BlahDeviceLinkState, on page: IdentityWizardPageController, generation: Int) {
        switch state {
        case let .code(url, expires):
            page.node.primaryHidden = true
            page.node.setStatus(nil)
            expiration?.cancel()
            imageDisposable.set((qrCode(string: url, color: .black, backgroundColor: .white, icon: .none, ecl: "M")
                |> map { _, generator -> UIImage? in
                    let size = CGSize(width: 768.0, height: 768.0)
                    return generator(TransformImageArguments(corners: ImageCorners(), imageSize: size, boundingSize: size,
                        intrinsicInsets: UIEdgeInsets(), scale: 1.0))?.generateImage()
                } |> deliverOnMainQueue).start(next: { [weak page] in page?.node.setQRImage($0) }))
            let expiration = DispatchWorkItem { [weak self, weak page] in
                guard let self, self.generation == generation else { return }
                page?.node.setQRImage(nil)
                page?.node.setStatus(self.strings.blah_Identity_Working)
            }
            self.expiration = expiration
            DispatchQueue.main.asyncAfter(deadline: .now() + max(0.0, Double(expires) - network.globalTime), execute: expiration)
        case .approved:
            expiration?.cancel()
            imageDisposable.set(nil)
            page.node.setQRImage(nil)
            page.node.setStatus(strings.blah_Identity_SigningIn)
        case .passwordNeeded, .signedIn:
            continuationState = state
            page.node.primaryHidden = true
            page.node.setStatus(strings.blah_Identity_SigningIn)
            guard let completeDeviceLink else {
                page.node.setStatus(strings.blah_IdentityWizard_Interrupted, error: true)
                return
            }
            completeDeviceLink(state, { [weak self, weak page] error in
                guard let self, self.generation == generation else { return }
                if let error {
                    page?.node.setStatus(error, error: true)
                    page?.node.primaryHidden = false
                } else { self.finish(.signedIn) }
            })
        case let .failed(error):
            stopWork()
            page.node.setStatus(error, error: true)
        }
    }

    func documentPicker(_ controller: UIDocumentPickerViewController, didPickDocumentsAt urls: [URL]) {
        guard let url = urls.first, let home = importHome, let page = importPage else { return }
        let access = url.startAccessingSecurityScopedResource()
        defer { if access { url.stopAccessingSecurityScopedResource() } }
        guard let size = try? url.resourceValues(forKeys: [.fileSizeKey]).fileSize, size <= 262144,
            let data = try? Data(contentsOf: url) else { page.node.setStatus(strings.blah_Identity_InvalidFile, error: true); return }
        let alert = UIAlertController(title: strings.blah_Identity_BackupPassword, message: strings.blah_Identity_BackupNotice, preferredStyle: .alert)
        alert.addTextField { field in
            field.isSecureTextEntry = true
            field.autocapitalizationType = .none
            field.autocorrectionType = .no
            field.accessibilityLabel = self.strings.blah_Identity_BackupPassword
        }
        alert.addAction(UIAlertAction(title: strings.Common_Cancel, style: .cancel))
        alert.addAction(UIAlertAction(title: strings.Login_Continue, style: .default) { [weak self, weak page, weak alert] _ in
            guard let self, let page else { return }
            let password = alert?.textFields?.first?.text ?? ""
            self.run(on: page, savingIdentity: true, work: { try await BlahIdentityStore.shared.importRecovery(data, password: password, home: home, biometrics: false) },
                completed: { [weak self] id in self?.ready(id: id) })
        })
        page.present(alert, animated: true)
    }

    private func share(_ data: Data, from page: IdentityWizardPageController) {
        do {
            let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            shareFolders.append(folder)
            let url = folder.appendingPathComponent("profile.cbor")
            try data.write(to: url, options: [.atomic, .completeFileProtection])
            let share = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            share.popoverPresentationController?.sourceView = page.view
            share.popoverPresentationController?.sourceRect = page.view.bounds
            share.completionWithItemsHandler = { _, _, _, _ in try? FileManager.default.removeItem(at: folder) }
            page.present(share, animated: true)
        } catch { page.node.setStatus(error.localizedDescription, error: true) }
    }
}

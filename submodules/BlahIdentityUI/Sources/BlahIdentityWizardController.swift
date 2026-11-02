import Foundation
import UIKit
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
import WalletWordsScreen
import WalletImportScreen

public enum BlahAuthorizationAction {
    case create
    case words
    case qr
    case cloud(id: String)
}

private enum IdentityWizardResult {
    case dismissed
    case saved(String)
    case signedIn
}

public func blahHomeController(network: Network, sharedContext: SharedAccountContext, presentationData: PresentationData,
    completed: @escaping (String) -> Void) -> ViewController {
    let coordinator = IdentityWizardCoordinator(network: network, sharedContext: sharedContext, presentationData: presentationData,
        isLogin: false, completeDeviceLink: nil, cancelSignIn: nil, completed: { _ in })
    let host = identityWizardHost(coordinator: coordinator, presentationData: presentationData)
    coordinator.homeSelected = { completed($0.domain) }
    coordinator.showHome(value: "")
    return host
}

public func blahAuthorizationController(network: Network, sharedContext: SharedAccountContext, presentationData: PresentationData,
    action: BlahAuthorizationAction, signIn: @escaping (String) -> Void,
    cancelSignIn: @escaping () -> Void,
    completeDeviceLink: @escaping (BlahDeviceLinkState, @escaping (String?) -> Void) -> Void) -> ViewController {
    let coordinator = IdentityWizardCoordinator(network: network, sharedContext: sharedContext, presentationData: presentationData,
        isLogin: true, signIn: signIn, completeDeviceLink: completeDeviceLink, cancelSignIn: cancelSignIn, completed: { _ in })
    let host = identityWizardHost(coordinator: coordinator, presentationData: presentationData)
    coordinator.action = action
    Task { @MainActor [weak coordinator] in
        if let home = try? await BlahIdentityStore.shared.home(slot: network.blahIdentitySlot) {
            coordinator?.start(home: home)
        } else { coordinator?.showHome(value: "") }
    }
    return host
}

func identityPublicationController(network: Network, sharedContext: SharedAccountContext, presentationData: PresentationData,
    pending: BlahPendingPublication, published: Bool = false, error: String? = nil, refreshAfterPublication: Bool = true,
    completed: @escaping (Bool) -> Void = { _ in }) -> ViewController {
    let coordinator = IdentityWizardCoordinator(network: network, sharedContext: sharedContext,
        presentationData: presentationData, isLogin: false, publicationOnly: true, refreshAfterPublication: refreshAfterPublication,
        completeDeviceLink: nil, cancelSignIn: nil, completed: { result in
            if case .saved = result { completed(true) } else { completed(false) }
        })
    let host = identityWizardHost(coordinator: coordinator, presentationData: presentationData)
    coordinator.showPendingPublication(pending, published: published, error: error)
    return host
}

private func identityWizardHost(coordinator: IdentityWizardCoordinator, presentationData: PresentationData) -> IdentityWizardHostController {
    let navigation = NavigationController(mode: .single, theme: NavigationControllerTheme(presentationTheme: presentationData.theme))
    let host = IdentityWizardHostController(navigation: navigation, coordinator: coordinator, presentationData: presentationData)
    coordinator.host = host
    coordinator.navigation = navigation
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
        navigationItem.rightBarButtonItem = UIBarButtonItem(title: owner.publicationOnly ? presentationData.strings.blah_IdentityWizard_Later : presentationData.strings.Common_Cancel,
            style: .plain, target: self, action: #selector(cancelPressed))
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

private final class IdentityWizardCoordinator: NSObject {
    let publicationOnly: Bool
    private let refreshAfterPublication: Bool
    weak var navigation: NavigationController?
    weak var host: IdentityWizardHostController?
    private let network: Network
    private let sharedContext: SharedAccountContext
    private let presentationData: PresentationData
    var action: BlahAuthorizationAction = .create
    var homeSelected: ((BlahHome) -> Void)?
    private let signIn: ((String) -> Void)?
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
    private var shareFolders: [URL] = []
    private var strings: PresentationStrings { presentationData.strings }
    private var current: IdentityWizardPageController? { navigation?.viewControllers.last as? IdentityWizardPageController }

    init(network: Network, sharedContext: SharedAccountContext, presentationData: PresentationData, isLogin: Bool, signIn: ((String) -> Void)? = nil, publicationOnly: Bool = false, refreshAfterPublication: Bool = true,
        completeDeviceLink: ((BlahDeviceLinkState, @escaping (String?) -> Void) -> Void)?, cancelSignIn: (() -> Void)?,
        completed: @escaping (IdentityWizardResult) -> Void) {
        self.network = network
        self.sharedContext = sharedContext
        self.presentationData = presentationData
        self.isLogin = isLogin
        self.signIn = signIn
        self.publicationOnly = publicationOnly
        self.refreshAfterPublication = refreshAfterPublication
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
    }

    func cancel() {
        finish(.dismissed)
    }

    func finish(_ result: IdentityWizardResult, dismiss: Bool = true) {
        guard !finished else { return }
        finished = true
        let preserveIdentity: Bool
        if case .signedIn = result { preserveIdentity = true } else { preserveIdentity = publicationOnly }
        stopWork(preserveSignIn: preserveIdentity)
        current?.view.endEditing(true)
        if dismiss { host?.dismiss() }
        completed(result)
    }

    private func push(_ model: IdentityWizardPage, replacing: Bool = false) -> IdentityWizardPageController {
        let page = IdentityWizardPageController(owner: self, page: model, presentationData: presentationData)
        if replacing || navigation?.viewControllers.isEmpty == true { navigation?.setViewControllers([page], animated: false) }
        else {
            current?.view.endEditing(true)
            navigation?.pushViewController(page)
        }
        _ = page.displayNode
        return page
    }

    private func run<T>(on page: IdentityWizardPageController,
        work: @escaping () async throws -> T, completed: @escaping (T) -> Void) {
        guard !page.node.busy, !finished else { return }
        page.node.busy = true
        page.node.setStatus(nil)
        let generation = self.generation
        task = Task { @MainActor [weak self, weak page] in
            do {
                let result = try await work()
                try Task.checkCancellation()
                guard let self, let page, self.generation == generation, !self.finished else { return }
                page.node.busy = false
                completed(result)
            } catch {
                guard let self, let page, !Task.isCancelled, self.generation == generation else { return }
                page.node.busy = false
                page.node.primaryHidden = false
                page.node.setStatus(blahIdentityErrorDescription(error), error: true)
                // Signing can succeed before a publication failure. Keep the exact revision retryable.
                if let pending = try? await BlahIdentityStore.shared.pendingPublication(slot: self.network.blahIdentitySlot) {
                    self.showPublication(id: pending.id, profile: pending.profile, url: pending.url, hosted: pending.hostingDomain != nil)
                }
            }
        }
    }

    func showHome(value: String) {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_HomeTitle, text: strings.blah_IdentityWizard_HomeText,
            placeholder: strings.blah_IdentityWizard_HomePlaceholder, value: value, primary: strings.Login_Continue,
            auxiliary: strings.blah_IdentityWizard_Scan))
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            let input = page.node.value
            self.run(on: page, work: { [network = self.network] in
                try await network.connectBlahHome(domain: input)
                return try await BlahIdentityStore.shared.home(slot: network.blahIdentitySlot)!
            }, completed: { [weak self, weak page] home in
                guard self != nil, page != nil else { return }
                Task { @MainActor [weak self, weak page] in
                    guard let self, let page else { return }
                    if let homeSelected = self.homeSelected {
                        homeSelected(home)
                        self.finish(.dismissed)
                        return
                    }
                    self.resumeOrContinue(home: home, on: page)
                }
            })
        }
        page.node.auxiliary = { [weak self, weak page] in
            guard let self, let page else { return }
            let scanner = QrCodeScanScreen(sharedContext: self.sharedContext, info: self.strings.blah_IdentityWizard_ScanText,
                validate: { (try? BlahProfileHost.homeDomain($0)) != nil })
            scanner.completion = { [weak page, weak scanner] value in
                if let value, let domain = try? BlahProfileHost.homeDomain(value) { page?.node.value = domain.name; scanner?.dismissAnimated() }
            }
            page.present(scanner, in: .window(.root))
        }
    }

    func start(home: BlahHome) {
        let page = push(IdentityWizardPage(title: strings.blah_Login_Title, text: strings.blah_Identity_Working,
            primary: strings.blah_IdentityWizard_Retry))
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            self.resumeOrContinue(home: home, on: page)
        }
        resumeOrContinue(home: home, on: page)
    }

    private func resumeOrContinue(home: BlahHome, on page: IdentityWizardPageController) {
        run(on: page, work: { [network] in try await BlahIdentityStore.shared.identity(slot: network.blahIdentitySlot) }, completed: { [weak self, weak page] existing in
            guard let self, let page else { return }
            if let existing {
                let resume = self.push(IdentityWizardPage(title: self.strings.blah_IdentityWizard_ResumeTitle,
                    text: self.strings.blah_IdentityWizard_ResumeText(existing.domain).string,
                    primary: self.strings.Login_Continue, auxiliary: self.strings.blah_IdentityWizard_Restart))
                resume.node.primary = { [weak self] in self?.ready(id: existing.id) }
                resume.node.auxiliary = { [weak self, weak resume] in
                    guard let self, let resume else { return }
                    self.run(on: resume, work: { [network = self.network] in
                        try await network.restartBlahAuthorization()
                    }, completed: { [weak self, weak resume] home in
                        guard let self, let resume else { return }
                        self.continueFromHome(home, on: resume)
                    })
                }
            } else { self.continueFromHome(home, on: page) }
        })
    }

    private func continueFromHome(_ home: BlahHome, on page: IdentityWizardPageController) {
        switch action {
        case let .cloud(id):
            run(on: page, work: { [network] in
                try await BlahIdentityStore.shared.restoreCloud(id: id, slot: network.blahIdentitySlot, biometrics: false)
            }, completed: { [weak self] identity in self?.ready(id: identity.id) })
        case .qr: showQR(domain: nil, homeDomain: home.domain)
        default: showDomain(home: home)
        }
    }

    private func showDomain(home: BlahHome) {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_DomainTitle, text: strings.blah_IdentityWizard_DomainText,
            placeholder: strings.blah_IdentityWizard_DomainPlaceholder, primary: strings.Login_Continue))
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            let domain = page.node.value
            switch self.action {
            case .words:
                do { self.showWordsEntry(domain: try BlahProfileHost.domain(domain).name, on: page) }
                catch { page.node.setStatus(blahIdentityErrorDescription(error), error: true) }
            case .qr:
                self.showQR(domain: domain, homeDomain: home.domain)
            case .create, .cloud:
                self.run(on: page, work: { try await BlahIdentityStore.shared.probe(domain: domain, home: home) }, completed: { [weak self, weak page] result in
                    guard let self else { return }
                    switch result {
                    case let .available(domain): self.showMint(domain: domain, home: home)
                    case .existing: page?.node.setStatus(self.strings.blah_IdentityWizard_NameTaken, error: true)
                    }
                })
            }
        }
    }

    private func showWordsEntry(domain: String, on page: IdentityWizardPageController) {
        let input = WalletRecoveryWordsInput(validate: { (try? IdentitySeed(phrase: $0.joined(separator: " "))) != nil }, completed: { [weak self, weak page] words in
            guard let self, let page else { return }
            _ = self.navigation?.popViewController(animated: false)
            self.run(on: page, work: { [network = self.network] in
                try await BlahIdentityStore.shared.restoreWords(words, domain: domain, slot: network.blahIdentitySlot)
            }, completed: { [weak self] identity in self?.ready(id: identity.id) })
        })
        navigation?.pushViewController(WalletImportScreen(sharedContext: sharedContext, recovery: input))
    }

    private func showMint(domain: String, home: BlahHome) {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_MintTitle,
            text: strings.blah_IdentityWizard_MintText(domain).string, primary: strings.blah_IdentityWizard_Mint, mintOptions: true))
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            self.run(on: page, work: { try await BlahIdentityStore.shared.generateWords() }, completed: { [weak self, weak page] words in
                guard let self, let page else { return }
                let screen = WalletWordsScreen(sharedContext: self.sharedContext, words: words,
                    verification: { [sharedContext = self.sharedContext] completed in
                        WalletImportScreen(sharedContext: sharedContext,
                            recovery: WalletRecoveryWordsInput(validate: { _ in true }, completed: { _ in }), verifying: words, completion: completed)
                    }, completion: { [weak self, weak page] in
                        guard let self, let page else { return }
                        let biometrics = page.node.biometrics
                        let sync = page.node.sync
                        self.run(on: page, work: { [network = self.network] in
                            try await BlahIdentityStore.shared.mint(words: words, domain: domain, slot: network.blahIdentitySlot,
                                home: home, biometrics: biometrics, sync: sync)
                        }, completed: { [weak self] result in
                            switch result.publication {
                            case .published: self?.ready(id: result.id)
                            case let .manual(profile, url): self?.showPublication(id: result.id, profile: profile, url: url)
                            }
                        })
                    })
                self.navigation?.pushViewController(screen)
            })
        }
    }

    private func showPublication(id: String, profile: Data, url: String, hosted: Bool = false) {
        let page = publicationPage(profile: profile, url: url, hosted: hosted)
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            self.run(on: page, work: {
                if hosted { try await BlahIdentityStore.shared.retryPublication(slot: self.network.blahIdentitySlot) }
                else { try await BlahIdentityStore.shared.confirmPublication(slot: self.network.blahIdentitySlot) }
            }, completed: { [weak self] in self?.ready(id: id) })
        }
    }

    private func publicationPage(profile: Data, url: String, hosted: Bool = false, replacing: Bool = false) -> IdentityWizardPageController {
        let page = push(IdentityWizardPage(title: strings.blah_IdentityWizard_PublishTitle,
            text: (hosted ? strings.blah_IdentityWizard_HostedPublishText : strings.blah_IdentityWizard_PublishText) + "\n\n" + url,
            primary: hosted ? strings.blah_IdentityWizard_RetryPublication : strings.blah_IdentityWizard_Uploaded,
            auxiliary: hosted ? nil : strings.blah_IdentityWizard_Share), replacing: replacing)
        page.node.auxiliary = { [weak self, weak page] in if let page { self?.share(profile, from: page) } }
        return page
    }

    func showPendingPublication(_ pending: BlahPendingPublication, published: Bool, error: String?) {
        let page = publicationPage(profile: pending.profile, url: pending.url, hosted: pending.hostingDomain != nil, replacing: true)
        page.node.setStatus(error, error: true)
        if published {
            configurePublicationRefresh(on: page, id: pending.id)
        } else {
            page.node.primary = { [weak self, weak page] in
                guard let self, let page else { return }
                self.run(on: page, work: { () async throws -> BlahPendingPublication? in
                    if let current = try await BlahIdentityStore.shared.pendingPublication(slot: self.network.blahIdentitySlot), current.profile != pending.profile {
                        return current
                    }
                    if pending.hostingDomain != nil { try await BlahIdentityStore.shared.retryPublication(slot: self.network.blahIdentitySlot) }
                    else { try await BlahIdentityStore.shared.confirmPublication(slot: self.network.blahIdentitySlot) }
                    return nil
                }, completed: { [weak self, weak page] renewed in
                    guard let self, let page else { return }
                    if let renewed { self.showPendingPublication(renewed, published: false, error: nil); return }
                    self.configurePublicationRefresh(on: page, id: pending.id)
                    self.refreshPublication(on: page, id: pending.id, allowUnlock: false)
                })
            }
        }
    }

    private func configurePublicationRefresh(on page: IdentityWizardPageController, id: String) {
        page.node.setPrimaryTitle(strings.blah_IdentityWizard_RetryPublication)
        page.node.primary = { [weak self, weak page] in
            guard let self, let page else { return }
            self.refreshPublication(on: page, id: id, allowUnlock: true)
        }
    }

    private func refreshPublication(on page: IdentityWizardPageController, id: String, allowUnlock: Bool) {
        run(on: page, work: { [self] () async throws -> BlahPendingPublication? in
            if !refreshAfterPublication {
                return try await BlahIdentityStore.shared.pendingPublication(slot: network.blahIdentitySlot)
            }
            do {
                return try await refreshIdentityPublication(network: network, id: id, allowUnlock: allowUnlock)
            } catch {
                throw IdentityPublicationFailure(message: strings.blah_IdentityWizard_RefreshFailed(error.localizedDescription).string)
            }
        }, completed: { [weak self] pending in
            guard let self else { return }
            if let pending { self.showPendingPublication(pending, published: false, error: nil) }
            else { self.finish(.saved(id)) }
        })
        if page.node.busy { page.node.setStatus(refreshAfterPublication ? strings.blah_IdentityWizard_Refreshing : strings.blah_Identity_Working) }
    }

    private func ready(id: String) {
        guard isLogin else { finish(.saved(id)); return }
        guard let page = current else { return }
        run(on: page, work: { [network] in try await BlahIdentityStore.shared.pendingPublication(slot: network.blahIdentitySlot) }, completed: { [weak self, weak page] pending in
            guard let self, let page else { return }
            if let pending {
                self.showPublication(id: pending.id, profile: pending.profile, url: pending.url, hosted: pending.hostingDomain != nil)
            } else {
                self.run(on: page, work: { [network = self.network] in try await BlahIdentityStore.shared.bind(slot: network.blahIdentitySlot) }, completed: { [weak self] domain in
                    guard let self else { return }
                    self.signIn?(domain)
                    self.finish(.signedIn)
                })
            }
        })
    }

    func showQR(domain: String?, homeDomain: String) {
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

    private func startQR(on page: IdentityWizardPageController, domain: String?, homeDomain: String) {
        stopWork()
        page.node.primaryHidden = true
        page.node.setStatus(strings.blah_Identity_Working)
        run(on: page, work: { [network] in
            try await network.connectBlahHome(domain: homeDomain)
        }, completed: { [weak self, weak page] in
            guard let self, let page else { return }
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

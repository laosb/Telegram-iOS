import Foundation
import BlahIdentity
import BlahIdentityUI
import UIKit
import AsyncDisplayKit
import Display
import TelegramCore
import TelegramPresentationData
import SolidRoundedButtonNode
import AuthorizationUtils

// The controller also owns Settings' change-number flow. Keep its original view
// behind this interface so the Blah login UI can evolve independently.
protocol AuthorizationPhoneEntryNode: AnyObject {
    var currentNumber: String { get }
    var codeAndNumber: (Int32?, String?, String) { get set }
    var formattedCodeAndNumber: (String, String) { get }
    var syncContacts: Bool { get }
    var inProgress: Bool { get set }
    var codeNode: ASDisplayNode { get }
    var numberNode: ASDisplayNode { get }
    var buttonNode: ASDisplayNode { get }
    var accountUpdated: ((UnauthorizedAccount) -> Void)? { get set }
    var retryPasskey: (() -> Void)? { get set }
    var selectCountryCode: (() -> Void)? { get set }
    var checkPhone: (() -> Void)? { get set }
    func updateCountryCode()
    func updateDisplayPasskeyLoginOption()
    func activateInput()
    func animateError()
    func willAnimateIn(buttonFrame: CGRect, buttonTitle: String, animationSnapshot: UIView, textSnapshot: UIView)
    func animateIn(buttonFrame: CGRect, buttonTitle: String, animationSnapshot: UIView, textSnapshot: UIView)
    func containerLayoutUpdated(_ layout: ContainerViewLayout, navigationBarHeight: CGFloat, transition: ContainedViewLayoutTransition)
}

final class BlahAuthorizationEntryNode: ASDisplayNode, AuthorizationPhoneEntryNode {
    private let strings: PresentationStrings
    private let theme: PresentationTheme
    private(set) var homeConnected = false
    private let logoNode = ASImageNode()
    private let titleNode = ImmediateTextNode()
    private let noticeNode = ImmediateTextNode()
    private let proceedNode: SolidRoundedButtonNode
    private let scrollNode = ASDisplayNode(viewBlock: { UIScrollView() })
    private var actionNodes: [SolidRoundedButtonNode] = []
    private var validLayout: (ContainerViewLayout, CGFloat)?
    var action: ((BlahAuthorizationAction) -> Void)?
    private let debugAction: () -> Void

    var accountUpdated: ((UnauthorizedAccount) -> Void)?
    var retryPasskey: (() -> Void)?
    var selectCountryCode: (() -> Void)?
    var checkPhone: (() -> Void)?

    var currentNumber: String { return "" }

    var codeAndNumber: (Int32?, String?, String) {
        get { return (999, nil, "") }
        set {}
    }

    let syncContacts = false
    var formattedCodeAndNumber: (String, String) { return ("", "") }
    var codeNode: ASDisplayNode { return self.proceedNode }
    var numberNode: ASDisplayNode { return self.proceedNode }
    var buttonNode: ASDisplayNode { return self.proceedNode }

    var inProgress = false {
        didSet {
            if self.inProgress != oldValue {
                if self.inProgress {
                    self.proceedNode.transitionToProgress()
                } else {
                    self.proceedNode.transitionFromProgress()
                }
            }
            self.textChanged()
        }
    }

    init(strings: PresentationStrings, theme: PresentationTheme, debugAction: @escaping () -> Void) {
        self.strings = strings
        self.theme = theme
        self.debugAction = debugAction
        self.proceedNode = SolidRoundedButtonNode(title: strings.Login_Continue, theme: SolidRoundedButtonTheme(theme: theme), glass: false, height: 50.0, cornerRadius: 25.0)
        super.init()

        self.setViewBlock({ UITracingLayerView() })
        self.backgroundColor = theme.list.plainBackgroundColor

        self.logoNode.image = UIImage(bundleImageName: "Blah/LoginLogo")
        self.logoNode.contentMode = .scaleAspectFit
        self.logoNode.isAccessibilityElement = false
        self.titleNode.attributedText = NSAttributedString(string: strings.blah_Login_Title, font: Font.bold(28.0), textColor: theme.list.itemPrimaryTextColor, paragraphAlignment: .center)
        self.titleNode.maximumNumberOfLines = 0
        self.titleNode.isAccessibilityElement = true
        self.titleNode.accessibilityLabel = strings.blah_Login_Title
        self.titleNode.accessibilityTraits = .header
        self.noticeNode.attributedText = NSAttributedString(string: strings.blah_IdentityWizard_HomeText, font: Font.regular(17.0), textColor: theme.list.itemPrimaryTextColor, paragraphAlignment: .center)
        self.noticeNode.maximumNumberOfLines = 0
        self.noticeNode.isAccessibilityElement = true
        self.noticeNode.accessibilityLabel = strings.blah_Login_Subtitle

        self.proceedNode.progressType = .embedded
        self.proceedNode.isEnabled = true
        self.proceedNode.accessibilityIdentifier = "Auth.PhoneEntry.ContinueButton"
        self.proceedNode.pressed = { [weak self] in self?.submit() }

        self.addSubnode(self.scrollNode)
        for node in [self.logoNode, self.titleNode, self.noticeNode, self.proceedNode] as [ASDisplayNode] {
            self.scrollNode.addSubnode(node)
        }
        let scroll = self.scrollNode.view as! UIScrollView
        scroll.contentInsetAdjustmentBehavior = .never
        func button(_ title: String, action: BlahAuthorizationAction) {
            let node = SolidRoundedButtonNode(title: title, theme: SolidRoundedButtonTheme(theme: theme), glass: false, height: 50.0, cornerRadius: 25.0)
            node.pressed = { [weak self] in guard let self, !self.inProgress else { return }; self.action?(action) }
            self.actionNodes.append(node)
            self.scrollNode.addSubnode(node)
        }
        button(strings.blah_Login_Words, action: .words)
        button(strings.blah_Login_QR, action: .qr)
        self.actionNodes.forEach { $0.isHidden = true }
        Task { @MainActor [weak self] in
            let identities = (try? await BlahIdentityStore.shared.cloudIdentities()) ?? []
            guard let self else { return }
            for identity in identities {
                let node = SolidRoundedButtonNode(title: strings.blah_Login_Cloud(identity.domain).string,
                    theme: SolidRoundedButtonTheme(theme: theme), glass: false, height: 50.0, cornerRadius: 25.0)
                node.pressed = { [weak self] in guard let self, !self.inProgress else { return }; self.action?(.cloud(id: identity.id)) }
                node.isHidden = !self.homeConnected
                self.actionNodes.append(node)
                self.scrollNode.addSubnode(node)
            }
            if let (layout, height) = self.validLayout { self.containerLayoutUpdated(layout, navigationBarHeight: height, transition: .immediate) }
        }
    }

    func setHome(_ domain: String) {
        self.homeConnected = true
        self.proceedNode.title = self.strings.blah_Login_Create
        self.noticeNode.attributedText = NSAttributedString(string: domain, font: Font.regular(17.0), textColor: self.theme.list.itemPrimaryTextColor, paragraphAlignment: .center)
        self.noticeNode.accessibilityLabel = domain
        self.actionNodes.forEach { $0.isHidden = false }
        if let (layout, height) = self.validLayout { self.containerLayoutUpdated(layout, navigationBarHeight: height, transition: .immediate) }
    }

    override func didLoad() {
        super.didLoad()
        let debugTap = UITapGestureRecognizer(target: self, action: #selector(self.openDebug))
        debugTap.numberOfTapsRequired = 10
        self.titleNode.isUserInteractionEnabled = true
        self.titleNode.view.addGestureRecognizer(debugTap)
    }

    @objc private func openDebug() { self.debugAction() }

    private func textChanged() {
        self.proceedNode.isEnabled = !self.inProgress
    }

    private func submit() {
        guard !self.inProgress else { return }
        self.checkPhone?()
    }

    func activateInput() {}
    func animateError() {}

    // Country updates and phone/passkey copy must not replace the Blah form.
    func updateCountryCode() {}
    func updateDisplayPasskeyLoginOption() {}
    func willAnimateIn(buttonFrame: CGRect, buttonTitle: String, animationSnapshot: UIView, textSnapshot: UIView) {}
    func animateIn(buttonFrame: CGRect, buttonTitle: String, animationSnapshot: UIView, textSnapshot: UIView) {}

    func containerLayoutUpdated(_ layout: ContainerViewLayout, navigationBarHeight: CGFloat, transition: ContainedViewLayoutTransition) {
        self.validLayout = (layout, navigationBarHeight)
        let top = max(navigationBarHeight, layout.statusBarHeight ?? 0.0)
        transition.updateFrame(node: self.scrollNode, frame: CGRect(x: 0, y: top, width: layout.size.width, height: layout.size.height - top))
        let width = min(430.0, layout.size.width - layout.safeInsets.left - layout.safeInsets.right) - 48.0
        let x = floorToScreenPixels((layout.size.width - width) / 2.0)
        var y: CGFloat = 24
        let available = CGSize(width: width, height: .greatestFiniteMagnitude)
        let titleSize = self.titleNode.updateLayout(available)
        let noticeSize = self.noticeNode.updateLayout(available)
        transition.updateFrame(node: self.logoNode, frame: CGRect(x: floor((layout.size.width - 100) / 2), y: y, width: 100, height: 100))
        y += 118
        for (node, size) in [(self.titleNode, titleSize), (self.noticeNode, noticeSize)] {
            transition.updateFrame(node: node, frame: CGRect(x: x, y: y, width: width, height: size.height))
            y += size.height + 18
        }
        for node in [self.proceedNode] + (self.homeConnected ? self.actionNodes : []) {
            let height = node.updateLayout(width: width, transition: transition)
            transition.updateFrame(node: node, frame: CGRect(x: x, y: y, width: width, height: height))
            y += height + 12
        }
        (self.scrollNode.view as! UIScrollView).contentSize = CGSize(width: layout.size.width, height: y + layout.safeInsets.bottom + 24)
    }
}

import Foundation
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

final class BlahAuthorizationEntryNode: ASDisplayNode, AuthorizationPhoneEntryNode, UITextFieldDelegate {
    private let logoNode = ASImageNode()
    private let titleNode = ImmediateTextNode()
    private let noticeNode = ImmediateTextNode()
    private let inputNode = TextFieldNode()
    private let separatorNode = ASDisplayNode()
    private let proceedNode: SolidRoundedButtonNode
    private let debugAction: () -> Void

    var accountUpdated: ((UnauthorizedAccount) -> Void)?
    var retryPasskey: (() -> Void)?
    var selectCountryCode: (() -> Void)?
    var checkPhone: (() -> Void)?

    var currentNumber: String {
        let value = (self.inputNode.textField.text ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        // Only bare ASCII-digit numbers get the fixed +999 prefix. Preserve
        // all other identifiers and numbers that already include the prefix.
        if value.isEmpty || !value.utf8.allSatisfy({ $0 >= 48 && $0 <= 57 }) || value.hasPrefix("999") {
            return value
        }
        return "+999" + value
    }

    var codeAndNumber: (Int32?, String?, String) {
        get { return (999, nil, self.currentNumber) }
        set {
            self.inputNode.textField.text = newValue.2
            self.textChanged()
        }
    }

    let syncContacts = false
    var formattedCodeAndNumber: (String, String) { return ("", self.currentNumber) }
    var codeNode: ASDisplayNode { return self.inputNode }
    var numberNode: ASDisplayNode { return self.inputNode }
    var buttonNode: ASDisplayNode { return self.proceedNode }

    var inProgress = false {
        didSet {
            self.inputNode.textField.isEnabled = !self.inProgress
            self.inputNode.alpha = self.inProgress ? 0.6 : 1.0
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
        self.debugAction = debugAction
        self.proceedNode = SolidRoundedButtonNode(title: strings.blah_Login_Continue, theme: SolidRoundedButtonTheme(theme: theme), glass: false, height: 50.0, cornerRadius: 25.0)
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
        self.noticeNode.attributedText = NSAttributedString(string: strings.blah_Login_Subtitle, font: Font.regular(17.0), textColor: theme.list.itemPrimaryTextColor, paragraphAlignment: .center)
        self.noticeNode.maximumNumberOfLines = 0
        self.noticeNode.isAccessibilityElement = true
        self.noticeNode.accessibilityLabel = strings.blah_Login_Subtitle

        let field = self.inputNode.textField
        field.font = Font.regular(20.0)
        field.textColor = theme.list.itemPrimaryTextColor
        field.textAlignment = .natural
        field.tintColor = theme.list.itemAccentColor
        field.keyboardAppearance = theme.rootController.keyboardColor.keyboardAppearance
        field.keyboardType = .emailAddress
        field.autocapitalizationType = .none
        field.autocorrectionType = .no
        field.spellCheckingType = .no
        field.textContentType = .username
        field.returnKeyType = .continue
        field.enablesReturnKeyAutomatically = true
        field.placeholder = strings.blah_Login_Placeholder
        field.accessibilityLabel = strings.blah_Login_Placeholder
        field.accessibilityIdentifier = "Auth.BlahEntry.IdentifierField"
        field.disableAutomaticKeyboardHandling = [.forward, .backward]
        field.delegate = self
        field.addTarget(self, action: #selector(self.textChanged), for: .editingChanged)

        self.separatorNode.isLayerBacked = true
        self.separatorNode.backgroundColor = theme.list.itemPlainSeparatorColor
        self.proceedNode.progressType = .embedded
        self.proceedNode.isEnabled = false
        self.proceedNode.accessibilityIdentifier = "Auth.PhoneEntry.ContinueButton"
        self.proceedNode.pressed = { [weak self] in self?.submit() }

        for node in [self.logoNode, self.titleNode, self.noticeNode, self.inputNode, self.separatorNode, self.proceedNode] as [ASDisplayNode] {
            self.addSubnode(node)
        }
    }

    override func didLoad() {
        super.didLoad()
        let debugTap = UITapGestureRecognizer(target: self, action: #selector(self.openDebug))
        debugTap.numberOfTapsRequired = 10
        self.titleNode.isUserInteractionEnabled = true
        self.titleNode.view.addGestureRecognizer(debugTap)
    }

    @objc private func openDebug() { self.debugAction() }

    @objc private func textChanged() {
        self.proceedNode.isEnabled = !self.inProgress && !self.currentNumber.isEmpty
    }

    private func submit() {
        guard !self.inProgress, !self.currentNumber.isEmpty else { return }
        self.checkPhone?()
    }

    func textFieldShouldReturn(_ textField: UITextField) -> Bool {
        self.submit()
        return false
    }

    func activateInput() { self.inputNode.textField.becomeFirstResponder() }
    func animateError() { self.inputNode.layer.addShakeAnimation() }

    // Country updates and phone/passkey copy must not replace the Blah form.
    func updateCountryCode() {}
    func updateDisplayPasskeyLoginOption() {}
    func willAnimateIn(buttonFrame: CGRect, buttonTitle: String, animationSnapshot: UIView, textSnapshot: UIView) {}
    func animateIn(buttonFrame: CGRect, buttonTitle: String, animationSnapshot: UIView, textSnapshot: UIView) {
        self.layer.animateAlpha(from: 0.0, to: 1.0, duration: 0.25)
    }

    func containerLayoutUpdated(_ layout: ContainerViewLayout, navigationBarHeight: CGFloat, transition: ContainedViewLayoutTransition) {
        let insets = layout.insets(options: [])
        let top = max(navigationBarHeight, layout.statusBarHeight ?? 0.0)
        let bottom = max(insets.bottom, layout.inputHeight ?? 0.0)
        let width = min(430.0, layout.size.width - layout.safeInsets.left - layout.safeInsets.right) - 48.0
        let availableSize = CGSize(width: width, height: .greatestFiniteMagnitude)
        let titleSize = self.titleNode.updateLayout(availableSize)
        let noticeSize = self.noticeNode.updateLayout(availableSize)
        let buttonHeight = self.proceedNode.updateLayout(width: width, transition: transition)
        let buttonY = layout.size.height - bottom - buttonHeight - 24.0
        transition.updateFrame(node: self.proceedNode, frame: CGRect(x: floorToScreenPixels((layout.size.width - width) / 2.0), y: buttonY, width: width, height: buttonHeight))

        var items: [AuthorizationLayoutItem] = []
        // Make room for the field and Continue on small screens with a keyboard.
        let showLogo = buttonY - top > titleSize.height + noticeSize.height + 190.0
        self.logoNode.isHidden = !showLogo
        if showLogo {
            items.append(AuthorizationLayoutItem(node: self.logoNode, size: CGSize(width: 100.0, height: 100.0), spacingBefore: AuthorizationLayoutItemSpacing(weight: 10.0, maxValue: 10.0), spacingAfter: AuthorizationLayoutItemSpacing(weight: 0.0, maxValue: 0.0)))
        }
        for (node, size, spacing) in [(self.titleNode as ASDisplayNode, titleSize, CGFloat(18.0)), (self.noticeNode as ASDisplayNode, noticeSize, CGFloat(18.0))] {
            items.append(AuthorizationLayoutItem(node: node, size: size, spacingBefore: AuthorizationLayoutItemSpacing(weight: spacing, maxValue: spacing), spacingAfter: AuthorizationLayoutItemSpacing(weight: 0.0, maxValue: 0.0)))
        }
        // Match AuthorizationSequenceEmailEntryControllerNode's field and underline.
        items.append(AuthorizationLayoutItem(node: self.inputNode, size: CGSize(width: width - 40.0, height: 44.0), spacingBefore: AuthorizationLayoutItemSpacing(weight: 18.0, maxValue: 30.0), spacingAfter: AuthorizationLayoutItemSpacing(weight: 0.0, maxValue: 0.0)))
        items.append(AuthorizationLayoutItem(node: self.separatorNode, size: CGSize(width: width, height: UIScreenPixel), spacingBefore: AuthorizationLayoutItemSpacing(weight: 0.0, maxValue: 0.0), spacingAfter: AuthorizationLayoutItemSpacing(weight: 0.0, maxValue: 0.0)))
        let _ = layoutAuthorizationItems(bounds: CGRect(x: 0.0, y: top, width: layout.size.width, height: max(0.0, buttonY - top - 16.0)), items: items, transition: transition, failIfDoesNotFit: false)
    }
}

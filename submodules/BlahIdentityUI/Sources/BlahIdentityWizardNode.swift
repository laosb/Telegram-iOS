import Foundation
import UIKit
import AsyncDisplayKit
import Display
import PresentationDataUtils
import TelegramPresentationData
import SolidRoundedButtonNode

struct IdentityWizardPage {
    var title: String
    var text: String
    var placeholder: String? = nil
    var value = ""
    var primary: String
    var secondary: String? = nil
    var auxiliary: String? = nil
    var mintOptions = false
    var qr = false
}

final class BlahIdentityWizardNode: ASDisplayNode, UITextFieldDelegate {
    private let scrollNode = ASDisplayNode(viewBlock: { UIScrollView() })
    private let titleNode = ImmediateTextNode()
    private let textNode = ImmediateTextNode()
    private let fieldNode = ASDisplayNode(viewBlock: { UITextField() })
    private let lineNode = ASDisplayNode()
    private let imageNode = ASImageNode()
    private let syncLabel = ImmediateTextNode()
    private let biometricLabel = ImmediateTextNode()
    private let syncNode = ASDisplayNode(viewBlock: { UISwitch() })
    private let biometricNode = ASDisplayNode(viewBlock: { UISwitch() })
    private let footerNode = ImmediateTextNode()
    private let statusNode = ImmediateTextNode()
    private let primaryNode: SolidRoundedButtonNode
    private let secondaryNode = HighlightableButtonNode()
    private let auxiliaryNode = HighlightableButtonNode()
    private let page: IdentityWizardPage
    private let theme: PresentationTheme
    private var validLayout: (ContainerViewLayout, CGFloat)?
    var primary: (() -> Void)?
    var secondary: (() -> Void)?
    var auxiliary: (() -> Void)?
    var value: String {
        get { (fieldNode.view as! UITextField).text ?? "" }
        set { (fieldNode.view as! UITextField).text = newValue; updateEnabled() }
    }
    var sync: Bool { (syncNode.view as! UISwitch).isOn }
    var biometrics: Bool { (biometricNode.view as! UISwitch).isOn }
    var primaryHidden = false { didSet { relayout() } }
    var busy = false {
        didSet {
            if busy != oldValue {
                if busy { primaryNode.transitionToProgress() } else { primaryNode.transitionFromProgress() }
            }
            fieldNode.isUserInteractionEnabled = !busy
            syncNode.isUserInteractionEnabled = !busy
            biometricNode.isUserInteractionEnabled = !busy
            secondaryNode.isUserInteractionEnabled = !busy
            auxiliaryNode.isUserInteractionEnabled = !busy
            updateEnabled()
        }
    }

    init(page: IdentityWizardPage, presentationData: PresentationData) {
        self.page = page
        self.theme = presentationData.theme
        self.primaryNode = SolidRoundedButtonNode(title: page.primary, theme: SolidRoundedButtonTheme(theme: presentationData.theme), glass: false, height: 50.0, cornerRadius: 25.0)
        super.init()
        self.setViewBlock({ UITracingLayerView() })
        self.backgroundColor = theme.list.plainBackgroundColor
        let scroll = scrollNode.view as! UIScrollView
        scroll.keyboardDismissMode = .interactive
        scroll.alwaysBounceVertical = false
        scroll.contentInsetAdjustmentBehavior = .never
        for (node, text, size, bold) in [(titleNode, page.title, CGFloat(28.0), true), (textNode, page.text, CGFloat(17.0), false),
            (syncLabel, presentationData.strings.blah_IdentityWizard_Sync, CGFloat(16.0), false),
            (biometricLabel, presentationData.strings.blah_IdentityWizard_FaceID, CGFloat(16.0), false),
            (footerNode, presentationData.strings.blah_Identity_SyncNotice, CGFloat(13.0), false)] {
            node.maximumNumberOfLines = 0
            node.attributedText = NSAttributedString(string: text, font: bold ? Font.bold(size) : Font.regular(size),
                textColor: node === footerNode ? theme.list.itemSecondaryTextColor : theme.list.itemPrimaryTextColor,
                paragraphAlignment: node === syncLabel || node === biometricLabel ? .left : .center)
            node.isAccessibilityElement = true
            node.accessibilityLabel = text
        }
        titleNode.accessibilityTraits = .header
        let field = fieldNode.view as! UITextField
        field.font = Font.regular(20.0)
        field.textColor = theme.list.itemPrimaryTextColor
        field.tintColor = theme.list.itemAccentColor
        field.attributedPlaceholder = NSAttributedString(string: page.placeholder ?? "", font: Font.regular(20.0), textColor: theme.list.itemPlaceholderTextColor)
        field.text = page.value
        field.accessibilityLabel = page.placeholder
        field.keyboardType = .URL
        field.returnKeyType = .continue
        field.autocapitalizationType = .none
        field.autocorrectionType = .no
        field.clearButtonMode = .whileEditing
        field.delegate = self
        field.addTarget(self, action: #selector(textChanged), for: .editingChanged)
        lineNode.backgroundColor = theme.list.itemPlainSeparatorColor
        let syncSwitch = syncNode.view as! UISwitch
        syncSwitch.isOn = true
        syncSwitch.accessibilityLabel = presentationData.strings.blah_IdentityWizard_Sync
        (biometricNode.view as! UISwitch).accessibilityLabel = presentationData.strings.blah_IdentityWizard_FaceID
        imageNode.contentMode = .scaleAspectFit
        imageNode.backgroundColor = .white
        imageNode.isAccessibilityElement = true
        imageNode.accessibilityLabel = presentationData.strings.blah_IdentityWizard_QRTitle
        primaryNode.progressType = .embedded
        primaryNode.pressed = { [weak self] in self?.submit() }
        secondaryNode.setTitle(page.secondary ?? "", with: Font.regular(17.0), with: theme.list.itemAccentColor, for: .normal)
        auxiliaryNode.setTitle(page.auxiliary ?? "", with: Font.regular(17.0), with: theme.list.itemAccentColor, for: .normal)
        secondaryNode.addTarget(self, action: #selector(secondaryPressed), forControlEvents: .touchUpInside)
        auxiliaryNode.addTarget(self, action: #selector(auxiliaryPressed), forControlEvents: .touchUpInside)
        statusNode.maximumNumberOfLines = 0
        addSubnode(scrollNode)
        for node in [titleNode, textNode, fieldNode, lineNode, imageNode, syncLabel, biometricLabel, syncNode, biometricNode, footerNode, auxiliaryNode, statusNode] as [ASDisplayNode] {
            scrollNode.addSubnode(node)
        }
        addSubnode(primaryNode)
        addSubnode(secondaryNode)
        updateEnabled()
    }

    func activateInput() { if page.placeholder != nil { fieldNode.view.becomeFirstResponder() } }
    func setQRImage(_ image: UIImage?) { imageNode.image = image }
    func setStatus(_ text: String?, error: Bool = false) {
        statusNode.attributedText = text.map { NSAttributedString(string: $0, font: Font.regular(15.0),
            textColor: error ? theme.list.itemDestructiveColor : theme.list.itemSecondaryTextColor, paragraphAlignment: .center) }
        statusNode.isAccessibilityElement = text != nil
        statusNode.accessibilityLabel = text
        relayout()
    }
    @objc private func textChanged() { updateEnabled() }
    @objc private func secondaryPressed() { if !busy { secondary?() } }
    @objc private func auxiliaryPressed() { if !busy { auxiliary?() } }
    private func submit() { if primaryNode.isEnabled { primary?() } }
    func textFieldShouldReturn(_ textField: UITextField) -> Bool { submit(); return true }
    private func updateEnabled() {
        primaryNode.isEnabled = !busy && (page.placeholder == nil || !value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    }
    private func relayout() {
        if let (layout, height) = validLayout { containerLayoutUpdated(layout, navigationBarHeight: height, transition: .immediate) }
    }

    func containerLayoutUpdated(_ layout: ContainerViewLayout, navigationBarHeight: CGFloat, transition: ContainedViewLayoutTransition) {
        validLayout = (layout, navigationBarHeight)
        let top = max(navigationBarHeight, layout.statusBarHeight ?? 0.0)
        let bottom = max(layout.insets(options: []).bottom, layout.inputHeight ?? 0.0)
        let width = max(1.0, min(430.0, layout.size.width - layout.safeInsets.left - layout.safeInsets.right) - 48.0)
        let x = floorToScreenPixels((layout.size.width - width) / 2.0)
        let buttonHeight = primaryNode.updateLayout(width: width, transition: transition)
        let secondaryHeight: CGFloat = page.secondary == nil ? 0.0 : 44.0
        let buttonY = layout.size.height - bottom - 24.0 - secondaryHeight - (primaryHidden ? 0.0 : buttonHeight)
        primaryNode.isHidden = primaryHidden
        transition.updateFrame(node: primaryNode, frame: CGRect(x: x, y: buttonY, width: width, height: buttonHeight))
        secondaryNode.isHidden = page.secondary == nil
        transition.updateFrame(node: secondaryNode, frame: CGRect(x: x, y: buttonY + (primaryHidden ? 0.0 : buttonHeight), width: width, height: secondaryHeight))
        let viewportHeight = max(0.0, buttonY - top - 16.0)
        transition.updateFrame(node: scrollNode, frame: CGRect(x: 0.0, y: top, width: layout.size.width, height: viewportHeight))
        var y: CGFloat = viewportHeight > 480.0 ? 52.0 : 16.0
        func text(_ node: ImmediateTextNode, width: CGFloat, x: CGFloat, spacing: CGFloat = 20.0) {
            let size = node.updateLayout(CGSize(width: width, height: .greatestFiniteMagnitude))
            transition.updateFrame(node: node, frame: CGRect(x: x, y: y, width: width, height: size.height))
            y += size.height + spacing
        }
        text(titleNode, width: width, x: x)
        text(textNode, width: width, x: x, spacing: 28.0)
        fieldNode.isHidden = page.placeholder == nil
        lineNode.isHidden = page.placeholder == nil
        if page.placeholder != nil {
            transition.updateFrame(node: fieldNode, frame: CGRect(x: x, y: y, width: width, height: 48.0))
            transition.updateFrame(node: lineNode, frame: CGRect(x: x, y: y + 48.0, width: width, height: UIScreenPixel))
            y += 68.0
        }
        imageNode.isHidden = !page.qr
        if page.qr {
            let size = min(240.0, width)
            transition.updateFrame(node: imageNode, frame: CGRect(x: floorToScreenPixels((layout.size.width - size) / 2.0), y: y, width: size, height: size))
            y += size + 24.0
        }
        for node in [syncLabel, biometricLabel, syncNode, biometricNode, footerNode] as [ASDisplayNode] { node.isHidden = !page.mintOptions }
        if page.mintOptions {
            for (label, toggle) in [(syncLabel, syncNode), (biometricLabel, biometricNode)] {
                let size = label.updateLayout(CGSize(width: width - 66.0, height: .greatestFiniteMagnitude))
                let height = max(44.0, size.height)
                transition.updateFrame(node: label, frame: CGRect(x: x, y: y + (height - size.height) / 2.0, width: width - 66.0, height: size.height))
                transition.updateFrame(node: toggle, frame: CGRect(x: x + width - 51.0, y: y + (height - 31.0) / 2.0, width: 51.0, height: 31.0))
                y += height + 12.0
            }
            text(footerNode, width: width, x: x)
        }
        auxiliaryNode.isHidden = page.auxiliary == nil
        if page.auxiliary != nil {
            transition.updateFrame(node: auxiliaryNode, frame: CGRect(x: x, y: y, width: width, height: 44.0))
            y += 56.0
        }
        text(statusNode, width: width, x: x, spacing: 12.0)
        (scrollNode.view as! UIScrollView).contentSize = CGSize(width: layout.size.width, height: y)
    }
}

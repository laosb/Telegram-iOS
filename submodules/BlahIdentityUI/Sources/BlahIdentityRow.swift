import Display
import ItemListUI
import TelegramPresentationData

struct IdentityRow: ItemListNodeEntry {
    enum Kind: Hashable {
        case header, text, removable, disclosure, `switch`, action
    }

    struct StableId: Hashable {
        let index: Int32
        let kind: Kind
    }

    let index: Int32
    let section: ItemListSectionId
    let title: String
    var detail: String? = nil
    var value: Bool? = nil
    var isText = false
    var isHeader = false
    var isDestructive = false
    var isEnabled = true
    var isRemovable = false
    private var kind: Kind {
        if isHeader { return .header }
        else if isText { return .text }
        else if isRemovable { return .removable }
        else if detail != nil { return .disclosure }
        else if value != nil { return .switch }
        else { return .action }
    }

    // ItemList updates same-id nodes in place; updateNode drops nodes of another item kind.
    var stableId: StableId { StableId(index: index, kind: kind) }

    static func <(lhs: IdentityRow, rhs: IdentityRow) -> Bool { lhs.index < rhs.index }

    func item(presentationData: ItemListPresentationData, arguments: Any) -> ListViewItem {
        let actions = arguments as! IdentityActions
        if isHeader {
            return ItemListSectionHeaderItem(presentationData: presentationData, text: title, sectionId: section)
        } else if isText {
            return ItemListTextItem(presentationData: presentationData, text: .plain(title), sectionId: section)
        } else if isRemovable {
            return ItemListCheckboxItem(presentationData: presentationData, systemStyle: .glass,
                title: title, subtitle: detail, subtitleNumberOfLines: 0, style: .right, checked: false,
                enabled: isEnabled, zeroSeparatorInsets: false, sectionId: section,
                action: { actions.invoke(self.index, nil) },
                deleteAction: isEnabled ? { actions.remove(self.index) } : nil)
        } else if let detail {
            return ItemListDisclosureItem(presentationData: presentationData, systemStyle: .glass,
                title: title, enabled: isEnabled, label: detail, labelStyle: .multilineDetailText,
                sectionId: section, style: .blocks, action: { actions.invoke(self.index, nil) })
        } else if let value {
            return ItemListSwitchItem(presentationData: presentationData, systemStyle: .glass,
                title: title, value: value, enabled: isEnabled, sectionId: section, style: .blocks,
                updated: { actions.invoke(self.index, $0) })
        } else {
            return ItemListActionItem(presentationData: presentationData, systemStyle: .glass,
                title: title, kind: !isEnabled ? .disabled : isDestructive ? .destructive : .generic,
                alignment: .natural, sectionId: section, style: .blocks, action: { actions.invoke(self.index, nil) })
        }
    }
}

final class IdentityActions {
    var invoke: (Int32, Bool?) -> Void = { _, _ in }
    var remove: (Int32) -> Void = { _ in }
}


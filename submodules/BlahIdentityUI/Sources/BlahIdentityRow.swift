import Display
import ItemListUI
import TelegramPresentationData

struct IdentityRow: ItemListNodeEntry {
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
                title: title, enabled: isEnabled, label: detail, labelStyle: .multilineDetailText,
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

final class IdentityActions {
    var invoke: (Int32, Bool?) -> Void = { _, _ in }
}


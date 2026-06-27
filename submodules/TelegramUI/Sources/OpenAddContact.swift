import Foundation
import TelegramCore
import Display
import AccountContext
import ShareController
import PeerInfoUI
import PhoneNumberFormat

func openAddContactImpl(context: AccountContext, peer: EnginePeer?, firstName: String = "", lastName: String = "", phoneNumber: String, label: String = "_$!<Mobile>!$_", present: @escaping (ViewController, Any?) -> Void, pushController: @escaping (ViewController) -> Void, completed: @escaping () -> Void = {}) {
    let controller = context.sharedContext.makeNewContactScreen(
        context: context,
        peer: peer,
        firstName: firstName.isEmpty ? nil : firstName,
        lastName: lastName.isEmpty ? nil : lastName,
        phoneNumber: cleanPhoneNumber(phoneNumber, removePlus: true),
        shareViaException: false,
        completion: { peer, stableId, contactData in
            if let peer = peer {
                if let infoController = context.sharedContext.makePeerInfoController(context: context, updatedPresentationData: nil, peer: peer, mode: .generic, avatarInitiallyExpanded: false, fromChat: false, requestsContext: nil) {
                    pushController(infoController)
                }
            } else if let stableId, let contactData {
                pushController(deviceContactInfoController(context: ShareControllerAppAccountContext(context: context), environment: ShareControllerAppEnvironment(sharedContext: context.sharedContext), subject: .vcard(nil, stableId, contactData), completed: nil, cancelled: nil))
            }
            completed()
        }
    )
    pushController(controller)
}

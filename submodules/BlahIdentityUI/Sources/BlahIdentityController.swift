import Foundation
import UIKit
import AccountContext
import BlahDiem
import WalletImportScreen
import BlahIdentity
import Display
import TelegramCore
import TelegramPresentationData

// Drop in-memory seeds on background; the Secure Enclave ACL is the unlock gate.
let identityBackgroundLock = NotificationCenter.default.addObserver(
    forName: UIApplication.didEnterBackgroundNotification, object: nil, queue: .main
) { _ in Task { await BlahIdentityStore.shared.lock() } }

public func blahIdentityController(network: Network, sharedContext: SharedAccountContext,
    presentationData: PresentationData) -> ViewController {
    _ = identityBackgroundLock
    return blahIdentityDetailsController(network: network, sharedContext: sharedContext, presentationData: presentationData)
}

public func blahEnterRecoveryWordsController(network: Network, sharedContext: SharedAccountContext, completed: @escaping () -> Void) -> ViewController {
    weak var weakController: ViewController?
    let input = WalletRecoveryWordsInput(validate: { (try? IdentitySeed(phrase: $0.joined(separator: " "))) != nil }, completed: { words in
        Task { @MainActor in
            do {
                _ = try await BlahIdentityStore.shared.enterRecoveryWords(words, slot: network.blahIdentitySlot)
                if let controller = weakController {
                    _ = (controller.navigationController as? NavigationController)?.popViewController(animated: true)
                }
                completed()
            } catch {
                let strings = sharedContext.currentPresentationData.with { $0 }.strings
                let alert = UIAlertController(title: strings.blah_Identity_RecoveryWords, message: blahIdentityErrorDescription(error), preferredStyle: .alert)
                alert.addAction(UIAlertAction(title: strings.Common_OK, style: .cancel))
                weakController?.present(alert, animated: true)
            }
        }
    })
    let controller = WalletImportScreen(sharedContext: sharedContext, recovery: input)
    weakController = controller
    return controller
}

public func presentBlahSignInError(_ error: String, sharedContext: SharedAccountContext, from controller: UIViewController,
    signIn: @escaping (String) -> Void) {
    let strings = sharedContext.currentPresentationData.with { $0 }.strings
    let alert: UIAlertController
    if error == "SIGNUP_EMAIL_REQUIRED" {
        alert = UIAlertController(title: strings.blah_Identity_AdmissionEmail,
            message: strings.blah_Identity_AdmissionNotice, preferredStyle: .alert)
        alert.addTextField { $0.keyboardType = .emailAddress; $0.autocapitalizationType = .none }
        alert.addAction(UIAlertAction(title: strings.Common_Cancel, style: .cancel))
        alert.addAction(UIAlertAction(title: strings.Login_Continue, style: .default) { [weak alert] _ in
            guard let email = alert?.textFields?.first?.text, !email.isEmpty else { return }
            signIn(email)
        })
    } else {
        alert = UIAlertController(title: strings.blah_Login_Title, message: error, preferredStyle: .alert)
        alert.addAction(UIAlertAction(title: strings.Common_OK, style: .cancel))
    }
    controller.present(alert, animated: true)
}

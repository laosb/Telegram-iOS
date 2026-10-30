import Foundation
import UIKit
import AccountContext
import BlahIdentity
import BlahDiem
import Display
import MtProtoKit
import SwiftSignalKit
import TelegramCore
import TelegramPresentationData

@MainActor private var publicationAccounts = Set<String>()
@MainActor private var publicationChecks = Set<String>()
@MainActor private var publicationRechecks: [String: () -> Void] = [:]

/// Publication prompts are once per launch; outstanding DC refreshes retry on every activation.
public func presentBlahPendingPublication(context: AccountContext, from controller: UIViewController) {
    guard context.sharedContext.applicationBindings.isMainApp else { return }
    Task { @MainActor [weak controller] in
        guard let currentController = controller,
            context.sharedContext.mainWindow?.viewController === currentController else { return }
        let network = context.account.network
        let slot = network.blahIdentitySlot
        guard publicationChecks.insert(slot).inserted else {
            publicationRechecks[slot] = { [weak controller] in
                guard let controller else { return }
                presentBlahPendingPublication(context: context, from: controller)
            }
            return
        }
        defer {
            publicationChecks.remove(slot)
            publicationRechecks.removeValue(forKey: slot)?()
        }
        _ = identityBackgroundLock
        do {
            // Retry best-effort numbering if the login attempt failed to save it.
            // A locked identity must not prevent publication of an already saved revision.
            try? await BlahIdentityStore.shared.number(slot: slot, account: context.account.peerId.id._internalGetInt64Value())
            guard var pending = try await BlahIdentityStore.shared.pendingPublication(slot: slot) else {
                if let id = try await BlahIdentityStore.shared.refreshPending(slot: slot) {
                    _ = try? await refreshIdentityPublication(network: network, id: id, allowUnlock: false)
                }
                return
            }
            guard !publicationAccounts.contains(slot) else { return }
            var published = false
            var message: String?
            if pending.hostingDomain != nil {
                do {
                    try await BlahIdentityStore.shared.retryPublication(id: pending.id)
                    published = true
                    if let renewed = try await refreshIdentityPublication(network: network, id: pending.id, allowUnlock: false) {
                        pending = renewed
                        published = false
                    } else { return }
                } catch {
                    message = published
                        ? context.sharedContext.currentPresentationData.with { $0 }.strings.blah_IdentityWizard_RefreshFailed(error.localizedDescription).string
                        : error.localizedDescription
                }
            }
            guard publicationRechecks[slot] == nil,
                let controller = controller as? NavigationController,
                context.sharedContext.mainWindow?.viewController === controller else { return }
            publicationAccounts.insert(slot)
            let overlay = identityPublicationController(network: network, sharedContext: context.sharedContext,
                presentationData: context.sharedContext.currentPresentationData.with { $0 },
                pending: pending, published: published, error: message)
            controller.presentOverlay(controller: overlay)
        } catch { /* The persisted work is retried on the next activation. */ }
    }
}

/// Returns the exact revision that must be published if unlocking or maintenance advanced it.
func refreshIdentityPublication(network: Network, id: String, allowUnlock: Bool) async throws -> BlahPendingPublication? {
    let store = BlahIdentityStore.shared
    let slot = network.blahIdentitySlot
    guard try await store.boundIdentityID(slot: slot) == id else { throw BlahIdentityError.wrongHome }
    if let pending = try await store.pendingPublication(slot: slot) { return pending }
    guard try await store.refreshPending(slot: slot) == id else {
        return try await store.pendingPublication(slot: slot)
    }
    if (try? await store.inspect(slot: slot))?.id != id {
        guard allowUnlock else { throw BlahIdentityError.locked }
        _ = try await store.unlock(id: id, slot: slot)
    }
    if let pending = try await store.pendingPublication(slot: slot) { return pending }
    let identity = try await store.inspect(slot: slot)
    guard identity.id == id else { throw BlahIdentityError.wrongHome }
    let profile = Data(identity.profile.encoding)
    try Task.checkCancellation()
    let refresh: Signal<String?, NoError> = network.blahRefreshPublishedProfile(profile: profile)
        |> map { _ -> String? in nil }
        |> then(.single(nil))
        |> `catch` { .single(identityPublicationRefreshError($0)) }
    let results = AsyncStream<String?> { continuation in
        let disposable = refresh.start(next: {
            continuation.yield($0)
            continuation.finish()
        })
        continuation.onTermination = { _ in disposable.dispose() }
    }
    var iterator = results.makeAsyncIterator()
    guard let error = await iterator.next() else { throw CancellationError() }
    try Task.checkCancellation()
    // Even a failed proof can race a renewal; publication takes precedence over refresh retry.
    if let pending = try await store.pendingPublication(slot: slot) { return pending }
    if let error { throw IdentityPublicationFailure(message: error) }
    guard try await store.boundIdentityID(slot: slot) == id else { throw BlahIdentityError.wrongHome }
    try await store.markRefreshed(id: id, profile: profile)
    if let pending = try await store.pendingPublication(slot: slot) { return pending }
    guard try await store.refreshPending(slot: slot) == nil else { throw BlahIdentityError.staleProfile }
    return try await store.pendingPublication(slot: slot)
}

struct IdentityPublicationFailure: LocalizedError {
    let message: String
    var errorDescription: String? { message }
}

func identityPublicationRefreshError(_ error: MTRpcError) -> String {
    let prefix = "BLAH_IDENTITY: "
    return error.errorDescription.hasPrefix(prefix) ? String(error.errorDescription.dropFirst(prefix.count)) : error.errorDescription
}

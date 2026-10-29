import Foundation
import UIKit
import BlahIdentity
import Display
import ItemListUI
import SwiftSignalKit
import TelegramCore
import TelegramPresentationData

private struct DeviceLinkRow: ItemListNodeEntry {
    let stableId: Int32
    let section: ItemListSectionId
    let title: String
    var value: Bool? = nil
    var isAction = false
    var enabled = true

    static func <(lhs: DeviceLinkRow, rhs: DeviceLinkRow) -> Bool { lhs.stableId < rhs.stableId }

    func item(presentationData: ItemListPresentationData, arguments: Any) -> ListViewItem {
        let actions = arguments as! DeviceLinkActions
        if let value {
            return ItemListSwitchItem(presentationData: presentationData, systemStyle: .glass,
                title: title, value: value, enabled: enabled, maximumNumberOfLines: 0, sectionId: section, style: .blocks,
                updated: { actions.invoke(self.stableId, $0) })
        } else if isAction {
            return ItemListActionItem(presentationData: presentationData, systemStyle: .glass,
                title: title, kind: enabled ? .generic : .disabled, alignment: .center,
                sectionId: section, style: .blocks, action: { actions.invoke(self.stableId, nil) })
        } else {
            return ItemListTextItem(presentationData: presentationData, text: .plain(title), sectionId: section)
        }
    }
}

private final class DeviceLinkActions {
    var invoke: (Int32, Bool?) -> Void = { _, _ in }
    var cancel: () -> Void = {}
}

public func blahDeviceLinkController(account: Account, url: String, presentationData: PresentationData,
    activeSessionsContext: ActiveSessionsContext, completion: @escaping (Bool) -> Void) -> ViewController {
    let coordinator = DeviceLinkCoordinator(account: account, url: url, presentationData: presentationData,
        activeSessionsContext: activeSessionsContext, completion: completion)
    let actions = DeviceLinkActions()
    actions.invoke = { [weak coordinator] id, value in coordinator?.invoke(id, value) }
    actions.cancel = { [weak coordinator] in coordinator?.close() }
    let presentation = ItemListPresentationData(presentationData)
    let signal = coordinator.rows.get() |> map { rows -> (ItemListControllerState, (ItemListNodeState, DeviceLinkActions)) in
        let state = ItemListControllerState(presentationData: presentation,
            title: .text(presentationData.strings.blah_DeviceLink_Title),
            leftNavigationButton: ItemListNavigationButton(content: .text(presentationData.strings.Common_Cancel),
                style: .regular, enabled: true, action: actions.cancel), rightNavigationButton: nil,
            backNavigationButton: ItemListBackButton(title: presentationData.strings.Common_Back))
        return (state, (ItemListNodeState(presentationData: presentation, entries: rows, style: .blocks,
            animateChanges: false), actions))
    }
    let controller = ItemListController(presentationData: presentation, updatedPresentationData: .single(presentation),
        state: signal, tabBarItem: nil)
    coordinator.controller = controller
    controller.navigationPresentation = .modal
    controller.presentationArguments = ViewControllerPresentationArguments(presentationAnimation: .modalSheet)
    controller.enableInteractiveDismiss = true
    controller.attemptNavigation = { [weak coordinator] _ in
        coordinator?.cancel()
        return true
    }
    controller.didDisappear = { [coordinator] _ in
        if !coordinator.isSharing { coordinator.cancel() }
    }
    coordinator.inspect()
    return controller
}

private final class DeviceLinkCoordinator {
    let rows = ValuePromise<[DeviceLinkRow]>([], ignoreRepeated: true)
    weak var controller: ItemListController?
    private let account: Account
    private let url: String
    private let presentationData: PresentationData
    private let activeSessionsContext: ActiveSessionsContext
    private let completion: (Bool) -> Void
    private let disposable = MetaDisposable()
    private var approval: BlahDeviceLinkApproval?
    private var publication: (profile: Data, url: String, retry: () -> Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError>)?
    private var publicationNeedsUnlock = false
    private var transferIdentity = false
    private var busy = false
    private var done = false
    private var closed = false
    private var generation = 0
    private var message: String?
    private var observer: NSObjectProtocol?
    private var shareFolder: URL?
    private(set) var isSharing = false
    private var strings: PresentationStrings { presentationData.strings }

    init(account: Account, url: String, presentationData: PresentationData,
        activeSessionsContext: ActiveSessionsContext, completion: @escaping (Bool) -> Void) {
        self.account = account
        self.url = url
        self.presentationData = presentationData
        self.activeSessionsContext = activeSessionsContext
        self.completion = completion
        observer = NotificationCenter.default.addObserver(forName: UIApplication.didEnterBackgroundNotification,
            object: nil, queue: .main) { [weak self] _ in
            self?.suspend()
        }
    }

    deinit {
        disposable.dispose()
        if let observer { NotificationCenter.default.removeObserver(observer) }
        if let shareFolder { try? FileManager.default.removeItem(at: shareFolder) }
        Task { await BlahIdentityStore.shared.lock() }
    }

    func inspect() {
        guard !busy && !closed else { return }
        if let components = URLComponents(string: url.trimmingCharacters(in: .whitespacesAndNewlines)),
            !(components.queryItems ?? []).contains(where: { $0.name == "blah" && !($0.value ?? "").isEmpty }) {
            message = strings.blah_DeviceLink_Required
            refresh()
            return
        }
        busy = true
        message = nil
        refresh()
        let generation = self.generation
        disposable.set((blahApproveDeviceLink(account: account, url: url) |> deliverOnMainQueue).start(next: { [weak self] approval in
            guard let self, !self.closed, self.generation == generation else { return }
            self.approval = approval
            self.busy = false
            self.refresh()
        }, error: { [weak self] error in
            guard let self, !self.closed, self.generation == generation else { return }
            self.busy = false
            self.message = self.errorMessage(error)
            self.refresh()
        }))
    }

    func invoke(_ id: Int32, _ value: Bool?) {
        guard !busy && !closed else { return }
        switch id {
        case 3:
            transferIdentity = value ?? false
            refresh()
        case 4:
            if let approval { run(approval.approve(transferIdentity: transferIdentity)) }
        case 7:
            shareProfile()
        case 8:
            if let publication {
                if publicationNeedsUnlock {
                    let transferIdentity = self.transferIdentity
                    // Returning from the publisher must unlock again. Only retry automatically
                    // if the freshly prepared revision is the file the user just uploaded.
                    let signal = blahApproveDeviceLink(account: account, url: url)
                    |> mapToSignal { approval in approval.approve(transferIdentity: transferIdentity) }
                    |> mapToSignal { result -> Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError> in
                        if case let .manualPublication(profile, _, retry) = result, profile == publication.profile {
                            return retry()
                        }
                        return .single(result)
                    }
                    run(signal)
                } else {
                    run(publication.retry())
                }
            }
        case 10:
            close()
        case 11:
            inspect()
        default:
            break
        }
    }

    private func run(_ signal: Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError>) {
        busy = true
        message = nil
        refresh()
        let generation = self.generation
        disposable.set((signal |> deliverOnMainQueue).start(next: { [weak self] result in
            guard let self, !self.closed, self.generation == generation else { return }
            self.busy = false
            switch result {
            case .done:
                self.done = true
                self.publication = nil
                self.approval = nil
                self.activeSessionsContext.loadMore()
                // The requesting device completes sign-in after receiving the grant.
                let sessions = self.activeSessionsContext
                Queue.mainQueue().after(1.5, { sessions.loadMore() })
                Task { await BlahIdentityStore.shared.lock() }
            case let .manualPublication(profile, url, retry):
                self.publication = (profile, url, retry)
                self.publicationNeedsUnlock = false
            }
            self.refresh()
        }, error: { [weak self] error in
            guard let self, !self.closed, self.generation == generation else { return }
            self.busy = false
            self.message = self.errorMessage(error)
            self.refresh()
        }))
    }

    private func errorMessage(_ error: BlahDeviceLinkError) -> String {
        let description = error.localizedDescription
        let message = description.hasPrefix("BLAH_IDENTITY: ") ? String(description.dropFirst(15)) : description
        switch message {
        case "BLAH_LINK_REQUIRED", "DEVICE_LINK_REQUIRED":
            return strings.blah_DeviceLink_Required
        case "LOGIN_TOKEN_EXPIRED", "LOGIN_TOKEN_INVALID", "AUTH_TOKEN_EXPIRED", "AUTH_TOKEN_INVALID", "BLAH_LINK_CANCELLED":
            return strings.blah_DeviceLink_Expired
        case "DEVICE_LINK_PROFILE_STALE":
            return strings.blah_DeviceLink_ProfileStale
        case "BLAH_LINK_PROFILE_CHANGED":
            return strings.blah_DeviceLink_ProfileChanged
        case "BLAH_LINK_APPROVAL_REQUIRED":
            return strings.blah_DeviceLink_ApprovalRequired
        case "BLAH_LINK_ALGORITHM", "unsupportedAlgorithm":
            return strings.blah_DeviceLink_Algorithm
        case "DEVICE_LINK_INVALID":
            return strings.blah_DeviceLink_Invalid
        default:
            return message
        }
    }

    private func refresh() {
        var entries: [DeviceLinkRow] = []
        if done {
            entries.append(DeviceLinkRow(stableId: 9, section: 0, title: strings.blah_DeviceLink_Done))
            entries.append(DeviceLinkRow(stableId: 10, section: 1, title: strings.Common_Done, isAction: true))
        } else if let publication {
            entries.append(DeviceLinkRow(stableId: 5, section: 0, title: strings.blah_DeviceLink_Publish))
            entries.append(DeviceLinkRow(stableId: 6, section: 0, title: publication.url))
            entries.append(DeviceLinkRow(stableId: 7, section: 1, title: strings.blah_DeviceLink_ShareProfile, isAction: true, enabled: !busy))
            entries.append(DeviceLinkRow(stableId: 8, section: 1, title: strings.blah_DeviceLink_Uploaded, isAction: true, enabled: !busy))
        } else if let approval {
            entries.append(DeviceLinkRow(stableId: 0, section: 0, title: strings.blah_DeviceLink_Confirm))
            entries.append(DeviceLinkRow(stableId: 1, section: 0, title: approval.label))
            entries.append(DeviceLinkRow(stableId: 2, section: 0, title: "\(approval.domain)\n\(approval.id)"))
            entries.append(DeviceLinkRow(stableId: 3, section: 1, title: strings.blah_DeviceLink_Transfer,
                value: transferIdentity, enabled: !busy))
            entries.append(DeviceLinkRow(stableId: 4, section: 2, title: strings.blah_DeviceLink_Approve, isAction: true, enabled: !busy))
        } else if !busy {
            entries.append(DeviceLinkRow(stableId: 11, section: 0, title: strings.blah_DeviceLink_Retry, isAction: true))
        }
        if busy || message != nil {
            entries.append(DeviceLinkRow(stableId: 12, section: 3, title: busy ? strings.blah_DeviceLink_Working : message!))
        }
        rows.set(entries)
    }

    private func shareProfile() {
        guard let publication, let controller else { return }
        do {
            if let shareFolder { try? FileManager.default.removeItem(at: shareFolder) }
            let folder = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
            try FileManager.default.createDirectory(at: folder, withIntermediateDirectories: true)
            shareFolder = folder
            let url = folder.appendingPathComponent("profile.cbor")
            try publication.profile.write(to: url, options: .atomic)
            let share = UIActivityViewController(activityItems: [url], applicationActivities: nil)
            share.popoverPresentationController?.sourceView = controller.view
            share.popoverPresentationController?.sourceRect = controller.view.bounds
            share.completionWithItemsHandler = { [weak self] _, _, _, _ in
                try? FileManager.default.removeItem(at: folder)
                self?.isSharing = false
            }
            isSharing = true
            controller.present(share, animated: true)
        } catch {
            message = error.localizedDescription
            refresh()
        }
    }

    private func suspend() {
        guard !closed && !done else { return }
        generation += 1
        disposable.set(nil)
        busy = false
        approval = nil
        publicationNeedsUnlock = publication != nil
        message = strings.blah_DeviceLink_Interrupted
        Task { await BlahIdentityStore.shared.lock() }
        refresh()
    }

    func cancel() {
        guard !closed else { return }
        closed = true
        generation += 1
        disposable.dispose()
        approval = nil
        publication = nil
        Task { await BlahIdentityStore.shared.lock() }
        completion(done)
    }

    func close() {
        controller?.dismiss()
        cancel()
    }
}

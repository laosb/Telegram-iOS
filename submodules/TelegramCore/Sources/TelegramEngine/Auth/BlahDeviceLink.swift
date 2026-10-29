import Foundation
import BlahDiem
import BlahIdentity
import MtProtoKit
import Postbox
import SwiftSignalKit
public import TelegramApi

@available(iOS 18.0, macOS 15.0, *)
public enum BlahDeviceLinkState {
    case code(url: String, expires: Int32)
    case approved
    case passwordNeeded
    case signedIn(Api.auth.Authorization)
    case failed(String)
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahDeviceLinkError: Error, LocalizedError {
    case generic(String)

    public var errorDescription: String? {
        switch self {
        case let .generic(message): return message
        }
    }
}

/// Owns one QR attempt. Only public request material leaves BlahIdentityStore.
@available(iOS 18.0, macOS 15.0, *)
public final class BlahDeviceLinkAttempt {
    private let network: Network
    private let label: String
    private let exceptIds: [Int64]
    private let expectedDomain: String?
    private let id = UUID()
    private let state = Promise<BlahDeviceLinkState>()
    private let operation = MetaDisposable()
    private let updates = MetaDisposable()
    private var timer: SwiftSignalKit.Timer?
    private var generation = 0
    private var stopped = false
    private var busy = false
    private var pollRequested = false
    private var link: BlahDeviceLinkRequestData?
    private var token: Data?
    private var expires: Int32 = 0
    private let deadline = Date().addingTimeInterval(600)

    public var states: Signal<BlahDeviceLinkState, NoError> { return self.state.get() |> deliverOnMainQueue }

    public init(network: Network, label: String, exceptIds: [Int64], expectedDomain: String? = nil) {
        self.network = network
        self.label = label
        self.exceptIds = exceptIds
        self.expectedDomain = expectedDomain
        Queue.mainQueue().async { [weak self] in self?.start() }
    }

    deinit {
        self.operation.dispose()
        self.updates.dispose()
        self.timer?.invalidate()
        if !self.stopped {
            let id = self.id
            Task { await BlahIdentityStore.shared.cancelDeviceLink(id: id) }
        }
    }

    public func cancel() {
        if Queue.mainQueue().isCurrent() { self.stop() }
        else { Queue.mainQueue().async { [weak self] in self?.stop() } }
    }

    private func stop(preserveIdentity: Bool = false) {
        guard !self.stopped else { return }
        self.stopped = true
        self.generation += 1
        self.operation.dispose()
        self.updates.dispose()
        self.timer?.invalidate()
        self.timer = nil
        self.link = nil
        self.token = nil
        let id = self.id
        Task {
            if preserveIdentity { await BlahIdentityStore.shared.finishDeviceLink(id: id) }
            else { await BlahIdentityStore.shared.cancelDeviceLink(id: id) }
        }
    }

    private func finish(_ state: BlahDeviceLinkState) {
        switch state {
        case .passwordNeeded, .signedIn: self.stop(preserveIdentity: true)
        default: self.stop()
        }
        self.state.set(.single(state))
    }

    private func start() {
        guard !self.stopped else { return }
        self.updates.set((self.network.blahLoginTokenEvents.signal() |> deliverOnMainQueue).start(next: { [weak self] _ in
            self?.pollRequested = true
            self?.poll()
        }))
        let timer = SwiftSignalKit.Timer(timeout: 1.0, repeat: true, completion: { [weak self] in self?.poll() }, queue: .mainQueue())
        self.timer = timer
        timer.start()
        self.busy = true
        let generation = self.generation
        let id = self.id
        let slot = self.network.blahIdentitySlot
        let label = self.label
        let expectedDomain = self.expectedDomain
        let begin = self.network.blahHomeReady.get() |> filter { $0 } |> take(1)
        |> castError(MTRpcError.self) |> mapToSignal { _ in
            blahTask { try await BlahIdentityStore.shared.beginDeviceLink(id: id, slot: slot, label: label, expectedDomain: expectedDomain) }
        } |> deliverOnMainQueue
        self.operation.set(begin.start(next: { [weak self] link in
            guard let self, !self.stopped, self.generation == generation else { return }
            self.link = link
            self.busy = false
            self.issueToken()
        }, error: { [weak self] error in
            guard let self, !self.stopped, self.generation == generation else { return }
            self.finish(.failed(blahDeviceLinkErrorText(error)))
        }))
    }

    private func issueToken() {
        guard !self.stopped, !self.busy, let link = self.link else { return }
        self.busy = true
        let generation = self.generation
        self.operation.set((self.network.blahExportDeviceLink(request: link.request, exceptIds: self.exceptIds)
        |> deliverOnMainQueue).start(next: { [weak self] result in
            guard let self, !self.stopped, self.generation == generation else { return }
            self.busy = false
            switch result {
            case let .loginToken(value):
                let token = value.token.makeData()
                guard token.count == 32, Double(value.expires) > self.network.globalTime else {
                    self.finish(.failed("DEVICE_LINK_INVALID")); return
                }
                self.token = token
                self.expires = value.expires
                self.state.set(.single(.code(url: "tg://login?token=\(blahLinkBase64(token))&blah=\(link.parameter)", expires: value.expires)))
                if self.pollRequested { self.poll() }
            case .loginTokenMigrateTo:
                self.finish(.failed("BLAH_HOME_MIGRATION_REFUSED"))
            default:
                self.finish(.failed("DEVICE_LINK_INVALID"))
            }
        }, error: { [weak self] error in
            guard let self, !self.stopped, self.generation == generation else { return }
            self.finish(.failed(blahDeviceLinkErrorText(error)))
        }))
    }

    private func poll() {
        guard !self.stopped else { return }
        guard Date() < self.deadline else { self.finish(.failed("LOGIN_TOKEN_EXPIRED")); return }
        guard !self.busy, let token = self.token, let link = self.link else { return }
        self.busy = true
        self.pollRequested = false
        let generation = self.generation
        self.operation.set((self.network.blahGetDeviceLink(token: token) |> deliverOnMainQueue).start(next: { [weak self] result in
            guard let self, !self.stopped, self.generation == generation else { return }
            self.busy = false
            guard result.request == link.request else { self.finish(.failed("DEVICE_LINK_INVALID")); return }
            if let response = result.response {
                self.complete(link: link, response: response)
            } else if Double(self.expires) <= self.network.globalTime {
                self.issueToken()
            } else if self.pollRequested {
                self.poll()
            }
        }, error: { [weak self] error in
            guard let self, !self.stopped, self.generation == generation else { return }
            self.busy = false
            if error.errorDescription == "LOGIN_TOKEN_EXPIRED" {
                self.issueToken()
            } else if error.errorCode < 500 {
                self.finish(.failed(blahDeviceLinkErrorText(error)))
            }
            // Transient server failures retry on the next poll, including missed update hints.
        }))
    }

    private func complete(link: BlahDeviceLinkRequestData, response: Data) {
        self.busy = true
        self.timer?.invalidate()
        let generation = self.generation
        self.operation.set((blahTask {
            try await BlahIdentityStore.shared.installDeviceLink(id: link.id, request: link.request, response: response)
        } |> deliverOnMainQueue).start(next: { [weak self] _ in
            guard let self, !self.stopped, self.generation == generation else { return }
            self.state.set(.single(.approved))
            guard !self.stopped, self.generation == generation else { return }
            self.operation.set((self.network.blahExportDeviceLink(request: nil, exceptIds: self.exceptIds)
            |> deliverOnMainQueue).start(next: { [weak self] result in
                guard let self, !self.stopped, self.generation == generation else { return }
                switch result {
                case let .loginTokenSuccess(value): self.finish(.signedIn(value.authorization))
                case .loginTokenMigrateTo: self.finish(.failed("BLAH_HOME_MIGRATION_REFUSED"))
                default: self.finish(.failed("DEVICE_LINK_INVALID"))
                }
            }, error: { [weak self] error in
                guard let self, !self.stopped, self.generation == generation else { return }
                if error.errorDescription == "SESSION_PASSWORD_NEEDED" { self.finish(.passwordNeeded) }
                else { self.finish(.failed(blahDeviceLinkErrorText(error))) }
            }))
        }, error: { [weak self] error in
            guard let self, !self.stopped, self.generation == generation else { return }
            self.finish(.failed(blahDeviceLinkErrorText(error)))
        }))
    }
}

private func blahDeviceLinkErrorText(_ error: MTRpcError) -> String {
    return error.errorDescription.contains("_MIGRATE_") ? "BLAH_HOME_MIGRATION_REFUSED" : error.errorDescription
}

private func blahLinkBase64(_ data: Data) -> String {
    return data.base64EncodedString().replacingOccurrences(of: "+", with: "-")
        .replacingOccurrences(of: "/", with: "_").replacingOccurrences(of: "=", with: "")
}

@available(iOS 18.0, macOS 15.0, *)
private func blahParseDeviceLink(_ link: String) throws -> (token: Data, code: DeviceLinkCode) {
    guard link.utf8.count <= 8192,
        let url = URLComponents(string: link.trimmingCharacters(in: .whitespacesAndNewlines)),
        url.scheme?.lowercased() == "tg", url.host?.lowercased() == "login", url.user == nil, url.password == nil,
        url.port == nil, url.path.isEmpty || url.path == "/", url.fragment == nil else {
        throw BlahDeviceLinkError.generic("DEVICE_LINK_INVALID")
    }
    let items = url.queryItems ?? []
    let parameters = items.filter { $0.name == "blah" }
    guard let parameter = parameters.first?.value, !parameter.isEmpty else {
        throw BlahDeviceLinkError.generic("BLAH_LINK_REQUIRED")
    }
    let tokens = items.filter { $0.name == "token" }
    let alphabet = Set("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_".utf8)
    guard parameters.count == 1, tokens.count == 1, let text = tokens[0].value,
        text.utf8.count == 43, text.utf8.allSatisfy({ alphabet.contains($0) }),
        parameter.utf8.allSatisfy({ alphabet.contains($0) }),
        let token = Data(base64Encoded: text.replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/") + "="),
        token.count == 32, blahLinkBase64(token) == text else {
        throw BlahDeviceLinkError.generic("DEVICE_LINK_INVALID")
    }
    do { return (token, try DeviceLinkCode(parameter: parameter)) }
    catch { throw BlahDeviceLinkError.generic("DEVICE_LINK_INVALID") }
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahDeviceLinkApproveResult {
    case done
    case manualPublication(profile: Data, url: String, retry: () -> Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError>)
}

@available(iOS 18.0, macOS 15.0, *)
public final class BlahDeviceLinkApproval {
    public let label: String
    public let domain: String
    public let id: String
    private let account: Account
    private let token: Data
    private let code: DeviceLinkCode
    private let request: Data
    private let deadline = Date().addingTimeInterval(300)

    fileprivate init(account: Account, token: Data, code: DeviceLinkCode, request: Data, label: String, domain: String, id: String) {
        self.account = account
        self.token = token
        self.code = code
        self.request = request
        self.label = label
        self.domain = domain
        self.id = id
    }

    public func approve(transferIdentity: Bool) -> Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError> {
        return blahTask {
            guard Date() < self.deadline else { throw BlahDeviceLinkError.generic("LOGIN_TOKEN_EXPIRED") }
            let store = BlahIdentityStore.shared
            let slot = self.account.network.blahIdentitySlot
            guard try await store.boundIdentityID(slot: slot) == self.id else { throw BlahIdentityError.wrongHome }
            _ = try await store.unlock(id: self.id, slot: slot)
            return try await store.prepareDeviceLinkApproval(slot: slot, id: self.id,
                account: self.account.peerId.id._internalGetInt64Value(), request: self.request)
        } |> mapError { .generic(blahDeviceLinkErrorText($0)) }
        |> mapToSignal { prepared -> Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError> in
            switch prepared.publication {
            case .published:
                return self.accept(profile: prepared.profile, transferIdentity: transferIdentity)
            case let .manual(profile, url):
                return .single(.manualPublication(profile: profile, url: url, retry: {
                    self.accept(profile: prepared.profile, transferIdentity: transferIdentity)
                }))
            }
        } |> deliverOnMainQueue
    }

    private func accept(profile: Data, transferIdentity: Bool) -> Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError> {
        return blahTask {
            guard Date() < self.deadline else { throw BlahDeviceLinkError.generic("LOGIN_TOKEN_EXPIRED") }
            return try await BlahIdentityStore.shared.sealDeviceLinkApproval(slot: self.account.network.blahIdentitySlot,
                id: self.id, account: self.account.peerId.id._internalGetInt64Value(), request: self.request,
                parameter: self.code.parameter, profile: profile, transferIdentity: transferIdentity)
        } |> mapError { .generic(blahDeviceLinkErrorText($0)) }
        |> mapToSignal { response in self.acceptResponse(response, profile: profile, retry: 0) }
        |> deliverOnMainQueue
    }

    private func acceptResponse(_ response: Data, profile: Data, retry: Int) -> Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError> {
        return self.account.network.blahAcceptDeviceLink(token: self.token, response: response, profile: profile)
        |> map { _ in BlahDeviceLinkApproveResult.done }
        |> `catch` { error -> Signal<BlahDeviceLinkApproveResult, BlahDeviceLinkError> in
            let delays: [UInt64] = [1, 2, 4, 8, 15]
            guard error.errorDescription == "DEVICE_LINK_PROFILE_STALE", retry < delays.count else {
                return .fail(.generic(blahDeviceLinkErrorText(error)))
            }
            return blahTask {
                try await Task.sleep(nanoseconds: delays[retry] * 1_000_000_000)
                guard Date() < self.deadline else { throw BlahDeviceLinkError.generic("LOGIN_TOKEN_EXPIRED") }
                return true
            } |> mapError { .generic(blahDeviceLinkErrorText($0)) }
            |> mapToSignal { _ in self.acceptResponse(response, profile: profile, retry: retry + 1) }
        }
    }
}

@available(iOS 18.0, macOS 15.0, *)
public func blahApproveDeviceLink(account: Account, url: String) -> Signal<BlahDeviceLinkApproval, BlahDeviceLinkError> {
    let parsed: (token: Data, code: DeviceLinkCode)
    do { parsed = try blahParseDeviceLink(url) }
    catch { return .fail(.generic(error.localizedDescription)) }
    return account.network.blahGetDeviceLink(token: parsed.token)
    |> mapError { .generic(blahDeviceLinkErrorText($0)) }
    |> mapToSignal { result in
        return blahTask {
            guard parsed.code.matches(Array(result.request)) else { throw BlahDeviceLinkError.generic("DEVICE_LINK_INVALID") }
            let request = try DeviceLinkRequest(encoding: Array(result.request))
            let store = BlahIdentityStore.shared
            let slot = account.network.blahIdentitySlot
            try await store.validateRestoredBinding(slot: slot)
            guard let id = try await store.boundIdentityID(slot: slot),
                let entry = try await store.list().first(where: { $0.id == id }) else { throw BlahIdentityError.wrongHome }
            return BlahDeviceLinkApproval(account: account, token: parsed.token, code: parsed.code,
                request: result.request, label: request.label, domain: entry.domain, id: id)
        } |> mapError { .generic(blahDeviceLinkErrorText($0)) }
    } |> deliverOnMainQueue
}

@available(iOS 18.0, macOS 15.0, *)
public func blahCompleteDeviceLinkSignIn(accountManager: AccountManager<TelegramAccountManagerTypes>, account: UnauthorizedAccount,
    authorization: Api.auth.Authorization, syncContacts: Bool, willCommit: (() -> Void)? = nil) -> Signal<Void, BlahDeviceLinkError> {
    guard case let .authorization(value) = authorization else { return .fail(.generic("DEVICE_LINK_INVALID")) }
    if let token = value.futureAuthToken { storeFutureLoginToken(accountManager: accountManager, token: token.makeData()) }
    return Signal<Void, BlahDeviceLinkError>.single(()) |> deliverOnMainQueue |> mapToSignal {
        // Notify the UI before state observers can remove its modal. No fallible work remains.
        willCommit?()
        return account.postbox.transaction { transaction -> Signal<Void, BlahDeviceLinkError> in
            let user = TelegramUser(user: value.user)
            initializedAppSettingsAfterLogin(transaction: transaction, appVersion: account.networkArguments.appVersion, syncContacts: syncContacts)
            transaction.setState(AuthorizedAccountState(isTestingEnvironment: account.testingEnvironment,
                masterDatacenterId: account.masterDatacenterId, peerId: user.id, state: nil, invalidatedChannels: []))
            return accountManager.transaction { transaction -> Void in
                switchToAuthorizedAccount(transaction: transaction, account: account, isSupportUser: false)
            } |> castError(BlahDeviceLinkError.self)
        } |> castError(BlahDeviceLinkError.self) |> switchToLatest
    }
}

@available(iOS 18.0, macOS 15.0, *)
public func blahContinueDeviceLinkWithPassword(account: UnauthorizedAccount, syncContacts: Bool, willCommit: (() -> Void)? = nil) -> Signal<Void, BlahDeviceLinkError> {
    return account.network.request(Api.functions.account.getPassword(), automaticFloodWait: false)
    |> mapError { .generic(blahDeviceLinkErrorText($0)) }
    |> deliverOnMainQueue
    |> mapToSignal { result -> Signal<Void, BlahDeviceLinkError> in
        switch result {
        case let .password(value):
            willCommit?()
            return account.postbox.transaction { transaction -> Void in
                transaction.setState(UnauthorizedAccountState(isTestingEnvironment: account.testingEnvironment,
                    masterDatacenterId: account.masterDatacenterId, contents: .passwordEntry(hint: value.hint ?? "",
                        number: nil, code: nil, suggestReset: false, syncContacts: syncContacts)))
            } |> castError(BlahDeviceLinkError.self)
        }
    }
}

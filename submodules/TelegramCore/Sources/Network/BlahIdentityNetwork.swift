import Foundation
import Postbox
import BlahDiem
import BlahIdentity
import MtProtoKit
import SwiftSignalKit
import TelegramApi

private let blahLoginMethods: Set<String> = ["auth.sendCode", "auth.signUp", "auth.signIn", "auth.checkPassword", "auth.recoverPassword"]
func blahNeedsIdentity(_ name: String) -> Bool {
    return blahLoginMethods.contains(name) || name.contains("LoginToken") || name.contains("PasskeyLogin") || name == "auth.importWebTokenAuthorization"
}

extension Network {
    public func takeBlahIdentityError() -> String? { return self.blahIdentityError.swap(nil) }

    public var blahIdentitySlot: String { return URL(fileURLWithPath: self.basePath).lastPathComponent }

    func restoreBlahHome() {
        Task {
            do {
                if let home = try await BlahIdentityStore.shared.home(slot: self.blahIdentitySlot) {
                    let refreshed = try await BlahIdentityStore.shared.connect(domain: home.domain, slot: self.blahIdentitySlot)
                    try await self.activateBlahHome(refreshed)
                }
            } catch { /* Keep the connection closed. Identity Manager offers discovery retry. */ }
        }
    }

    public func connectBlahHome(domain: String) async throws {
        if try await BlahIdentityStore.shared.home(slot: self.blahIdentitySlot) == nil,
            self.context.authInfoForDatacenter(withId: self.datacenterId, selector: .persistent) != nil {
            throw BlahIdentityError.wrongHome
        }
        let home = try await BlahIdentityStore.shared.connect(domain: domain, slot: self.blahIdentitySlot)
        try await self.activateBlahHome(home)
    }

    private func activateBlahHome(_ home: BlahHome) async throws {
        let (_, dc) = try await home.verified()
        let endpoints = dc.endpoints.filter { $0.transport == .tcp && !$0.tls }
        guard !endpoints.isEmpty, self.datacenterId == 1 else { throw BlahIdentityError.wrongHome }
        let config = CustomDCConfig(defaultDcId: 1, dcs: [.init(id: 1,
            endpoints: endpoints.map { (ip: $0.host, port: Int($0.port)) }, rsaPublicKeyPem: dc.transportPublicKey)])
        await withCheckedContinuation { (continuation: CheckedContinuation<Void, Never>) in
            self.queue.async {
                config.apply(to: self.context)
                self.blahHomeReady.set(true)
                continuation.resume()
            }
        }
    }

    private func blahBinding() async -> (Int64, Int64) {
        return await withCheckedContinuation { continuation in
            self.mtProto.identityBinding { key, session in continuation.resume(returning: (key, session)) }
        }
    }

    func blahRequest<T>(_ data: (FunctionDescription, Buffer, DeserializeFunctionResponse<T>)) -> Signal<T, MTRpcError> {
        guard blahLoginMethods.contains(data.0.name) else {
            return .fail(MTRpcError(errorCode: 400, errorDescription: "BLAH_IDENTITY_REQUIRED"))
        }
        let request: Signal<T, MTRpcError>
        if data.0.name == "auth.sendCode" || data.0.name == "auth.signUp" {
            request = self.blahProven(data)
        } else {
            request = self.blahRawRequest(data, automaticFloodWait: false)
        }
        let authorized = request |> mapToSignal { result -> Signal<T, MTRpcError> in
            var authorization = result as? Api.auth.Authorization
            if let sent = result as? Api.auth.SentCode, case let .sentCodeSuccess(value) = sent {
                authorization = value.authorization
            }
            guard let authorization, case let .authorization(value) = authorization else { return .single(result) }
            let user = TelegramUser(user: value.user)
            return blahTask {
                try await BlahIdentityStore.shared.number(slot: self.blahIdentitySlot, account: user.id.id._internalGetInt64Value())
                return true
            } |> mapToSignal { _ in
                self.blahProven(Api.functions.account.getAuthorizations()) |> map { _ in result }
            }
        }
        return authorized |> mapError { error in
            if error.errorDescription.hasPrefix("BLAH_IDENTITY: ") {
                let _ = self.blahIdentityError.swap(String(error.errorDescription.dropFirst(15)))
            } else if error.errorDescription == "SIGNUP_EMAIL_REQUIRED" {
                let _ = self.blahIdentityError.swap("This DC requires an admission email. Open Identity Manager, enter the email, and sign in again.")
            }
            return error
        }
    }

    private func blahProven<T>(_ data: (FunctionDescription, Buffer, DeserializeFunctionResponse<T>)) -> Signal<T, MTRpcError> {
        return blahTask { try await BlahIdentityStore.shared.bind(slot: self.blahIdentitySlot) }
        |> mapToSignal { domain -> Signal<(Data, Int32), MTRpcError> in
            let buffer = Buffer()
            buffer.appendInt32(Int32(bitPattern: 0xdceefd53))
            serializeString(domain, buffer: buffer, boxed: false)
            let description = FunctionDescription(name: "blah.requestIdentityChallenge", parameters: [])
            let parse = DeserializeFunctionResponse<(Data, Int32)> { buffer in
                let reader = BufferReader(buffer)
                guard reader.readInt32() == Int32(bitPattern: 0xa5bf10f6),
                    let challenge = parseBytes(reader), let expires = reader.readInt32() else { return nil }
                return (challenge.makeData(), expires)
            }
            return self.blahRawRequest((description, buffer, parse), automaticFloodWait: false)
        } |> mapToSignal { challenge in
            return blahTask {
                let binding = await self.blahBinding()
                let proof = try await BlahIdentityStore.shared.prove(slot: self.blahIdentitySlot,
                    challenge: challenge.0, expires: challenge.1, query: data.1.makeData(), keyID: binding.0, sessionID: binding.1)
                let current = await self.blahBinding()
                guard binding == current else { throw BlahIdentityError.invalidProfile }
                return proof
            } |> mapToSignal { proof in
                let buffer = Buffer()
                buffer.appendInt32(Int32(bitPattern: 0x525b7c28))
                serializeBytes(Buffer(data: proof), buffer: buffer, boxed: false)
                buffer.appendBuffer(data.1)
                return self.blahRawRequest((FunctionDescription(name: "blah.invokeWithIdentityProof", parameters: []), buffer, data.2), automaticFloodWait: false)
            }
        }
    }
}

private func blahTask<T>(_ body: @escaping () async throws -> T) -> Signal<T, MTRpcError> {
    return Signal { subscriber in
        let task = Task {
            do {
                let value = try await body()
                if !Task.isCancelled { subscriber.putNext(value); subscriber.putCompletion() }
            } catch {
                if !Task.isCancelled { subscriber.putError(MTRpcError(errorCode: 400, errorDescription: "BLAH_IDENTITY: " + error.localizedDescription)) }
            }
        }
        return ActionDisposable { task.cancel() }
    }
}

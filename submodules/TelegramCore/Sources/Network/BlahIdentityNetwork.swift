import Foundation
import Postbox
import BlahDiem
import BlahIdentity
import MtProtoKit
import SwiftSignalKit
internal import TelegramApi

private let blahLoginMethods: Set<String> = ["auth.sendCode", "auth.signUp", "auth.signIn", "auth.checkPassword", "auth.recoverPassword"]
func blahNeedsIdentity(_ name: String) -> Bool {
    return blahLoginMethods.contains(name) || name.contains("LoginToken") || name.contains("PasskeyLogin") || name == "auth.importWebTokenAuthorization"
}

extension Network {
    public func takeBlahIdentityError() -> String? { return self.blahIdentityError.swap(nil) }

    public var blahIdentitySlot: String { return URL(fileURLWithPath: self.basePath).lastPathComponent }

    func blahLoginOperation<T, E>(genericError: E, _ operation: @escaping (@escaping (MTRpcError) -> E) -> Signal<T, E>) -> Signal<T, E> {
        return deferred {
            let _ = self.blahIdentityError.swap(nil)
            let message = Atomic<String?>(value: nil)
            return operation { error in
                let _ = message.swap(blahLoginErrorText(error.errorDescription)
                    ?? "The DC refused the request (\(error.errorDescription)).")
                return genericError
            }
            |> mapError { error in
                let _ = self.blahIdentityError.swap(message.swap(nil))
                return error
            }
        }
    }

    /// Makes the DC refetch the published profile under this account's device proof.
    public func blahRefreshPublishedProfile(profile: Data? = nil) -> Signal<Never, MTRpcError> {
        return self.blahProven(Api.functions.account.getAuthorizations(), expectedProfile: profile) |> ignoreValues
    }

    func restoreBlahHome() {
        // initializedNetwork carries supplementary in the MTProto environment.
        let refresh = !self.context.apiEnvironment.disableUpdates
        Task {
            do {
                if let home = try await BlahIdentityStore.shared.restoreHome(slot: self.blahIdentitySlot, refresh: refresh) {
                    try await BlahIdentityStore.shared.validateRestoredBinding(slot: self.blahIdentitySlot, required: self.blahRequiresRestoredBinding)
                    try await self.activateBlahHome(home)
                }
            } catch {
                let _ = self.blahIdentityError.swap(error.localizedDescription)
            }
        }
    }

    public func connectBlahHome(domain: String) async throws {
        if try await BlahIdentityStore.shared.home(slot: self.blahIdentitySlot) == nil,
            self.context.authInfoForDatacenter(withId: self.datacenterId, selector: .persistent) != nil {
            throw BlahIdentityError.wrongHome
        }
        let home = try await BlahIdentityStore.shared.connect(domain: domain, slot: self.blahIdentitySlot)
        try await BlahIdentityStore.shared.validateRestoredBinding(slot: self.blahIdentitySlot, required: self.blahRequiresRestoredBinding)
        try await self.activateBlahHome(home)
    }

    private func activateBlahHome(_ home: BlahHome) async throws {
        let (_, dc) = try await home.verified()
        let endpoints = dc.endpoints.filter { $0.transport == .tcp && !$0.tls }
        guard !endpoints.isEmpty, self.datacenterId == 1 else { throw BlahIdentityError.wrongHome }
        let config = CustomDCConfig(dcs: [.init(id: 1,
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
            self.mainSession.identityBinding { key, session in continuation.resume(returning: (key, session)) }
        }
    }

    func blahRequest<T>(_ data: (FunctionDescription, Buffer, DeserializeFunctionResponse<T>)) -> Signal<T, MTRpcError> {
        return deferred {
            let _ = self.blahIdentityError.swap(nil)
            return self.blahLoginRequest(data) |> mapError { self.blahStoreLoginError($0) }
        }
    }

    private func blahLoginRequest<T>(_ data: (FunctionDescription, Buffer, DeserializeFunctionResponse<T>)) -> Signal<T, MTRpcError> {
        guard blahLoginMethods.contains(data.0.name) else {
            return .fail(MTRpcError(errorCode: 400, errorDescription: "BLAH_IDENTITY_REQUIRED"))
        }
        let request: Signal<T, MTRpcError>
        if data.0.name == "auth.sendCode" || data.0.name == "auth.signUp" {
            request = self.blahProven(data)
        } else {
            request = self.blahRawRequest(data, automaticFloodWait: false)
        }
        return request |> mapToSignal { result -> Signal<T, MTRpcError> in
            var authorization = result as? Api.auth.Authorization
            if let sent = result as? Api.auth.SentCode, case let .sentCodeSuccess(value) = sent {
                authorization = value.authorization
            }
            guard let authorization, case let .authorization(value) = authorization else { return .single(result) }
            let user = TelegramUser(user: value.user)
            return blahTask {
                try await BlahIdentityStore.shared.number(slot: self.blahIdentitySlot, account: user.id.id._internalGetInt64Value())
                return try await BlahIdentityStore.shared.pendingPublication(slot: self.blahIdentitySlot) == nil
            } |> mapToSignal { published -> Signal<T, MTRpcError> in
                guard published else { return .single(result) }
                return self.blahProven(Api.functions.account.getAuthorizations()) |> map { _ in result }
            }
        }
    }

    private func blahStoreLoginError(_ error: MTRpcError) -> MTRpcError {
        let error = error.errorDescription.contains("_MIGRATE_")
            ? MTRpcError(errorCode: 400, errorDescription: "BLAH_HOME_MIGRATION_REFUSED") : error
        let _ = self.blahIdentityError.swap(blahLoginErrorText(error.errorDescription))
        return error
    }

    func blahProven<T>(_ data: (FunctionDescription, Buffer, DeserializeFunctionResponse<T>), expectedProfile: Data? = nil) -> Signal<T, MTRpcError> {
        return blahTask { try await BlahIdentityStore.shared.bind(slot: self.blahIdentitySlot) }
        |> mapToSignal { domain -> Signal<(Data, Int32), MTRpcError> in
            let buffer = Buffer()
            buffer.appendInt32(Int32(bitPattern: 0xfb8f651a)) // blah.invokeWithLayer
            buffer.appendInt32(1)
            buffer.appendInt32(Int32(bitPattern: 0xdceefd53))
            serializeBytes(Buffer(data: Data(domain.utf8)), buffer: buffer, boxed: false)
            let description = FunctionDescription(name: "blah.requestIdentityChallenge", parameters: [])
            let parse = DeserializeFunctionResponse<(Data, Int32)> { buffer in
                let reader = BufferReader(buffer)
                guard reader.readInt32() == Int32(bitPattern: 0x2b2e0aab),
                    let challenge = parseBytes(reader), let expires = reader.readInt32() else { return nil }
                return (challenge.makeData(), expires)
            }
            return self.blahRawRequest((description, buffer, parse), automaticFloodWait: false)
        } |> mapToSignal { challenge in
            return blahTask { () -> Data in
                let binding = await self.blahBinding()
                guard binding.0 != 0, binding.1 != 0 else { throw BlahIdentityError.invalidProfile }
                let proof = try await BlahIdentityStore.shared.prove(slot: self.blahIdentitySlot,
                    challenge: challenge.0, expires: challenge.1, query: data.1.makeData(), keyID: binding.0, sessionID: binding.1, expectedProfile: expectedProfile)
                let current = await self.blahBinding()
                guard binding == current else { throw BlahIdentityError.invalidProfile }
                return proof
            } |> mapToSignal { proof -> Signal<T, MTRpcError> in
                let buffer = Buffer()
                buffer.appendInt32(Int32(bitPattern: 0xfb8f651a)) // blah.invokeWithLayer
                buffer.appendInt32(1)
                buffer.appendInt32(Int32(bitPattern: 0x61b4c668))
                serializeBytes(Buffer(data: proof), buffer: buffer, boxed: false)
                blahAppendQuery(data.1, to: buffer)
                return self.blahRawRequest((FunctionDescription(name: "blah.invokeWithIdentityProof", parameters: []), buffer, data.2), automaticFloodWait: false)
            }
        }
    }
}

func blahTask<T>(_ body: @escaping () async throws -> T) -> Signal<T, MTRpcError> {
    return Signal { subscriber in
        let task = Task {
            do {
                let value = try await body()
                if !Task.isCancelled { subscriber.putNext(value); subscriber.putCompletion() }
            } catch {
                if !Task.isCancelled { subscriber.putError(MTRpcError(errorCode: 400, errorDescription: "BLAH_IDENTITY: " + blahIdentityErrorDescription(error))) }
            }
        }
        return ActionDisposable { task.cancel() }
    }
}

func blahLoginErrorText(_ code: String) -> String? {
    if code.hasPrefix("BLAH_IDENTITY: ") { return String(code.dropFirst("BLAH_IDENTITY: ".count)) }
    if code == "SIGNUP_EMAIL_REQUIRED" { return code }
    if code.hasPrefix("FLOOD_WAIT") { return nil }
    if code.hasPrefix("PASSWORD_RECOVERY_EXPIRED") { return nil }
    if code.hasPrefix("PHONE_CODE_") || code.contains("_MIGRATE_") { return nil }
    switch code {
    case "FIRSTNAME_INVALID", "LASTNAME_INVALID", "SESSION_PASSWORD_NEEDED", "PHONE_NUMBER_INVALID",
        "PHONE_NUMBER_FLOOD", "PHONE_NUMBER_BANNED", "UPDATE_APP_TO_LOGIN", "PHONE_NUMBER_UNOCCUPIED",
        "EMAIL_CODE_INVALID", "CODE_HASH_EXPIRED", "EMAIL_TOKEN_INVALID", "EMAIL_ADDRESS_INVALID", "PASSWORD_HASH_INVALID":
        return nil
    default: break
    }
    let message: String
    switch code {
    case "IDENTITY_ALREADY_REGISTERED": message = "This identity already has an account on this DC. Go back and sign in again."
    case "IDENTITY_NOT_REGISTERED": message = "This identity does not have an account on this DC. Create an account first."
    case "IDENTITY_PROOF_INVALID": message = "The DC could not verify your identity proof."
    case "IDENTITY_PROFILE_UNAVAILABLE": message = "The DC could not fetch your published profile. Check that your profile server is reachable and serves the profile correctly."
    case "IDENTITY_PROFILE_INVALID": message = "Your published profile is malformed, invalid or expired. Publish a valid profile, then try again."
    case "IDENTITY_PROFILE_STALE": message = "Your published profile is older than or conflicts with the profile this DC has accepted. Publish your latest profile, then try again."
    case "IDENTITY_HOME_INVALID": message = "Your published profile does not have a valid home delegation for this DC. Check your home and publish your latest profile."
    case "IDENTITY_DEVICE_INVALID": message = "The DC could not verify this device. The profile listing this device may not be published yet. Publish your latest profile, then try again."
    case "IDENTITY_ACCOUNT_MISMATCH": message = "Your published profile does not name this account yet. Publish your latest profile, then sign in again."
    case "IDENTITY_PROOF_REQUIRED": message = "The DC requires an identity proof. Unlock your identity and sign in again."
    case "BLAH_IDENTITY_REQUIRED": message = "This sign-in method requires a Blah identity. Choose an identity to continue."
    case "IDENTITY_CHALLENGE_INVALID": message = "The identity challenge is invalid or expired. Try signing in again."
    case "SIGNUP_CLOSED": message = "This DC is not accepting new accounts."
    case "DEVICE_AUTH_REQUIRED": message = "The DC requires an authorized identity device."
    case "DEVICE_AUTHORITY_INVALID": message = "This device is no longer authorized by the identity profile."
    case "PROFILE_UNAVAILABLE": message = "The DC could not reach your profile server. Try again when it is available."
    case "PROFILE_INVALID": message = "The DC could not verify the published identity profile."
    case "BLAH_HOME_MIGRATION_REFUSED": message = "The DC requested a different home. Add another account to use a different home."
    case "INTERNAL_NO_PASSWORD": message = "The DC did not provide the password verification data. Try signing in again."
    case "KDF_ERROR": message = "The app could not calculate the password proof. Try signing in again."
    case "INTERNAL": message = "The DC encountered an internal error. Try again later."
    case "RPC_TIMEOUT": message = "The DC did not respond in time. Try again."
    default: return "The DC refused the request (\(code))."
    }
    return "\(message) (\(code))"
}

struct BlahDeviceLinkWireResult {
    let request: Data
    let response: Data?
}

extension Network {
    func blahGetDeviceLink(token: Data) -> Signal<BlahDeviceLinkWireResult, MTRpcError> {
        guard token.count == 32, self.datacenterId == 1 else {
            return .fail(MTRpcError(errorCode: 400, errorDescription: "DEVICE_LINK_INVALID"))
        }
        let buffer = Buffer()
        buffer.appendInt32(Int32(bitPattern: 0x0df49ce9)) // blah.getDeviceLink
        serializeBytes(Buffer(data: token), buffer: buffer, boxed: false)
        let parse = DeserializeFunctionResponse<BlahDeviceLinkWireResult> { buffer in
            guard buffer.size <= DeviceLinkRequest.maximumBytes + DeviceLinkResponse.maximumBytes + 32 else { return nil }
            let reader = BufferReader(buffer)
            guard reader.readInt32() == Int32(bitPattern: 0x0e8e43c5),
                let flags = reader.readInt32(), flags & ~1 == 0,
                let request = blahReadLinkBytes(reader, maximum: DeviceLinkRequest.maximumBytes) else { return nil }
            let response: Data?
            if flags & 1 != 0 {
                guard let bytes = blahReadLinkBytes(reader, maximum: DeviceLinkResponse.maximumBytes) else { return nil }
                response = bytes
            } else { response = nil }
            guard reader.offset == UInt(buffer.size) else { return nil }
            return BlahDeviceLinkWireResult(request: request, response: response)
        }
        return self.blahRawRequest(blahLayered((FunctionDescription(name: "blah.getDeviceLink", parameters: []), buffer, parse)), automaticFloodWait: false)
    }

    func blahExportDeviceLink(request: Data?, exceptIds: [Int64]) -> Signal<Api.auth.LoginToken, MTRpcError> {
        return deferred {
            let _ = self.blahIdentityError.swap(nil)
            return self.blahExportDeviceLinkRequest(request: request, exceptIds: exceptIds)
            |> mapError { self.blahStoreLoginError($0) }
        }
    }

    private func blahExportDeviceLinkRequest(request: Data?, exceptIds: [Int64]) -> Signal<Api.auth.LoginToken, MTRpcError> {
        guard self.datacenterId == 1, !self.blahApiHash.isEmpty else {
            return .fail(MTRpcError(errorCode: 400, errorDescription: "BLAH_HOME_MIGRATION_REFUSED"))
        }
        let data = Api.functions.auth.exportLoginToken(apiId: self.context.apiEnvironment.apiId,
            apiHash: self.blahApiHash, exceptIds: exceptIds)
        if let request {
            guard request.count <= DeviceLinkRequest.maximumBytes else {
                return .fail(MTRpcError(errorCode: 400, errorDescription: "DEVICE_LINK_INVALID"))
            }
            return self.blahRawRequest(blahLayered(blahLinked(data, link: request)), automaticFloodWait: false)
        }
        // Completion proves the new device's possession, with no link wrapper.
        return self.blahProven(data) |> mapToSignal { result -> Signal<Api.auth.LoginToken, MTRpcError> in
            guard case let .loginTokenSuccess(success) = result,
                case let .authorization(authorization) = success.authorization else { return .single(result) }
            let user = TelegramUser(user: authorization.user)
            return blahTask {
                try await BlahIdentityStore.shared.number(slot: self.blahIdentitySlot, account: user.id.id._internalGetInt64Value())
                return try await BlahIdentityStore.shared.pendingPublication(slot: self.blahIdentitySlot) == nil
            } |> mapToSignal { published -> Signal<Api.auth.LoginToken, MTRpcError> in
                guard published else { return .single(result) }
                return self.blahProven(Api.functions.account.getAuthorizations()) |> map { _ in result }
            }
        }
    }

    func blahAcceptDeviceLink(token: Data, response: Data, profile: Data) -> Signal<Api.Authorization, MTRpcError> {
        guard self.datacenterId == 1, token.count == 32, !response.isEmpty,
            response.count <= DeviceLinkResponse.maximumBytes else {
            return .fail(MTRpcError(errorCode: 400, errorDescription: "DEVICE_LINK_INVALID"))
        }
        // Layer -> identity proof -> device link -> accept. The proof covers the sealed response.
        return self.blahProven(blahLinked(Api.functions.auth.acceptLoginToken(token: Buffer(data: token)), link: response), expectedProfile: profile)
    }
}

private func blahLayered<T>(_ data: (FunctionDescription, Buffer, DeserializeFunctionResponse<T>)) -> (FunctionDescription, Buffer, DeserializeFunctionResponse<T>) {
    let buffer = Buffer()
    buffer.appendInt32(Int32(bitPattern: 0xfb8f651a))
    buffer.appendInt32(1)
    blahAppendQuery(data.1, to: buffer)
    return (data.0, buffer, data.2)
}

private func blahLinked<T>(_ data: (FunctionDescription, Buffer, DeserializeFunctionResponse<T>), link: Data) -> (FunctionDescription, Buffer, DeserializeFunctionResponse<T>) {
    let buffer = Buffer()
    buffer.appendInt32(Int32(bitPattern: 0xf7e9bfa5))
    serializeBytes(Buffer(data: link), buffer: buffer, boxed: false)
    blahAppendQuery(data.1, to: buffer)
    return (FunctionDescription(name: "blah.invokeWithDeviceLink", parameters: []), buffer, data.2)
}

private func blahAppendQuery(_ query: Buffer, to buffer: Buffer) {
    // Buffer.appendBuffer copies memory but does not advance its size in this checkout.
    query.withUnsafeMutablePointer { bytes, count in
        if let bytes, count != 0 { buffer.appendBytes(bytes, length: count) }
    }
}

private func blahReadLinkBytes(_ reader: BufferReader, maximum: Int) -> Data? {
    guard let prefix = reader.readBytesAsInt32(1), prefix != 255 else { return nil }
    let length: Int
    let header: Int
    if prefix == 254 {
        guard let value = reader.readBytesAsInt32(3), value >= 254 else { return nil }
        length = Int(value)
        header = 4
    } else {
        length = Int(prefix)
        header = 1
    }
    guard length > 0, length <= maximum, let bytes = reader.readBuffer(length) else { return nil }
    let padding = (4 - (header + length) % 4) % 4
    if padding != 0 {
        guard let bytes = reader.readBuffer(padding), bytes.makeData().allSatisfy({ $0 == 0 }) else { return nil }
    }
    return bytes.makeData()
}

import Foundation
import Postbox
internal import TelegramApi
import SwiftSignalKit
import MtProtoKit

func requestRecentAccountSessions(account: Account) -> Signal<([RecentAccountSession], Int32), NoError> {
    return account.network.request(Api.functions.account.getAuthorizations())
    |> retryRequestIfNotFrozen
    |> map { result -> ([RecentAccountSession], Int32) in
        guard let result else {
            return ([], 1)
        }
        var sessions: [RecentAccountSession] = []
        var ttlDays: Int32 = 1
        switch result {
            case let .authorizations(authorizationsData):
                let (authorizationTtlDays, authorizations) = (authorizationsData.authorizationTtlDays, authorizationsData.authorizations)
                for authorization in authorizations {
                    sessions.append(RecentAccountSession(apiAuthorization: authorization))
                }
            ttlDays = authorizationTtlDays
        }
        return (sessions, ttlDays)
    }
}

public enum TerminateSessionError {
    case generic
    case freshReset
}

private func resetBlahSession<T>(account: Account, hash: Int64?, reset: @escaping () -> Signal<T, MTRpcError>) -> Signal<Void, TerminateSessionError> {
    return account.network.blahPrepareSessionTermination(hash: hash)
    |> mapToSignal { _ in
        reset() |> `catch` { error -> Signal<T, MTRpcError> in
            guard error.errorDescription == "DEVICE_STILL_LISTED" else { return .fail(error) }
            return (.single(()) |> delay(0.5, queue: Queue.concurrentDefaultQueue()))
            |> mapToSignal { reset() }
        }
    }
    |> mapError { error -> TerminateSessionError in
        return error.errorCode == 406 ? .freshReset : .generic
    }
    |> map { _ in () }
}

func terminateAccountSession(account: Account, hash: Int64) -> Signal<Void, TerminateSessionError> {
    return resetBlahSession(account: account, hash: hash, reset: {
        account.network.request(Api.functions.account.resetAuthorization(hash: hash))
    })
}

func terminateOtherAccountSessions(account: Account) -> Signal<Void, TerminateSessionError> {
    return resetBlahSession(account: account, hash: nil, reset: {
        account.network.request(Api.functions.auth.resetAuthorizations())
    })
}

public enum UpadteAuthorizationTTLError {
    case generic
}

func setAuthorizationTTL(account: Account, ttl: Int32) -> Signal<Void, UpadteAuthorizationTTLError> {
    return account.network.request(Api.functions.account.setAuthorizationTTL(authorizationTtlDays: ttl))
    |> mapError { error -> UpadteAuthorizationTTLError in
        return .generic
    }
    |> mapToSignal { _ -> Signal<Void, UpadteAuthorizationTTLError> in
        return .single(Void())
    }
}

public enum UpdateSessionError {
    case generic
}

func updateAccountSessionAcceptsSecretChats(account: Account, hash: Int64, accepts: Bool) -> Signal<Void, UpdateSessionError> {
    return account.network.request(Api.functions.account.changeAuthorizationSettings(flags: 1 << 0, hash: hash, encryptedRequestsDisabled: accepts ? .boolFalse : .boolTrue, callRequestsDisabled: nil))
    |> mapError { error -> UpdateSessionError in
        return .generic
    }
    |> mapToSignal { _ -> Signal<Void, UpdateSessionError> in
        return .single(Void())
    }
}

func updateAccountSessionAcceptsIncomingCalls(account: Account, hash: Int64, accepts: Bool) -> Signal<Void, UpdateSessionError> {
    return account.network.request(Api.functions.account.changeAuthorizationSettings(flags: 1 << 1, hash: hash, encryptedRequestsDisabled: nil, callRequestsDisabled: accepts ? .boolFalse : .boolTrue))
    |> mapError { error -> UpdateSessionError in
        return .generic
    }
    |> mapToSignal { _ -> Signal<Void, UpdateSessionError> in
        return .single(Void())
    }
}

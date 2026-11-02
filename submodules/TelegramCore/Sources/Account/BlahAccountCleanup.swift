import BlahIdentity
import Postbox
import SwiftSignalKit

func blahInvalidateAccountCustody(slot: String) -> Signal<Void, NoError> {
    return Signal { subscriber in
        let task = Task {
            do { try await BlahIdentityStore.shared.invalidate(slot: slot) }
            catch { Logger.shared.log("AccountManager", "Blah custody deletion deferred") }
            subscriber.putNext(())
            subscriber.putCompletion()
        }
        return ActionDisposable { task.cancel() }
    }
}

func blahRemoveAccountCustody(slot: String) -> Signal<Void, NoError> {
    return Signal { subscriber in
        let task = Task {
            while !Task.isCancelled {
                do {
                    try await BlahIdentityStore.shared.remove(slot: slot)
                    subscriber.putNext(())
                    subscriber.putCompletion()
                    return
                } catch {
                    Logger.shared.log("AccountManager", "Blah slot cleanup deferred")
                    do { try await Task.sleep(nanoseconds: 2_000_000_000) } catch { return }
                }
            }
        }
        return ActionDisposable { task.cancel() }
    }
}

func blahDiscardLegacyCustody(accountManager: AccountManager<TelegramAccountManagerTypes>) -> Task<Void, Never> {
    return Task {
        while !Task.isCancelled {
            var discarded = false
            do {
                try await BlahIdentityStore.shared.discardLegacyCustody()
                discarded = true
            } catch { Logger.shared.log("managedCleanupAccounts", "Blah legacy deletion deferred") }
            do {
                let slots = try await BlahIdentityStore.shared.pendingLegacyLogouts()
                let view = await accountManager.accountRecords().get()
                for slot in slots {
                    if let record = view.records.first(where: { accountRecordIdPathName($0.id) == slot }) {
                        await logoutFromAccount(id: record.id, accountManager: accountManager, alreadyLoggedOutRemotely: true).get()
                    }
                    try await BlahIdentityStore.shared.acknowledgeLegacyLogout(slot: slot)
                }
                if discarded { return }
            } catch { Logger.shared.log("managedCleanupAccounts", "Blah legacy cleanup deferred") }
            do { try await Task.sleep(nanoseconds: 2_000_000_000) } catch { return }
        }
    }
}

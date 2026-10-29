import Foundation
import TelegramCore

public enum BlahIdentitySignInAction {
    case saved(id: String)
    case link(domain: String, homeDomain: String)
}

// Only routing information crosses to the new unauthorized account.
public enum BlahIdentitySignInHandoff {
    private static let lock = NSLock()
    private static var pending: (id: UUID, sourceAccountId: AccountRecordId, action: BlahIdentitySignInAction, expires: Date)?

    public static func put(_ action: BlahIdentitySignInAction, sourceAccountId: AccountRecordId) -> UUID {
        lock.lock()
        defer { lock.unlock() }
        let id = UUID()
        pending = (id, sourceAccountId, action, Date().addingTimeInterval(300.0))
        return id
    }

    public static func take(excluding accountId: AccountRecordId) -> BlahIdentitySignInAction? {
        lock.lock()
        defer { lock.unlock() }
        guard let value = pending else { return nil }
        guard value.expires > Date() else { pending = nil; return nil }
        guard value.sourceAccountId != accountId else { return nil }
        pending = nil
        return value.action
    }

    public static func cancel(_ id: UUID) {
        lock.lock()
        defer { lock.unlock() }
        if pending?.id == id { pending = nil }
    }
}

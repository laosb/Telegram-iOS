import Foundation
import BlahDiem
import DiemSwiftCrypto

@available(iOS 18.0, macOS 15.0, *)
public struct BlahHome: Codable, Sendable {
    public let domain: String
    public let profile: Data

    public func verified() async throws -> (Profile, DCProfile) {
        let signed = try Profile(encoding: Array(profile))
        try await signed.verify(using: SwiftCryptoBackend())
        let dc = try DCProfile(signed)
        guard dc.domains.contains(domain), dc.namespaceGeneration != nil else { throw BlahIdentityError.invalidProfile }
        return (signed, dc)
    }

    public static func discover(_ input: String, previous: BlahHome?) async throws -> BlahHome {
        let domain = input.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard DomainName.isValid(domain) else { throw BlahIdentityError.invalidProfile }
        let home = BlahHome(domain: domain, profile: try await BlahProfileHost.fetch(domain))
        let (next, dc) = try await home.verified()
        if let previous {
            let before = try Profile(encoding: Array(previous.profile))
            let oldDC = try DCProfile(before)
            guard previous.domain == domain, before.id == next.id, oldDC.namespaceGeneration == dc.namespaceGeneration else {
                throw BlahIdentityError.wrongHome
            }
            try BlahProfileHost.requireMonotonic(next, after: before)
        }
        return home
    }
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahProfileHost {
    private static let maximumBytes = 100000

    public static func fetch(_ domain: String) async throws -> Data {
        guard DomainName.isValid(domain), let url = URL(string: "https://\(domain)/.well-known/blah/profile.cbor") else {
            throw BlahIdentityError.invalidProfile
        }
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 15
        let session = URLSession(configuration: configuration, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.setValue("application/cbor", forHTTPHeaderField: "Accept")
        let (bytes, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse, response.statusCode == 200,
            response.mimeType == "application/cbor", response.expectedContentLength <= maximumBytes else {
            throw BlahIdentityError.invalidProfile
        }
        var data = Data()
        for try await byte in bytes {
            guard data.count < maximumBytes else { throw BlahIdentityError.invalidProfile }
            data.append(byte)
        }
        return data
    }

    static func requireMonotonic(_ next: Profile, after previous: Profile) throws {
        guard next.id == previous.id, next.generation >= previous.generation,
            next.revision >= previous.revision,
            next.revision != previous.revision || next.digest == previous.digest else {
            throw BlahIdentityError.staleProfile
        }
    }
}

private final class NoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

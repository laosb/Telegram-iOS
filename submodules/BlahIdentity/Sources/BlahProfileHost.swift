import Foundation
import CryptoKit
import BlahDiem
import DiemSwiftCrypto

@available(iOS 18.0, macOS 15.0, *)
public struct BlahHome: Codable, Sendable {
    public let domain: String
    public let profile: Data

    public func verified() async throws -> (DCProfile, DCProfile.Content) {
        let signed = try DCProfile(encoding: Array(profile))
        try await signed.verify(using: SwiftCryptoBackend())
        guard signed.serves(domain), signed.namespaceGeneration != nil else { throw BlahIdentityError.invalidProfile }
        return (signed, signed.content)
    }

    public static func discover(_ input: String, previous: BlahHome?) async throws -> BlahHome {
        let domain = try BlahProfileHost.domain(input).name
        let home = BlahHome(domain: domain, profile: try await BlahProfileHost.fetch(domain))
        let (next, dc) = try await home.verified()
        if let previous {
            let before = try DCProfile(encoding: Array(previous.profile))
            try await before.verify(using: SwiftCryptoBackend(), at: before.validity.notBefore)
            guard previous.domain == domain, before.id == next.id, before.namespaceGeneration == dc.namespaceGeneration else {
                throw BlahIdentityError.wrongHome
            }
            try BlahProfileHost.requireMonotonic(next, after: before)
        }
        return home
    }
}

@available(iOS 18.0, macOS 15.0, *)
public enum BlahProfileHost {
    static func domain(_ input: String) throws -> DomainName {
        guard let domain = DomainName(normalizing: input.trimmingCharacters(in: .whitespacesAndNewlines)) else {
            throw BlahIdentityError.invalidProfile
        }
        return domain
    }

    public static func fetch(_ domain: String) async throws -> Data {
        guard DomainName.isValid(domain) else {
            throw BlahIdentityError.invalidProfile
        }
        let response = try await BlahHostingHTTPClient().send(HostingHTTPRequest(method: .get,
            url: "https://\(domain)/.well-known/blah/profile.cbor", headers: ["Accept": "application/cbor"]))
        guard response.status == 200,
            response.header("content-type")?.split(separator: ";").first?.trimmingCharacters(in: .whitespaces).lowercased() == "application/cbor"
        else { throw BlahIdentityError.invalidProfile }
        return Data(response.body)
    }

    static func requireMonotonic(_ next: some Profile, after previous: some Profile) throws {
        guard next.id == previous.id, next.generation >= previous.generation,
            next.revision >= previous.revision,
            next.revision != previous.revision || next.digest == previous.digest else {
            throw BlahIdentityError.staleProfile
        }
    }
}

/// Credential-free transport shared by discovery and Diem's hosted-name client.
@available(iOS 18.0, macOS 15.0, *)
struct BlahHostingHTTPClient: HostingHTTPClient {
    func send(_ outbound: HostingHTTPRequest) async throws -> HostingHTTPResponse {
        guard let url = URL(string: outbound.url), url.scheme == "https",
            let host = url.host, DomainName.isValid(host), url.user == nil, url.password == nil,
            url.fragment == nil, url.port == nil,
            outbound.headers.keys.allSatisfy({ ["accept", "content-type", "diem-hosting-proof"].contains($0.lowercased()) }),
            outbound.headers.values.allSatisfy({ !$0.contains("\r") && !$0.contains("\n") })
        else { throw BlahIdentityError.invalidProfile }
        try Task.checkCancellation()
        let configuration = URLSessionConfiguration.ephemeral
        configuration.httpCookieStorage = nil
        configuration.urlCredentialStorage = nil
        configuration.requestCachePolicy = .reloadIgnoringLocalCacheData
        configuration.timeoutIntervalForRequest = 30
        configuration.timeoutIntervalForResource = 30
        let session = URLSession(configuration: configuration, delegate: NoRedirect(), delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        var request = URLRequest(url: url)
        request.httpMethod = outbound.method.rawValue
        request.httpBody = outbound.body.map(Data.init)
        for (name, value) in outbound.headers { request.setValue(value, forHTTPHeaderField: name) }
        request.setValue("identity", forHTTPHeaderField: "Accept-Encoding")
        let (bytes, response) = try await session.bytes(for: request)
        guard let response = response as? HTTPURLResponse,
            response.expectedContentLength <= CBOR.maximumBytes,
            response.value(forHTTPHeaderField: "Content-Encoding").map({ $0.lowercased() == "identity" }) ?? true else {
            throw BlahIdentityError.invalidProfile
        }
        var data = Data()
        for try await byte in bytes {
            try Task.checkCancellation()
            guard data.count < CBOR.maximumBytes else { throw BlahIdentityError.invalidProfile }
            data.append(byte)
        }
        var headers: [String: String] = [:]
        for (name, value) in response.allHeaderFields {
            let name = String(describing: name).lowercased()
            headers[name] = headers[name].map { $0 + ", " + String(describing: value) } ?? String(describing: value)
        }
        return HostingHTTPResponse(status: response.statusCode, headers: headers, body: Array(data))
    }
}

/// Platform SHA-256 keeps hosted-name claims off the UI thread and cancellable.
@available(iOS 18.0, macOS 15.0, *)
struct BlahHostingProofOfWork: ProofOfWorkSolver {
    func solve(_ puzzle: ProofOfWorkPuzzle) async throws -> [UInt8] {
        var counter: UInt64 = 0
        let prefix = puzzle.input.count
        var input = puzzle.input + [UInt8](repeating: 0, count: 8)
        while true {
            if counter % 1024 == 0 {
                try Task.checkCancellation()
                await Task.yield()
            }
            withUnsafeBytes(of: counter.bigEndian) { bytes in
                for i in 0..<8 { input[prefix + i] = bytes[i] }
            }
            var leading = 0
            for byte in SHA256.hash(data: input) {
                leading += byte.leadingZeroBitCount
                if byte != 0 { break }
            }
            if leading >= puzzle.requiredBits { return Array(input[prefix...]) }
            guard counter != UInt64.max else { throw ProfileHostingError.unsolvable(puzzle.label) }
            counter += 1
        }
    }
}

private final class NoRedirect: NSObject, URLSessionTaskDelegate, @unchecked Sendable {
    func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
        newRequest request: URLRequest, completionHandler: @escaping (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

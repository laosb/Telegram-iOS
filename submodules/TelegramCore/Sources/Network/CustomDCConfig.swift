import Foundation
import MtProtoKit

public struct CustomDCConfig {
    public struct DC {
        public let id: Int
        public let endpoints: [(ip: String, port: Int)]
        public let rsaPublicKeyPem: String

        public init(id: Int, endpoints: [(ip: String, port: Int)], rsaPublicKeyPem: String) {
            self.id = id
            self.endpoints = endpoints
            self.rsaPublicKeyPem = rsaPublicKeyPem
        }
    }

    public let dcs: [DC]

    public init(dcs: [DC]) {
        self.dcs = dcs
    }

    /// Each independently pinned Blah home occupies DC 1 in its own account slot.
    public static var initialDatacenterId: Int { 1 }

    /// Installs the complete verified address/RSA allowlist for this account's home.
    public func apply(to context: MTContext) {
        var addressSets: [NSNumber: MTDatacenterAddressSet] = [:]
        var publicKeys: [NSNumber: [[String: Any]]] = [:]
        for dc in dcs {
            let addresses = dc.endpoints.compactMap { endpoint -> MTDatacenterAddress? in
                guard let port = UInt16(exactly: endpoint.port), port != 0 else { return nil }
                return MTDatacenterAddress(
                    ip: endpoint.ip,
                    port: port,
                    preferForMedia: false,
                    restrictToTcp: false,
                    cdn: false,
                    preferForProxy: false,
                    secret: nil
                )
            }
            let id = NSNumber(value: dc.id)
            addressSets[id] = MTDatacenterAddressSet(addressList: addresses)
            publicKeys[id] = [["key": dc.rsaPublicKeyPem]]
        }
        context.setPinnedDatacenterAddresses(addressSets, publicKeys: publicKeys)
    }
}

import Foundation
import MtProtoKit

// _customDCConfigData is provided by CustomDCConfigGenerated.swift (auto-generated at build time).

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

    public let defaultDcId: Int
    public let dcs: [DC]

    public init(defaultDcId: Int, dcs: [DC]) {
        self.defaultDcId = defaultDcId
        self.dcs = dcs
    }

    /// The active custom DC config, or `nil` when running against the standard Telegram network.
    public static var shared: CustomDCConfig? { _customDCConfigData }

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

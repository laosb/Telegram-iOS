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

    /// Returns the custom `defaultDcId` when a server config is active, otherwise falls back
    /// to the standard Telegram convention (DC 1 for debug builds, DC 2 for release).
    public static var initialDatacenterId: Int {
        if let dc = _customDCConfigData { return dc.defaultDcId }
        #if DEBUG
        return 1
        #else
        return 2
        #endif
    }

    /// Overrides seed addresses and pre-loads RSA public keys for each custom DC.
    public func apply(to context: MTContext) {
        for dc in dcs {
            let addresses = dc.endpoints.compactMap { endpoint -> MTDatacenterAddress? in
                MTDatacenterAddress(
                    ip: endpoint.ip,
                    port: UInt16(endpoint.port),
                    preferForMedia: false,
                    restrictToTcp: false,
                    cdn: false,
                    preferForProxy: false,
                    secret: nil
                )
            }
            if !addresses.isEmpty {
                context.setSeedAddressSetForDatacenterWithId(
                    dc.id,
                    seedAddressSet: MTDatacenterAddressSet(addressList: addresses)
                )
            }
            context.updatePublicKeysForDatacenter(withId: dc.id, publicKeys: [["key": dc.rsaPublicKeyPem]])
        }
    }
}

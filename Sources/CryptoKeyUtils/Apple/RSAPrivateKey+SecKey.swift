#if canImport(Security)
import Foundation
import Security

extension RSAPrivateKey: SecKeyConvertible {
    public var secKey: SecKey {
        get throws {
            try SecKeyUtils.makeSecKey(
                dataCandidates: [try pkcs1der, try pkcs8der],
                keyType: kSecAttrKeyTypeRSA,
                keyClass: kSecAttrKeyClassPrivate,
                keySizeInBits: publicKey.bitSize
            )
        }
    }
}
#endif
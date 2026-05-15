#if canImport(Security)
import Foundation
import Security

extension RSAPublicKey: SecKeyConvertible {
    public var secKey: SecKey {
        get throws {
            try SecKeyUtils.makeSecKey(
                data: pkcs1der,
                keyType: kSecAttrKeyTypeRSA,
                keyClass: kSecAttrKeyClassPublic,
                keySizeInBits: bitSize
            )
        }
    }
}
#endif
#if canImport(Security)
import Foundation
import Security

extension ECPublicKey: SecKeyConvertible {
    public var secKey: SecKey {
        get throws {
            try SecKeyUtils.makeSecKey(
                data: x963,
                keyType: try SecKeyUtils.secKeyType(for: curve),
                keyClass: kSecAttrKeyClassPublic,
                keySizeInBits: curve.keySizeInBits
            )
        }
    }
}
#endif
#if canImport(Security)
import Foundation
import Security

extension ECPrivateKey: SecKeyConvertible {
    public var secKey: SecKey {
        get throws {
            var keyData = publicKey.x963
            keyData.append(d)
            return try SecKeyUtils.makeSecKey(
                data: keyData,
                keyType: try SecKeyUtils.secKeyType(for: curve),
                keyClass: kSecAttrKeyClassPrivate,
                keySizeInBits: curve.keySizeInBits
            )
        }
    }
}
#endif
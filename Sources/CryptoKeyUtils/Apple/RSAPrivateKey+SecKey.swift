#if canImport(Security)
import Foundation
import Security

extension RSAPrivateKey: SecKeyConvertible {
    public init(secKey: SecKey) throws {
        let descriptor = try SecKeyUtils.descriptor(for: secKey)
        guard descriptor.keyType == kSecAttrKeyTypeRSA as String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Expected RSA sec key type, got \(descriptor.keyType)")
        }
        guard descriptor.keyClass == kSecAttrKeyClassPrivate as String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Expected private sec key class, got \(descriptor.keyClass)")
        }

        try self.init(der: SecKeyUtils.externalRepresentation(of: secKey))
    }

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
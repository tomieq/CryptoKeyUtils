#if canImport(Security)
import Foundation
import Security

extension RSAPublicKey: SecKeyConvertible {
    public init(secKey: SecKey) throws {
        let descriptor = try SecKeyUtils.descriptor(for: secKey)
        guard descriptor.keyType == kSecAttrKeyTypeRSA as String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Expected RSA sec key type, got \(descriptor.keyType)")
        }
        guard descriptor.keyClass == kSecAttrKeyClassPublic as String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Expected public sec key class, got \(descriptor.keyClass)")
        }

        try self.init(der: SecKeyUtils.externalRepresentation(of: secKey))
    }

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
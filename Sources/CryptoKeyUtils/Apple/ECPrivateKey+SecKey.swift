#if canImport(Security)
import Foundation
import Security

extension ECPrivateKey: SecKeyConvertible {
    public init(secKey: SecKey) throws {
        let descriptor = try SecKeyUtils.descriptor(for: secKey)
        guard descriptor.keyClass == kSecAttrKeyClassPrivate as String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Expected private sec key class, got \(descriptor.keyClass)")
        }

        let curve = try SecKeyUtils.curve(for: descriptor)
        let keyData = try SecKeyUtils.externalRepresentation(of: secKey)
        let key = try ECPrivateKey(x963: keyData)
        guard key.curve == curve else {
            throw SecKeyConversionError.invalidExternalRepresentation(reason: "Expected EC private key curve \(curve), got \(key.curve)")
        }
        self = key
    }

    public var secKey: SecKey {
        get throws {
            return try SecKeyUtils.makeSecKey(
                data: x963,
                keyType: try SecKeyUtils.secKeyType(for: curve),
                keyClass: kSecAttrKeyClassPrivate,
                keySizeInBits: curve.keySizeInBits
            )
        }
    }
}
#endif
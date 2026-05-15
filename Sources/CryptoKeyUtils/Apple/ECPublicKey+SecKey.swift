#if canImport(Security)
import Foundation
import Security

extension ECPublicKey: SecKeyConvertible {
    public init(secKey: SecKey) throws {
        let descriptor = try SecKeyUtils.descriptor(for: secKey)
        guard descriptor.keyClass == kSecAttrKeyClassPublic as String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Expected public sec key class, got \(descriptor.keyClass)")
        }

        let curve = try SecKeyUtils.curve(for: descriptor)
        let keyData = try SecKeyUtils.externalRepresentation(of: secKey)
        let key = try ECPublicKey(x963: keyData)
        guard key.curve == curve else {
            throw SecKeyConversionError.invalidExternalRepresentation(reason: "Expected EC public key curve \(curve), got \(key.curve)")
        }
        self = key
    }

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
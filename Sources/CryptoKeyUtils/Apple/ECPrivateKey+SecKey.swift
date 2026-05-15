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
        let expectedLength = 1 + 3 * curve.valueLength
        guard keyData.count == expectedLength else {
            throw SecKeyConversionError.invalidExternalRepresentation(reason: "Expected EC private key length \(expectedLength), got \(keyData.count)")
        }
        guard keyData.first == 0x04 else {
            throw SecKeyConversionError.invalidExternalRepresentation(reason: "Expected EC private key to start with 0x04")
        }

        let payload = keyData.dropFirst()
        self.init(
            x: Data(payload.prefix(curve.valueLength)),
            y: Data(payload.dropFirst(curve.valueLength).prefix(curve.valueLength)),
            d: Data(payload.dropFirst(2 * curve.valueLength)),
            curve: curve
        )
    }

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
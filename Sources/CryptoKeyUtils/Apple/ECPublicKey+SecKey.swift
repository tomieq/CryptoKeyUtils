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
        let expectedLength = 1 + 2 * curve.valueLength
        guard keyData.count == expectedLength else {
            throw SecKeyConversionError.invalidExternalRepresentation(reason: "Expected EC public key length \(expectedLength), got \(keyData.count)")
        }
        guard keyData.first == 0x04 else {
            throw SecKeyConversionError.invalidExternalRepresentation(reason: "Expected EC public key to start with 0x04")
        }

        let payload = keyData.dropFirst()
        self.init(
            x: Data(payload.prefix(curve.valueLength)),
            y: Data(payload.dropFirst(curve.valueLength)),
            curve: curve
        )
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
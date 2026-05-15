#if canImport(Security)
import Foundation
import Security

enum SecKeyUtils {
    struct Descriptor {
        let keyType: String
        let keyClass: String
        let keySizeInBits: Int
    }

    static func makeSecKey(data: Data, keyType: CFString, keyClass: CFString, keySizeInBits: Int) throws -> SecKey {
        try makeSecKey(
            dataCandidates: [data],
            keyType: keyType,
            keyClass: keyClass,
            keySizeInBits: keySizeInBits
        )
    }

    static func makeSecKey(dataCandidates: [Data], keyType: CFString, keyClass: CFString, keySizeInBits: Int) throws -> SecKey {
        let attributes: CFDictionary = [
            kSecAttrKeyType: keyType,
            kSecAttrKeyClass: keyClass,
            kSecAttrKeySizeInBits: keySizeInBits
        ] as CFDictionary

        var lastError: String?
        for data in dataCandidates {
            var error: Unmanaged<CFError>?
            if let key = SecKeyCreateWithData(data as CFData, attributes, &error) {
                return key
            }
            if let error {
                let cfError = error.takeRetainedValue()
                lastError = CFErrorCopyDescription(cfError) as String
            }
        }

        throw SecKeyConversionError.keyCreationFailed(reason: lastError ?? "SecKeyCreateWithData returned nil")
    }

    static func externalRepresentation(of secKey: SecKey) throws -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(secKey, &error) else {
            if let error {
                let cfError = error.takeRetainedValue()
                throw SecKeyConversionError.externalRepresentationFailed(reason: CFErrorCopyDescription(cfError) as String)
            }
            throw SecKeyConversionError.externalRepresentationFailed(reason: "SecKeyCopyExternalRepresentation returned nil")
        }
        return data as Data
    }

    static func descriptor(for secKey: SecKey) throws -> Descriptor {
        guard let cfAttributes = SecKeyCopyAttributes(secKey) else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "SecKeyCopyAttributes returned nil")
        }
        let attributes = cfAttributes as NSDictionary
        guard let keyType = attributes[kSecAttrKeyType] as? String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Missing kSecAttrKeyType")
        }
        guard let keyClass = attributes[kSecAttrKeyClass] as? String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Missing kSecAttrKeyClass")
        }
        guard let keySizeInBits = attributes[kSecAttrKeySizeInBits] as? Int ?? (attributes[kSecAttrKeySizeInBits] as? NSNumber)?.intValue else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Missing kSecAttrKeySizeInBits")
        }
        return Descriptor(keyType: keyType, keyClass: keyClass, keySizeInBits: keySizeInBits)
    }

    static func secKeyType(for curve: ECCurve) throws -> CFString {
        switch curve {
        case .secp256r1, .secp384r1, .secp521r1:
            return kSecAttrKeyTypeECSECPrimeRandom
        case .curve25519, .secp256k1:
            throw SecKeyConversionError.unsupportedCurve(curve)
        }
    }

    static func curve(for descriptor: Descriptor) throws -> ECCurve {
        guard descriptor.keyType == kSecAttrKeyTypeECSECPrimeRandom as String else {
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Expected EC sec key type, got \(descriptor.keyType)")
        }

        switch descriptor.keySizeInBits {
        case 256:
            return .secp256r1
        case 384:
            return .secp384r1
        case 521:
            return .secp521r1
        default:
            throw SecKeyConversionError.invalidSecKeyAttributes(reason: "Unsupported EC key size: \(descriptor.keySizeInBits)")
        }
    }
}
#endif
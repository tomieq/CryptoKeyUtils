#if canImport(Security)
import Foundation
import Security

enum SecKeyUtils {
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

    static func secKeyType(for curve: ECCurve) throws -> CFString {
        switch curve {
        case .secp256r1, .secp384r1, .secp521r1:
            return kSecAttrKeyTypeECSECPrimeRandom
        case .curve25519, .secp256k1:
            throw SecKeyConversionError.unsupportedCurve(curve)
        }
    }
}
#endif
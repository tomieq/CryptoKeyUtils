#if canImport(Security)
import Foundation
import Security
import Testing
import CryptoKeyUtils

struct SecKeyConvertibleTests {
    @Test
    func rsaPublicKeyToSecKey() throws {
        let pemString = """
            -----BEGIN PUBLIC KEY-----
            MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAKj34GkxFhD90vcNLYLInFEX6Ppy1tPf
            9Cnzj4p4WGeKLs1Pt8QuKUpRKfFLfRYC9AIKjbJTWit+CqvjWYzvQwECAwEAAQ==
            -----END PUBLIC KEY-----
            """

        let key = try RSAPublicKey(pem: pemString)
        let secKey = try key.secKey

        #expect(try secKey.externalRepresentation() == key.pkcs1der)
    }

    @Test
    func rsaPrivateKeyToSecKey() throws {
        let sourceKey = try makeRSAKeyPair(sizeInBits: 2048)
        let externalRepresentation = try sourceKey.externalRepresentation()
        let key = try RSAPrivateKey(der: externalRepresentation)
        let secKey = try key.secKey

        #expect(try secKey.externalRepresentation() == externalRepresentation)
    }

    @Test
    func ecPublicKeyToSecKey() throws {
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPublicKey(.hexString(x: x, y: y, curve: .secp256r1))
        let secKey = try key.secKey

        #expect(try secKey.externalRepresentation() == key.x963)
    }

    @Test
    func ecPrivateKeyToSecKey() throws {
        let d = "53893267A86D63D134001E5690436FE6AFB05F04820BA58A2197347C97B5279A"
        let x = "405964ECD9FB3142E17FFC9A765300F50005761207275E27A98F554BB78E904B"
        let y = "2E4D27C6DBA042BD31C5326049F24198A667213EBF61FA31918E9DD535D6BF7B"
        let key = try ECPrivateKey(.hexString(x: x, y: y, d: d, curve: .secp256r1))
        let secKey = try key.secKey

        var expected = key.publicKey.x963
        expected.append(key.d)
        #expect(try secKey.externalRepresentation() == expected)
    }

    @Test
    func ecUnsupportedCurveThrows() throws {
        let x = Data(repeating: 1, count: 32)
        let y = Data(repeating: 2, count: 32)
        let key = ECPublicKey(x: x, y: y, curve: .secp256k1)

        #expect(throws: SecKeyConversionError.self) {
            _ = try key.secKey
        }
    }
}

private extension SecKey {
    func externalRepresentation() throws -> Data {
        var error: Unmanaged<CFError>?
        guard let data = SecKeyCopyExternalRepresentation(self, &error) else {
            if let error {
                let cfError = error.takeRetainedValue()
                throw NSError(
                    domain: kCFErrorDomainOSStatus as String,
                    code: CFErrorGetCode(cfError),
                    userInfo: [NSLocalizedDescriptionKey: CFErrorCopyDescription(cfError) as String]
                )
            }
            throw NSError(domain: kCFErrorDomainOSStatus as String, code: Int(errSecParam), userInfo: nil)
        }
        return data as Data
    }
}

private func makeRSAKeyPair(sizeInBits: Int) throws -> SecKey {
    let attributes: CFDictionary = [
        kSecAttrKeyType: kSecAttrKeyTypeRSA,
        kSecAttrKeySizeInBits: sizeInBits
    ] as CFDictionary

    var error: Unmanaged<CFError>?
    guard let key = SecKeyCreateRandomKey(attributes, &error) else {
        if let error {
            let cfError = error.takeRetainedValue()
            throw NSError(
                domain: kCFErrorDomainOSStatus as String,
                code: CFErrorGetCode(cfError),
                userInfo: [NSLocalizedDescriptionKey: CFErrorCopyDescription(cfError) as String]
            )
        }
        throw NSError(domain: kCFErrorDomainOSStatus as String, code: Int(errSecParam), userInfo: nil)
    }
    return key
}
#endif